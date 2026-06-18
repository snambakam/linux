// SPDX-License-Identifier: GPL-2.0-only
/*
 * vbs_park - minimal KVM VM-planes secure-plane park loop
 *
 * This provides only the secure-plane (plane >0) side of the VM-planes
 * park/dispatch handshake so that an otherwise ordinary kernel can act as
 * plane 1.  It is deliberately independent of the full VBS/HEKI stack
 * (CONFIG_VBS): it implements no security policy.  Its single job is to hand
 * control back to the normal plane (plane 0) via the KVM_HC_VBS_VTL_RETURN
 * hypercall and then service VTL calls from the shared calling area.
 *
 * Control flow (all within plane 0's single KVM_RUN; see
 * arch/x86/kvm/x86.c __kvm_emulate_hypercall):
 *
 *   plane 0                        KVM                       plane 1 (here)
 *   -------                        ---                       --------------
 *   fill calling area
 *   HC_VBS_VTL_CALL(ca_gpa) ─────▶ switch_plane ───────────▶ resume in
 *                                  (RAX := ca_gpa)            vtl_return()
 *                                                            handle call_id
 *                                                            write ca->status
 *   resume after VTL_CALL ◀─────── switch_plane ◀─────────── HC_VBS_VTL_RETURN
 *
 * Activated by the "vbs_park" kernel command-line option; without it this
 * kernel boots normally and never parks.
 */

#define pr_fmt(fmt) "vbs-park: " fmt

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/kvm_para.h>
#include <asm/kvm_para.h>

/*
 * Shared-memory calling area.  MUST match struct vbs_kvm_ca in
 * security/vbs/kvm_planes.c (the normal-plane <-> secure-plane wire ABI):
 *
 *   [ call_pending | call_id | status | arg_size | resp_size | buffer ]
 */
struct vtl_ca {
	__u8	call_pending;	/* 1 while call is in flight		*/
	__u8	rsvd[3];
	__u32	call_id;	/* request id (set by caller)		*/
	__s32	status;		/* return code (set by responder)	*/
	__u32	arg_size;	/* request payload size			*/
	__u32	resp_size;	/* response payload size		*/
	__u8	buffer[];	/* request data in, response data out	*/
} __packed;

/* Set from the "vbs_park" kernel command-line option. */
static bool vbs_park_active __ro_after_init;

static int __init vbs_park_setup(char *str)
{
	vbs_park_active = true;
	return 1;
}
__setup("vbs_park", vbs_park_setup);

/*
 * Park the secure plane and hand control back to the normal plane.  On the
 * next VTL call KVM resumes us here with the calling-area GPA in the
 * hypercall return value (RAX).  @status is carried for tracing only; the
 * real result is already in the calling area.
 */
static u64 vtl_return(long status)
{
	return kvm_hypercall1(KVM_HC_VBS_VTL_RETURN, (unsigned long)status);
}

static int vbs_park_fn(void *unused)
{
	long status = 0;

	pr_info("secure-plane park loop started\n");

	for (;;) {
		struct vtl_ca *ca;
		u64 ca_gpa;

		/* Park; resume with the next request's calling-area GPA. */
		ca_gpa = vtl_return(status);
		if (!ca_gpa) {
			status = -EINVAL;
			continue;
		}

		ca = memremap(ca_gpa, PAGE_SIZE, MEMREMAP_WB);
		if (!ca) {
			pr_err_ratelimited("failed to map calling area 0x%llx\n",
					   ca_gpa);
			status = -EFAULT;
			continue;
		}

		/*
		 * No security policy lives here: acknowledge the call as a
		 * no-op so the normal plane can make progress.  Replace this
		 * with real handlers (or move plane 1 to a dedicated SVSM) to
		 * enforce actual VBS semantics.
		 */
		pr_info_ratelimited("VTL call id=0x%x arg_size=%u (no-op)\n",
				    ca->call_id, ca->arg_size);
		ca->status    = 0;
		ca->resp_size = 0;
		status = 0;

		memunmap(ca);
	}

	return 0;
}

static int __init vbs_park_init(void)
{
	struct task_struct *t;

	if (!vbs_park_active)
		return 0;

	t = kthread_run(vbs_park_fn, NULL, "vbs-park");
	if (IS_ERR(t)) {
		pr_err("failed to start park loop: %ld\n", PTR_ERR(t));
		return PTR_ERR(t);
	}

	return 0;
}
late_initcall(vbs_park_init);
