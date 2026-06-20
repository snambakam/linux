// SPDX-License-Identifier: GPL-2.0-only
/*
 * secure_monitor - KVM VM-planes secure-plane monitor
 *
 * This is the secure-plane (plane >0) side of the VM-planes park/dispatch
 * handshake.  It lets an otherwise ordinary kernel act as the secure plane
 * (conventionally plane 1 / VTL1 / VMPL0, though the index is not hard-coded)
 * without pulling in the full VBS/HEKI stack (CONFIG_VBS).  Its single job is
 * to hand control back to the normal plane (plane 0) via the
 * KVM_HC_VBS_VTL_RETURN hypercall and then service VTL calls from the shared
 * calling area.
 *
 * Control flow (all within plane 0's single KVM_RUN; see
 * arch/x86/kvm/x86.c __kvm_emulate_hypercall):
 *
 *   normal plane                   KVM                       secure plane
 *   ------------                   ---                       ------------
 *   fill calling area
 *   HC_VBS_VTL_CALL(ca_gpa) ─────▶ switch_plane ───────────▶ resume in
 *                                  (RAX := ca_gpa)            secmon_vtl_return()
 *                                                            dispatch(call_id)
 *                                                            write ca->status
 *   resume after VTL_CALL ◀─────── switch_plane ◀─────────── HC_VBS_VTL_RETURN
 *
 * Because all planes of a VM share the same memslots (struct kvm_plane has no
 * memslots of its own; they live in struct kvm), the secure plane sees the
 * same guest-physical address space as the normal plane and can read the
 * calling area and the GPAs referenced by each request directly.  This same
 * sharing means the secure plane must explicitly hide its own RAM from the
 * normal plane: on startup it walks its system RAM and asks KVM (via
 * KVM_HC_VBS_SET_MEM_ATTRS) to deny the normal plane read/write/exec access,
 * so plane 0 cannot read secure-plane memory.
 *
 * For now every VTL call is acknowledged as a no-op so the normal plane can
 * make progress; the remaining per-call handlers (HEKI memory protection,
 * kernel sealing, …) are plumbed in incrementally.
 *
 * Activated by the "secure_monitor" kernel command-line option; without it
 * this kernel boots normally and never parks.
 */

#define pr_fmt(fmt) "vbs-secmon: " fmt

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/vbs.h>
#include <linux/kvm_para.h>
#include <asm/kvm_para.h>

/*
 * Shared-memory calling area.  MUST match struct vbs_kvm_ca in
 * security/vbs/kvm_planes.c (the normal-plane <-> secure-plane wire ABI):
 *
 *   [ call_pending | call_id | status | arg_size | resp_size | buffer ]
 */
struct vbs_kvm_ca {
	__u8	call_pending;	/* 1 while call is in flight		*/
	__u8	rsvd[3];
	__u32	call_id;	/* request id (set by caller)		*/
	__s32	status;		/* return code (set by responder)	*/
	__u32	arg_size;	/* request payload size			*/
	__u32	resp_size;	/* response payload size		*/
	__u8	buffer[];	/* request data in, response data out	*/
} __packed;

/* Set from the "secure_monitor" kernel command-line option. */
static bool secmon_active __ro_after_init;

static int __init secmon_setup(char *str)
{
	secmon_active = true;
	return 1;
}
__setup("secure_monitor", secmon_setup);

/*
 * Park the secure plane and hand control back to the normal plane.  On the
 * next VTL call KVM resumes us here with the calling-area GPA in the
 * hypercall return value (RAX).  @status is carried for tracing only; the
 * real result is already in the calling area.
 */
static u64 secmon_vtl_return(long status)
{
	return kvm_hypercall1(KVM_HC_VBS_VTL_RETURN, (unsigned long)status);
}

/*
 * Apply EPT permissions on a normal-plane GPA range from the secure plane.
 *
 * The secure plane cannot issue the host KVM_SET_MEMORY_ATTRIBUTES ioctl, so
 * it asks KVM to do it via the KVM_HC_VBS_SET_MEM_ATTRS hypercall, which KVM
 * honours only for a higher-privilege plane (it applies the attributes to the
 * plane directly below the caller).  @perms carries the access bits the
 * normal plane should retain (VBS_MEM_*); KVM translates a cleared
 * read/write/exec bit into NO_READ / NO_WRITE / NO_EXEC.  @perms == 0 hides
 * the range entirely.
 */
static int secmon_apply_attrs(u64 gpa, u64 size, u32 perms)
{
	long ret;

	pr_debug("apply_attrs gpa=0x%llx size=0x%llx perms=%c%c%c\n",
		 gpa, size,
		 (perms & VBS_MEM_READ)  ? 'r' : '-',
		 (perms & VBS_MEM_WRITE) ? 'w' : '-',
		 (perms & VBS_MEM_EXEC)  ? 'x' : '-');

	ret = kvm_hypercall3(KVM_HC_VBS_SET_MEM_ATTRS, gpa, size, perms);
	if (ret)
		return (int)ret;

	return 0;
}

/*
 * Hide one range of this plane's RAM from the normal plane.  perms = 0 means
 * "retain no access" (no read/write/exec), so the normal plane faults and is
 * denied if it tries to touch secure-plane memory.
 */
static int secmon_hide_range(unsigned long start_pfn, unsigned long nr_pages,
			     void *arg)
{
	unsigned long gpa = start_pfn << PAGE_SHIFT;
	unsigned long size = nr_pages << PAGE_SHIFT;
	int r;

	r = secmon_apply_attrs(gpa, size, 0);
	if (r)
		pr_warn("failed to protect RAM [0x%lx+0x%lx]: %d\n",
			gpa, size, r);
	else
		pr_info("protected RAM [0x%lx+0x%lx] from normal plane\n",
			gpa, size);

	/* Continue with the remaining ranges even if one fails. */
	return 0;
}

/*
 * Deny the normal plane access to all of the secure plane's own RAM.  Runs
 * while the normal plane is frozen in the KVM_RUN that switched to us, so
 * there is no window during which the memory is both populated and still
 * readable by the normal plane.
 */
static void secmon_protect_self(void)
{
	walk_system_ram_range(0, max_pfn, NULL, secmon_hide_range);
}

static int secmon_monitor_fn(void *unused)
{
	long status = 0;

	pr_info("secure monitor started\n");

	/* Seal our memory from the normal plane before handing control back. */
	secmon_protect_self();

	for (;;) {
		struct vbs_kvm_ca *ca;
		u64 ca_gpa;

		/* Park; resume with the next request's calling-area GPA. */
		ca_gpa = secmon_vtl_return(status);
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
		 * No handlers are plumbed in yet: acknowledge the call as a
		 * no-op so the normal plane can make progress.  Real per-call
		 * dispatch is added incrementally.
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

static int __init secmon_init(void)
{
	struct task_struct *t;

	if (!secmon_active)
		return 0;

	t = kthread_run(secmon_monitor_fn, NULL, "vbs-secmon");
	if (IS_ERR(t)) {
		pr_err("failed to start secure monitor: %ld\n", PTR_ERR(t));
		return PTR_ERR(t);
	}

	return 0;
}
late_initcall(secmon_init);
