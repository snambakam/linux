// SPDX-License-Identifier: GPL-2.0-only
/*
 * VBS secure-plane monitor — in-guest VTL dispatcher
 *
 * This is the secure-plane counterpart of the normal-plane kvm_planes
 * backend.  The SAME kernel image boots as both the normal plane and the
 * secure plane; when booted as the secure plane (selected via the
 * "vbs_secure_plane" kernel command-line option) this monitor takes over
 * and services VTL calls issued by the normal plane.
 *
 * "Secure plane" is the highest-privilege plane of the VM (conventionally
 * plane 1 / VTL1 / VMPL0, but a VM may have up to KVM_MAX_PLANES planes and
 * the index is not hard-coded here).  "Normal plane" is the requesting,
 * lower-privilege plane (conventionally plane 0).
 *
 * Control flow (all within the normal plane's single KVM_RUN, see
 * arch/x86/kvm/x86.c ____kvm_emulate_hypercall):
 *
 *   normal plane                   KVM                       secure plane
 *   ------------                   ---                       ------------
 *   fill calling area
 *   HC_VBS_VTL_CALL(ca_gpa) ─────▶ switch_plane ───────────▶ resume in
 *                                  (RAX := ca_gpa)            secmon_vtl_return()
 *                                                            dispatch(call_id)
 *                                                            write ca->status
 *   resume after VTL_CALL ◀─────── switch_plane ◀─────────── HC_VBS_VTL_RETURN(status)
 *   read ca->status
 *
 * Because all planes of a VM share the same memslots (struct kvm_plane has
 * no memslots of its own; they live in struct kvm), the secure plane sees
 * the same guest-physical address space as the normal plane and can read
 * the calling area and the GPAs referenced by each request directly.
 */

#define pr_fmt(fmt) "vbs-secmon: " fmt

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/vbs.h>
#include <linux/kvm_para.h>
#include <asm/kvm_para.h>

#include "heki.h"

/*
 * Shared-memory calling area — must match struct vbs_kvm_ca in kvm_planes.c
 * (this is the normal-plane <-> secure-plane wire ABI).
 *
 *   [ call_pending | call_id | status | arg_size | resp_size | buffer ]
 */
struct vbs_kvm_ca {
	__u8	call_pending;	/* 1 while call is in flight		*/
	__u8	rsvd[3];
	__u32	call_id;	/* enum vbs_call_id (set by caller)	*/
	__s32	status;		/* return code (set by responder)	*/
	__u32	arg_size;	/* request payload size			*/
	__u32	resp_size;	/* response payload size		*/
	__u8	buffer[];	/* request data in, response data out	*/
} __packed;

/* Set from the "vbs_secure_plane" kernel command-line option. */
static bool secmon_active __ro_after_init;

static int __init secmon_setup(char *str)
{
	secmon_active = true;
	return 1;
}
__setup("vbs_secure_plane", secmon_setup);

/*
 * Park the secure plane and hand control back to the normal plane.  On the
 * next VTL call, KVM resumes us here with the calling-area GPA in the
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
 * The secure plane cannot issue the host KVM_SET_MEMORY_ATTRIBUTES ioctl,
 * so it asks KVM to do it via the KVM_HC_VBS_SET_MEM_ATTRS hypercall, which
 * KVM honours only for a higher-privilege plane.  @perms carries the access
 * bits the normal plane should retain (VBS_MEM_*); KVM translates a cleared
 * write/exec bit into NO_WRITE / NO_EXEC memory attributes.
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

/* ── per-call handlers ────────────────────────────────────────────────── */

static int secmon_do_protect_memory(const void *arg, u32 arg_size)
{
	const struct vbs_protect_memory_req *r = arg;

	if (arg_size < sizeof(*r))
		return -EINVAL;

	return secmon_apply_attrs(r->gpa, r->size, r->perms);
}

static int secmon_do_seal_kernel(const void *arg, u32 arg_size)
{
	const struct vbs_seal_kernel_req *r = arg;
	int ret;

	if (arg_size < sizeof(*r))
		return -EINVAL;

	/* Kernel text: read + execute, no write. */
	ret = secmon_apply_attrs(r->text_gpa, r->text_size,
				 VBS_MEM_READ | VBS_MEM_EXEC);
	if (ret)
		return ret;

	/* Kernel rodata: read only, no write, no execute. */
	return secmon_apply_attrs(r->rodata_gpa, r->rodata_size,
				  VBS_MEM_READ);
}

static int secmon_do_set_module_perms(const void *arg, u32 arg_size)
{
	const struct vbs_set_module_perms_req *hdr = arg;
	const struct vbs_module_section *sec;
	u32 i, n;

	if (arg_size < sizeof(*hdr))
		return -EINVAL;

	n = hdr->nr_sections;
	if (arg_size < sizeof(*hdr) + n * sizeof(*sec))
		return -EINVAL;

	sec = (const struct vbs_module_section *)(hdr + 1);
	for (i = 0; i < n; i++) {
		int ret = secmon_apply_attrs(sec[i].gpa, sec[i].size,
					     sec[i].perms);
		if (ret)
			return ret;
	}

	return 0;
}

static long secmon_dispatch(u32 call_id, const void *arg, u32 arg_size,
			    u32 *resp_size)
{
	*resp_size = 0;

	switch (call_id) {
	case VBS_CALL_INIT:
	case VBS_CALL_SHUTDOWN:
		return 0;

	case VBS_CALL_PROTECT_MEMORY:
		return secmon_do_protect_memory(arg, arg_size);
	case VBS_CALL_SEAL_KERNEL:
		return secmon_do_seal_kernel(arg, arg_size);

	case VBS_CALL_SET_MODULE_PERMS:
		return secmon_do_set_module_perms(arg, arg_size);

	/*
	 * Module/kexec validation and key management are acknowledged for
	 * now (mirroring the previous userspace dispatcher); real signature
	 * verification runs here in a later stage.
	 */
	case VBS_CALL_VALIDATE_MODULE:
	case VBS_CALL_UNLOAD_MODULE:
	case VBS_CALL_ADD_KEY:
	case VBS_CALL_REVOKE_KEY:
	case VBS_CALL_SEND_CERTS:
	case VBS_CALL_KEXEC_VALIDATE:
	case VBS_CALL_KEXEC_INVALIDATE:
		return 0;

	default:
		pr_warn_ratelimited("unknown call_id 0x%x\n", call_id);
		return -ENOSYS;
	}
}

/* ── monitor loop ─────────────────────────────────────────────────────── */

static int secmon_monitor_fn(void *unused)
{
	long status = 0;

	pr_info("secure monitor started\n");

	for (;;) {
		struct vbs_kvm_ca *ca;
		u64 ca_gpa;
		u32 call_id, arg_size, resp_size = 0;

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

		call_id  = ca->call_id;
		arg_size = ca->arg_size;
		if (arg_size > PAGE_SIZE - sizeof(*ca))
			arg_size = PAGE_SIZE - sizeof(*ca);

		status = secmon_dispatch(call_id, ca->buffer, arg_size,
					 &resp_size);

		ca->status    = (s32)status;
		ca->resp_size = resp_size;

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
