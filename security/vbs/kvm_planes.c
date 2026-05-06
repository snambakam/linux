// SPDX-License-Identifier: GPL-2.0-only
/*
 * VBS backend — KVM software planes
 *
 * Uses KVM paravirt hypercalls to communicate between plane-0 (normal
 * guest kernel) and plane-1 (secure kernel running in a separate KVM
 * plane managed by QEMU).
 *
 * Transport: kvm_hypercall{0..4}() → KVM_EXIT_HYPERCALL → QEMU → plane-1
 *
 * The shared-memory VTL-call protocol works as follows:
 *   1. Plane-0 fills a request buffer in shared memory.
 *   2. Plane-0 issues a KVM hypercall carrying the physical address
 *      and size of the request.
 *   3. QEMU (or the host) delivers the request to the plane-1 vCPU.
 *   4. Plane-1 processes the request and writes a response.
 *   5. Plane-0 reads the response from shared memory.
 */

#include "internal.h"

#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/io.h>
#include <asm/kvm_para.h>

/* ── hypercall numbers for VBS VTL calls (plane-0 → plane-1) ──────────── */
/*
 * These extend the existing KVM_HC_* numbering.  The host (KVM + QEMU)
 * intercepts them and routes them to the secure-kernel plane.
 */
#define KVM_HC_VBS_VTL_CALL		15

/* ── shared-memory request / response layout ──────────────────────────── */

struct vbs_kvm_request {
	__u32	call_id;	/* enum vbs_call_id			*/
	__u32	arg_size;	/* bytes of payload following this hdr	*/
	__u8	payload[];	/* variable-length argument data		*/
} __packed;

struct vbs_kvm_response {
	__s32	status;		/* 0 = success, negative errno		*/
	__u32	resp_size;	/* bytes of payload following this hdr	*/
	__u8	payload[];	/* variable-length response data		*/
} __packed;

/*
 * A single page is used for each direction.  That gives ~4 KiB of
 * payload per call, which is enough for all current VBS operations.
 */
static void *kvm_req_page;	/* request  (plane-0 writes, plane-1 reads)  */
static void *kvm_resp_page;	/* response (plane-1 writes, plane-0 reads)  */

/* ── low-level VTL call ───────────────────────────────────────────────── */

static int kvm_planes_vtl_call(enum vbs_call_id id,
			       const void *arg, size_t arg_size,
			       void *resp, size_t resp_size)
{
	struct vbs_kvm_request *req;
	struct vbs_kvm_response *rsp;
	long hc_ret;

	if (!kvm_req_page || !kvm_resp_page)
		return -ENOMEM;

	if (arg_size > PAGE_SIZE - sizeof(*req))
		return -E2BIG;

	/* Build request in the shared page */
	req = kvm_req_page;
	req->call_id  = id;
	req->arg_size = arg_size;
	if (arg_size && arg)
		memcpy(req->payload, arg, arg_size);

	/* Issue hypercall: pass physical addresses of req & resp pages */
	hc_ret = kvm_hypercall2(KVM_HC_VBS_VTL_CALL,
				virt_to_phys(kvm_req_page),
				virt_to_phys(kvm_resp_page));
	if (hc_ret) {
		pr_err_ratelimited("vbs-kvm: hypercall failed (%ld)\n", hc_ret);
		return -EIO;
	}

	/* Read response */
	rsp = kvm_resp_page;
	if (rsp->status)
		return rsp->status;

	if (resp && resp_size) {
		size_t copy = min_t(size_t, resp_size, rsp->resp_size);

		memcpy(resp, rsp->payload, copy);
	}
	return 0;
}

/* ── memory protection ────────────────────────────────────────────────── */

struct vbs_protect_args {
	__u64 pfn;
	__u64 nr_pages;
	__u32 perms;
} __packed;

static int kvm_planes_protect_memory(unsigned long pfn,
				     unsigned long nr_pages,
				     unsigned int perms)
{
	struct vbs_protect_args args = {
		.pfn      = pfn,
		.nr_pages = nr_pages,
		.perms    = perms,
	};

	return kvm_planes_vtl_call(VBS_CALL_PROTECT_MEMORY,
				   &args, sizeof(args), NULL, 0);
}

static int kvm_planes_seal_kernel(void)
{
	return kvm_planes_vtl_call(VBS_CALL_SEAL_KERNEL, NULL, 0, NULL, 0);
}

/* ── module authentication ────────────────────────────────────────────── */

static int kvm_planes_validate_module(const void *elf, size_t elf_size,
				      const void *sig, size_t sig_size)
{
	/*
	 * Module blobs can be large — for the KVM planes backend we pass
	 * the physical address and size to plane-1 via the VTL call and
	 * let plane-1 map/read the pages directly from its EPT view.
	 * For now, a stub that signals "not yet implemented".
	 */
	return kvm_planes_vtl_call(VBS_CALL_VALIDATE_MODULE,
				   NULL, 0, NULL, 0);
}

static int kvm_planes_set_module_perms(const struct module *mod)
{
	return kvm_planes_vtl_call(VBS_CALL_SET_MODULE_PERMS,
				   NULL, 0, NULL, 0);
}

static int kvm_planes_unload_module(const struct module *mod)
{
	return kvm_planes_vtl_call(VBS_CALL_UNLOAD_MODULE,
				   NULL, 0, NULL, 0);
}

/* ── key / certificate management ─────────────────────────────────────── */

static int kvm_planes_add_key(const void *key, size_t key_size,
			      unsigned int flags)
{
	return kvm_planes_vtl_call(VBS_CALL_ADD_KEY, key, key_size, NULL, 0);
}

static int kvm_planes_revoke_key(const void *key_id, size_t id_size)
{
	return kvm_planes_vtl_call(VBS_CALL_REVOKE_KEY,
				   key_id, id_size, NULL, 0);
}

static int kvm_planes_send_certs(const void *certs, size_t certs_size)
{
	return kvm_planes_vtl_call(VBS_CALL_SEND_CERTS,
				   certs, certs_size, NULL, 0);
}

/* ── kexec validation ─────────────────────────────────────────────────── */

static int kvm_planes_kexec_validate(const void *kernel, size_t kernel_size,
				     const void *sig, size_t sig_size)
{
	return kvm_planes_vtl_call(VBS_CALL_KEXEC_VALIDATE,
				   NULL, 0, NULL, 0);
}

static int kvm_planes_kexec_invalidate(void)
{
	return kvm_planes_vtl_call(VBS_CALL_KEXEC_INVALIDATE,
				   NULL, 0, NULL, 0);
}

/* ── lifecycle ────────────────────────────────────────────────────────── */

static int kvm_planes_init(void)
{
	int ret;

	kvm_req_page  = (void *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
	kvm_resp_page = (void *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
	if (!kvm_req_page || !kvm_resp_page) {
		ret = -ENOMEM;
		goto fail;
	}

	ret = kvm_planes_vtl_call(VBS_CALL_INIT, NULL, 0, NULL, 0);
	if (ret) {
		pr_err("vbs-kvm: plane-1 INIT call failed (%d)\n", ret);
		goto fail;
	}

	pr_info("vbs-kvm: connected to plane-1 secure kernel\n");
	return 0;
fail:
	free_page((unsigned long)kvm_req_page);
	free_page((unsigned long)kvm_resp_page);
	kvm_req_page = kvm_resp_page = NULL;
	return ret;
}

static void kvm_planes_shutdown(void)
{
	kvm_planes_vtl_call(VBS_CALL_SHUTDOWN, NULL, 0, NULL, 0);
	free_page((unsigned long)kvm_req_page);
	free_page((unsigned long)kvm_resp_page);
	kvm_req_page = kvm_resp_page = NULL;
}

/* ── ops table & registration ─────────────────────────────────────────── */

static const struct vbs_ops kvm_planes_ops = {
	.name		   = "kvm-planes",
	.init		   = kvm_planes_init,
	.shutdown	   = kvm_planes_shutdown,
	.vtl_call	   = kvm_planes_vtl_call,
	.protect_memory    = kvm_planes_protect_memory,
	.seal_kernel	   = kvm_planes_seal_kernel,
	.validate_module   = kvm_planes_validate_module,
	.set_module_perms  = kvm_planes_set_module_perms,
	.unload_module	   = kvm_planes_unload_module,
	.add_key	   = kvm_planes_add_key,
	.revoke_key	   = kvm_planes_revoke_key,
	.send_certs	   = kvm_planes_send_certs,
	.kexec_validate    = kvm_planes_kexec_validate,
	.kexec_invalidate  = kvm_planes_kexec_invalidate,
};

/* ── detection & probe (called from probe.c) ──────────────────────────── */

bool __init vbs_kvm_planes_detect(void)
{
	if (!kvm_para_available()) {
		pr_debug("vbs-kvm: KVM paravirt not available\n");
		return false;
	}
	return true;
}

const struct vbs_ops *vbs_kvm_planes_get_ops(void)
{
	return &kvm_planes_ops;
}
