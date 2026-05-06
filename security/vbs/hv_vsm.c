// SPDX-License-Identifier: GPL-2.0-only
/*
 * VBS backend — Hyper-V VSM (Virtual Secure Mode)
 *
 * Uses native Hyper-V hypercalls to communicate between VTL0 (normal
 * kernel) and VTL1 (secure kernel / SKCI).
 *
 * Transport: hv_do_hypercall() with VTL-targeted input pages.
 *
 * On Hyper-V the VTL architecture is a first-class feature:
 *   - VTL0 runs the normal OS kernel.
 *   - VTL1 runs the secure kernel that enforces HVCI / Credential Guard.
 *   - VTL switches are performed via HvVtlCall / HvVtlReturn hypercalls.
 *   - Memory protection is enforced per-VTL via the second-level address
 *     translation (SLAT / EPT / NPT) controlled by the hypervisor.
 */

#include "internal.h"

#include <linux/slab.h>
#include <linux/mm.h>

#include <asm/mshyperv.h>
#include <asm/hyperv-tlfs.h>

/* ── Hyper-V VTL call / return hypercall numbers ──────────────────────── */
#define HVCALL_VTL_CALL			0x0011
#define HVCALL_VTL_RETURN		0x0012

/*
 * VBS-specific hypercall — used to send structured VBS requests to VTL1.
 * This sits in the vendor-extension range and is routed by the Hyper-V
 * secure kernel to the appropriate VBS service handler.
 */
#define HVCALL_VBS_REQUEST		0x0200

/* ── shared-memory request / response layout ──────────────────────────── */

struct vbs_hv_request {
	__u32	call_id;	/* enum vbs_call_id			*/
	__u32	arg_size;	/* bytes of payload following this hdr	*/
	__u8	payload[];
} __packed;

struct vbs_hv_response {
	__s32	status;		/* 0 = success, negative errno		*/
	__u32	resp_size;
	__u8	payload[];
} __packed;

/* Hypercall input / output pages (one page each, allocated once) */
static void *hv_input_page;
static void *hv_output_page;

/* ── low-level VTL call ───────────────────────────────────────────────── */

static int hv_vsm_vtl_call(enum vbs_call_id id,
			   const void *arg, size_t arg_size,
			   void *resp, size_t resp_size)
{
	struct vbs_hv_request *req;
	struct vbs_hv_response *rsp;
	u64 status;

	if (!hv_input_page || !hv_output_page)
		return -ENOMEM;

	if (arg_size > PAGE_SIZE - sizeof(*req))
		return -E2BIG;

	/* Build request in the hypercall input page */
	req = hv_input_page;
	memset(req, 0, PAGE_SIZE);
	req->call_id  = id;
	req->arg_size = arg_size;
	if (arg_size && arg)
		memcpy(req->payload, arg, arg_size);

	memset(hv_output_page, 0, PAGE_SIZE);

	status = hv_do_hypercall(HVCALL_VBS_REQUEST,
				 hv_input_page, hv_output_page);
	if (!hv_result_success(status)) {
		pr_err_ratelimited("vbs-hv: hypercall failed (0x%llx)\n",
				   status);
		return -EIO;
	}

	/* Read response from the output page */
	rsp = hv_output_page;
	if (rsp->status)
		return rsp->status;

	if (resp && resp_size) {
		size_t copy = min_t(size_t, resp_size, rsp->resp_size);

		memcpy(resp, rsp->payload, copy);
	}
	return 0;
}

/* ── memory protection ────────────────────────────────────────────────── */

struct vbs_hv_protect_args {
	__u64 pfn;
	__u64 nr_pages;
	__u32 perms;
} __packed;

static int hv_vsm_protect_memory(unsigned long pfn, unsigned long nr_pages,
				 unsigned int perms)
{
	struct vbs_hv_protect_args args = {
		.pfn      = pfn,
		.nr_pages = nr_pages,
		.perms    = perms,
	};

	return hv_vsm_vtl_call(VBS_CALL_PROTECT_MEMORY,
			       &args, sizeof(args), NULL, 0);
}

static int hv_vsm_seal_kernel(void)
{
	return hv_vsm_vtl_call(VBS_CALL_SEAL_KERNEL, NULL, 0, NULL, 0);
}

/* ── module authentication ────────────────────────────────────────────── */

static int hv_vsm_validate_module(const void *elf, size_t elf_size,
				  const void *sig, size_t sig_size)
{
	return hv_vsm_vtl_call(VBS_CALL_VALIDATE_MODULE, NULL, 0, NULL, 0);
}

static int hv_vsm_set_module_perms(const struct module *mod)
{
	return hv_vsm_vtl_call(VBS_CALL_SET_MODULE_PERMS, NULL, 0, NULL, 0);
}

static int hv_vsm_unload_module(const struct module *mod)
{
	return hv_vsm_vtl_call(VBS_CALL_UNLOAD_MODULE, NULL, 0, NULL, 0);
}

/* ── key / certificate management ─────────────────────────────────────── */

static int hv_vsm_add_key(const void *key, size_t key_size,
			  unsigned int flags)
{
	return hv_vsm_vtl_call(VBS_CALL_ADD_KEY, key, key_size, NULL, 0);
}

static int hv_vsm_revoke_key(const void *key_id, size_t id_size)
{
	return hv_vsm_vtl_call(VBS_CALL_REVOKE_KEY, key_id, id_size, NULL, 0);
}

static int hv_vsm_send_certs(const void *certs, size_t certs_size)
{
	return hv_vsm_vtl_call(VBS_CALL_SEND_CERTS,
			       certs, certs_size, NULL, 0);
}

/* ── kexec validation ─────────────────────────────────────────────────── */

static int hv_vsm_kexec_validate(const void *kernel, size_t kernel_size,
				 const void *sig, size_t sig_size)
{
	return hv_vsm_vtl_call(VBS_CALL_KEXEC_VALIDATE, NULL, 0, NULL, 0);
}

static int hv_vsm_kexec_invalidate(void)
{
	return hv_vsm_vtl_call(VBS_CALL_KEXEC_INVALIDATE, NULL, 0, NULL, 0);
}

/* ── lifecycle ────────────────────────────────────────────────────────── */

static int hv_vsm_init(void)
{
	int ret;

	/*
	 * Use the Hyper-V provided hypercall input/output pages.
	 * Allocate our own pair so we don't conflict with other users.
	 */
	hv_input_page  = (void *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
	hv_output_page = (void *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
	if (!hv_input_page || !hv_output_page) {
		ret = -ENOMEM;
		goto fail;
	}

	ret = hv_vsm_vtl_call(VBS_CALL_INIT, NULL, 0, NULL, 0);
	if (ret) {
		pr_err("vbs-hv: VTL1 secure kernel INIT failed (%d)\n", ret);
		goto fail;
	}

	pr_info("vbs-hv: connected to Hyper-V VTL1 secure kernel\n");
	return 0;

fail:
	free_page((unsigned long)hv_input_page);
	free_page((unsigned long)hv_output_page);
	hv_input_page = hv_output_page = NULL;
	return ret;
}

static void hv_vsm_shutdown(void)
{
	hv_vsm_vtl_call(VBS_CALL_SHUTDOWN, NULL, 0, NULL, 0);
	free_page((unsigned long)hv_input_page);
	free_page((unsigned long)hv_output_page);
	hv_input_page = hv_output_page = NULL;
}

/* ── ops table & registration ─────────────────────────────────────────── */

static const struct vbs_ops hv_vsm_ops = {
	.name		   = "hv-vsm",
	.init		   = hv_vsm_init,
	.shutdown	   = hv_vsm_shutdown,
	.vtl_call	   = hv_vsm_vtl_call,
	.protect_memory    = hv_vsm_protect_memory,
	.seal_kernel	   = hv_vsm_seal_kernel,
	.validate_module   = hv_vsm_validate_module,
	.set_module_perms  = hv_vsm_set_module_perms,
	.unload_module	   = hv_vsm_unload_module,
	.add_key	   = hv_vsm_add_key,
	.revoke_key	   = hv_vsm_revoke_key,
	.send_certs	   = hv_vsm_send_certs,
	.kexec_validate    = hv_vsm_kexec_validate,
	.kexec_invalidate  = hv_vsm_kexec_invalidate,
};

/* ── detection & probe (called from probe.c) ──────────────────────────── */

bool __init vbs_hv_vsm_detect(void)
{
	if (!hv_is_hyperv_initialized())
		return false;

	if (ms_hyperv.vtl != 0) {
		pr_debug("vbs-hv: not at VTL0 (vtl=%u), skipping\n",
			 ms_hyperv.vtl);
		return false;
	}

	return true;
}

const struct vbs_ops *vbs_hv_vsm_get_ops(void)
{
	return &hv_vsm_ops;
}
