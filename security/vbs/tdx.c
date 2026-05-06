// SPDX-License-Identifier: GPL-2.0-only
/*
 * VBS backend — Intel TDX service TD
 *
 * Uses TDG.VP.VMCALL (TDVMCALL) to communicate between the main TD
 * (plane-0) and a service TD (plane-1) that provides security services.
 *
 * Transport: TDVMCALL with a VBS-specific sub-function leaf.  The VMM
 *            (QEMU / KVM) routes the call to the service TD, which
 *            shares memory with the main TD for request/response data.
 *
 * Note: Service TD support is still evolving in the TDX architecture.
 *       This backend provides the framework and will be updated as the
 *       inter-TD communication spec is finalised.
 */

#include "internal.h"

#include <linux/cc_platform.h>
#include <linux/mm.h>

#include <asm/shared/tdx.h>
#include <asm/tdx.h>

/*
 * VBS-specific TDVMCALL sub-function.  Chosen from the vendor-specific
 * range (>= 0x10010000) to avoid conflicts with the GHCI-defined leaves.
 */
#define TDVMCALL_VBS			0x10010000ULL

/* VBS sub-commands passed in R12 */
#define TDX_VBS_INIT			0
#define TDX_VBS_SHUTDOWN		1
#define TDX_VBS_PROTECT_MEMORY		2
#define TDX_VBS_SEAL_KERNEL		3
#define TDX_VBS_VALIDATE_MODULE		4
#define TDX_VBS_SET_MODULE_PERMS	5
#define TDX_VBS_UNLOAD_MODULE		6
#define TDX_VBS_ADD_KEY			7
#define TDX_VBS_REVOKE_KEY		8
#define TDX_VBS_SEND_CERTS		9
#define TDX_VBS_KEXEC_VALIDATE		10
#define TDX_VBS_KEXEC_INVALIDATE	11

/* ── shared-memory buffers ────────────────────────────────────────────── */

/*
 * Shared (decrypted) pages for passing request and response data between
 * the main TD and the service TD.  Marked shared via cc_mkdec() so the
 * VMM and service TD can access them.
 */
static void *tdx_req_page;
static void *tdx_resp_page;

/* ── low-level VBS TDVMCALL ───────────────────────────────────────────── */

/*
 * Issue a VBS call to the service TD through the VMM.
 *
 * Register usage (TDVMCALL convention):
 *   R11 = sub-function leaf (TDVMCALL_VBS)
 *   R12 = VBS command ID
 *   R13 = physical address of request buffer (shared)
 *   R14 = physical address of response buffer (shared)
 *   R15 = request size
 */
static int tdx_vbs_call(u32 cmd, const void *arg, size_t arg_size,
			void *resp, size_t resp_size)
{
	struct tdx_module_args args = {};
	u64 ret;

	if (arg && arg_size) {
		if (arg_size > PAGE_SIZE || !tdx_req_page)
			return -E2BIG;
		memcpy(tdx_req_page, arg, arg_size);
	}

	args.r11 = TDVMCALL_VBS;
	args.r12 = cmd;
	args.r13 = tdx_req_page ? cc_mkdec(virt_to_phys(tdx_req_page)) : 0;
	args.r14 = tdx_resp_page ? cc_mkdec(virt_to_phys(tdx_resp_page)) : 0;
	args.r15 = arg_size;

	ret = __tdx_hypercall(&args);
	if (ret) {
		pr_err_ratelimited("vbs-tdx: TDVMCALL failed (0x%llx)\n", ret);
		return -EIO;
	}

	/* R10 holds the VMM return status */
	if (args.r10) {
		pr_err_ratelimited("vbs-tdx: service TD returned 0x%llx\n",
				   args.r10);
		return -EREMOTEIO;
	}

	if (resp && resp_size && tdx_resp_page) {
		size_t copy = min_t(size_t, resp_size, PAGE_SIZE);

		memcpy(resp, tdx_resp_page, copy);
	}
	return 0;
}

static int tdx_vbs_vtl_call(enum vbs_call_id id,
			    const void *arg, size_t arg_size,
			    void *resp, size_t resp_size)
{
	return tdx_vbs_call(id, arg, arg_size, resp, resp_size);
}

/* ── memory protection ────────────────────────────────────────────────── */

struct vbs_tdx_protect_args {
	__u64 pfn;
	__u64 nr_pages;
	__u32 perms;
} __packed;

static int tdx_vbs_protect_memory(unsigned long pfn, unsigned long nr_pages,
				  unsigned int perms)
{
	struct vbs_tdx_protect_args args = {
		.pfn      = pfn,
		.nr_pages = nr_pages,
		.perms    = perms,
	};

	return tdx_vbs_call(TDX_VBS_PROTECT_MEMORY,
			    &args, sizeof(args), NULL, 0);
}

static int tdx_vbs_seal_kernel(void)
{
	return tdx_vbs_call(TDX_VBS_SEAL_KERNEL, NULL, 0, NULL, 0);
}

/* ── module authentication ────────────────────────────────────────────── */

static int tdx_vbs_validate_module(const void *elf, size_t elf_size,
				   const void *sig, size_t sig_size)
{
	return tdx_vbs_call(TDX_VBS_VALIDATE_MODULE, NULL, 0, NULL, 0);
}

static int tdx_vbs_set_module_perms(const struct module *mod)
{
	return tdx_vbs_call(TDX_VBS_SET_MODULE_PERMS, NULL, 0, NULL, 0);
}

static int tdx_vbs_unload_module(const struct module *mod)
{
	return tdx_vbs_call(TDX_VBS_UNLOAD_MODULE, NULL, 0, NULL, 0);
}

/* ── key / certificate management ─────────────────────────────────────── */

static int tdx_vbs_add_key(const void *key, size_t key_size,
			   unsigned int flags)
{
	return tdx_vbs_call(TDX_VBS_ADD_KEY, key, key_size, NULL, 0);
}

static int tdx_vbs_revoke_key(const void *key_id, size_t id_size)
{
	return tdx_vbs_call(TDX_VBS_REVOKE_KEY, key_id, id_size, NULL, 0);
}

static int tdx_vbs_send_certs(const void *certs, size_t certs_size)
{
	return tdx_vbs_call(TDX_VBS_SEND_CERTS, certs, certs_size, NULL, 0);
}

/* ── kexec validation ─────────────────────────────────────────────────── */

static int tdx_vbs_kexec_validate(const void *kernel, size_t kernel_size,
				  const void *sig, size_t sig_size)
{
	return tdx_vbs_call(TDX_VBS_KEXEC_VALIDATE, NULL, 0, NULL, 0);
}

static int tdx_vbs_kexec_invalidate(void)
{
	return tdx_vbs_call(TDX_VBS_KEXEC_INVALIDATE, NULL, 0, NULL, 0);
}

/* ── lifecycle ────────────────────────────────────────────────────────── */

static int tdx_vbs_init(void)
{
	int ret;

	/*
	 * Allocate shared pages for inter-TD communication.  These must
	 * be marked as shared (decrypted) so the service TD can read them.
	 */
	tdx_req_page  = (void *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
	tdx_resp_page = (void *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
	if (!tdx_req_page || !tdx_resp_page) {
		ret = -ENOMEM;
		goto fail;
	}

	/*
	 * Convert to shared pages.  set_memory_decrypted() clears the
	 * encryption bit so the VMM / service TD can access these pages.
	 */
	ret = set_memory_decrypted((unsigned long)tdx_req_page, 1);
	if (ret)
		goto fail;
	ret = set_memory_decrypted((unsigned long)tdx_resp_page, 1);
	if (ret)
		goto fail_re_encrypt_req;

	ret = tdx_vbs_call(TDX_VBS_INIT, NULL, 0, NULL, 0);
	if (ret) {
		pr_err("vbs-tdx: service TD init failed (%d)\n", ret);
		goto fail_re_encrypt;
	}

	pr_info("vbs-tdx: connected to TDX service TD\n");
	return 0;

fail_re_encrypt:
	set_memory_encrypted((unsigned long)tdx_resp_page, 1);
fail_re_encrypt_req:
	set_memory_encrypted((unsigned long)tdx_req_page, 1);
fail:
	free_page((unsigned long)tdx_req_page);
	free_page((unsigned long)tdx_resp_page);
	tdx_req_page = tdx_resp_page = NULL;
	return ret;
}

static void tdx_vbs_shutdown(void)
{
	tdx_vbs_call(TDX_VBS_SHUTDOWN, NULL, 0, NULL, 0);

	if (tdx_resp_page) {
		set_memory_encrypted((unsigned long)tdx_resp_page, 1);
		free_page((unsigned long)tdx_resp_page);
	}
	if (tdx_req_page) {
		set_memory_encrypted((unsigned long)tdx_req_page, 1);
		free_page((unsigned long)tdx_req_page);
	}
	tdx_req_page = tdx_resp_page = NULL;
}

/* ── ops table & registration ─────────────────────────────────────────── */

static const struct vbs_ops tdx_vbs_ops = {
	.name		   = "tdx-service-td",
	.init		   = tdx_vbs_init,
	.shutdown	   = tdx_vbs_shutdown,
	.vtl_call	   = tdx_vbs_vtl_call,
	.protect_memory    = tdx_vbs_protect_memory,
	.seal_kernel	   = tdx_vbs_seal_kernel,
	.validate_module   = tdx_vbs_validate_module,
	.set_module_perms  = tdx_vbs_set_module_perms,
	.unload_module	   = tdx_vbs_unload_module,
	.add_key	   = tdx_vbs_add_key,
	.revoke_key	   = tdx_vbs_revoke_key,
	.send_certs	   = tdx_vbs_send_certs,
	.kexec_validate    = tdx_vbs_kexec_validate,
	.kexec_invalidate  = tdx_vbs_kexec_invalidate,
};

/* ── detection & probe (called from probe.c) ──────────────────────────── */

bool __init vbs_tdx_detect(void)
{
	return cc_platform_has(CC_ATTR_GUEST_TDX);
}

const struct vbs_ops *vbs_tdx_get_ops(void)
{
	return &tdx_vbs_ops;
}
