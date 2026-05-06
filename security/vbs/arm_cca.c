// SPDX-License-Identifier: GPL-2.0-only
/*
 * VBS backend — Arm CCA (Confidential Compute Architecture)
 *
 * Uses the RSI (Realm Services Interface) to communicate between the
 * Realm guest (plane-0) and the RMM (Realm Management Monitor) or a
 * security service running in a higher-privileged realm.
 *
 * Transport: SMC calls via arm_smccc_smc() using SMC_RSI_HOST_CALL for
 *            RPC-style requests to the host/monitor, and direct RSI
 *            commands for memory state management (RIPAS transitions).
 *
 * Memory model:
 *   - Protected (RIPAS_RAM): RMM-backed, encrypted, inaccessible to host
 *   - Shared (RIPAS_EMPTY):  Host-backed, used for I/O and communication
 *   - The highest IPA bit marks shared vs protected pages
 */

#include "internal.h"

#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/arm-smccc.h>

#include <asm/rsi.h>

/* ── VBS host-call command IDs ────────────────────────────────────────── */
/*
 * VBS requests are sent to the host via SMC_RSI_HOST_CALL.  The host
 * call structure is placed in a shared (RIPAS_EMPTY) page.  The first
 * 16 bytes encode the VBS-specific command header.
 */
#define CCA_VBS_MAGIC		0x56425343	/* "VBSC" */

struct vbs_cca_host_req {
	__u32	magic;		/* CCA_VBS_MAGIC			*/
	__u32	call_id;	/* enum vbs_call_id / CCA_VBS_* cmd	*/
	__u32	arg_size;	/* bytes of payload following this hdr	*/
	__u32	reserved;
	__u8	payload[];
} __packed;

struct vbs_cca_host_resp {
	__s32	status;		/* 0 = success, negative errno		*/
	__u32	resp_size;
	__u8	payload[];
} __packed;

/* VBS sub-commands */
#define CCA_VBS_INIT			0
#define CCA_VBS_SHUTDOWN		1
#define CCA_VBS_PROTECT_MEMORY		2
#define CCA_VBS_SEAL_KERNEL		3
#define CCA_VBS_VALIDATE_MODULE		4
#define CCA_VBS_SET_MODULE_PERMS	5
#define CCA_VBS_UNLOAD_MODULE		6
#define CCA_VBS_ADD_KEY			7
#define CCA_VBS_REVOKE_KEY		8
#define CCA_VBS_SEND_CERTS		9
#define CCA_VBS_KEXEC_VALIDATE		10
#define CCA_VBS_KEXEC_INVALIDATE	11

/* Shared pages for host communication (RIPAS_EMPTY / decrypted) */
static void *cca_req_page;
static void *cca_resp_page;

/* ── low-level host call ──────────────────────────────────────────────── */

static int cca_vbs_host_call(u32 cmd, const void *arg, size_t arg_size,
			     void *resp, size_t resp_size)
{
	struct vbs_cca_host_req *req;
	struct vbs_cca_host_resp *rsp;
	struct arm_smccc_res res;
	unsigned long ret;

	if (!cca_req_page || !cca_resp_page)
		return -ENOMEM;

	if (arg_size > PAGE_SIZE - sizeof(*req))
		return -E2BIG;

	/* Build request in the shared page */
	req = cca_req_page;
	memset(req, 0, PAGE_SIZE);
	req->magic    = CCA_VBS_MAGIC;
	req->call_id  = cmd;
	req->arg_size = arg_size;
	if (arg_size && arg)
		memcpy(req->payload, arg, arg_size);

	memset(cca_resp_page, 0, PAGE_SIZE);

	/*
	 * SMC_RSI_HOST_CALL: arg1 = IPA of host call structure.
	 * The host (VMM) reads the request, processes it, writes the
	 * response into cca_resp_page, then returns control.
	 */
	arm_smccc_smc(SMC_RSI_HOST_CALL, virt_to_phys(cca_req_page),
		      0, 0, 0, 0, 0, 0, &res);
	ret = res.a0;
	if (ret != RSI_SUCCESS) {
		pr_err_ratelimited("vbs-cca: RSI host call failed (%lu)\n",
				   ret);
		return -EIO;
	}

	/* Read response */
	rsp = cca_resp_page;
	if (rsp->status)
		return rsp->status;

	if (resp && resp_size) {
		size_t copy = min_t(size_t, resp_size, rsp->resp_size);

		memcpy(resp, rsp->payload, copy);
	}
	return 0;
}

static int cca_vbs_vtl_call(enum vbs_call_id id,
			    const void *arg, size_t arg_size,
			    void *resp, size_t resp_size)
{
	return cca_vbs_host_call(id, arg, arg_size, resp, resp_size);
}

/* ── memory protection ────────────────────────────────────────────────── */

/*
 * On Arm CCA, memory protection is handled natively via RIPAS transitions.
 * The RMM enforces that protected (RIPAS_RAM) pages are inaccessible to
 * the host.  For VBS-style per-page permission control (R/W/X), we
 * forward the request to the security service via a host call.
 */

struct vbs_cca_protect_args {
	__u64 pfn;
	__u64 nr_pages;
	__u32 perms;
} __packed;

static int cca_vbs_protect_memory(unsigned long pfn, unsigned long nr_pages,
				  unsigned int perms)
{
	struct vbs_cca_protect_args args = {
		.pfn      = pfn,
		.nr_pages = nr_pages,
		.perms    = perms,
	};

	return cca_vbs_host_call(CCA_VBS_PROTECT_MEMORY,
				 &args, sizeof(args), NULL, 0);
}

static int cca_vbs_seal_kernel(void)
{
	return cca_vbs_host_call(CCA_VBS_SEAL_KERNEL, NULL, 0, NULL, 0);
}

/* ── module authentication ────────────────────────────────────────────── */

static int cca_vbs_validate_module(const void *elf, size_t elf_size,
				   const void *sig, size_t sig_size)
{
	return cca_vbs_host_call(CCA_VBS_VALIDATE_MODULE, NULL, 0, NULL, 0);
}

static int cca_vbs_set_module_perms(const struct module *mod)
{
	return cca_vbs_host_call(CCA_VBS_SET_MODULE_PERMS, NULL, 0, NULL, 0);
}

static int cca_vbs_unload_module(const struct module *mod)
{
	return cca_vbs_host_call(CCA_VBS_UNLOAD_MODULE, NULL, 0, NULL, 0);
}

/* ── key / certificate management ─────────────────────────────────────── */

static int cca_vbs_add_key(const void *key, size_t key_size,
			   unsigned int flags)
{
	return cca_vbs_host_call(CCA_VBS_ADD_KEY, key, key_size, NULL, 0);
}

static int cca_vbs_revoke_key(const void *key_id, size_t id_size)
{
	return cca_vbs_host_call(CCA_VBS_REVOKE_KEY, key_id, id_size, NULL, 0);
}

static int cca_vbs_send_certs(const void *certs, size_t certs_size)
{
	return cca_vbs_host_call(CCA_VBS_SEND_CERTS,
				 certs, certs_size, NULL, 0);
}

/* ── kexec validation ─────────────────────────────────────────────────── */

static int cca_vbs_kexec_validate(const void *kernel, size_t kernel_size,
				  const void *sig, size_t sig_size)
{
	return cca_vbs_host_call(CCA_VBS_KEXEC_VALIDATE, NULL, 0, NULL, 0);
}

static int cca_vbs_kexec_invalidate(void)
{
	return cca_vbs_host_call(CCA_VBS_KEXEC_INVALIDATE, NULL, 0, NULL, 0);
}

/* ── lifecycle ────────────────────────────────────────────────────────── */

static int cca_vbs_init(void)
{
	int ret;

	/*
	 * Allocate shared pages for host communication.  Convert them
	 * to RIPAS_EMPTY so the host/VMM can access them.
	 */
	cca_req_page  = (void *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
	cca_resp_page = (void *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
	if (!cca_req_page || !cca_resp_page) {
		ret = -ENOMEM;
		goto fail;
	}

	/* Mark as shared (RIPAS_EMPTY) for host access */
	ret = set_memory_decrypted((unsigned long)cca_req_page, 1);
	if (ret)
		goto fail;
	ret = set_memory_decrypted((unsigned long)cca_resp_page, 1);
	if (ret)
		goto fail_re_encrypt_req;

	ret = cca_vbs_host_call(CCA_VBS_INIT, NULL, 0, NULL, 0);
	if (ret) {
		pr_err("vbs-cca: realm VBS init failed (%d)\n", ret);
		goto fail_re_encrypt;
	}

	pr_info("vbs-cca: connected to Arm CCA security service\n");
	return 0;

fail_re_encrypt:
	set_memory_encrypted((unsigned long)cca_resp_page, 1);
fail_re_encrypt_req:
	set_memory_encrypted((unsigned long)cca_req_page, 1);
fail:
	free_page((unsigned long)cca_req_page);
	free_page((unsigned long)cca_resp_page);
	cca_req_page = cca_resp_page = NULL;
	return ret;
}

static void cca_vbs_shutdown(void)
{
	cca_vbs_host_call(CCA_VBS_SHUTDOWN, NULL, 0, NULL, 0);

	if (cca_resp_page) {
		set_memory_encrypted((unsigned long)cca_resp_page, 1);
		free_page((unsigned long)cca_resp_page);
	}
	if (cca_req_page) {
		set_memory_encrypted((unsigned long)cca_req_page, 1);
		free_page((unsigned long)cca_req_page);
	}
	cca_req_page = cca_resp_page = NULL;
}

/* ── ops table & registration ─────────────────────────────────────────── */

static const struct vbs_ops cca_vbs_ops = {
	.name		   = "arm-cca",
	.init		   = cca_vbs_init,
	.shutdown	   = cca_vbs_shutdown,
	.vtl_call	   = cca_vbs_vtl_call,
	.protect_memory    = cca_vbs_protect_memory,
	.seal_kernel	   = cca_vbs_seal_kernel,
	.validate_module   = cca_vbs_validate_module,
	.set_module_perms  = cca_vbs_set_module_perms,
	.unload_module	   = cca_vbs_unload_module,
	.add_key	   = cca_vbs_add_key,
	.revoke_key	   = cca_vbs_revoke_key,
	.send_certs	   = cca_vbs_send_certs,
	.kexec_validate    = cca_vbs_kexec_validate,
	.kexec_invalidate  = cca_vbs_kexec_invalidate,
};

/* ── detection & probe (called from probe.c) ──────────────────────────── */

bool __init vbs_cca_detect(void)
{
	return is_realm_world();
}

const struct vbs_ops *vbs_cca_get_ops(void)
{
	return &cca_vbs_ops;
}
