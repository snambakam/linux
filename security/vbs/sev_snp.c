// SPDX-License-Identifier: GPL-2.0-only
/*
 * VBS backend — AMD SEV-SNP
 *
 * Uses the SVSM (Secure VM Service Module) protocol to communicate
 * between the guest (VMPL2+) and the SVSM running at VMPL0.
 *
 * Transport: VMGEXIT with SVM_VMGEXIT_SNP_RUN_VMPL exit code,
 *            parameters passed via the SVSM Calling Area (CAA).
 *
 * The SVSM already provides core services (PVALIDATE, attestation,
 * vTPM).  This backend extends it with VBS-specific calls for
 * memory protection, module authentication, and key management
 * using a new VBS SVSM protocol number.
 */

#include "internal.h"

#include <linux/cc_platform.h>

#include <asm/sev.h>

/*
 * VBS SEV-SNP protocol — extends the existing SVSM protocol numbering.
 * Protocol 0 = core, 1 = attestation, 2 = vTPM, 3 = VBS.
 */
#define SEV_SNP_VBS_CALL(x)		((3ULL << 32) | (x))

/* VBS-specific SEV-SNP call IDs (mapped from enum vbs_call_id) */
#define SEV_SNP_VBS_INIT		0
#define SEV_SNP_VBS_SHUTDOWN		1
#define SEV_SNP_VBS_PROTECT_MEMORY	2
#define SEV_SNP_VBS_SEAL_KERNEL		3
#define SEV_SNP_VBS_VALIDATE_MODULE	4
#define SEV_SNP_VBS_SET_MODULE_PERMS	5
#define SEV_SNP_VBS_UNLOAD_MODULE	6
#define SEV_SNP_VBS_ADD_KEY		7
#define SEV_SNP_VBS_REVOKE_KEY		8
#define SEV_SNP_VBS_SEND_CERTS		9
#define SEV_SNP_VBS_KEXEC_VALIDATE	10
#define SEV_SNP_VBS_KEXEC_INVALIDATE	11

/* ── low-level VTL call via SEV-SNP ───────────────────────────────────── */

/*
 * Issue a VBS call through the SVSM protocol.
 *
 * The CAA svsm_buffer is used to pass request/response data.
 * RAX encodes the protocol (3 = VBS) and call ID.
 * RCX carries the physical address of any auxiliary data buffer.
 * RDX carries the size of the auxiliary data.
 */
static int sev_snp_vbs_call(u32 call_id, const void *arg, size_t arg_size,
			    void *resp, size_t resp_size)
{
	struct svsm_call call = {};
	int ret;

	call.rax = SEV_SNP_VBS_CALL(call_id);
	if (arg && arg_size) {
		call.rcx = __pa(arg);
		call.rdx = arg_size;
	}
	if (resp && resp_size) {
		call.r8 = __pa(resp);
		call.r9 = resp_size;
	}

	ret = svsm_perform_call_protocol(&call);
	if (ret)
		pr_err_ratelimited("vbs-sev-snp: call %u failed (%d)\n",
				   call_id, ret);
	return ret;
}

static int sev_snp_vbs_vtl_call(enum vbs_call_id id,
				const void *arg, size_t arg_size,
				void *resp, size_t resp_size)
{
	return sev_snp_vbs_call(id, arg, arg_size, resp, resp_size);
}

/* ── memory protection ────────────────────────────────────────────────── */

struct vbs_sev_snp_protect_args {
	__u64 pfn;
	__u64 nr_pages;
	__u32 perms;
} __packed;

static int sev_snp_vbs_protect_memory(unsigned long pfn,
				      unsigned long nr_pages,
				      unsigned int perms)
{
	struct vbs_sev_snp_protect_args args = {
		.pfn      = pfn,
		.nr_pages = nr_pages,
		.perms    = perms,
	};

	return sev_snp_vbs_call(SEV_SNP_VBS_PROTECT_MEMORY,
				&args, sizeof(args), NULL, 0);
}

static int sev_snp_vbs_seal_kernel(void)
{
	return sev_snp_vbs_call(SEV_SNP_VBS_SEAL_KERNEL, NULL, 0, NULL, 0);
}

/* ── module authentication ────────────────────────────────────────────── */

static int sev_snp_vbs_validate_module(const void *elf, size_t elf_size,
				       const void *sig, size_t sig_size)
{
	/*
	 * Module ELF may be large.  Pass its physical address and size
	 * to VMPL0 so the SVSM can read it from the shared address space.
	 */
	return sev_snp_vbs_call(SEV_SNP_VBS_VALIDATE_MODULE,
				NULL, 0, NULL, 0);
}

static int sev_snp_vbs_set_module_perms(const struct module *mod)
{
	return sev_snp_vbs_call(SEV_SNP_VBS_SET_MODULE_PERMS,
				NULL, 0, NULL, 0);
}

static int sev_snp_vbs_unload_module(const struct module *mod)
{
	return sev_snp_vbs_call(SEV_SNP_VBS_UNLOAD_MODULE, NULL, 0, NULL, 0);
}

/* ── key / certificate management ─────────────────────────────────────── */

static int sev_snp_vbs_add_key(const void *key, size_t key_size,
			       unsigned int flags)
{
	return sev_snp_vbs_call(SEV_SNP_VBS_ADD_KEY, key, key_size, NULL, 0);
}

static int sev_snp_vbs_revoke_key(const void *key_id, size_t id_size)
{
	return sev_snp_vbs_call(SEV_SNP_VBS_REVOKE_KEY, key_id, id_size, NULL, 0);
}

static int sev_snp_vbs_send_certs(const void *certs, size_t certs_size)
{
	return sev_snp_vbs_call(SEV_SNP_VBS_SEND_CERTS,
				certs, certs_size, NULL, 0);
}

/* ── kexec validation ─────────────────────────────────────────────────── */

static int sev_snp_vbs_kexec_validate(const void *kernel, size_t kernel_size,
				      const void *sig, size_t sig_size)
{
	return sev_snp_vbs_call(SEV_SNP_VBS_KEXEC_VALIDATE, NULL, 0, NULL, 0);
}

static int sev_snp_vbs_kexec_invalidate(void)
{
	return sev_snp_vbs_call(SEV_SNP_VBS_KEXEC_INVALIDATE, NULL, 0, NULL, 0);
}

/* ── lifecycle ────────────────────────────────────────────────────────── */

static int sev_snp_vbs_init(void)
{
	int ret;

	ret = sev_snp_vbs_call(SEV_SNP_VBS_INIT, NULL, 0, NULL, 0);
	if (ret) {
		pr_err("vbs-sev-snp: VBS init failed (%d)\n", ret);
		return ret;
	}

	pr_info("vbs-sev-snp: connected to SVSM at VMPL0\n");
	return 0;
}

static void sev_snp_vbs_shutdown(void)
{
	sev_snp_vbs_call(SEV_SNP_VBS_SHUTDOWN, NULL, 0, NULL, 0);
}

/* ── ops table & registration ─────────────────────────────────────────── */

static const struct vbs_ops sev_snp_vbs_ops = {
	.name		   = "sev-snp",
	.init		   = sev_snp_vbs_init,
	.shutdown	   = sev_snp_vbs_shutdown,
	.vtl_call	   = sev_snp_vbs_vtl_call,
	.protect_memory    = sev_snp_vbs_protect_memory,
	.seal_kernel	   = sev_snp_vbs_seal_kernel,
	.validate_module   = sev_snp_vbs_validate_module,
	.set_module_perms  = sev_snp_vbs_set_module_perms,
	.unload_module	   = sev_snp_vbs_unload_module,
	.add_key	   = sev_snp_vbs_add_key,
	.revoke_key	   = sev_snp_vbs_revoke_key,
	.send_certs	   = sev_snp_vbs_send_certs,
	.kexec_validate    = sev_snp_vbs_kexec_validate,
	.kexec_invalidate  = sev_snp_vbs_kexec_invalidate,
};

/* ── detection & probe (called from probe.c) ──────────────────────────── */

bool __init vbs_sev_snp_detect(void)
{
	if (!cc_platform_has(CC_ATTR_GUEST_SEV_SNP))
		return false;

	if (snp_vmpl == 0) {
		pr_debug("vbs-sev-snp: running at VMPL0, no SVSM above us\n");
		return false;
	}

	return true;
}

const struct vbs_ops *vbs_sev_snp_get_ops(void)
{
	return &sev_snp_vbs_ops;
}
