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
#include <linux/kvm_para.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/workqueue.h>
#include <linux/elf.h>
#include <asm/sections.h>
#include <asm/kvm_para.h>
#include <asm/processor.h>

#include "heki.h"

/* ── shared-memory calling area (modelled after the SVSM CAA) ─────── */

/*
 * Single shared page used for both request and response data.
 * The protocol is synchronous: plane-0 writes the request, issues a
 * hypercall, blocks until QEMU returns, then reads the response from
 * the same page.  No concurrent access is possible.
 *
 * Layout (within one 4 KiB page):
 *   [ call_pending | call_id | status | arg_size | resp_size | buffer ]
 */
struct vbs_kvm_ca {
	__u8	call_pending;	/* 1 while call is in flight		*/
	__u8	rsvd[3];
	__u32	call_id;	/* enum vbs_call_id (set by caller)	*/
	__s32	status;		/* return code (set by responder)	*/
	__u32	arg_size;	/* request payload size			*/
	__u32	resp_size;	/* response payload size			*/
	__u8	buffer[];	/* request data in, response data out	*/
} __packed;

#define VBS_CA_BUF_SIZE	(PAGE_SIZE - sizeof(struct vbs_kvm_ca))

static void *kvm_ca_page;	/* single calling-area page		*/

/* ── low-level VTL call ───────────────────────────────────────────────── */

struct kvm_vtl_call_ctx {
	enum vbs_call_id id;
	const void	*arg;
	size_t		arg_size;
	void		*resp;
	size_t		resp_size;
};

/*
 * Issue the VTL call hypercall.  MUST run on the BSP (CPU0): KVM switches
 * planes per logical CPU (the secure sibling is common->vcpus[1] of the
 * *calling* CPU), and the secure plane is a single in-guest kernel that
 * boots only on CPU0's sibling.  Driven via work_on_cpu() so the hypercall
 * always lands on CPU0 regardless of the caller's CPU.
 */
static long kvm_planes_vtl_call_on_cpu(void *data)
{
	struct kvm_vtl_call_ctx *ctx = data;
	struct vbs_kvm_ca *ca = kvm_ca_page;
	long hc_ret;

	/* Build request */
	ca->call_id  = ctx->id;
	ca->arg_size = ctx->arg_size;
	ca->status   = 0;
	ca->resp_size = 0;
	if (ctx->arg_size && ctx->arg)
		memcpy(ca->buffer, ctx->arg, ctx->arg_size);
	ca->call_pending = 1;

	/* Issue hypercall: pass physical address of the calling area */
	hc_ret = kvm_hypercall1(KVM_HC_VBS_VTL_CALL,
				virt_to_phys(kvm_ca_page));
	ca->call_pending = 0;

	if (hc_ret) {
		pr_err_ratelimited("vbs-kvm: hypercall failed (%ld)\n", hc_ret);
		return -EIO;
	}

	if (ca->status)
		return ca->status;

	/* Read response from the same buffer */
	if (ctx->resp && ctx->resp_size && ca->resp_size) {
		size_t copy = min_t(size_t, ctx->resp_size, ca->resp_size);

		memcpy(ctx->resp, ca->buffer, copy);
	}
	return 0;
}

static int kvm_planes_vtl_call(enum vbs_call_id id,
			       const void *arg, size_t arg_size,
			       void *resp, size_t resp_size)
{
	struct kvm_vtl_call_ctx ctx = {
		.id        = id,
		.arg       = arg,
		.arg_size  = arg_size,
		.resp      = resp,
		.resp_size = resp_size,
	};

	if (!kvm_ca_page)
		return -ENOMEM;

	if (arg_size > VBS_CA_BUF_SIZE)
		return -E2BIG;

	/* Pin the plane switch to CPU0's secure sibling (the only booted one). */
	return work_on_cpu(0, kvm_planes_vtl_call_on_cpu, &ctx);
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
	struct vbs_seal_kernel_req req = {
		.text_gpa    = __pa_symbol(_stext),
		.text_size   = PAGE_ALIGN((u64)(_etext - _stext)),
		.rodata_gpa  = __pa_symbol(__start_rodata),
		.rodata_size = PAGE_ALIGN((u64)(__end_rodata - __start_rodata)),
		.cr3         = read_cr3_pa(),
	};

	pr_info("vbs-kvm: seal_kernel text=[0x%llx+0x%llx] rodata=[0x%llx+0x%llx] cr3=0x%llx\n",
		req.text_gpa, req.text_size,
		req.rodata_gpa, req.rodata_size, req.cr3);

	return kvm_planes_vtl_call(VBS_CALL_SEAL_KERNEL,
				   &req, sizeof(req), NULL, 0);
}

/* ── module authentication ────────────────────────────────────────────── */

static int kvm_planes_validate_module(const void *elf, size_t elf_size,
				      const void *sig, size_t sig_size)
{
	struct vbs_validate_module_req req = {};
	struct page *elf_page;
	const Elf64_Ehdr *ehdr;

	if (!elf || !elf_size)
		return -EINVAL;

	/*
	 * sig_size is repurposed: 1 = kernel's own sig check passed,
	 * 0 = module is unsigned or sig check failed.
	 */
	req.sig_ok = sig_size ? 1 : 0;

	/* Try to extract the module name from the ELF .modinfo section.
	 * For now, just use a placeholder — the name is available at
	 * the call site in load_module() but not passed through the
	 * vbs_ops interface which takes (elf, elf_size, sig, sig_size).
	 */
	ehdr = elf;
	if (elf_size >= sizeof(*ehdr) && ehdr->e_ident[0] == 0x7f)
		strscpy(req.name, "module", sizeof(req.name));
	else
		strscpy(req.name, "unknown", sizeof(req.name));

	/* Get GPA of the ELF blob */
	elf_page = vmalloc_to_page(elf);
	if (elf_page) {
		req.elf_gpa  = page_to_phys(elf_page) +
			       offset_in_page(elf);
		req.elf_size = elf_size;
	}

	pr_debug("vbs-kvm: validate_module elf_gpa=0x%llx size=0x%llx sig_ok=%u\n",
		 req.elf_gpa, req.elf_size, req.sig_ok);

	return kvm_planes_vtl_call(VBS_CALL_VALIDATE_MODULE,
				   &req, sizeof(req), NULL, 0);
}

static int kvm_planes_set_module_perms(const struct module *mod)
{
	struct {
		struct vbs_set_module_perms_req hdr;
		struct vbs_module_section sections[MOD_MEM_NUM_TYPES];
	} __packed req = {};
	int i, n = 0;

	strscpy(req.hdr.name, mod->name, sizeof(req.hdr.name));

	for (i = 0; i < MOD_MEM_NUM_TYPES; i++) {
		const struct module_memory *mem = &mod->mem[i];
		struct vbs_module_section *sec;
		unsigned long gpa;
		struct page *p;

		if (!mem->base || !mem->size)
			continue;

		p = vmalloc_to_page(mem->base);
		if (!p)
			continue;

		gpa = page_to_phys(p) + offset_in_page(mem->base);
		sec = &req.sections[n];
		sec->gpa   = gpa;
		sec->size  = PAGE_ALIGN(mem->size);
		sec->type  = i;

		/* Set permissions based on section type */
		switch (i) {
		case MOD_TEXT:
		case MOD_INIT_TEXT:
			sec->perms = VBS_MEM_READ | VBS_MEM_EXEC;
			break;
		case MOD_RODATA:
		case MOD_RO_AFTER_INIT:
		case MOD_INIT_RODATA:
			sec->perms = VBS_MEM_READ;
			break;
		default: /* MOD_DATA, MOD_INIT_DATA */
			sec->perms = VBS_MEM_READ | VBS_MEM_WRITE;
			break;
		}
		n++;
	}

	req.hdr.nr_sections = n;

	pr_debug("vbs-kvm: set_module_perms %s: %d sections\n",
		 mod->name, n);

	return kvm_planes_vtl_call(VBS_CALL_SET_MODULE_PERMS,
				   &req,
				   sizeof(req.hdr) + n * sizeof(req.sections[0]),
				   NULL, 0);
}

static int kvm_planes_unload_module(const struct module *mod)
{
	struct vbs_unload_module_req req = {};

	strscpy(req.name, mod->name, sizeof(req.name));

	return kvm_planes_vtl_call(VBS_CALL_UNLOAD_MODULE,
				   &req, sizeof(req), NULL, 0);
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
	struct vbs_kexec_validate_req req = {};
	struct page *page;

	if (!kernel || !kernel_size)
		return -EINVAL;

	/*
	 * sig_size is repurposed: 1 = kernel's sig check passed,
	 * 0 = unsigned or failed (same pattern as module validation).
	 */
	req.sig_ok = sig_size ? 1 : 0;
	req.kernel_size = kernel_size;

	/* Get GPA of the kernel image buffer (first page) */
	page = vmalloc_to_page(kernel);
	if (page)
		req.kernel_gpa = page_to_phys(page) + offset_in_page(kernel);

	pr_info("vbs-kvm: kexec_validate gpa=0x%llx size=0x%llx sig_ok=%u\n",
		req.kernel_gpa, req.kernel_size, req.sig_ok);

	return kvm_planes_vtl_call(VBS_CALL_KEXEC_VALIDATE,
				   &req, sizeof(req), NULL, 0);
}

static int kvm_planes_kexec_invalidate(void)
{
	pr_info("vbs-kvm: kexec_invalidate\n");
	return kvm_planes_vtl_call(VBS_CALL_KEXEC_INVALIDATE,
				   NULL, 0, NULL, 0);
}

/* ── lifecycle ────────────────────────────────────────────────────────── */

static int kvm_planes_init(void)
{
	int ret;

	kvm_ca_page = (void *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
	if (!kvm_ca_page)
		return -ENOMEM;

	ret = kvm_planes_vtl_call(VBS_CALL_INIT, NULL, 0, NULL, 0);
	if (ret) {
		pr_err("vbs-kvm: plane-1 INIT call failed (%d)\n", ret);
		free_page((unsigned long)kvm_ca_page);
		kvm_ca_page = NULL;
		return ret;
	}

	pr_info("vbs-kvm: connected to plane-1 secure kernel\n");
	return 0;
}

static void kvm_planes_shutdown(void)
{
	kvm_planes_vtl_call(VBS_CALL_SHUTDOWN, NULL, 0, NULL, 0);
	free_page((unsigned long)kvm_ca_page);
	kvm_ca_page = NULL;
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
