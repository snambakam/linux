/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * VBS — Virtualization-Based Security
 *
 * Transport-agnostic interface between the guest OS (plane-0 / VTL0 / VMPL2+)
 * and the secure kernel (plane-1 / VTL1 / VMPL0 / service TD).
 *
 * Backends:
 *   - KVM software planes   (KVM_X86_DEFAULT_VM, QEMU-managed vCPU threads)
 *   - AMD SEV-SNP VMPL/SVSM (KVM_X86_SNP_VM, hardware VMPLs, SVSM protocol)
 *   - Intel TDX service TD   (future — separate TD with shared memory)
 *   - Hyper-V VSM            (native VTL hypercalls)
 *   - Arm CCA               (RSI host calls from Realm guest to RMM)
 *
 * The guest kernel calls vbs_*() functions.  The active backend translates
 * them into the appropriate transport (hypercall, VMGEXIT, shared-memory IPC).
 */

#ifndef _LINUX_VBS_H
#define _LINUX_VBS_H

#include <linux/types.h>
#include <linux/errno.h>

struct module;

/* ────────────────────────────────────────────────────────────────────────── */
/*  Memory protection flags                                                  */
/* ────────────────────────────────────────────────────────────────────────── */

/* Permissions that the secure kernel can enforce on lower-plane memory.     */
#define VBS_MEM_READ		BIT(0)
#define VBS_MEM_WRITE		BIT(1)
#define VBS_MEM_EXEC		BIT(2)

/* ────────────────────────────────────────────────────────────────────────── */
/*  VTL-call request codes (plane-0 → plane-1 direction)                    */
/* ────────────────────────────────────────────────────────────────────────── */

enum vbs_call_id {
	/* Core lifecycle */
	VBS_CALL_INIT			= 0x0001, /* plane-0 boot complete     */
	VBS_CALL_SHUTDOWN		= 0x0002, /* plane-0 shutting down      */

	/* Memory protection (HEKI) */
	VBS_CALL_PROTECT_MEMORY	= 0x0100, /* set page permissions       */
	VBS_CALL_SEAL_KERNEL		= 0x0101, /* make kernel text immutable */

	/* Module authentication */
	VBS_CALL_VALIDATE_MODULE	= 0x0200, /* verify module signature    */
	VBS_CALL_SET_MODULE_PERMS	= 0x0201, /* set module section perms   */
	VBS_CALL_UNLOAD_MODULE		= 0x0202, /* module being freed         */

	/* Key / certificate management */
	VBS_CALL_ADD_KEY		= 0x0300, /* add runtime key             */
	VBS_CALL_REVOKE_KEY		= 0x0301, /* revoke a key               */
	VBS_CALL_SEND_CERTS		= 0x0302, /* send system certificates   */

	/* Kexec validation */
	VBS_CALL_KEXEC_VALIDATE	= 0x0400, /* validate kexec kernel      */
	VBS_CALL_KEXEC_INVALIDATE	= 0x0401, /* invalidate kexec state     */
};

/* ────────────────────────────────────────────────────────────────────────── */
/*  Backend operations (one implementation per platform)                     */
/* ────────────────────────────────────────────────────────────────────────── */

/**
 * struct vbs_ops - operations provided by an VBS backend
 *
 * All callbacks are optional; returning -ENOTSUP means the backend does
 * not implement that feature.  The core VBS layer will call these from
 * process context with preemption enabled.
 */
struct vbs_ops {
	const char *name;	/* "kvm-planes", "svsm", "hv-vsm", … */

	/*
	 * Lifecycle
	 */

	/** @init: called once after plane-0 kernel boot is complete. */
	int (*init)(void);

	/** @shutdown: called before plane-0 halts/reboots. */
	void (*shutdown)(void);

	/*
	 * Raw VTL call — send an arbitrary request to the secure kernel
	 * and wait for a response.  @id is the call code, @arg / @arg_size
	 * point to request-specific data, @resp / @resp_size receive the
	 * reply.  Returns 0 on success, negative errno on failure.
	 */
	int (*vtl_call)(enum vbs_call_id id,
			const void *arg, size_t arg_size,
			void *resp, size_t resp_size);

	/*
	 * Memory protection (HEKI)
	 *
	 * Ask the secure kernel to enforce @perms (VBS_MEM_*) on the
	 * physical page range [pfn, pfn + nr_pages) from the perspective
	 * of the lower plane.
	 */
	int (*protect_memory)(unsigned long pfn, unsigned long nr_pages,
			      unsigned int perms);

	/**
	 * @seal_kernel: make the running kernel's text and rodata immutable.
	 * After this call, any attempt to write to kernel text from the
	 * lower plane traps to the secure kernel.
	 */
	int (*seal_kernel)(void);

	/*
	 * Module authentication
	 *
	 * @validate_module: send a module's ELF blob to the secure kernel
	 * for signature verification.  Returns 0 if the signature is valid.
	 *
	 * @set_module_perms: after relocation, set per-section EPT permissions
	 * for the module (text=RX, rodata=R, data=RW).
	 *
	 * @unload_module: notify the secure kernel that a module is being freed
	 * so it can release EPT overrides.
	 */
	int (*validate_module)(const void *elf, size_t elf_size,
			       const void *sig, size_t sig_size);
	int (*set_module_perms)(const struct module *mod);
	int (*unload_module)(const struct module *mod);

	/*
	 * Key / certificate management
	 */
	int (*add_key)(const void *key, size_t key_size, unsigned int flags);
	int (*revoke_key)(const void *key_id, size_t id_size);
	int (*send_certs)(const void *certs, size_t certs_size);

	/*
	 * Kexec validation
	 */
	int (*kexec_validate)(const void *kernel, size_t kernel_size,
			      const void *sig, size_t sig_size);
	int (*kexec_invalidate)(void);
};

/* ────────────────────────────────────────────────────────────────────────── */
/*  Core VBS API (called by guest kernel subsystems)                        */
/* ────────────────────────────────────────────────────────────────────────── */

#ifdef CONFIG_VBS

/**
 * vbs_register_backend() - register the platform-specific backend.
 *
 * Called once during early boot by the platform detection code.
 * Only one backend can be active at a time.
 */
int vbs_register_backend(const struct vbs_ops *ops);

/**
 * vbs_available() - returns true if a backend is registered and ready.
 */
bool vbs_available(void);

/* Convenience wrappers — each calls through the active backend's ops. */
int vbs_protect_memory(unsigned long pfn, unsigned long nr_pages,
			unsigned int perms);
int vbs_seal_kernel(void);
int vbs_validate_module(const void *elf, size_t elf_size,
			 const void *sig, size_t sig_size);
int vbs_set_module_perms(const struct module *mod);
int vbs_unload_module(const struct module *mod);
int vbs_add_key(const void *key, size_t key_size, unsigned int flags);
int vbs_revoke_key(const void *key_id, size_t id_size);
int vbs_send_certs(const void *certs, size_t certs_size);
int vbs_kexec_validate(const void *kernel, size_t kernel_size,
			const void *sig, size_t sig_size);
int vbs_kexec_invalidate(void);

#else /* !CONFIG_VBS */

static inline bool vbs_available(void) { return false; }
static inline int vbs_protect_memory(unsigned long pfn,
	unsigned long nr_pages, unsigned int perms) { return -ENOSYS; }
static inline int vbs_seal_kernel(void) { return -ENOSYS; }
static inline int vbs_validate_module(const void *elf, size_t elf_size,
	const void *sig, size_t sig_size) { return -ENOSYS; }
static inline int vbs_set_module_perms(const struct module *mod)
	{ return -ENOSYS; }
static inline int vbs_unload_module(const struct module *mod)
	{ return -ENOSYS; }
static inline int vbs_add_key(const void *key, size_t key_size,
	unsigned int flags) { return -ENOSYS; }
static inline int vbs_revoke_key(const void *key_id, size_t id_size)
	{ return -ENOSYS; }
static inline int vbs_send_certs(const void *certs, size_t certs_size)
	{ return -ENOSYS; }
static inline int vbs_kexec_validate(const void *kernel, size_t kernel_size,
	const void *sig, size_t sig_size) { return -ENOSYS; }
static inline int vbs_kexec_invalidate(void) { return -ENOSYS; }

#endif /* CONFIG_VBS */
#endif /* _LINUX_VBS_H */
