/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * HEKI — Hypervisor-Enforced Kernel Integrity
 *
 * Shared data structures between the guest kernel (plane-0) and the
 * VBS secure kernel / QEMU dispatcher.  These structs are placed in
 * the VBS CAA page buffer and must be kept in sync with the QEMU-side
 * definitions.
 */
#ifndef _VBS_HEKI_H
#define _VBS_HEKI_H

#include <linux/types.h>

/*
 * VBS_CALL_PROTECT_MEMORY payload — request EPT permission changes on
 * a contiguous GPA range from the perspective of the calling plane.
 */
struct vbs_protect_memory_req {
	__u64	gpa;		/* guest-physical address (page-aligned)  */
	__u64	size;		/* region size in bytes (page-aligned)    */
	__u32	perms;		/* desired permissions: VBS_MEM_* flags   */
	__u32	flags;		/* reserved, must be 0                   */
} __packed;

/*
 * VBS_CALL_SEAL_KERNEL payload — plane-0 sends the GPAs of its kernel
 * text and rodata sections so that the secure side can make them
 * immutable (NO_WRITE in the lower plane's EPT).
 */
struct vbs_seal_kernel_req {
	__u64	text_gpa;	/* _stext physical address               */
	__u64	text_size;	/* _etext - _stext                       */
	__u64	rodata_gpa;	/* __start_rodata physical address        */
	__u64	rodata_size;	/* __end_rodata - __start_rodata          */
	__u64	cr3;		/* plane-0 kernel CR3 for verification    */
} __packed;

/* ── Module authentication ────────────────────────────────────────────── */

/*
 * VBS_CALL_VALIDATE_MODULE payload — plane-0 sends the GPA of the module
 * ELF blob and its appended PKCS#7 signature for plane-1 verification.
 * The module blob is in guest physical memory; the secure side reads it
 * directly via the GPA (no copy through the CAA page).
 */
struct vbs_validate_module_req {
	char	name[56];	/* module name (null-terminated)          */
	__u64	elf_gpa;	/* GPA of the module ELF data             */
	__u64	elf_size;	/* size of the ELF data (excl. signature) */
	__u32	sig_ok;		/* 1 if kernel's sig check passed         */
	__u32	reserved;	/* padding                               */
} __packed;

/*
 * Per-section descriptor for VBS_CALL_SET_MODULE_PERMS.
 * Sent as an array in the CAA buffer after the module name.
 */
struct vbs_module_section {
	__u64	gpa;		/* section GPA (page-aligned)             */
	__u64	size;		/* section size (page-aligned)            */
	__u32	perms;		/* VBS_MEM_* permission flags             */
	__u32	type;		/* enum mod_mem_type                      */
} __packed;

/*
 * VBS_CALL_SET_MODULE_PERMS payload — after relocation, plane-0 sends
 * the per-section layout so plane-1 can set EPT permissions.
 * Sections follow immediately after this header in the buffer.
 */
struct vbs_set_module_perms_req {
	char	name[56];	/* module name (null-terminated)          */
	__u32	nr_sections;	/* number of vbs_module_section entries   */
	__u32	flags;		/* reserved, must be 0                   */
	/* struct vbs_module_section sections[]; follows in buffer */
} __packed;

/*
 * VBS_CALL_UNLOAD_MODULE payload — module is being freed.
 */
struct vbs_unload_module_req {
	char	name[56];	/* module name (null-terminated)          */
} __packed;

/* ── x86-64 page table walker (for plane-1 auditing) ─────────────────── */

/* Classification of a guest-physical page based on page table walk */
enum heki_page_class {
	HEKI_PAGE_UNMAPPED	= 0,
	HEKI_PAGE_TEXT		= 1,	/* executable, read-only  (kernel text) */
	HEKI_PAGE_RODATA	= 2,	/* non-executable, read-only            */
	HEKI_PAGE_DATA_RW	= 3,	/* non-executable, read-write           */
	HEKI_PAGE_DATA_RX	= 4,	/* executable, read-write (DANGEROUS)   */
};

/*
 * Callback invoked for each mapped page during a page table walk.
 * @va:    virtual address of the page
 * @pa:    guest-physical address of the page
 * @size:  page size (4K, 2M, or 1G)
 * @pclass: classification based on PTE permission bits
 * @priv:  opaque context from the caller
 *
 * Return 0 to continue walking, non-zero to stop.
 */
typedef int (*heki_walk_cb)(unsigned long va, unsigned long pa,
			    unsigned long size, enum heki_page_class pclass,
			    void *priv);

#ifdef CONFIG_X86_64
/*
 * Walk x86-64 4-level page tables starting from @cr3.
 * @read_gpa: function to read @len bytes from guest physical address @gpa
 *            into @buf.  Returns 0 on success.
 * @va_start, @va_end: virtual address range to walk (0 for full walk)
 * @cb:     callback invoked for each mapped page
 * @priv:   opaque context passed to the callback
 *
 * Returns 0 on success, negative errno on failure.
 */
int heki_walk_x86_tables(unsigned long cr3,
			 int (*read_gpa)(u64 gpa, void *buf, size_t len,
					 void *ctx),
			 void *read_ctx,
			 unsigned long va_start, unsigned long va_end,
			 heki_walk_cb cb, void *priv);
#endif /* CONFIG_X86_64 */

#endif /* _VBS_HEKI_H */
