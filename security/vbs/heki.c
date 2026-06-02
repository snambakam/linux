// SPDX-License-Identifier: GPL-2.0-only
/*
 * HEKI — Hypervisor-Enforced Kernel Integrity
 *
 * x86-64 page table walker and kernel protection logic.
 *
 * The page table walker is designed to be called from plane-1 (the secure
 * kernel) to audit plane-0's page tables.  It is parameterised with a
 * read_gpa() callback so it can work both in-kernel (for plane-1 with
 * direct GPA access) and from QEMU (future, for host-side auditing).
 *
 * The seal_kernel helper runs in plane-0 and sends the kernel text/rodata
 * GPA ranges to the secure side via the VBS VTL call mechanism.
 */

#include "heki.h"
#include "internal.h"

#include <linux/kernel.h>
#include <linux/string.h>
#include <asm/sections.h>

#ifdef CONFIG_X86_64
#include <asm/page.h>

/* ── x86-64 page table constants ──────────────────────────────────────── */

#define PT_ENTRIES		512
#define PT_ENTRY_SIZE		8

/* PTE bit positions */
#define PTE_PRESENT		BIT_ULL(0)
#define PTE_WRITABLE		BIT_ULL(1)
#define PTE_USER		BIT_ULL(2)
#define PTE_PS			BIT_ULL(7)	/* page size (huge page) */
#define PTE_NX			BIT_ULL(63)	/* no-execute */

/* Physical address mask for 4-level paging (bits 12..51) */
#define PTE_ADDR_MASK		0x000FFFFFFFFFF000ULL

/* Page sizes */
#define PAGE_SIZE_4K		(1UL << 12)
#define PAGE_SIZE_2M		(1UL << 21)
#define PAGE_SIZE_1G		(1UL << 30)

/* Virtual address extraction helpers */
static inline unsigned int pml4_index(unsigned long va)
{
	return (va >> 39) & 0x1FF;
}

static inline unsigned int pdpt_index(unsigned long va)
{
	return (va >> 30) & 0x1FF;
}

static inline unsigned int pd_index(unsigned long va)
{
	return (va >> 21) & 0x1FF;
}

static inline unsigned int pt_index(unsigned long va)
{
	return (va >> 12) & 0x1FF;
}

/*
 * Classify a page based on its PTE permission bits.
 */
static enum heki_page_class classify_pte(u64 pte)
{
	bool writable = !!(pte & PTE_WRITABLE);
	bool executable = !(pte & PTE_NX);

	if (executable && !writable)
		return HEKI_PAGE_TEXT;
	if (!executable && !writable)
		return HEKI_PAGE_RODATA;
	if (!executable && writable)
		return HEKI_PAGE_DATA_RW;
	/* executable + writable — W^X violation */
	return HEKI_PAGE_DATA_RX;
}

/*
 * Read a single page table entry from guest physical memory.
 */
static int read_pte(u64 table_gpa, unsigned int index,
		    int (*read_gpa)(u64, void *, size_t, void *),
		    void *ctx, u64 *pte_out)
{
	u64 entry_gpa = table_gpa + (u64)index * PT_ENTRY_SIZE;

	return read_gpa(entry_gpa, pte_out, sizeof(*pte_out), ctx);
}

/*
 * Walk a page table (PT) level — 4K pages.
 */
static int walk_pt(u64 pt_gpa, unsigned long va_base,
		   int (*read_gpa)(u64, void *, size_t, void *), void *ctx,
		   unsigned long va_start, unsigned long va_end,
		   heki_walk_cb cb, void *priv)
{
	unsigned int start_idx, end_idx, i;
	int ret;

	start_idx = (va_start > va_base) ? pt_index(va_start) : 0;
	end_idx   = (va_end && va_end < va_base + PT_ENTRIES * PAGE_SIZE_4K)
		    ? pt_index(va_end - 1) : PT_ENTRIES - 1;

	for (i = start_idx; i <= end_idx; i++) {
		u64 pte;
		unsigned long va = va_base + (unsigned long)i * PAGE_SIZE_4K;

		ret = read_pte(pt_gpa, i, read_gpa, ctx, &pte);
		if (ret)
			return ret;
		if (!(pte & PTE_PRESENT))
			continue;

		ret = cb(va, pte & PTE_ADDR_MASK, PAGE_SIZE_4K,
			 classify_pte(pte), priv);
		if (ret)
			return ret;
	}
	return 0;
}

/*
 * Walk a page directory (PD) level — 2M huge pages or recurse into PT.
 */
static int walk_pd(u64 pd_gpa, unsigned long va_base,
		   int (*read_gpa)(u64, void *, size_t, void *), void *ctx,
		   unsigned long va_start, unsigned long va_end,
		   heki_walk_cb cb, void *priv)
{
	unsigned int start_idx, end_idx, i;
	int ret;

	start_idx = (va_start > va_base) ? pd_index(va_start) : 0;
	end_idx   = (va_end && va_end < va_base + (unsigned long)PT_ENTRIES * PAGE_SIZE_2M)
		    ? pd_index(va_end - 1) : PT_ENTRIES - 1;

	for (i = start_idx; i <= end_idx; i++) {
		u64 pde;
		unsigned long va = va_base + (unsigned long)i * PAGE_SIZE_2M;

		ret = read_pte(pd_gpa, i, read_gpa, ctx, &pde);
		if (ret)
			return ret;
		if (!(pde & PTE_PRESENT))
			continue;

		if (pde & PTE_PS) {
			/* 2M huge page */
			ret = cb(va, pde & PTE_ADDR_MASK, PAGE_SIZE_2M,
				 classify_pte(pde), priv);
			if (ret)
				return ret;
		} else {
			ret = walk_pt(pde & PTE_ADDR_MASK, va,
				      read_gpa, ctx, va_start, va_end,
				      cb, priv);
			if (ret)
				return ret;
		}
	}
	return 0;
}

/*
 * Walk a page directory pointer table (PDPT) — 1G huge pages or recurse.
 */
static int walk_pdpt(u64 pdpt_gpa, unsigned long va_base,
		     int (*read_gpa)(u64, void *, size_t, void *), void *ctx,
		     unsigned long va_start, unsigned long va_end,
		     heki_walk_cb cb, void *priv)
{
	unsigned int start_idx, end_idx, i;
	int ret;

	start_idx = (va_start > va_base) ? pdpt_index(va_start) : 0;
	end_idx   = (va_end && va_end < va_base + (unsigned long)PT_ENTRIES * PAGE_SIZE_1G)
		    ? pdpt_index(va_end - 1) : PT_ENTRIES - 1;

	for (i = start_idx; i <= end_idx; i++) {
		u64 pdpte;
		unsigned long va = va_base + (unsigned long)i * PAGE_SIZE_1G;

		ret = read_pte(pdpt_gpa, i, read_gpa, ctx, &pdpte);
		if (ret)
			return ret;
		if (!(pdpte & PTE_PRESENT))
			continue;

		if (pdpte & PTE_PS) {
			/* 1G huge page */
			ret = cb(va, pdpte & PTE_ADDR_MASK, PAGE_SIZE_1G,
				 classify_pte(pdpte), priv);
			if (ret)
				return ret;
		} else {
			ret = walk_pd(pdpte & PTE_ADDR_MASK, va,
				      read_gpa, ctx, va_start, va_end,
				      cb, priv);
			if (ret)
				return ret;
		}
	}
	return 0;
}

/**
 * heki_walk_x86_tables - walk x86-64 4-level page tables
 * @cr3:        value of CR3 (page table root physical address)
 * @read_gpa:   callback to read bytes from a guest physical address
 * @read_ctx:   opaque context passed to read_gpa
 * @va_start:   start of virtual address range (0 = from beginning)
 * @va_end:     end of virtual address range (0 = to end)
 * @cb:         callback invoked for each present page
 * @priv:       opaque context passed to cb
 *
 * Walks the full PML4 → PDPT → PD → PT hierarchy, invoking @cb for
 * every present page (4K, 2M, or 1G) within [va_start, va_end).
 *
 * Returns 0 on success, or the first non-zero return from @cb / @read_gpa.
 */
int heki_walk_x86_tables(unsigned long cr3,
			 int (*read_gpa)(u64 gpa, void *buf, size_t len,
					 void *ctx),
			 void *read_ctx,
			 unsigned long va_start, unsigned long va_end,
			 heki_walk_cb cb, void *priv)
{
	u64 pml4_gpa = cr3 & PTE_ADDR_MASK;
	unsigned int i;
	int ret;

	if (!read_gpa || !cb)
		return -EINVAL;

	/*
	 * Walk PML4 entries.  Each PML4 entry covers 512 GB.
	 * For the kernel half of the address space on x86-64,
	 * entries 256..511 map the kernel virtual addresses
	 * (0xffff800000000000 and above).
	 */
	for (i = 0; i < PT_ENTRIES; i++) {
		u64 pml4e;
		/* Each PML4 entry covers 512 GiB */
		unsigned long va_base = (unsigned long)i << 39;

		/*
		 * Sign-extend for canonical addresses: entries 256..511
		 * map the upper half (kernel space).
		 */
		if (i >= 256)
			va_base |= 0xFFFF000000000000UL;

		/* Skip entries outside the requested range */
		if (va_end && va_base >= va_end)
			break;
		if (va_start) {
			unsigned long entry_end = va_base +
				(1UL << 39) - 1;
			if (entry_end < va_start)
				continue;
		}

		ret = read_pte(pml4_gpa, i, read_gpa, read_ctx, &pml4e);
		if (ret)
			return ret;
		if (!(pml4e & PTE_PRESENT))
			continue;

		ret = walk_pdpt(pml4e & PTE_ADDR_MASK, va_base,
				read_gpa, read_ctx, va_start, va_end,
				cb, priv);
		if (ret)
			return ret;
	}

	return 0;
}

#endif /* CONFIG_X86_64 */
