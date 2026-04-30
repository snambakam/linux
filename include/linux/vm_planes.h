/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_VM_PLANES_H
#define _LINUX_VM_PLANES_H

#include <linux/init.h>
#include <linux/types.h>

#ifdef CONFIG_VM_PLANES

#define VM_PLANE_KERNEL_NAME_MAX	128
#define VM_PLANE_CMDLINE_MAX		512

enum vm_plane_kernel_format {
	VM_PLANE_KFMT_RAW = 0,
	VM_PLANE_KFMT_BZIMAGE,
	VM_PLANE_KFMT_ELF,
};

struct vm_plane_config {
	phys_addr_t load_offset;
	phys_addr_t memory_size;
	phys_addr_t entry_point;
	unsigned int vcpu_count;
	unsigned int kernel_format;
	char kernel[VM_PLANE_KERNEL_NAME_MAX];
	char cmdline[VM_PLANE_CMDLINE_MAX];
};

void __init arch_init_vm_planes(void);
int __init load_vm_plane_kernels(unsigned int plane_count,
				 struct vm_plane_config *plane_cfg);

#endif /* CONFIG_VM_PLANES */

#endif /* _LINUX_VM_PLANES_H */
