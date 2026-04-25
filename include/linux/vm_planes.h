/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_VM_PLANES_H
#define _LINUX_VM_PLANES_H

#include <linux/init.h>
#include <linux/types.h>

#ifdef CONFIG_VM_PLANES

#define VM_PLANE_KERNEL_NAME_MAX	128

struct vm_plane_config {
	phys_addr_t load_offset;
	phys_addr_t memory_size;
	char kernel[VM_PLANE_KERNEL_NAME_MAX];
};

void __init arch_init_vm_planes(void);

#endif /* CONFIG_VM_PLANES */

#endif /* _LINUX_VM_PLANES_H */
