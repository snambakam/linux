// SPDX-License-Identifier: GPL-2.0-only
/*
 * VBS — Virtualization-Based Security core
 *
 * Dispatches calls from guest kernel subsystems to the active
 * platform-specific backend (KVM planes, SVSM, Hyper-V VSM, …).
 */

#include "internal.h"

#include <linux/mutex.h>

static const struct vbs_ops *vbs_backend;
static DEFINE_MUTEX(vbs_lock);

int vbs_register_backend(const struct vbs_ops *ops)
{
	int ret = 0;

	if (!ops || !ops->name)
		return -EINVAL;

	mutex_lock(&vbs_lock);
	if (vbs_backend) {
		pr_err("vbs: backend \"%s\" already registered, rejecting \"%s\"\n",
		       vbs_backend->name, ops->name);
		ret = -EBUSY;
	} else {
		vbs_backend = ops;
		pr_info("vbs: registered backend \"%s\"\n", ops->name);
	}
	mutex_unlock(&vbs_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(vbs_register_backend);

bool vbs_available(void)
{
	return READ_ONCE(vbs_backend) != NULL;
}
EXPORT_SYMBOL_GPL(vbs_available);

/* ── convenience wrappers ─────────────────────────────────────────────── */

int vbs_protect_memory(unsigned long pfn, unsigned long nr_pages,
		       unsigned int perms)
{
	const struct vbs_ops *ops = READ_ONCE(vbs_backend);

	if (!ops)
		return -ENODEV;
	if (!ops->protect_memory)
		return -EOPNOTSUPP;
	return ops->protect_memory(pfn, nr_pages, perms);
}
EXPORT_SYMBOL_GPL(vbs_protect_memory);

int vbs_seal_kernel(void)
{
	const struct vbs_ops *ops = READ_ONCE(vbs_backend);

	if (!ops)
		return -ENODEV;
	if (!ops->seal_kernel)
		return -EOPNOTSUPP;
	return ops->seal_kernel();
}
EXPORT_SYMBOL_GPL(vbs_seal_kernel);

int vbs_validate_module(const void *elf, size_t elf_size,
			const void *sig, size_t sig_size)
{
	const struct vbs_ops *ops = READ_ONCE(vbs_backend);

	if (!ops)
		return -ENODEV;
	if (!ops->validate_module)
		return -EOPNOTSUPP;
	return ops->validate_module(elf, elf_size, sig, sig_size);
}
EXPORT_SYMBOL_GPL(vbs_validate_module);

int vbs_set_module_perms(const struct module *mod)
{
	const struct vbs_ops *ops = READ_ONCE(vbs_backend);

	if (!ops)
		return -ENODEV;
	if (!ops->set_module_perms)
		return -EOPNOTSUPP;
	return ops->set_module_perms(mod);
}
EXPORT_SYMBOL_GPL(vbs_set_module_perms);

int vbs_unload_module(const struct module *mod)
{
	const struct vbs_ops *ops = READ_ONCE(vbs_backend);

	if (!ops)
		return -ENODEV;
	if (!ops->unload_module)
		return -EOPNOTSUPP;
	return ops->unload_module(mod);
}
EXPORT_SYMBOL_GPL(vbs_unload_module);

int vbs_add_key(const void *key, size_t key_size, unsigned int flags)
{
	const struct vbs_ops *ops = READ_ONCE(vbs_backend);

	if (!ops)
		return -ENODEV;
	if (!ops->add_key)
		return -EOPNOTSUPP;
	return ops->add_key(key, key_size, flags);
}
EXPORT_SYMBOL_GPL(vbs_add_key);

int vbs_revoke_key(const void *key_id, size_t id_size)
{
	const struct vbs_ops *ops = READ_ONCE(vbs_backend);

	if (!ops)
		return -ENODEV;
	if (!ops->revoke_key)
		return -EOPNOTSUPP;
	return ops->revoke_key(key_id, id_size);
}
EXPORT_SYMBOL_GPL(vbs_revoke_key);

int vbs_send_certs(const void *certs, size_t certs_size)
{
	const struct vbs_ops *ops = READ_ONCE(vbs_backend);

	if (!ops)
		return -ENODEV;
	if (!ops->send_certs)
		return -EOPNOTSUPP;
	return ops->send_certs(certs, certs_size);
}
EXPORT_SYMBOL_GPL(vbs_send_certs);

int vbs_kexec_validate(const void *kernel, size_t kernel_size,
		       const void *sig, size_t sig_size)
{
	const struct vbs_ops *ops = READ_ONCE(vbs_backend);

	if (!ops)
		return -ENODEV;
	if (!ops->kexec_validate)
		return -EOPNOTSUPP;
	return ops->kexec_validate(kernel, kernel_size, sig, sig_size);
}
EXPORT_SYMBOL_GPL(vbs_kexec_validate);

int vbs_kexec_invalidate(void)
{
	const struct vbs_ops *ops = READ_ONCE(vbs_backend);

	if (!ops)
		return -ENODEV;
	if (!ops->kexec_invalidate)
		return -EOPNOTSUPP;
	return ops->kexec_invalidate();
}
EXPORT_SYMBOL_GPL(vbs_kexec_invalidate);

/* ── HEKI: automatic kernel sealing at late init ──────────────────────── */

static int __init vbs_heki_late_init(void)
{
	const struct vbs_ops *ops = READ_ONCE(vbs_backend);
	int ret;

	if (!ops) {
		pr_debug("vbs: HEKI: no backend, skipping kernel seal\n");
		return 0;
	}

	/* Initialize the backend (allocates shared memory, etc.) */
	if (ops->init) {
		ret = ops->init();
		if (ret) {
			pr_warn("vbs: HEKI: backend init failed (%d)\n", ret);
			return 0;
		}
	}

	pr_info("vbs: HEKI: sealing kernel text and rodata\n");
	ret = vbs_seal_kernel();
	if (ret)
		pr_warn("vbs: HEKI: seal_kernel failed (%d)\n", ret);
	else
		pr_info("vbs: HEKI: kernel sealed successfully\n");

	return 0;
}
late_initcall(vbs_heki_late_init);
