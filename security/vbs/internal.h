/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * VBS internal header — shared between probe.c and backend implementations.
 */
#ifndef _SECURITY_VBS_INTERNAL_H
#define _SECURITY_VBS_INTERNAL_H

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/vbs.h>

/* Each backend exports a detect + get_ops pair for the centralized probe. */

#ifdef CONFIG_VBS_SEV_SNP
bool __init vbs_sev_snp_detect(void);
const struct vbs_ops *vbs_sev_snp_get_ops(void);
#endif

#ifdef CONFIG_VBS_TDX
bool __init vbs_tdx_detect(void);
const struct vbs_ops *vbs_tdx_get_ops(void);
#endif

#ifdef CONFIG_VBS_ARM_CCA
bool __init vbs_cca_detect(void);
const struct vbs_ops *vbs_cca_get_ops(void);
#endif

#ifdef CONFIG_VBS_HV_VSM
bool __init vbs_hv_vsm_detect(void);
const struct vbs_ops *vbs_hv_vsm_get_ops(void);
#endif

#ifdef CONFIG_VBS_KVM_PLANES
bool __init vbs_kvm_planes_detect(void);
const struct vbs_ops *vbs_kvm_planes_get_ops(void);
#endif

#endif /* _SECURITY_VBS_INTERNAL_H */
