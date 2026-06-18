# SPDX-License-Identifier: GPL-2.0-only
obj-$(CONFIG_VBS) += vbs.o
# probe.o must link before core.o so that, at rootfs_initcall level, the
# backend is registered (vbs_probe_init) before the HEKI seal runs
# (vbs_heki_late_init in core.o).
vbs-y := probe.o core.o

vbs-$(CONFIG_VBS_HEKI)		+= heki.o
obj-$(CONFIG_VBS_KVM_PLANES)	+= kvm_planes.o
obj-$(CONFIG_VBS_KVM_PLANES)	+= secure_monitor.o
obj-$(CONFIG_VBS_SEV_SNP)	+= sev_snp.o
obj-$(CONFIG_VBS_TDX)		+= tdx.o
obj-$(CONFIG_VBS_HV_VSM)	+= hv_vsm.o
obj-$(CONFIG_VBS_ARM_CCA)	+= arm_cca.o
