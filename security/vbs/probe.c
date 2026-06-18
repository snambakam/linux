// SPDX-License-Identifier: GPL-2.0-only
/*
 * VBS platform detection and backend selection
 *
 * Single initcall that probes the platform and registers the appropriate
 * VBS backend.  Detection order (first match wins):
 *
 *   1. Hardware CoCo — these are mutually exclusive by nature:
 *      a. AMD SEV-SNP with SVSM  (VMPL > 0, SVSM at VMPL0)
 *      b. Intel TDX service TD   (running inside a Trust Domain)
 *      c. Arm CCA               (Realm guest with RSI)
 *
 *   2. Hypervisor-specific:
 *      d. Hyper-V VSM            (Hyper-V guest at VTL0)
 *
 *   3. Software emulation:
 *      e. KVM software planes    (KVM paravirt guest)
 *
 * Only one backend can be active.  The first successful probe wins.
 */

#include "internal.h"

/* Stubs for backends not configured */
#ifndef CONFIG_VBS_SEV_SNP
static inline bool vbs_sev_snp_detect(void) { return false; }
static inline const struct vbs_ops *vbs_sev_snp_get_ops(void) { return NULL; }
#endif
#ifndef CONFIG_VBS_TDX
static inline bool vbs_tdx_detect(void) { return false; }
static inline const struct vbs_ops *vbs_tdx_get_ops(void) { return NULL; }
#endif
#ifndef CONFIG_VBS_ARM_CCA
static inline bool vbs_cca_detect(void) { return false; }
static inline const struct vbs_ops *vbs_cca_get_ops(void) { return NULL; }
#endif
#ifndef CONFIG_VBS_HV_VSM
static inline bool vbs_hv_vsm_detect(void) { return false; }
static inline const struct vbs_ops *vbs_hv_vsm_get_ops(void) { return NULL; }
#endif
#ifndef CONFIG_VBS_KVM_PLANES
static inline bool vbs_kvm_planes_detect(void) { return false; }
static inline const struct vbs_ops *vbs_kvm_planes_get_ops(void) { return NULL; }
#endif

/* ── probe table ──────────────────────────────────────────────────────── */

struct vbs_probe_entry {
	const char *name;
	bool (*detect)(void);
	const struct vbs_ops *(*get_ops)(void);
};

static const struct vbs_probe_entry vbs_probe_table[] __initconst = {
	/*
	 * Hardware confidential-compute backends first.
	 * These are mutually exclusive — a machine is SEV-SNP *or* TDX
	 * *or* CCA, never more than one.
	 */
	{ "AMD SEV-SNP",	vbs_sev_snp_detect,	vbs_sev_snp_get_ops },
	{ "Intel TDX",		vbs_tdx_detect,		vbs_tdx_get_ops },
	{ "Arm CCA",		vbs_cca_detect,		vbs_cca_get_ops },

	/* Hypervisor-specific */
	{ "Hyper-V VSM",	vbs_hv_vsm_detect,	vbs_hv_vsm_get_ops },

	/* Software emulation (lowest priority) */
	{ "KVM planes",		vbs_kvm_planes_detect,	vbs_kvm_planes_get_ops },
};

/* ── single boot-time probe ───────────────────────────────────────────── */

static int __init vbs_probe_init(void)
{
	int i, ret;

	for (i = 0; i < ARRAY_SIZE(vbs_probe_table); i++) {
		const struct vbs_probe_entry *e = &vbs_probe_table[i];

		if (!e->detect())
			continue;

		pr_info("vbs: detected %s platform\n", e->name);

		ret = vbs_register_backend(e->get_ops());
		if (ret) {
			pr_err("vbs: failed to register %s backend (%d)\n",
			       e->name, ret);
			return ret;
		}
		return 0;
	}

	pr_debug("vbs: no supported platform detected\n");
	return 0;
}

/*
 * Run at rootfs_initcall level: platform detection (CPUID, MSRs, SMCCC)
 * is complete by this point, the VM planes have been set up (init/ links
 * before security/), and subsystems that consume VBS (module loading, HEKI,
 * device drivers, userspace) have not yet started.
 */
rootfs_initcall(vbs_probe_init);
