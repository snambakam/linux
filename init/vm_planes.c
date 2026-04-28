// SPDX-License-Identifier: GPL-2.0-only

#include <linux/init.h>
#include <linux/initrd.h>
#include <linux/kernel.h>
#include <linux/memblock.h>
#include <linux/kstrtox.h>
#include <linux/string.h>
#include <linux/kvm_para.h>
#include <linux/vm_planes.h>
#include <linux/elf.h>
#include <asm/cpu.h>
#include <asm/kvm_para.h>
#include <asm-generic/early_ioremap.h>

#ifdef CONFIG_VM_PLANES
static bool __initdata enable_vm_planes_requested;

#define VM_PLANES_CONFIG_FILE		"config-vm-planes"
#define VM_PLANES_DEFAULT_COUNT		1

struct vm_plane_parse_state {
	phys_addr_t load_offset;
	phys_addr_t memory_size;
	unsigned int vcpu_count;
	unsigned int kernel_format;
	char kernel[VM_PLANE_KERNEL_NAME_MAX];
};

#define VM_PLANES_UNSET_VALUE	((phys_addr_t)~0)

struct cpio_newc_header {
	char c_magic[6];
	char c_ino[8];
	char c_mode[8];
	char c_uid[8];
	char c_gid[8];
	char c_nlink[8];
	char c_mtime[8];
	char c_filesize[8];
	char c_devmajor[8];
	char c_devminor[8];
	char c_rdevmajor[8];
	char c_rdevminor[8];
	char c_namesize[8];
	char c_check[8];
};

static int __init parse_hex_field(const char *field, size_t len, u32 *value)
{
	u32 v = 0;
	size_t i;

	for (i = 0; i < len; i++) {
		u8 c = field[i];

		v <<= 4;
		if (c >= '0' && c <= '9')
			v |= c - '0';
		else if (c >= 'a' && c <= 'f')
			v |= c - 'a' + 10;
		else if (c >= 'A' && c <= 'F')
			v |= c - 'A' + 10;
		else
			return -EINVAL;
	}

	*value = v;
	return 0;
}

static int __init parse_plane_count_line(const char *line, size_t len,
					 unsigned int *plane_count)
{
	const char *keys[] = { "PLANE_COUNT=", "CONFIG_PLANE_COUNT=" };
	unsigned int i;

	while (len && (*line == ' ' || *line == '\t')) {
		line++;
		len--;
	}

	if (!len || *line == '#')
		return -ENOENT;

	for (i = 0; i < ARRAY_SIZE(keys); i++) {
		size_t key_len = strlen(keys[i]);
		size_t val_len = 0;
		char tmp[32];

		if (len <= key_len || strncmp(line, keys[i], key_len))
			continue;

		line += key_len;
		len -= key_len;
		while (val_len < len && line[val_len] != ' ' &&
		       line[val_len] != '\t' && line[val_len] != '#')
			val_len++;

		if (!val_len || val_len >= sizeof(tmp))
			return -EINVAL;

		memcpy(tmp, line, val_len);
		tmp[val_len] = '\0';

		if (kstrtouint(tmp, 0, plane_count))
			return -EINVAL;
		if (!*plane_count)
			return -EINVAL;

		return 0;
	}

	return -ENOENT;
}

static int __init parse_plane_count_kconfig(const char *buf, size_t len,
					    unsigned int *plane_count)
{
	const char *p = buf;
	const char *end = buf + len;

	while (p < end) {
		const char *eol = memchr(p, '\n', end - p);
		size_t line_len = eol ? (size_t)(eol - p) : (size_t)(end - p);
		int ret = parse_plane_count_line(p, line_len, plane_count);

		if (!ret)
			return 0;

		p += line_len;
		if (p < end && *p == '\n')
			p++;
	}

	return -ENOENT;
}

static int __init parse_plane_cfg_line(const char *line, size_t len,
				       unsigned int plane_count,
				       struct vm_plane_config *plane_cfg,
				       struct vm_plane_parse_state *state)
{
	char tmp[192];
	char *p, *key, *val;
	unsigned int plane_id;
	u64 parsed_u64;
	phys_addr_t parsed;

	if (len >= sizeof(tmp))
		return -E2BIG;

	memcpy(tmp, line, len);
	tmp[len] = '\0';

	p = strim(tmp);
	if (!*p || *p == '#')
		return -ENOENT;

	val = strchr(p, '#');
	if (val)
		*val = '\0';
	p = strim(p);
	if (!*p)
		return -ENOENT;

	if (!strncmp(p, "CONFIG_", 7))
		p += 7;

	if (strncmp(p, "PLANE_", 6))
		return -ENOENT;
	p += 6;

	key = strchr(p, '_');
	if (!key)
		return -EINVAL;
	*key++ = '\0';

	if (kstrtouint(p, 10, &plane_id) || plane_id >= plane_count)
		return -EINVAL;

	val = strchr(key, '=');
	if (!val)
		return -EINVAL;
	*val++ = '\0';

	key = strim(key);
	val = strim(val);
	if (!*val)
		return -EINVAL;

	if (!strcmp(key, "KERNEL")) {
		size_t val_len = strlen(val);

		if (val[0] == '"') {
			if (val_len < 2 || val[val_len - 1] != '"')
				return -EINVAL;
			val[val_len - 1] = '\0';
			val++;
			val = strim(val);
		}

		if (!*val)
			return -EINVAL;

		if (strscpy(plane_cfg[plane_id].kernel, val,
			    sizeof(plane_cfg[plane_id].kernel)) < 0)
			return -EINVAL;

		strscpy(state[plane_id].kernel, val,
			sizeof(state[plane_id].kernel));
		return 0;
	}

	if (!strcmp(key, "KERNEL_FORMAT")) {
		unsigned int fmt;

		if (!strcasecmp(val, "raw"))
			fmt = VM_PLANE_KFMT_RAW;
		else if (!strcasecmp(val, "bzimage"))
			fmt = VM_PLANE_KFMT_BZIMAGE;
		else if (!strcasecmp(val, "elf"))
			fmt = VM_PLANE_KFMT_ELF;
		else
			return -EINVAL;

		plane_cfg[plane_id].kernel_format = fmt;
		state[plane_id].kernel_format = fmt;
		return 0;
	}

	if (kstrtou64(val, 0, &parsed_u64))
		return -EINVAL;

	if (parsed_u64 > (u64)VM_PLANES_UNSET_VALUE)
		return -ERANGE;

	parsed = (phys_addr_t)parsed_u64;

	if (!strcmp(key, "LOAD_OFFSET")) {
		plane_cfg[plane_id].load_offset = parsed;
		state[plane_id].load_offset = parsed;
		return 0;
	}

	if (!strcmp(key, "MEMORY_SIZE")) {
		plane_cfg[plane_id].memory_size = parsed;
		state[plane_id].memory_size = parsed;
		return 0;
	}

	if (!strcmp(key, "VCPU_COUNT")) {
		if (parsed_u64 == 0 || parsed_u64 > UINT_MAX)
			return -EINVAL;
		plane_cfg[plane_id].vcpu_count = (unsigned int)parsed_u64;
		state[plane_id].vcpu_count = (unsigned int)parsed_u64;
		return 0;
	}

	return -ENOENT;
}

static int __init parse_vm_planes_kconfig(const char *buf, size_t len,
				  unsigned int *plane_count,
				  struct vm_plane_config **plane_cfg)
{
	const char *p = buf;
	const char *end = buf + len;
	struct vm_plane_parse_state *state;
	unsigned int i;
	int ret;

	ret = parse_plane_count_kconfig(buf, len, plane_count);
	if (ret)
		return ret;

	if (*plane_count > UINT_MAX / sizeof(**plane_cfg))
		return -E2BIG;

	*plane_cfg = memblock_alloc(*plane_count * sizeof(**plane_cfg),
				    SMP_CACHE_BYTES);
	if (!*plane_cfg)
		return -ENOMEM;

	state = memblock_alloc(*plane_count * sizeof(*state), SMP_CACHE_BYTES);
	if (!state)
		return -ENOMEM;

	memset(*plane_cfg, 0, *plane_count * sizeof(**plane_cfg));
	for (i = 0; i < *plane_count; i++) {
		state[i].load_offset = VM_PLANES_UNSET_VALUE;
		state[i].memory_size = VM_PLANES_UNSET_VALUE;
		state[i].vcpu_count = 0;
		state[i].kernel[0] = '\0';
	}

	while (p < end) {
		const char *eol = memchr(p, '\n', end - p);
		size_t line_len = eol ? (size_t)(eol - p) : (size_t)(end - p);

		ret = parse_plane_cfg_line(p, line_len, *plane_count,
					   *plane_cfg, state);
		if (ret && ret != -ENOENT)
			return ret;

		p += line_len;
		if (p < end && *p == '\n')
			p++;
	}

	/* Plane 0 is the already-running boot plane; only secondary planes
	 * must provide full allocation metadata.
	 */
	for (i = 1; i < *plane_count; i++) {
		if (state[i].load_offset == VM_PLANES_UNSET_VALUE ||
		    state[i].memory_size == VM_PLANES_UNSET_VALUE ||
		    !state[i].vcpu_count ||
		    !state[i].kernel[0])
			return -EINVAL;
	}

	return 0;
}

static bool __init cpio_name_match(const char *name, size_t namesize,
				   const char *target)
{
	while (namesize > 1 && (*name == '/' ||
	       (namesize > 2 && name[0] == '.' && name[1] == '/'))) {
		if (*name == '/') {
			name++;
			namesize--;
		} else {
			name += 2;
			namesize -= 2;
		}
	}

	return !strncmp(name, target, namesize - 1) &&
	       strlen(target) == namesize - 1;
}

static int __init vm_planes_get_cfg_from_initrd(unsigned int *plane_count,
					struct vm_plane_config **plane_cfg)
{
	const u8 *p = (const u8 *)(unsigned long)initrd_start;
	const u8 *end = (const u8 *)(unsigned long)initrd_end;

	if (!initrd_start || !initrd_end || initrd_end <= initrd_start)
		return -ENOENT;

	while (p + sizeof(struct cpio_newc_header) <= end) {
		const struct cpio_newc_header *hdr;
		const char *name;
		const u8 *data;
		u32 namesize, filesize;
		u32 name_align, data_align;
		int ret;

		hdr = (const struct cpio_newc_header *)p;
		if (memcmp(hdr->c_magic, "070701", 6) &&
		    memcmp(hdr->c_magic, "070702", 6))
			return -EINVAL;

		ret = parse_hex_field(hdr->c_namesize, sizeof(hdr->c_namesize), &namesize);
		if (ret)
			return ret;

		ret = parse_hex_field(hdr->c_filesize, sizeof(hdr->c_filesize), &filesize);
		if (ret)
			return ret;

		if (!namesize)
			return -EINVAL;

		p += sizeof(*hdr);
		if (p + namesize > end)
			return -EINVAL;

		name = (const char *)p;
		name_align = ALIGN(namesize, 4);
		if (p + name_align > end)
			return -EINVAL;

		data = p + name_align;
		if (data + filesize > end)
			return -EINVAL;

		if (!strcmp(name, "TRAILER!!!"))
			break;

		if (cpio_name_match(name, namesize, VM_PLANES_CONFIG_FILE))
			return parse_vm_planes_kconfig((const char *)data,
						filesize,
						plane_count,
						plane_cfg);

		data_align = ALIGN(filesize, 4);
		if (data + data_align < data || data + data_align > end)
			return -EINVAL;

		p = data + data_align;
	}

	return -ENOENT;
}

static int __init find_initrd_file(const char *filename,
				   const u8 **out_data, u32 *out_size)
{
	const u8 *p = (const u8 *)(unsigned long)initrd_start;
	const u8 *end = (const u8 *)(unsigned long)initrd_end;

	if (!initrd_start || !initrd_end || initrd_end <= initrd_start)
		return -ENOENT;

	while (p + sizeof(struct cpio_newc_header) <= end) {
		const struct cpio_newc_header *hdr;
		const char *name;
		const u8 *data;
		u32 namesize, filesize;
		u32 name_align, data_align;
		int ret;

		hdr = (const struct cpio_newc_header *)p;
		if (memcmp(hdr->c_magic, "070701", 6) &&
		    memcmp(hdr->c_magic, "070702", 6))
			return -EINVAL;

		ret = parse_hex_field(hdr->c_namesize,
				      sizeof(hdr->c_namesize), &namesize);
		if (ret)
			return ret;

		ret = parse_hex_field(hdr->c_filesize,
				      sizeof(hdr->c_filesize), &filesize);
		if (ret)
			return ret;

		if (!namesize)
			return -EINVAL;

		p += sizeof(*hdr);
		if (p + namesize > end)
			return -EINVAL;

		name = (const char *)p;
		name_align = ALIGN(namesize, 4);
		if (p + name_align > end)
			return -EINVAL;

		data = p + name_align;
		if (data + filesize > end)
			return -EINVAL;

		if (!strcmp(name, "TRAILER!!!"))
			break;

		if (cpio_name_match(name, namesize, filename)) {
			*out_data = data;
			*out_size = filesize;
			return 0;
		}

		data_align = ALIGN(filesize, 4);
		if (data + data_align < data || data + data_align > end)
			return -EINVAL;

		p = data + data_align;
	}

	return -ENOENT;
}

static int __init copy_to_early_mem(phys_addr_t dest, const void *src,
				    unsigned long size)
{
	unsigned long slop, clen;
	char *p;

	while (size) {
		slop = offset_in_page(dest);
		clen = size;
		if (clen > PAGE_SIZE - slop)
			clen = PAGE_SIZE - slop;
		p = early_memremap(dest & PAGE_MASK, clen + slop);
		if (!p)
			return -ENOMEM;
		memcpy(p + slop, src, clen);
		early_memunmap(p, clen + slop);
		dest += clen;
		src += clen;
		size -= clen;
	}
	return 0;
}

static int __init load_plane_kernel_raw(const u8 *data, u32 size,
					struct vm_plane_config *cfg)
{
	if (size > cfg->memory_size) {
		pr_err("vm_planes: raw kernel image (%u bytes) exceeds plane memory (%llu bytes)\n",
		       size, (unsigned long long)cfg->memory_size);
		return -ENOMEM;
	}

	return copy_to_early_mem(cfg->load_offset, data, size);
}

int __init load_vm_plane_kernels(unsigned int plane_count,
				 struct vm_plane_config *plane_cfg)
{
	unsigned int i;
	int err = 0;

	for (i = 1; i < plane_count; i++) {
		const u8 *data;
		u32 size;
		int ret;

		ret = find_initrd_file(plane_cfg[i].kernel, &data, &size);
		if (ret) {
			pr_err("vm_planes: plane %u: kernel image '%s' not found in initrd\n",
			       i, plane_cfg[i].kernel);
			err = ret;
			continue;
		}

		switch (plane_cfg[i].kernel_format) {
		case VM_PLANE_KFMT_RAW:
			ret = load_plane_kernel_raw(data, size,
						    &plane_cfg[i]);
			break;
		case VM_PLANE_KFMT_BZIMAGE:
		case VM_PLANE_KFMT_ELF:
			pr_err("vm_planes: plane %u: kernel format not yet supported\n",
			       i);
			err = -ENOSYS;
			continue;
		default:
			pr_err("vm_planes: plane %u: unknown kernel format %u\n",
			       i, plane_cfg[i].kernel_format);
			err = -EINVAL;
			continue;
		}

		if (ret) {
			pr_err("vm_planes: plane %u: failed to load kernel image: %d\n",
			       i, ret);
			err = ret;
		} else {
			pr_info("vm_planes: plane %u: loaded '%s' (%u bytes) at 0x%llx\n",
				i, plane_cfg[i].kernel,
				size, (unsigned long long)plane_cfg[i].load_offset);
		}
	}

	return err;
}

static int __init parse_enable_vm_planes(char *str)
{
	bool enable;

	if (!str) {
		enable_vm_planes_requested = true;
		return 0;
	}

	if (kstrtobool(str, &enable))
		return -EINVAL;

	enable_vm_planes_requested = enable;
	return 0;
}

early_param("enable-vm-planes", parse_enable_vm_planes);

int __init __weak alloc_vm_planes(unsigned int plane_count,
				   struct vm_plane_config *plane_cfg) { return -ENOSYS; }

int __init __weak activate_vm_planes(unsigned int plane_count) { return -ENOSYS; }

void __init arch_init_vm_planes(void)
{
	unsigned int plane_count = VM_PLANES_DEFAULT_COUNT;
	struct vm_plane_config *plane_cfg;
	int ret;

	if (!enable_vm_planes_requested)
		return;

	if (!kvm_para_available())
		return;

	if (vm_planes_get_cfg_from_initrd(&plane_count, &plane_cfg)) {
		pr_warn("vm_planes: failed to parse %s from initrd\n",
			VM_PLANES_CONFIG_FILE);
		return;
	}

	pr_info("vm_planes: enabling %u planes (ids 0..%u)\n",
		plane_count, plane_count - 1);

	ret = alloc_vm_planes(plane_count, plane_cfg);
	if (ret) {
		pr_err("vm_planes: failed to allocate planes: %d\n", ret);
		return;
	}

	ret = load_vm_plane_kernels(plane_count, plane_cfg);
	if (ret) {
		pr_err("vm_planes: failed to load plane kernels: %d\n", ret);
		return;
	}

	ret = activate_vm_planes(plane_count);
	if (ret)
		pr_err("vm_planes: failed to activate planes: %d\n", ret);
}

#endif /* CONFIG_VM_PLANES */
