#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <dlfcn.h>
#include <link.h>
#include <string.h>
#include <sys/param.h>

struct slot_search {
	const char *symbol;
	uintptr_t slot;
	uintptr_t object_base;
	const char *object_name;
};

static double (*volatile keep_strtod_reference)(const char *, char **);

static uintptr_t
object_runtime_address(const struct dl_phdr_info *info, uintptr_t value)
{
	return (uintptr_t)info->dlpi_addr + value;
}

static const char *
object_name(const struct dl_phdr_info *info)
{
	if (info->dlpi_name == NULL || info->dlpi_name[0] == '\0')
		return "<main executable>";
	return info->dlpi_name;
}

static int
find_slot_in_first_object(struct dl_phdr_info *info, size_t size, void *data)
{
	struct slot_search *search;
	const Elf_Phdr *phdr;
	const Elf_Dyn *dyn;
	const Elf_Sym *symtab;
	const char *strtab;
	const Elf_Rela *rela;
	const Elf_Rel *rel;
	uintptr_t jmprel;
	uintptr_t symtab_addr;
	uintptr_t strtab_addr;
	size_t pltrelsz;
	unsigned long pltrel_type;
	size_t count;
	size_t i;
	unsigned int sym_index;
	const char *sym_name;
	Elf_Half phnum;

	(void)size;

	search = data;
	jmprel = 0;
	symtab_addr = 0;
	strtab_addr = 0;
	pltrelsz = 0;
	pltrel_type = 0;

	phnum = info->dlpi_phnum;
	for (i = 0; i < phnum; i++) {
		phdr = &info->dlpi_phdr[i];
		if (phdr->p_type != PT_DYNAMIC)
			continue;

		dyn = (const Elf_Dyn *)(uintptr_t)(info->dlpi_addr + phdr->p_vaddr);
		for (;;) {
			switch (dyn->d_tag) {
			case DT_NULL:
				goto done_dynamic;
			case DT_JMPREL:
				jmprel = object_runtime_address(info,
				    (uintptr_t)dyn->d_un.d_ptr);
				break;
			case DT_PLTRELSZ:
				pltrelsz = (size_t)dyn->d_un.d_val;
				break;
			case DT_PLTREL:
				pltrel_type = (unsigned long)dyn->d_un.d_val;
				break;
			case DT_SYMTAB:
				symtab_addr = object_runtime_address(info,
				    (uintptr_t)dyn->d_un.d_ptr);
				break;
			case DT_STRTAB:
				strtab_addr = object_runtime_address(info,
				    (uintptr_t)dyn->d_un.d_ptr);
				break;
			}
			dyn++;
		}
done_dynamic:
		break;
	}

	if (jmprel == 0 || symtab_addr == 0 || strtab_addr == 0 || pltrelsz == 0)
		return 1;

	symtab = (const Elf_Sym *)symtab_addr;
	strtab = (const char *)strtab_addr;

	if (pltrel_type == DT_RELA) {
		rela = (const Elf_Rela *)jmprel;
		count = pltrelsz / sizeof(*rela);
		for (i = 0; i < count; i++) {
			sym_index = ELF_R_SYM(rela[i].r_info);
			sym_name = strtab + symtab[sym_index].st_name;
			if (strcmp(sym_name, search->symbol) == 0) {
				search->slot = (uintptr_t)info->dlpi_addr +
				    rela[i].r_offset;
				search->object_base = (uintptr_t)info->dlpi_addr;
				search->object_name = object_name(info);
				return 1;
			}
		}
	} else if (pltrel_type == DT_REL) {
		rel = (const Elf_Rel *)jmprel;
		count = pltrelsz / sizeof(*rel);
		for (i = 0; i < count; i++) {
			sym_index = ELF_R_SYM(rel[i].r_info);
			sym_name = strtab + symtab[sym_index].st_name;
			if (strcmp(sym_name, search->symbol) == 0) {
				search->slot = (uintptr_t)info->dlpi_addr +
				    rel[i].r_offset;
				search->object_base = (uintptr_t)info->dlpi_addr;
				search->object_name = object_name(info);
				return 1;
			}
		}
	}

	return 1;
}

static void
check_freebsd_macros(void)
{
	printf("macro check:\n");
#ifdef __FreeBSD__
	printf("  __FreeBSD__=%d\n", __FreeBSD__);
#else
	printf("  __FreeBSD__=<not defined>\n");
#endif
#ifdef __FreeBSD_version
	printf("  __FreeBSD_version=%d\n", __FreeBSD_version);
#else
	printf("  __FreeBSD_version=<not defined>\n");
#endif
	printf("\n");
}

static void
check_dlopen_null(void)
{
	void *handle;
	struct link_map *lmap;

	lmap = NULL;
	handle = dlopen(NULL, RTLD_LAZY);
	printf("dlopen(NULL) check:\n");
	if (handle == NULL) {
		printf("  dlopen error: %s\n\n", dlerror());
		return;
	}
	if (dlinfo(handle, RTLD_DI_LINKMAP, &lmap) != 0) {
		printf("  dlinfo error: %s\n\n", dlerror());
		dlclose(handle);
		return;
	}

	printf("  handle=%p\n", handle);
	printf("  lmap=%p\n", (void *)lmap);
	printf("  l_addr=0x%" PRIxPTR "\n", (uintptr_t)lmap->l_addr);
	printf("  l_ld=%p\n", (void *)lmap->l_ld);
#ifdef __FreeBSD__
#if __FreeBSD__ >= 13
	printf("  l_base=%p\n", (void *)lmap->l_base);
#endif
#endif
	dlclose(handle);
	printf("\n");
}

static void
check_rtld_noload_dlclose(void)
{
	void *handle;
	struct link_map *lmap;
	const Elf_Dyn *dyn;
	intmax_t before_tag;
	intmax_t after_tag;

	lmap = NULL;
	handle = dlopen("libc.so.7", RTLD_LAZY | RTLD_NOLOAD);
	printf("RTLD_NOLOAD + dlclose link_map check:\n");
	if (handle == NULL) {
		printf("  dlopen error: %s\n\n", dlerror());
		return;
	}
	if (dlinfo(handle, RTLD_DI_LINKMAP, &lmap) != 0) {
		printf("  dlinfo error: %s\n\n", dlerror());
		dlclose(handle);
		return;
	}

	dyn = (const Elf_Dyn *)lmap->l_ld;
	before_tag = (intmax_t)dyn[0].d_tag;
	printf("  before dlclose: lmap=%p l_ld=%p first_tag=%jd\n",
	    (void *)lmap, (void *)lmap->l_ld, (intmax_t)before_tag);
	dlclose(handle);
	dyn = (const Elf_Dyn *)lmap->l_ld;
	after_tag = (intmax_t)dyn[0].d_tag;
	printf("  after dlclose:  lmap=%p l_ld=%p first_tag=%jd\n",
	    (void *)lmap, (void *)lmap->l_ld, (intmax_t)after_tag);
	printf("  same first tag: %s\n\n",
	    before_tag == after_tag ? "yes" : "no");
}

static void
check_lazy_slot_vs_dlsym(void)
{
	struct slot_search search;
	uintptr_t before;
	uintptr_t after_dlsym;
	void *resolved;

	keep_strtod_reference = strtod;
	memset(&search, 0, sizeof(search));
	search.symbol = "strtod";
	(void)dl_iterate_phdr(find_slot_in_first_object, &search);

	printf("lazy GOT slot vs dlsym check:\n");
	if (search.slot == 0) {
		printf("  strtod slot: <not found>\n\n");
		return;
	}

	before = *(uintptr_t *)search.slot;
	resolved = dlsym(RTLD_DEFAULT, "strtod");
	after_dlsym = *(uintptr_t *)search.slot;

	printf("  object=%s\n", search.object_name);
	printf("  object_base=0x%" PRIxPTR "\n", search.object_base);
	printf("  slot=0x%" PRIxPTR "\n", search.slot);
	printf("  slot before dlsym=0x%" PRIxPTR "\n", before);
	printf("  dlsym strtod=%p\n", resolved);
	printf("  slot after dlsym=0x%" PRIxPTR "\n", after_dlsym);
	printf("  before equals dlsym: %s\n",
	    before == (uintptr_t)resolved ? "yes" : "no");
	printf("  after equals dlsym: %s\n\n",
	    after_dlsym == (uintptr_t)resolved ? "yes" : "no");
}

int
main(void)
{
	check_freebsd_macros();
	check_dlopen_null();
	check_rtld_noload_dlclose();
	check_lazy_slot_vs_dlsym();
	return 0;
}
