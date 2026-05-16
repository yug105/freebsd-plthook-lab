#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/user.h>
#include <dlfcn.h>
#include <libutil.h>
#include <link.h>
#include <string.h>
#include <unistd.h>

static const char *
program_header_type_name(Elf_Word type)
{
	if (type == PT_LOAD)
		return "PT_LOAD";
	if (type == PT_DYNAMIC)
		return "PT_DYNAMIC";
	return "OTHER";
}

struct find_address_data {
	const char *label;
	uintptr_t address;
	const char *object_name;
	Elf_Addr object_base;
};

struct plt_dump_data {
	const char *target_symbol;
};

struct plt_hook_data {
	const char *target_symbol;
	uintptr_t replacement;
	uintptr_t original;
	uintptr_t slot;
	const char *object_name;
	int saw_first_object;
	int patched;
};

typedef int (*puts_function)(const char *);

static uintptr_t original_puts;

static int
hooked_puts(const char *s)
{
	puts_function real_puts;

	real_puts = (puts_function)original_puts;
	if (real_puts == NULL)
		return EOF;

	(void)real_puts("[hooked puts]");
	return real_puts(s);
}

static const char *
vm_entry_type_name(int type)
{
	switch (type) {
	case KVME_TYPE_NONE:
		return "none";
	case KVME_TYPE_DEFAULT:
		return "default";
	case KVME_TYPE_VNODE:
		return "vnode";
	case KVME_TYPE_SWAP:
		return "swap";
	case KVME_TYPE_DEVICE:
		return "device";
	case KVME_TYPE_PHYS:
		return "phys";
	case KVME_TYPE_DEAD:
		return "dead";
#ifdef KVME_TYPE_SG
	case KVME_TYPE_SG:
		return "sg";
#endif
#ifdef KVME_TYPE_MGTDEVICE
	case KVME_TYPE_MGTDEVICE:
		return "mgtdevice";
#endif
#ifdef KVME_TYPE_GUARD
	case KVME_TYPE_GUARD:
		return "guard";
#endif
	case KVME_TYPE_UNKNOWN:
		return "unknown";
	default:
		return "other";
	}
}

static void
vm_protection_string(int protection, char out[4])
{
	out[0] = (protection & KVME_PROT_READ) != 0 ? 'r' : '-';
	out[1] = (protection & KVME_PROT_WRITE) != 0 ? 'w' : '-';
	out[2] = (protection & KVME_PROT_EXEC) != 0 ? 'x' : '-';
	out[3] = '\0';
}

static int
vm_protection_to_mprotect(int protection)
{
	int result;

	result = 0;
	if ((protection & KVME_PROT_READ) != 0)
		result |= PROT_READ;
	if ((protection & KVME_PROT_WRITE) != 0)
		result |= PROT_WRITE;
	if ((protection & KVME_PROT_EXEC) != 0)
		result |= PROT_EXEC;

	return result;
}

static int
find_vm_protection(uintptr_t address, int *protection)
{
	struct kinfo_vmentry *map;
	int count;
	int i;

	count = 0;
	map = kinfo_getvmmap(getpid(), &count);
	if (map == NULL) {
		perror("kinfo_getvmmap");
		return -1;
	}

	for (i = 0; i < count; i++) {
		if (address >= (uintptr_t)map[i].kve_start &&
		    address < (uintptr_t)map[i].kve_end) {
			*protection = vm_protection_to_mprotect(
			    map[i].kve_protection);
			free(map);
			return 0;
		}
	}

	free(map);
	return -1;
}

static const char *
object_name(const struct dl_phdr_info *info)
{
	const char *name;

	name = info->dlpi_name;
	if (name == NULL || name[0] == '\0')
		name = "<main executable>";

	return name;
}

static uintptr_t
object_runtime_address(const struct dl_phdr_info *info, uintptr_t value)
{
	return (uintptr_t)info->dlpi_addr + value;
}

static int
find_address_callback(struct dl_phdr_info *info, size_t size, void *data)
{
	struct find_address_data *search;
	const Elf_Phdr *phdr;
	uintptr_t target;
	uintptr_t start;
	uintptr_t end;
	Elf_Half i;

	(void)size;

	search = data;
	target = search->address;

	for (i = 0; i < info->dlpi_phnum; i++) {
		phdr = &info->dlpi_phdr[i];
		if (phdr->p_type != PT_LOAD)
			continue;

		start = (uintptr_t)info->dlpi_addr + phdr->p_vaddr;
		end = start + phdr->p_memsz;

		if (target >= start && target < end) {
			search->object_name = object_name(info);
			search->object_base = info->dlpi_addr;
			return 1;
		}
	}

	return 0;
}

static void
find_object_by_address(const char *label, uintptr_t address)
{
	struct find_address_data search;

	search.label = label;
	search.address = address;
	search.object_name = NULL;
	search.object_base = 0;

	(void)dl_iterate_phdr(find_address_callback, &search);

	printf("address search: %s\n", search.label);
	printf("  address: 0x%" PRIxPTR "\n", search.address);
	if (search.object_name != NULL) {
		printf("  object: %s\n", search.object_name);
		printf("  base address: 0x%" PRIxPTR "\n",
		    (uintptr_t)search.object_base);
	} else {
		printf("  object: <not found>\n");
	}
	printf("\n");
}

static void
find_object_by_symbol(const char *label, const char *symbol)
{
	void *address;
	const char *error;

	(void)dlerror();
	address = dlsym(RTLD_DEFAULT, symbol);
	error = dlerror();
	if (error != NULL) {
		printf("address search: %s\n", label);
		printf("  dlsym error: %s\n\n", error);
		return;
	}

	find_object_by_address(label, (uintptr_t)address);
}

static void
dump_plt_relocations_for_object(const struct dl_phdr_info *info,
    const char *target_symbol)
{
	const Elf_Phdr *phdr;
	const Elf_Dyn *dyn;
	const Elf_Rela *rela;
	const Elf_Rel *rel;
	const Elf_Sym *symtab;
	const char *strtab;
	uintptr_t jmprel;
	uintptr_t symtab_addr;
	uintptr_t strtab_addr;
	size_t pltrelsz;
	unsigned long pltrel_type;
	size_t count;
	size_t i;
	const char *sym_name;
	uintptr_t slot;
	unsigned int sym_index;
	int printed_header;

	jmprel = 0;
	symtab_addr = 0;
	strtab_addr = 0;
	pltrelsz = 0;
	pltrel_type = 0;
	printed_header = 0;

	for (i = 0; i < info->dlpi_phnum; i++) {
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
		return;

	symtab = (const Elf_Sym *)symtab_addr;
	strtab = (const char *)strtab_addr;

	printf("plt relocations: %s\n", object_name(info));
	printf("  base address: 0x%" PRIxPTR "\n", (uintptr_t)info->dlpi_addr);

	if (pltrel_type == DT_RELA) {
		rela = (const Elf_Rela *)jmprel;
		count = pltrelsz / sizeof(*rela);
		for (i = 0; i < count; i++) {
			sym_index = ELF_R_SYM(rela[i].r_info);
			sym_name = strtab + symtab[sym_index].st_name;
			slot = (uintptr_t)info->dlpi_addr + rela[i].r_offset;

			if (!printed_header) {
				printf("  format: RELA\n");
				printed_header = 1;
			}

			printf("  rel[%zu]: slot=0x%" PRIxPTR " symbol=%s\n",
			    i, slot, sym_name);
			if (target_symbol != NULL && strcmp(sym_name, target_symbol) == 0) {
				printf("    target match: yes\n");
			}
		}
	} else if (pltrel_type == DT_REL) {
		rel = (const Elf_Rel *)jmprel;
		count = pltrelsz / sizeof(*rel);
		for (i = 0; i < count; i++) {
			sym_index = ELF_R_SYM(rel[i].r_info);
			sym_name = strtab + symtab[sym_index].st_name;
			slot = (uintptr_t)info->dlpi_addr + rel[i].r_offset;

			if (!printed_header) {
				printf("  format: REL\n");
				printed_header = 1;
			}

			printf("  rel[%zu]: slot=0x%" PRIxPTR " symbol=%s\n",
			    i, slot, sym_name);
			if (target_symbol != NULL && strcmp(sym_name, target_symbol) == 0) {
				printf("    target match: yes\n");
			}
		}
	}

	printf("\n");
}

static int
dump_plt_relocations_callback(struct dl_phdr_info *info, size_t size, void *data)
{
	struct plt_dump_data *dump;

	(void)size;

	dump = data;
	dump_plt_relocations_for_object(info, dump->target_symbol);
	return 0;
}

static void
dump_plt_relocations(const char *target_symbol)
{
	struct plt_dump_data dump;

	dump.target_symbol = target_symbol;
	(void)dl_iterate_phdr(dump_plt_relocations_callback, &dump);
}

static int
patch_got_slot(uintptr_t slot, uintptr_t replacement, uintptr_t *original)
{
	long pagesize;
	uintptr_t page;
	int old_protection;

	pagesize = sysconf(_SC_PAGESIZE);
	if (pagesize <= 0) {
		perror("sysconf");
		return -1;
	}

	page = slot & ~((uintptr_t)pagesize - 1);
	if (find_vm_protection(slot, &old_protection) != 0) {
		fprintf(stderr, "could not find VM protection for slot 0x%" PRIxPTR
		    "\n", slot);
		return -1;
	}

	*original = *(uintptr_t *)slot;

	if (mprotect((void *)page, (size_t)pagesize,
	    old_protection | PROT_WRITE) != 0) {
		perror("mprotect writable");
		return -1;
	}

	*(uintptr_t *)slot = replacement;

	if (mprotect((void *)page, (size_t)pagesize, old_protection) != 0) {
		perror("mprotect restore");
		return -1;
	}

	return 0;
}

static int
check_rela_symbol(const struct dl_phdr_info *info, const Elf_Rela *rela,
    const Elf_Sym *symtab, const char *strtab,
    const struct plt_hook_data *hook, uintptr_t *slot_out)
{
	const char *sym_name;
	uintptr_t slot;
	unsigned int sym_index;
	Elf_Word name_offset;

	sym_index = ELF_R_SYM(rela->r_info);
	name_offset = symtab[sym_index].st_name;
	sym_name = strtab + name_offset;

	printf("    check rela: sym_index=%u name_offset=%u"
	    " r_offset=0x%" PRIxPTR " symbol=%s target=%s\n",
	    sym_index, (unsigned int)name_offset,
	    (uintptr_t)rela->r_offset, sym_name, hook->target_symbol);

	if (strcmp(sym_name, hook->target_symbol) != 0) {
		printf("    check rela: no match\n");
		return 0;
	}

	slot = (uintptr_t)info->dlpi_addr + rela->r_offset;
	printf("    check rela: MATCH slot=0x%" PRIxPTR "\n", slot);
	printf("    check rela: current slot value=0x%" PRIxPTR "\n",
	    *(uintptr_t *)slot);

	*slot_out = slot;
	return 1;
}
static int
hook_plt_symbol_in_object(const struct dl_phdr_info *info,
    struct plt_hook_data *hook)
{
	const Elf_Phdr *phdr;
	const Elf_Dyn *dyn;
	const Elf_Rela *rela;
	const Elf_Rel *rel;
	const Elf_Sym *symtab;
	const char *strtab;
	uintptr_t jmprel;
	uintptr_t symtab_addr;
	uintptr_t strtab_addr;
	size_t pltrelsz;
	unsigned long pltrel_type;
	size_t count;
	size_t i;
	const char *sym_name;
	uintptr_t slot;
	unsigned int sym_index;
	int result;

	jmprel = 0;
	symtab_addr = 0;
	strtab_addr = 0;
	pltrelsz = 0;
	pltrel_type = 0;

	for (i = 0; i < info->dlpi_phnum; i++) {
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
		return 0;

	symtab = (const Elf_Sym *)symtab_addr;
	strtab = (const char *)strtab_addr;

	if (pltrel_type == DT_RELA) {
		rela = (const Elf_Rela *)jmprel;
		count = pltrelsz / sizeof(*rela);
		for (i = 0; i < count; i++) {
			result = check_rela_symbol(info, &rela[i], symtab,
			    strtab, hook, &slot);
			if (result < 0)
				return -1;
			if (result == 0)
				continue;

			if (patch_got_slot(slot, hook->replacement,
			    &hook->original) != 0)
				return -1;
			hook->slot = slot;
			hook->object_name = object_name(info);
			hook->patched = 1;
			return 1;
		}
	} else if (pltrel_type == DT_REL) {
		rel = (const Elf_Rel *)jmprel;
		count = pltrelsz / sizeof(*rel);
		for (i = 0; i < count; i++) {
			sym_index = ELF_R_SYM(rel[i].r_info);
			sym_name = strtab + symtab[sym_index].st_name;
			if (strcmp(sym_name, hook->target_symbol) != 0)
				continue;

			slot = (uintptr_t)info->dlpi_addr + rel[i].r_offset;
			if (patch_got_slot(slot, hook->replacement,
			    &hook->original) != 0)
				return -1;
			hook->slot = slot;
			hook->object_name = object_name(info);
			hook->patched = 1;
			return 1;
		}
	}

	return 0;
}

static int
hook_plt_symbol_callback(struct dl_phdr_info *info, size_t size, void *data)
{
	struct plt_hook_data *hook;
	int result;

	(void)size;

	hook = data;
	if (hook->saw_first_object)
		return 1;
	hook->saw_first_object = 1;

	result = hook_plt_symbol_in_object(info, hook);
	if (result < 0)
		return 1;

	return result != 0 ? 1 : 0;
}

static int
hook_plt_symbol_in_main(const char *target_symbol, uintptr_t replacement,
    uintptr_t *original)
{
	struct plt_hook_data hook;

	hook.target_symbol = target_symbol;
	hook.replacement = replacement;
	hook.original = 0;
	hook.slot = 0;
	hook.object_name = NULL;
	hook.saw_first_object = 0;
	hook.patched = 0;

	(void)dl_iterate_phdr(hook_plt_symbol_callback, &hook);
	if (!hook.patched)
		return -1;

	*original = hook.original;
	printf("hooked %s in %s\n", target_symbol, hook.object_name);
	printf("  slot: 0x%" PRIxPTR "\n", hook.slot);
	printf("  original target: 0x%" PRIxPTR "\n", hook.original);
	printf("  replacement target: 0x%" PRIxPTR "\n\n", hook.replacement);

	return 0;
}

static void
dump_vmmap(void)
{
	struct kinfo_vmentry *map;
	char prot[4];
	const char *path;
	int count;
	int i;

	count = 0;
	map = kinfo_getvmmap(getpid(), &count);
	if (map == NULL) {
		perror("kinfo_getvmmap");
		return;
	}

	printf("vm map entries: %d\n", count);
	for (i = 0; i < count; i++) {
		vm_protection_string(map[i].kve_protection, prot);
		path = map[i].kve_path[0] != '\0' ? map[i].kve_path : "-";

		printf("  vm[%d]: start=0x%" PRIxMAX " end=0x%" PRIxMAX
		    " prot=%s type=%s path=%s\n",
		    i,
		    (uintmax_t)map[i].kve_start,
		    (uintmax_t)map[i].kve_end,
		    prot,
		    vm_entry_type_name(map[i].kve_type),
		    path);
	}
	printf("\n");

	free(map);
}

static void
local_function(void)
{
	puts("inside local_function");
}

static int
callback(struct dl_phdr_info *info, size_t size, void *data)
{
	const Elf_Phdr *phdr;
	Elf_Half i;

	(void)size;
	(void)data;

	printf("object name: %s\n", object_name(info));
	printf("base address: 0x%" PRIxPTR "\n", (uintptr_t)info->dlpi_addr);
	printf("program headers: %u\n", (unsigned int)info->dlpi_phnum);

	for (i = 0; i < info->dlpi_phnum; i++) {
		phdr = &info->dlpi_phdr[i];
		if (phdr->p_type != PT_LOAD && phdr->p_type != PT_DYNAMIC)
			continue;

		printf("  phdr[%u]: type=%s(%u) vaddr=0x%" PRIxPTR
		    " memsz=%zu\n",
		    (unsigned int)i,
		    program_header_type_name(phdr->p_type),
		    (unsigned int)phdr->p_type,
		    (uintptr_t)phdr->p_vaddr,
		    (size_t)phdr->p_memsz);
	}

	printf("\n");

	return 0;
}


int main(void)
{
	int result;

	result = dl_iterate_phdr(callback, NULL);
	if (result != 0) {
		fprintf(stderr, "dl_iterate_phdr stopped with: %d\n", result);
		return 1;
	}

	/*
	 * This is FreeBSD/ELF runtime introspection code. ISO C does not
	 * define a portable conversion between function pointers and void *,
	 * so keep the scan API based on integer process addresses instead.
	 */
	find_object_by_address("local_function", (uintptr_t)local_function);
	find_object_by_address("puts reference in executable", (uintptr_t)puts);
	find_object_by_symbol("puts resolved by dlsym", "puts");
	dump_plt_relocations("puts");
	if (hook_plt_symbol_in_main("puts", (uintptr_t)hooked_puts,
	    &original_puts) == 0) {
		puts("this call goes through the patched puts slot");
	}
	dump_vmmap();

	return 0;
}
