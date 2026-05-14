#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <dlfcn.h>
#include <link.h>
#include <string.h>

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

	return 0;
}
