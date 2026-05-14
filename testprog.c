#include <stdio.h>
#include <stdint.h>
#include <link.h>

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
	const void *address;
	const char *object_name;
	Elf_Addr object_base;
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
	target = (uintptr_t)search->address;

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
find_object_by_address(const char *label, const void *address)
{
	struct find_address_data search;

	search.label = label;
	search.address = address;
	search.object_name = NULL;
	search.object_base = 0;

	(void)dl_iterate_phdr(find_address_callback, &search);

	printf("address search: %s\n", search.label);
	printf("  address: %p\n", search.address);
	if (search.object_name != NULL) {
		printf("  object: %s\n", search.object_name);
		printf("  base address: %p\n", (void *)search.object_base);
	} else {
		printf("  object: <not found>\n");
	}
	printf("\n");
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
	printf("base address: %p\n", (void *)info->dlpi_addr);
	printf("program headers: %u\n", (unsigned int)info->dlpi_phnum);

	for (i = 0; i < info->dlpi_phnum; i++) {
		phdr = &info->dlpi_phdr[i];
		if (phdr->p_type != PT_LOAD && phdr->p_type != PT_DYNAMIC)
			continue;

		printf("  phdr[%u]: type=%s(%u) vaddr=%p memsz=%zu\n",
		    (unsigned int)i,
		    program_header_type_name(phdr->p_type),
		    (unsigned int)phdr->p_type,
		    (void *)phdr->p_vaddr,
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

	find_object_by_address("local_function", (const void *)&local_function);
	find_object_by_address("puts", (const void *)&puts);

	return 0;
}
