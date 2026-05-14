#include <stdio.h>
#include <link.h>

static int
callback(struct dl_phdr_info *info, size_t size, void *data)
{
	const char *name;
	const Elf_Phdr *phdr;
	Elf_Half i;

	(void)size;
	(void)data;

	name = info->dlpi_name;
	if (name == NULL || name[0] == '\0')
		name = "<main executable>";

	printf("object name: %s\n", name);
	printf("base address: %p\n", (void *)info->dlpi_addr);
	printf("program headers: %u\n", (unsigned int)info->dlpi_phnum);

	for (i = 0; i < info->dlpi_phnum; i++) {
		phdr = &info->dlpi_phdr[i];

		printf("  phdr[%u]: type=%u vaddr=%p memsz=%zu\n",
		    (unsigned int)i,
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

	return 0;
}
