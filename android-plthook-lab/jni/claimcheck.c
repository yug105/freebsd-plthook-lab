#include <dlfcn.h>
#include <inttypes.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern int target_call_puts(const char *);

static int
print_object_callback(struct dl_phdr_info *info, size_t size, void *data)
{
	size_t i;

	(void)size;
	(void)data;

	printf("object name: %s\n",
	    info->dlpi_name != NULL && info->dlpi_name[0] != '\0' ?
	    info->dlpi_name : "[main executable]");
	printf("base address: 0x%" PRIxPTR "\n", (uintptr_t)info->dlpi_addr);
	printf("program headers: %u\n", (unsigned int)info->dlpi_phnum);

	for (i = 0; i < info->dlpi_phnum; i++) {
		const ElfW(Phdr) *phdr = &info->dlpi_phdr[i];

		if (phdr->p_type != PT_LOAD && phdr->p_type != PT_DYNAMIC)
			continue;
		printf("  phdr[%zu]: type=%u vaddr=0x%" PRIxPTR
		    " memsz=%" PRIuPTR "\n", i, phdr->p_type,
		    (uintptr_t)phdr->p_vaddr, (uintptr_t)phdr->p_memsz);
	}

	printf("\n");
	return 0;
}

static void
print_proc_self_exe(void)
{
	char path[4096];
	ssize_t len;

	len = readlink("/proc/self/exe", path, sizeof(path) - 1);
	if (len < 0) {
		perror("readlink /proc/self/exe");
		return;
	}

	path[len] = '\0';
	printf("/proc/self/exe: %s\n\n", path);
}

int
main(void)
{
	void *self;
	void *puts_addr;

	printf("android claimcheck start\n");
#ifdef __ANDROID_API__
	printf("__ANDROID_API__: %d\n", __ANDROID_API__);
#endif
	printf("pointer size: %zu\n\n", sizeof(void *));

	print_proc_self_exe();
	dl_iterate_phdr(print_object_callback, NULL);

	self = dlopen(NULL, RTLD_NOW);
	printf("dlopen(NULL): %p\n", self);
	puts_addr = dlsym(RTLD_DEFAULT, "puts");
	printf("dlsym(RTLD_DEFAULT, \"puts\"): %p\n\n", puts_addr);
	if (self != NULL)
		dlclose(self);

	target_call_puts("target_call_puts reached");
	return 0;
}

