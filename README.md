# freebsd-plthook-lab

Small FreeBSD ELF runtime-introspection experiments inspired by plthook.

## Level 1

`testprog.c` uses `dl_iterate_phdr()` to print each loaded ELF object's:

- object name
- base address
- number of program headers

It also demonstrates address-to-object lookup by checking whether a runtime
address falls inside any `PT_LOAD` segment.

The current demo also walks `DT_JMPREL` so it can print the PLT relocation
entries and show the GOT slot behind imported symbols such as `puts`.

After finding the executable's `puts` PLT relocation, the demo patches that GOT
slot to point at a local `hooked_puts()` replacement. The replacement prints a
marker and then calls the original `puts` target saved from the slot before the
patch.

It also calls FreeBSD's `kinfo_getvmmap(getpid(), &count)` helper from
`libutil` to print the process virtual memory map. This gives a second view of
the same address space using kernel `KERN_PROC_VMMAP` data: each entry includes
the mapped range, permissions, mapping type, and backing path when one exists.

Function addresses are converted to `uintptr_t` before lookup. This keeps the
search logic working with process address values instead of treating function
pointers as `void *`. The conversion is still platform-specific ELF/POSIX
runtime code, not portable ISO C.

For imported functions, the direct C function name can refer to the executable's
PLT entry. The demo therefore prints both the executable's `puts` reference and
the address returned by `dlsym(RTLD_DEFAULT, "puts")`, which is the dynamic
linker's resolved symbol address.

Run on FreeBSD:

```sh
make
./testprog
```
