# freebsd-plthook-lab

Small FreeBSD ELF runtime-introspection experiments inspired by plthook.

## Level 1

`testprog.c` uses `dl_iterate_phdr()` to print each loaded ELF object's:

- object name
- base address
- number of program headers

Run on FreeBSD:

```sh
make
./testprog
```
