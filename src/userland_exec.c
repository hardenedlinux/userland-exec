/* ======================================================================
 * Copyright 2024 Rafael J. Cruz, All Rights Reserved.
 * This code similar to mettle/libreflect/src/*.c
 * The code is licensed persuant to accompanying the GPLv3 free software
 * license.
 * ======================================================================
 */

#include <arpa/inet.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <link.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "userland_exec.h"

#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif

#define PAGE_FLOOR(addr) ((addr) & (-PAGE_SIZE))
#define PAGE_CEIL(addr) (PAGE_FLOOR((addr) + PAGE_SIZE - 1))


#if UINTPTR_MAX > 0xffffffff
#define ELFCLASS_NATIVE ELFCLASS64
#else
#define ELFCLASS_NATIVE ELFCLASS32
#endif

#define ELFDATA_NATIVE ((htonl(1) == 1) ? ELFDATA2MSB : ELFDATA2LSB)

#if __aarch64__
#define JMP_WITH_STACK(dest, stack)                       \
	__asm__ volatile (                                \
		"mov sp, %[stack]\n"                      \
		"br %[entry]"                             \
		:                                         \
		: [stack] "r" (stack), [entry] "r" (dest) \
		: "memory"                                \
	)
#elif __arm__
#define JMP_WITH_STACK(dest, stack)                       \
	__asm__ volatile (                                \
		"mov sp, %[stack]\n"                      \
		"bx %[entry]"                             \
		:                                         \
		: [stack] "r" (stack), [entry] "r" (dest) \
		: "memory"                                \
	)
#elif __powerpc__
#define JMP_WITH_STACK(dest, stack)                       \
	__asm__ volatile (                                \
		"mr %%r1, %[stack]\n"                     \
		"mtlr %[entry]\n"                         \
		"blr"                                     \
		:                                         \
		: [stack] "r" (stack), [entry] "r" (dest) \
		: "memory"                                \
	)
#elif __x86_64__
#define JMP_WITH_STACK(dest, stack)                       \
	__asm__ volatile (                                \
		"movq %[stack], %%rsp\n"                  \
		"xor %%rdx, %%rdx\n"                      \
		"jmp *%[entry]"                           \
		:                                         \
		: [stack] "r" (stack), [entry] "r" (dest) \
		: "rdx", "memory"                         \
	)

#elif __x86__
#define JMP_WITH_STACK(dest, stack)                       \
	__asm__ volatile (                                \
		"mov %[stack], %%esp\n"                   \
		"xor %%edx, %%edx\n"                      \
		"jmp *%[entry]"                           \
		:                                         \
		: [stack] "r" (stack), [entry] "r" (dest) \
		: "edx", "memory"                         \
	)
#endif

struct mapped_elf {
	ElfW(Ehdr) *ehdr;
	ElfW(Addr) entry_point;
	char *interp;
};

void __attribute ((noreturn)) jmp_with_stack(size_t dest, size_t *stack)
{
	JMP_WITH_STACK(dest, stack);
	exit(EXIT_FAILURE);
}

void synthetic_auxv(size_t *auxv)
{
	unsigned long at_sysinfo_ehdr_value = getauxval(AT_SYSINFO_EHDR);

	auxv[0] = AT_BASE;
	auxv[2] = AT_PHDR;
	auxv[4] = AT_ENTRY;
	auxv[6] = AT_PHNUM;
	auxv[8] = AT_PHENT;
	auxv[10] = AT_PAGESZ; auxv[11] = PAGE_SIZE;
	auxv[12] = AT_SECURE;
	auxv[14] = AT_RANDOM; auxv[15] = (size_t)auxv;
	auxv[16] = AT_SYSINFO_EHDR; auxv[17] = at_sysinfo_ehdr_value;
	auxv[18] = AT_NULL; auxv[19] = 0;
}

void load_program_info(size_t *auxv, ElfW(Ehdr) *exe, ElfW(Ehdr) *interp)
{
	int i;
	size_t exe_loc = (size_t) exe, interp_loc = (size_t) interp;

	for (i = 0; auxv[i] || auxv[i + 1]; i += 2)
		switch (auxv[i]) {
		case AT_BASE:
			auxv[i + 1] = interp_loc;
			break;
		case AT_PHDR:
			auxv[i + 1] = exe_loc + exe->e_phoff;
			break;
		case AT_ENTRY:
			auxv[i + 1] = (exe->e_entry < exe_loc ?
					exe_loc + exe->e_entry : exe->e_entry);
			break;
		case AT_PHNUM:
			auxv[i + 1] = exe->e_phnum;
			break;
		case AT_PHENT:
			auxv[i + 1] = exe->e_phentsize;
			break;
		case AT_SECURE:
			auxv[i + 1] = 0;
			break;
		}
}

void stack_setup(size_t *stack_base, int argc, char **argv, char **env,
		size_t *auxv, ElfW(Ehdr) *exe, ElfW(Ehdr) *interp)
{
	size_t *auxv_base;
	int i;

	stack_base[0] = argc;
	for (i = 0; i < argc; i++)
		stack_base[i + 1] = (size_t)argv[i];
	stack_base[argc + 1] = 0;

	for (i = 0; env[i]; i++)
		stack_base[i + argc + 2] = (size_t)env[i];
	stack_base[i + argc + 3] = 0;

	auxv_base = stack_base + 1 + i + argc + 3;
	synthetic_auxv(auxv_base);
	load_program_info(auxv_base, exe, interp);
}


bool is_compatible_elf(const ElfW(Ehdr) *ehdr)
{
	return (ehdr->e_ident[EI_MAG0] == ELFMAG0 &&
			ehdr->e_ident[EI_MAG1] == ELFMAG1 &&
			ehdr->e_ident[EI_MAG2] == ELFMAG2 &&
			ehdr->e_ident[EI_MAG3] == ELFMAG3 &&
			ehdr->e_ident[EI_CLASS] == ELFCLASS_NATIVE &&
			ehdr->e_ident[EI_DATA] == ELFDATA_NATIVE);
}

void map_elf(const unsigned char *data, struct mapped_elf *obj)
{
	ElfW(Addr) dest = 0;
	ElfW(Ehdr) *ehdr;
	ElfW(Phdr) *phdr;

	unsigned char *mapping = MAP_FAILED;
	const unsigned char *source = 0;
	size_t len, virtual_offset = 0, total_to_map = 0;
	int i, prot;

	ehdr = (ElfW(Ehdr) *)data;
	phdr = (ElfW(Phdr) *)(data + ehdr->e_phoff);

	for(i = 0; i < ehdr->e_phnum; i++, phdr++)
		if (phdr->p_type == PT_LOAD)
			total_to_map = ((phdr->p_vaddr + phdr->p_memsz) > total_to_map
					? phdr->p_vaddr + phdr->p_memsz
					: total_to_map);

	phdr = (ElfW(Phdr) *)(data + ehdr->e_phoff);
	for (i = 0; i < ehdr->e_phnum; i++, phdr++) {
		if (phdr->p_type == PT_LOAD) {
			if (mapping == MAP_FAILED) {
				if (phdr->p_vaddr != 0)
					total_to_map -= phdr->p_vaddr;
				mapping = mmap((void *)PAGE_FLOOR(phdr->p_vaddr),
						PAGE_CEIL(total_to_map),
						PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE,
						-1, 0);
				if (mapping == MAP_FAILED) {
					fprintf(stderr, "Failed to mmap(): %s\n", strerror(errno));
					goto map_failed;
				}
				memset(mapping, 0, total_to_map);
				if (phdr->p_vaddr == 0)
					virtual_offset = (size_t) mapping;
				obj->ehdr = (ElfW(Ehdr) *) mapping;
				obj->entry_point = virtual_offset + ehdr->e_entry;
			}
			source = data + phdr->p_offset;
			dest = virtual_offset + phdr->p_vaddr;
			len = phdr->p_filesz;
			memcpy((void *)dest, source, len);

			prot = (((phdr->p_flags & PF_R) ? PROT_READ : 0) |
				((phdr->p_flags & PF_W) ? PROT_WRITE: 0) |
				((phdr->p_flags & PF_X) ? PROT_EXEC : 0));
			if (mprotect((void *)PAGE_FLOOR(dest),
			    PAGE_CEIL(phdr->p_memsz), prot) != 0) {
				goto mprotect_failed;
			}
		} else if (phdr->p_type == PT_INTERP) {
			obj->interp = (char *)phdr->p_offset;
		}

	}

	if (obj->interp)
		obj->interp = (char *) mapping + (size_t) obj->interp;

	return;

mprotect_failed:
	munmap(mapping, total_to_map);

map_failed:
	obj->ehdr = MAP_FAILED;
}


void userland_execv(const unsigned char *elf, char **argv, char **env,
		    size_t *stack)
{
	int fd;
	struct stat statbuf;
	unsigned char *data = NULL;
	size_t argc;

	struct mapped_elf exe = {0}, interp = {0};

	if (!is_compatible_elf((ElfW(Ehdr) *)elf)) {
		fprintf(stderr, "No compatible elf\n");
		exit(EXIT_FAILURE);
	}

	map_elf(elf, &exe);
	if (exe.ehdr == MAP_FAILED) {
		fprintf(stderr, "Unable to map ELF file: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (exe.interp) {
		fd = open(exe.interp, O_RDONLY);
		if (fd == -1) {
			fprintf(stderr, "Failed to open %p: %s\n", exe.interp,
				strerror(errno));
			exit(EXIT_FAILURE);
		}

		if (fstat(fd, &statbuf) == -1) {
			fprintf(stderr, "Failed to fstat(fd): %s\n",
				strerror(errno));
			exit(EXIT_FAILURE);
		}

		data = mmap(NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
		if (data == MAP_FAILED) {
			fprintf(stderr, "Unable to read ELF file in: %s\n",
				strerror(errno));
			exit(EXIT_FAILURE);
		}
		close(fd);

		map_elf(data, &interp);
		munmap(data, statbuf.st_size);
		if (interp.ehdr == MAP_FAILED) {
			fprintf(stderr, "Unable to map interpreter for ELF file: %s\n",
				strerror(errno));
			exit(EXIT_FAILURE);
		}
	} else {
		interp = exe;
	}

	for (argc = 0; argv[argc]; argc++);

	stack_setup(stack, argc, argv, env, NULL, exe.ehdr, interp.ehdr);

	jmp_with_stack(interp.entry_point, stack);
}
