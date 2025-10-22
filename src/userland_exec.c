/* ======================================================================
 * Copyright 2024 Rafael J. Cruz, All Rights Reserved.
 * This code similar to mettle/libreflect/src
 * The code is licensed persuant to accompanying the GPLv3 free software
 * license.
 * ======================================================================
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <link.h>
#include <signal.h>
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

#define PAGE_FLOOR(addr) ((uintptr_t)(addr) & (uintptr_t)(-PAGE_SIZE))
#define PAGE_CEIL(addr) (PAGE_FLOOR((uintptr_t)(addr) - 1 + PAGE_SIZE))


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

#elif __i386__
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

static unsigned char page[PAGE_SIZE];
static char path[PATH_MAX];

void __attribute ((noreturn)) jmp_with_stack(size_t dest, size_t *stack)
{
	dprintf("\n>>> JUMP AND AWAY!!!! <<<\n");
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

void stack_setup(size_t *stack_base, size_t argc, char **argv, char **env,
		ElfW(Ehdr) *exe, ElfW(Ehdr) *interp)
{
	size_t *auxv_base;
	size_t i;

	stack_base[0] = argc;
	for (i = 0; i < argc; i++)
		stack_base[i + 1] = (size_t)argv[i];
	stack_base[argc + 1] = 0;

	for (i = 0; env[i]; i++)
		stack_base[i + argc + 2] = (size_t)env[i];
	stack_base[i + argc + 2] = 0;

	auxv_base = stack_base + 1 + i + argc + 2;
	synthetic_auxv(auxv_base);
	load_program_info(auxv_base, exe, interp);
}

bool is_compatible_elf(const ElfW(Ehdr) *ehdr)
{
	return memcmp(ehdr->e_ident, ELFMAG, SELFMAG) == 0;
}

int data_file(unsigned char **data, size_t *data_size, const int fd)
{
	struct stat statbuf;
	unsigned char *mapping;

	if (fstat(fd, &statbuf) == -1) {
		eprintf("Failed to fstat(fd): %s\n", strerror(errno));
		return -1;
	}

	mapping = mmap(NULL, (size_t)statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mapping == MAP_FAILED) {
		eprintf("Unable to read file in: %s\n", strerror(errno));
		return -1;
	}

	if (!is_compatible_elf((ElfW(Ehdr) *)mapping)) {
		eprintf("No compatible elf\n");
		munmap(mapping, (size_t)statbuf.st_size);
		return -1;
	}

	*data = mapping;
	*data_size = (size_t)statbuf.st_size;
	return 0;
}

int create_memfd(size_t *total2load, const unsigned char *data)
{
	ElfW(Ehdr) *ehdr;
	ElfW(Phdr) *phdr;
	int mem_fd = -1;
	size_t load_size = 0;
	unsigned char *load = NULL;

	ehdr = (ElfW(Ehdr) *)data;
	phdr = (ElfW(Phdr) *)(data + ehdr->e_phoff);
	for (int i = 0; i < ehdr->e_phnum; i++, phdr++)
		if (phdr->p_type == PT_LOAD &&
		    (phdr->p_vaddr + phdr->p_memsz) > load_size) {
			load_size = phdr->p_vaddr + phdr->p_memsz;
			dprintf("Total mapping is now %08zx based on %08zx seg at %p\n",
				load_size, phdr->p_memsz, (void *)phdr->p_vaddr);
		}

	load_size = PAGE_CEIL(load_size);
	load = mmap(NULL, load_size, PROT_READ | PROT_WRITE,
		    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (load == MAP_FAILED) {
		eprintf("Unable to read ELF file in: %s\n", strerror(errno));
		goto memfd_fail;
	}
	memset(load, 0, load_size);

	phdr = (ElfW(Phdr) *)(data + ehdr->e_phoff);
	for (int i = 0; i < ehdr->e_phnum; i++, phdr++) {
		if (phdr->p_type == PT_LOAD) {
			memcpy(load + phdr->p_vaddr, // dst
			       data + phdr->p_offset, // src
			       phdr->p_filesz); // len
			dprintf("memcpy(%p, %p, %08zx)\n", load + phdr->p_vaddr,
				data + phdr->p_offset, phdr->p_filesz);
		}
	}

	mem_fd = memfd_create("tmp", MFD_ALLOW_SEALING);
	if (mem_fd == -1) {
		eprintf("failed to memfd_create: %s\n", strerror(errno));
		goto memfd_fail;
	}

	if (write(mem_fd, load, load_size) != (ssize_t)load_size) {
		eprintf("failed to write into mem_fd: %s\n", strerror(errno));
		close(mem_fd);
		return -1;
	}

	if (munmap(load, load_size) < 0) {
		eprintf("Failed to munmap load: %s\n", strerror(errno));
		goto memfd_fail;
	}

	*total2load = load_size;
	return mem_fd;

memfd_fail:
	if (mem_fd != -1)
		close(mem_fd);

	if (load != NULL && load != MAP_FAILED)
		munmap(load, load_size);

	return -1;
}

int map_load(struct mapped_elf *obj, const unsigned char *data,
	     const int mem_fd, const size_t load_size)
{
	ElfW(Ehdr) *ehdr;
	ElfW(Phdr) *phdr;
	unsigned char *remapping, *load = NULL;
	int prot;

	load = mmap(NULL, load_size, PROT_READ | PROT_WRITE,
		    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (load == MAP_FAILED) {
		eprintf("Failed to mmap final load: %s\n",strerror(errno));
		goto load_fail;
	}
	memset(load, 0, load_size);

	ehdr = (ElfW(Ehdr) *)data;
	phdr = (ElfW(Phdr) *)(data + ehdr->e_phoff);

	obj->ehdr = (ElfW(Ehdr) *)load;
	obj->entry_point = (size_t)load + ehdr->e_entry;

	for (int i = 0; i < ehdr->e_phnum; i++, phdr++) {
		if (phdr->p_type == PT_LOAD) {
			prot = (((phdr->p_flags & PF_R) ? PROT_READ : 0) |
				((phdr->p_flags & PF_W) ? PROT_WRITE: 0) |
				((phdr->p_flags & PF_X) ? PROT_EXEC : 0));
#if DEBUG
			static char *prot_str[] = { "NONE", "EXEC", "WRITE",
				"EXEC | WRITE", "READ", "EXEC | READ",
				"READ | WRITE", "EXEC | READ | WRITE"
			};
			dprintf("PROT(%s) - phdr->p_filesz(%lu)\n",
			       prot_str[(int)prot], (size_t)phdr->p_filesz);
#endif
			if (prot & (PROT_EXEC | PROT_WRITE))
				prot = PROT_READ | PROT_EXEC;

			if (munmap(load + PAGE_FLOOR(phdr->p_vaddr),
				   PAGE_CEIL(phdr->p_memsz +
					     phdr->p_vaddr % PAGE_SIZE)) < 0) {
				eprintf("Failed to munmap ehdr: %s\n", strerror(errno));
				goto load_fail;
			}
			remapping = mmap(load + PAGE_FLOOR(phdr->p_vaddr),
					 PAGE_CEIL(phdr->p_memsz +
						   phdr->p_vaddr % PAGE_SIZE),
					prot, MAP_PRIVATE | MAP_FIXED,
					mem_fd, (off_t)PAGE_FLOOR(phdr->p_vaddr));
			if (remapping == MAP_FAILED) {
				eprintf("Failed to mmap PT_LOAD: %s\n", strerror(errno));
				goto load_fail;
			}
			assert(remapping == load + PAGE_FLOOR(phdr->p_vaddr));
		} else if (phdr->p_type == PT_INTERP) {
			memcpy(path, data + phdr->p_offset, phdr->p_filesz);
			obj->interp = path;
			dprintf("interp path: %.*s\n", PATH_MAX, path);
		}
	}

	return 0;

load_fail:
	if (load != NULL && load != MAP_FAILED)
		munmap(load, load_size);

	memset(obj, 0, sizeof(struct mapped_elf));
	return -1;
}

int map_elffd(struct mapped_elf *obj, const int fd)
{
	int mem_fd = -1;
	size_t data_size = 0;
	size_t load_size = 0;
	unsigned char *data = NULL;

	if (data_file(&data, &data_size, fd))
		goto elffd_fail;
	dprintf("ELF mappend at %p with size %zu\n", data, data_size);

	mem_fd = create_memfd(&load_size, data);
	if (mem_fd == -1)
		goto elffd_fail;
	dprintf("Memory file created fd=%d with size %zu\n", mem_fd, load_size);

	if (map_load(obj, data, mem_fd, load_size))
		goto elffd_fail;

	if (munmap(data, data_size) < 0) {
		eprintf("Failed to munmap data: %s\n", strerror(errno));
		goto elffd_fail;
	}
	close(mem_fd);

	return 0;

elffd_fail:
	if (mem_fd != -1)
		close(mem_fd);

	if (data != NULL && data != MAP_FAILED)
		munmap(data, data_size);

	return -1;
}

void handle_pagefault(__attribute__((unused)) int sig,
	siginfo_t *si, __attribute__((unused)) void *context)
{
	void *remmap;
	dprintf("Segmentation fault handler triggered for address: %p\n",
		si->si_addr);

	memcpy(page, (void *)PAGE_FLOOR(si->si_addr), PAGE_SIZE);
	if (munmap((void *)PAGE_FLOOR(si->si_addr), PAGE_SIZE) == -1) {
		eprintf("munmap failed in the pagefault handler: %s\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}
	remmap = mmap((void *)PAGE_FLOOR(si->si_addr), PAGE_SIZE,
		      PROT_READ | PROT_WRITE,
		      MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
	// TODO: fixme, maybe retry mmap until success?
	if (remmap == MAP_FAILED ||
	    (size_t)remmap != (size_t)PAGE_FLOOR(si->si_addr)) {
		eprintf("not able to get the same virtual address\n");
		exit(EXIT_FAILURE);
	}
	memcpy(remmap, page, PAGE_SIZE);
}

void userland_execv(int fd, char **argv, char **env,
		    size_t *stack)
{
	int fd_interp;
	size_t argc;
	struct mapped_elf exe, interp;
	struct sigaction sa;

	memset(&exe, 0, sizeof(exe));
	memset(&interp, 0, sizeof(interp));
	memset(&sa, 0, sizeof(sa));

	// Set up segmentation fault handler
	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = handle_pagefault;
	if (sigaction(SIGSEGV, &sa, NULL) < 0) {
		eprintf("Sigaction error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (map_elffd(&exe, fd)) {
		eprintf("Unable to map ELF file: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	close(fd);

	if (exe.interp) {
		fd_interp = open(exe.interp, O_RDONLY);
		if (fd_interp == -1) {
			eprintf("Failed to open interp %p: %s\n", (void *)exe.interp,
				strerror(errno));
			exit(EXIT_FAILURE);
		}

		if (map_elffd(&interp, fd_interp)) {
			eprintf("Unable to map interpreter for ELF file: %s\n",
				strerror(errno));
			exit(EXIT_FAILURE);
		}
		close(fd_interp);
	} else {
		interp = exe;
	}

	for (argc = 0; argv[argc]; argc++);

	stack_setup(stack, argc, argv, env, exe.ehdr, interp.ehdr);

	jmp_with_stack(interp.entry_point, stack);
}
