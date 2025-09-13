/* ======================================================================
 * Copyright 2024 Rafael J. Cruz, All Rights Reserved.
 * The code is licensed persuant to accompanying the GPLv3 free software
 * license.
 * ======================================================================
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define PAGE_SIZE 4096

void *shared_memory;
struct sigaction old_action;

#define BUFFER_SIZE 512
#define PAGE_FLOOR(addr) (typeof(addr))((uintptr_t)(addr) & (uintptr_t)(-PAGE_SIZE))

struct mem_map {
	uintptr_t start_addr;
	uintptr_t end_addr;
	int prot;
};

void parse_memory_mapping(char *line, struct mem_map *mapping)
{
	char perms[5];
	int num_fields = sscanf(line, "%lx-%lx %4s", &mapping->start_addr,
				&mapping->end_addr, perms);

	if (num_fields < 3) {
		fprintf(stderr, "Error parsing /proc/self/maps line: %s\n", line);
		exit(EXIT_FAILURE);
	}
	mapping->prot = (perms[0] == 'r' ? PROT_READ : 0)
		      | (perms[1] == 'w' ? PROT_WRITE : 0)
		      | (perms[2] == 'x' ? PROT_EXEC : 0);
}

ssize_t read_line(int fd, char *buffer, size_t max_length)
{
	size_t i = 0;
	char ch;
	ssize_t result;

	while (i < max_length - 1) {
		result = read(fd, &ch, 1);
		if (result == -1)
			return -1;
		else if (result == 0)
			break;

		buffer[i++] = ch;

		if (ch == '\n')
			break;
	}

	buffer[i] = '\0';

	return (ssize_t) i;
}

// Signal handler for segmentation fault
void handle_pagefault(__attribute__((unused)) int sig, siginfo_t *si,
		      __attribute__((unused)) void *context)
{
	struct mem_map mapping;
	void *remmap;
	char line[BUFFER_SIZE], page[PAGE_SIZE];
	int fd;
	ssize_t bytes_read;

	printf("Segmentation fault handler triggered for address: %p\n", si->si_addr);

	fd = open("/proc/self/maps", O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "Error opening /proc/self/maps: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	while ((bytes_read = read_line(fd, line, sizeof(line))) > 0) {
		parse_memory_mapping(line, &mapping);
		if ((void *)mapping.start_addr <= si->si_addr
		    && (void *)mapping.end_addr > si->si_addr) {
			printf("start_addr: 0x%lx - end_addr: 0x%lx - prot: %d\n",
			       mapping.start_addr, mapping.end_addr, mapping.prot);

			memcpy(page, PAGE_FLOOR(si->si_addr), PAGE_SIZE);
			if (munmap(PAGE_FLOOR(si->si_addr), PAGE_SIZE) == -1) {
				fprintf(stderr, "munmap failed in the pagefault handler: %s\n",
					strerror(errno));
				exit(EXIT_FAILURE);
			}
			remmap = mmap(PAGE_FLOOR(si->si_addr), PAGE_SIZE,
				      PROT_READ | PROT_WRITE,
				      MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
			// TODO: fixme, maybe retry mmap until success?
			if (remmap == MAP_FAILED || (size_t)remmap != (size_t)PAGE_FLOOR(si->si_addr)) {
				fprintf(stderr, "not able to get the same virtual address\n");
				exit(EXIT_FAILURE);
			}
			memcpy(remmap, page, PAGE_SIZE);
			close(fd);
			return;
		}
	}

	if (bytes_read == -1) {
		fprintf(stderr, "Error reading /proc/self/maps: %s\n", strerror(errno));
		close(fd);
		exit(EXIT_FAILURE);
	}

	// If reach this part the signal may not be releated to userland-exec
	close(fd);
	exit(EXIT_FAILURE);
}

int main() {
	// Allocate shared memory page with mmap
	shared_memory = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (shared_memory == MAP_FAILED) {
		perror("mmap for shared memory");
		exit(EXIT_FAILURE);
	}

	// Initialize data in shared memory
	strcpy((char *)shared_memory, "Hello, shared memory!");

	// Set up segmentation fault handler
	struct sigaction sa;
	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = handle_pagefault;
	if (sigaction(SIGSEGV, &sa, NULL) == -1) {
		perror("sigaction");
		exit(EXIT_FAILURE);
	}

	// Make the shared memory read-only to trigger COW on write
	munmap(shared_memory, PAGE_SIZE);
	shared_memory = mmap(shared_memory, PAGE_SIZE, PROT_READ | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

	// Attempt to write, which should trigger the copy-on-write mechanism
	printf("Initial content: %s\n", (char *)shared_memory);

	// This line triggers the copy-on-write mechanism
	strcpy((char *)shared_memory, "This triggers copy-on-write!");

	// Verify contents after COW
	printf("New content after COW: %s\n", (char *)shared_memory);

	// try a second time
	strcpy((char *)shared_memory, "This not triggers copy-on-write!");
	printf("New content after COW (2): %s\n", (char *)shared_memory);

	munmap(shared_memory, PAGE_SIZE);

	return 0;
}