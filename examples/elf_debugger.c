/* ======================================================================
 * Copyright 2024 Rafael J. Cruz, All Rights Reserved.
 * The code is licensed persuant to accompanying the GPLv3 free software
 * license.
 * ======================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <elf.h>
#include <string.h>
#include <link.h>

static void print_ident(unsigned char *ident)
{
	int i;

	printf("Magic:   ");
	for (i = 0; i < EI_NIDENT; i++)
		printf("%02x ", ident[i]);
	printf("\n");

	printf("Class:                             %d\n", ident[EI_CLASS]);
	printf("Data:                              %d\n", ident[EI_DATA]);
	printf("Version:                           %d\n", ident[EI_VERSION]);
	printf("OS/ABI:                            %d\n", ident[EI_OSABI]);
	printf("ABI Version:                       %d\n", ident[EI_ABIVERSION]);
}

static void print_elf_header(ElfW(Ehdr) *ehdr)
{
	printf("ELF Header:\n");
	print_ident(ehdr->e_ident);

	printf("Type:                              %u\n", ehdr->e_type);
	printf("Machine:                           %u\n", ehdr->e_machine);
	printf("Version:                           %u\n", ehdr->e_version);
	printf("Entry point address:               0x%lx\n",
	       (unsigned long) ehdr->e_entry);
	printf("Start of program headers:          %lu (bytes into file)\n",
	       (unsigned long) ehdr->e_phoff);
	printf("Start of section headers:          %lu (bytes into file)\n",
	       (unsigned long) ehdr->e_shoff);
	printf("Flags:                             0x%x\n", ehdr->e_flags);
	printf("Size of this header:               %u (bytes)\n", ehdr->e_ehsize);
	printf("Size of program headers:           %u (bytes)\n",
	       ehdr->e_phentsize);
	printf("Number of program headers:         %u\n", ehdr->e_phnum);
	printf("Size of section headers:           %u (bytes)\n",
	       ehdr->e_shentsize);
	printf("Number of section headers:         %u\n", ehdr->e_shnum);
	printf("Section header string table index: %u\n", ehdr->e_shstrndx);
}

static void print_program_headers(ElfW(Phdr) *phdr, uint16_t phnum)
{
	int i;

	printf("\nProgram Headers:\n");
	for (i = 0; i < phnum; i++) {
		printf("  Type:                             ");
		switch (phdr[i].p_type) {
			case 0: printf("PT_NULL\n"); break;
			case 1: printf("PT_LOAD\n"); break;
			case 2: printf("PT_DYNAMIC\n"); break;
			case 3: printf("PT_INTERP\n"); break;
			case 4: printf("PT_NOTE\n"); break;
			case 5: printf("PT_SHLIB\n"); break;
			case 6: printf("PT_PHDR\n"); break;
			case 7: printf("PT_TLS\n"); break;
			case 0x60000000: printf("PT_LOOS\n"); break;
			case 0x6FFFFFFF: printf("PT_HIOS\n"); break;
			case 0x70000000: printf("PT_LOPROC\n"); break;
			case 0x7FFFFFFF: printf("PT_HIPROC\n"); break;
			case 0x6474E550: printf("PT_GNU_EH_FRAME\n"); break;
			case 0x6474E551: printf("PT_GNU_STACK\n"); break;
			case 0x6474E552: printf("PT_GNU_RELRO\n"); break;
			case 0x6474e553: printf("PT_GNU_PROPERTY\n"); break;
			default: printf("UNKNOWN(0x%x)\n", phdr[i].p_type);
		}
		printf("  Offset:                           0x%lx\n",
		       (unsigned long) phdr[i].p_offset);
		printf("  Virtual address:                  0x%lx\n",
		       (unsigned long) phdr[i].p_vaddr);
		printf("  Physical address:                 0x%lx\n",
		       (unsigned long) phdr[i].p_paddr);
		printf("  File size:                        %lu\n",
		       (unsigned long) phdr[i].p_filesz);
		printf("  Memory size:                      %lu\n",
		       (unsigned long) phdr[i].p_memsz);
		printf("  Flags:                            ");
		int prot = (((phdr[i].p_flags & PF_R) ? PROT_READ : 0) |
			    ((phdr[i].p_flags & PF_W) ? PROT_WRITE: 0) |
			    ((phdr[i].p_flags & PF_X) ? PROT_EXEC : 0));
		static char *prot_str[] = { "PROT_NONE", "PROT_EXEC",
			"PROT_WRITE", "PROT_EXEC | PROT_WRITE", "PROT_READ",
			"PROT_EXEC | PROT_READ", "PROT_READ | PROT_WRITE",
			"PROT_EXEC | PROT_READ | PROT_WRITE"
		};
		printf("%s\n", prot_str[(int)prot]);

		printf("  Alignment:                        %lu\n\n",
		       (unsigned long) phdr[i].p_align);
	}
}

int main(int argc, char *argv[])
{
	int fd;
	void *file_data;
	struct stat st;
	ElfW(Ehdr) *ehdr;
	ElfW(Phdr) *phdr;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <elf-file>\n", argv[0]);
		return 1;
	}

	fd = open(argv[1], O_RDONLY);
	if (fd == -1) {
		perror("Error opening file");
		return 1;
	}

	if (fstat(fd, &st) == -1) {
		perror("Error getting file size");
		close(fd);
		return 1;
	}

	file_data = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (file_data == MAP_FAILED) {
		perror("Error mapping file");
		close(fd);
		return 1;
	}

	ehdr = (ElfW(Ehdr) *)file_data;
	if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
		fprintf(stderr, "Not a valid ELF file.\n");
		munmap(file_data, (size_t)st.st_size);
		close(fd);
		return 1;
	}

	print_elf_header(ehdr);

	phdr = (ElfW(Phdr) *)((char *)file_data + ehdr->e_phoff);
	print_program_headers(phdr, ehdr->e_phnum);

	munmap(file_data, (size_t)st.st_size);
	close(fd);

	return 0;
}
