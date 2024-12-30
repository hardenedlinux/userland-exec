/* ======================================================================
 * Copyright 2024 Rafael J. Cruz, All Rights Reserved.
 * This code similar to mettle/libreflect/examples/noexec.c
 * The code is licensed persuant to accompanying the GPLv3 free software
 * license.
 * ======================================================================
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "userland_exec.h"

extern char **environ;

int main(int argc, char **argv)
{
	int fd;
	struct stat statbuf;
	unsigned char *data = NULL;

	if(argc < 2) {
		fprintf(stderr, "exec.bin [input file]\n");
		exit(EXIT_FAILURE);
	}

	fd = open(argv[1], O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "Failed to open %s: %s\n", argv[1], strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (fstat(fd, &statbuf) == -1) {
		fprintf(stderr, "Failed to fstat(fd): %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	data = mmap(NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (data == MAP_FAILED) {
		fprintf(stderr, "Unable to read ELF file in: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	close(fd);

	userland_execv(data, argv + 1, environ, (size_t *) argv - 1);
	return 0;
}