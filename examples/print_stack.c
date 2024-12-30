/* ======================================================================
 * Copyright 2024 Rafael J. Cruz, All Rights Reserved.
 * The code is licensed persuant to accompanying the GPLv3 free software
 * license.
 * ======================================================================
 */
#include <stdio.h>

extern char **environ;

int main(int argc, char **argv)
{
	int i, cnt;
	char **arg;
	size_t *stack = (size_t *)argv - 1;

	printf("argc: %d\n", argc);
	printf("\n");
	for (cnt = 0; argv[cnt] != NULL; cnt++) {
		printf("argv[%d]: %s\n", cnt, argv[cnt]);
	}
	printf("\n");

	for (cnt = 0; environ[cnt] != NULL; cnt++) {
		printf("envv[%d]: %s\n", cnt, environ[cnt]);
	}

	printf("Stack:\n");
	for (i = 0; stack[i] || stack[i + 1]; i++) {
		printf("  0x%08zx\n", stack[i]);
	}
	return 0;
}
