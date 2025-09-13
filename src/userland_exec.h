/* ======================================================================
 * Copyright 2024 Rafael J. Cruz, All Rights Reserved.
 * The code is licensed persuant to accompanying the GPLv3 free software
 * license.
 * ======================================================================
 */

#ifndef USERLAND_EXEC_H
#define USERLAND_EXEC_H

#include <stddef.h>

void userland_execv(const unsigned char *elf, char **argv, char **env,
		size_t *stack) __attribute__((nonnull (1, 2, 3, 4)));

#endif