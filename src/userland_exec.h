/* ======================================================================
 * Copyright 2024 Rafael J. Cruz, All Rights Reserved.
 * The code is licensed persuant to accompanying the GPLv3 free software
 * license.
 * ======================================================================
 */

#ifndef USERLAND_EXEC_H
#define USERLAND_EXEC_H

#include <stddef.h>

void userland_execv(int fd, char **argv, char **env, size_t *stack)
		__attribute__((nonnull (2, 3, 4)));

#ifdef LOG_ERROR
#include <stdio.h>
#define eprintf(...) (fprintf(stderr, __VA_ARGS__))
#else
#define eprintf(...)
#endif

#ifdef DEBUG
#include <stdio.h>
#define dprintf(...) (printf(__VA_ARGS__))
#else
#define dprintf(...)
#endif

#endif
