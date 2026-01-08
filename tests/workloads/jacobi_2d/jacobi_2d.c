// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Linutronix GmbH
 */
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "jacobi_2d.h"

static double *grid_a;
static double *grid_b;
static int iterations;

static inline int idx(int i, int j)
{
	return i * GRID_SIZE + j;
}

static void jacobi_2d_init_grid(double *grid)
{
	srand(time(NULL));

	/* Use random doubles between 0 and 1000 */
	for (int i = 0; i < GRID_SIZE; i++)
		for (int j = 0; j < GRID_SIZE; j++)
			grid[idx(i, j)] = (double)rand() / RAND_MAX * 1000;
}

static void jacobi_2d_step(double *src, double *dest)
{
	/* Lovely code for vectorization. */
	for (int i = 1; i < GRID_SIZE - 1; i++) {
		for (int j = 1; j < GRID_SIZE - 1; j++) {
			const double factor = 1.0 / 5.0;

			dest[idx(i, j)] =
				factor * (src[idx(i, j)] + src[idx(i - 1, j)] + src[idx(i + 1, j)] +
					  src[idx(i, j - 1)] + src[idx(i, j + 1)]);
		}
	}
}

int jacobi_2d_setup(int argc, char *argv[])
{
	if (argc != 2) {
		fprintf(stderr, "[jacobi_2d]: Usage: <iterations>\n");
		return -EINVAL;
	}

	iterations = atoi(argv[1]);
	if (iterations <= 0) {
		fprintf(stderr, "[jacobi_2d]: Usage: <iterations>\n");
		return -EINVAL;
	}

	grid_a = calloc(GRID_SIZE * GRID_SIZE, sizeof(double));
	grid_b = calloc(GRID_SIZE * GRID_SIZE, sizeof(double));

	if (!grid_a || !grid_b) {
		fprintf(stderr, "[jacobi_2d]: Grid allocation failed!\n");
		return -ENOMEM;
	}

	return 0;
}

int jacobi_2d_run(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	double *src = grid_a;
	double *dest = grid_b;

	jacobi_2d_init_grid(src);

	for (int i = 0; i < iterations; i++) {
		double *tmp;

		jacobi_2d_step(src, dest);

		tmp = src;
		src = dest;
		dest = tmp;
	}

	return 0;
}

__attribute__((destructor)) int jacobi_2d_finish(void)
{
	free(grid_a);
	free(grid_b);
	return 0;
}
