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

#include "workload.h"

#include "jacobi_2d.h"

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

int jacobi_2d_setup(struct workload_instance *instance, int argc, char *argv[])
{
	struct jacobi_2d *j2;

	if (argc != 2) {
		fprintf(stderr, "[jacobi_2d]: Usage: <iterations>\n");
		return -EINVAL;
	}

	j2 = calloc(1, sizeof(*j2));
	if (!j2)
		return -ENOMEM;

	j2->iterations = atoi(argv[1]);
	if (j2->iterations <= 0) {
		fprintf(stderr, "[jacobi_2d]: Usage: <iterations>\n");
		free(j2);
		return -EINVAL;
	}

	j2->grid_a = calloc(GRID_SIZE * GRID_SIZE, sizeof(double));
	j2->grid_b = calloc(GRID_SIZE * GRID_SIZE, sizeof(double));

	if (!j2->grid_a || !j2->grid_b) {
		fprintf(stderr, "[jacobi_2d]: Grid allocation failed!\n");
		free(j2);
		return -ENOMEM;
	}

	instance->priv = j2;

	return 0;
}

int jacobi_2d_run(struct workload_instance *instance, int argc, char *argv[])
{
	struct jacobi_2d *j2 = instance->priv;
	(void)argc;
	(void)argv;

	double *src = j2->grid_a;
	double *dest = j2->grid_b;

	jacobi_2d_init_grid(src);

	for (int i = 0; i < j2->iterations; i++) {
		double *tmp;

		jacobi_2d_step(src, dest);

		tmp = src;
		src = dest;
		dest = tmp;
	}

	return 0;
}

void jacobi_2d_teardown(struct workload_instance *instance)
{
	struct jacobi_2d *j2 = instance->priv;

	free(j2->grid_a);
	free(j2->grid_b);
	free(j2);
}
