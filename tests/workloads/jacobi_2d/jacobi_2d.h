// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Linutronix GmbH
 */

#ifndef JACOBI_2D_H
#define JACOBI_2D_H

struct workload_instance;

struct jacobi_2d {
	double *grid_a;
	double *grid_b;
	int iterations;
};

/*
 * Size: 100 x 100 x 8 -> 78.125 Kib.
 *
 * Keep the GRID_SIZE small, so that this code can be used with cycles times of 1ms. For larger
 * compute periods increase the number iterations passed to jacobi_2d_setup().
 *
 * Tested on i7-10700TE. Iterations: 1 -> ~300us.
 */
#define GRID_SIZE 100

/* Setup function */
int jacobi_2d_setup(struct workload_instance *instance, int argc, char *argv[]);

/* Teardown function */
void jacobi_2d_teardown(struct workload_instance *instance);

/* Run time function */
int jacobi_2d_run(struct workload_instance *instance, int argc, char *argv[]);

#endif /* JACOBI_2D_H */
