/**
 * @file	kl-lineartrend.h
 * @author	Steven Toth <stoth@kernellabs.com>
 * @copyright	Copyright (c) 2020-2025 Kernel Labs Inc. All Rights Reserved.
 * The source for this lives in libklmonitoring. Make sure any local change patches
 * are pushed upstream.
 * This isn't thread safe. For example, if you want to have thread#1 calling _add()
 * and thread#2 calling _calculate(), use your own mutex to prevent conflict.
 */

#ifndef KL_LINEARTREND_H
#define KL_LINEARTREND_H

#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>

#ifdef __cplusplus
extern "C"
{
#endif

struct kllineartrend_item_s
{
	double x;
	double y;
};

struct kllineartrend_context_s
{
	char name[128];

	uint32_t idx;
	uint32_t count;
	uint32_t maxCount;
	struct kllineartrend_item_s *list;
};

/**
 * @brief	Allocate a context.
 * @return   	Pointer on success, else NULL.
 */
struct kllineartrend_context_s *kllineartrend_alloc(uint32_t maxItems, const char *name);

/**
 * @brief	Release and de-allocate any memory resources associated with object.
 * @param[in]	struct kllineartrend_context_s *ctx - Object.
 */
void kllineartrend_free(struct kllineartrend_context_s *ctx);

/**
 * @brief	Duplicate an existing context, entirely.
 * @param[in]	struct kllineartrend_context_s *ctx - Object.
 * @return   	Pointer on success, else NULL.
 */
struct kllineartrend_context_s *kllineartrend_clone(struct kllineartrend_context_s *ctx);

/**
 * @brief	Add a new value to the set, for the current date/time.
 * @param[in]	struct kllineartrend_context_s *ctx - Object.
 * @param[in]	double x - X axis value
 * @param[in]	double y - Y axis value
 */
void kllineartrend_add(struct kllineartrend_context_s *ctx, double x, double y);

/**
 * @brief	Print the entire lineartrend to stdout.
 * @param[in]	struct kllineartrend_context_s *ctx - Brief description goes here.
 */
void kllineartrend_printf(struct kllineartrend_context_s *ctx);

/**
 * @brief	Calculate the slope, intercept and deviation for the current dataset.
 *          If the caller also wants a Rsquared evaluation, call that via kllineartrend_calculate_r_squared()
 *          after calling this function.
 * @param[in]	struct kllineartrend_context_s *ct - Object
 * @param[in]	double * - slope
 * @param[in]	double * - intercept
 * @param[out]	double * - deviation
 */
void kllineartrend_calculate(struct kllineartrend_context_s *ctx, double *slope, double *intercept, double *deviation);

/**
 * @brief	Calculate the R2 value for a current dataset and a previoudsly calculated slope and intercept.
 *          Call kllineartrend_calculate() to acquire the slope and intercept before calling this function.
 *          It's twice as expensive CPU wise to call this function compared to kllineartrend_calculate().
 *          So, this function is optional.
 * @param[in]	struct kllineartrend_context_s *ct - Object
 * @param[in]	double - slope
 * @param[in]	double - intercept
 * @param[out]	double - r_squared result
 */
void kllineartrend_calculate_r_squared(struct kllineartrend_context_s *ctx, double slope, double intercept, double *r2);

/**
 * @brief	Release and de-allocate any memory resources associated with object.
 * @param[in]	struct kllineartrend_context_s *ctx - Object.
 * @param[in]	const char *fn - Output filename, will be truncated then written to.
 */
int kllineartrend_save_csv(struct kllineartrend_context_s *ctx, const char *fn);

#ifdef __cplusplus
}
#endif

#endif /* KL_LINEARTREND_H */
