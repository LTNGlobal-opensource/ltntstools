/**
 * @file	kl-lineartrend.c
 * @author	Steven Toth <stoth@kernellabs.com>
 * @copyright	Copyright (c) 2020 Kernel Labs Inc. All Rights Reserved.
 */

/* See:
 *  https://stackoverflow.com/questions/43224/how-do-i-calculate-a-trendline-for-a-graph
 *  and chatgpt
 */
#include <kl-lineartrend.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <math.h>
#include <time.h>

/* val is widened to 64 bits so (start + i) can never wrap for any uint32_t maxCount. */
#define SANITIZE(ctx, val) ((uint32_t)((uint64_t)(val) % (ctx)->maxCount))

/* Return the ring position of the oldest entry and the number of valid entries. */
static void kllineartrend_range(struct kllineartrend_context_s *ctx, uint32_t *start, uint32_t *n)
{
	if (ctx->count < ctx->maxCount) {
		*start = 0;
		*n = ctx->count;
	} else {
		*start = ctx->idx;
		*n = ctx->maxCount;
	}
}

struct kllineartrend_context_s *kllineartrend_alloc(uint32_t maxItems, const char *name)
{
	if (maxItems == 0)
		return NULL;

	struct kllineartrend_context_s *ctx = (struct kllineartrend_context_s *)calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	ctx->maxCount = maxItems;
	ctx->list = (struct kllineartrend_item_s *)calloc(maxItems, sizeof(struct kllineartrend_item_s));
	if (!ctx->list) {
		free(ctx);
		return NULL;
	}
	snprintf(&ctx->name[0], sizeof(ctx->name), "%s", name ? name : "");

	return ctx;
}

void kllineartrend_free(struct kllineartrend_context_s *ctx)
{
	if (!ctx)
		return;

	free(ctx->list);
	free(ctx);
}

struct kllineartrend_context_s *kllineartrend_clone(struct kllineartrend_context_s *ctx)
{
	if (!ctx || !ctx->list || ctx->maxCount == 0)
		return NULL;

	struct kllineartrend_context_s *p = malloc(sizeof(*ctx));
	if (!p)
		return NULL;

	memcpy(p, ctx, sizeof(*ctx));
	/* calloc checks maxCount * sizeof() for overflow, a bare malloc multiply doesn't. */
	p->list = calloc(ctx->maxCount, sizeof(struct kllineartrend_item_s));
	if (!p->list) {
		free(p);
		return NULL;
	}
	memcpy(p->list, ctx->list, (size_t)ctx->maxCount * sizeof(struct kllineartrend_item_s));

	return p;
}

void kllineartrend_add(struct kllineartrend_context_s *ctx, double x, double y)
{
	struct kllineartrend_item_s *e = &ctx->list[ SANITIZE(ctx, ctx->idx) ];

	e->x = x;
	e->y = y;

	if (ctx->count < ctx->maxCount)
		ctx->count++;

	ctx->idx = SANITIZE(ctx, (uint64_t)ctx->idx + 1);
}

void kllineartrend_printf(struct kllineartrend_context_s *ctx)
{
	uint32_t start, n;
	kllineartrend_range(ctx, &start, &n);

	printf("linear trend: %s\n", ctx->name);
	for (uint32_t i = 0; i < n; i++) {
		uint32_t ptr = SANITIZE(ctx, (uint64_t)start + i);
		struct kllineartrend_item_s *e = &ctx->list[ ptr ];
		printf("%6" PRIu32 ": %12.8f %12.8f\n", ptr, e->x, e->y);
	}
}

int kllineartrend_save_csv(struct kllineartrend_context_s *ctx, const char *fn)
{
	uint32_t start, n;
	kllineartrend_range(ctx, &start, &n);

	int fd = open(fn, O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd < 0) {
		return -1;
	}

	double slope, intersect, deviation, r2;
	kllineartrend_calculate(ctx, &slope, &intersect, &deviation);
	kllineartrend_calculate_r_squared(ctx, slope, intersect, &r2);

	/* ctime_r: ctime() returns a shared static buffer and isn't thread safe. */
	char t[64] = { 0 };
	time_t now = time(NULL);
	if (ctime_r(&now, t) == NULL)
		t[0] = 0;
	size_t tlen = strlen(t);
	if (tlen > 0 && t[tlen - 1] == '\n')
		t[tlen - 1] = 0;

	dprintf(fd, "# Created %s\n", t);
	dprintf(fd, "# Trend '%s', %8" PRIu32 " entries, Slope %18.8f, Deviation is %12.2f, RSquared %18.8f\n",
		ctx->name,
		ctx->count,
		slope, deviation, r2);

	for (uint32_t i = 0; i < n; i++) {
		uint32_t ptr = SANITIZE(ctx, (uint64_t)start + i);
		struct kllineartrend_item_s *e = &ctx->list[ ptr ];
		dprintf(fd, "%8" PRIu32 ",%18.8f,%12.2f,\n", ptr, e->x, e->y);
	}

	close(fd);

	return 0; /* Ssccess */
}

void kllineartrend_calculate_r_squared(struct kllineartrend_context_s *ctx, double slope, double intercept, double *r)
{
	double ss_total = 0, ss_residual = 0;
	double y_mean = 0, ret;

	uint32_t start, n;
	kllineartrend_range(ctx, &start, &n);

	// Calculate the mean of y
	for (uint32_t i = 0; i < n; i++) {
		struct kllineartrend_item_s *e = &ctx->list[ SANITIZE(ctx, (uint64_t)start + i) ];

		y_mean += e->y;
	}
	y_mean /= ctx->count;

	// Calculate SS_total and SS_residual
	for (uint32_t i = 0; i < n; i++) {
		struct kllineartrend_item_s *e = &ctx->list[ SANITIZE(ctx, (uint64_t)start + i) ];

		double y_pred = slope * e->x + intercept;
		ss_total += pow(e->y - y_mean, 2);
		ss_residual += pow(e->y - y_pred, 2);
	}

	ret = 1 - (ss_residual / ss_total);

	*r = ret;
}

void kllineartrend_calculate(struct kllineartrend_context_s *ctx, double *slope, double *intercept, double *deviation)
{
	uint32_t start, n;
	kllineartrend_range(ctx, &start, &n);

	double count = 0;
	double sumX = 0, sumX2 = 0, sumY = 0, sumXY = 0;

	for (uint32_t i = 0; i < n; i++) {
		struct kllineartrend_item_s *e = &ctx->list[ SANITIZE(ctx, (uint64_t)start + i) ];

		count++;

		sumX += e->x;
		sumX2 += (e->x * e->x);
		sumY += e->y;
		sumXY += (e->x * e->y);
	}

	*slope = (sumXY - ((sumX * sumY) / count)) / (sumX2 - ((sumX * sumX) / count));
	*intercept = (sumY / count) - (*slope * (sumX / count));
	/* Fitted change across the window. Don't use b, it's a ring index bound, not a sample count. */
	*deviation = *slope * (count - 1);
}
