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

#define SANITIZE(ctx, val) ((val) % ctx->maxCount)

struct kllineartrend_context_s *kllineartrend_alloc(uint32_t maxItems, const char *name)
{
	struct kllineartrend_context_s *ctx = (struct kllineartrend_context_s *)calloc(1, sizeof(*ctx));

	ctx->maxCount = maxItems;
	ctx->list = (struct kllineartrend_item_s *)calloc(maxItems, sizeof(struct kllineartrend_item_s));
	strcpy(&ctx->name[0], name);

	return ctx;
}

void kllineartrend_free(struct kllineartrend_context_s *ctx)
{
	free(ctx->list);
	free(ctx);
}

struct kllineartrend_context_s *kllineartrend_clone(struct kllineartrend_context_s *ctx)
{
	struct kllineartrend_context_s *p = malloc(sizeof(*ctx));
	if (!p)
		return NULL;

	memcpy(p, ctx, sizeof(*ctx));
	p->list = malloc(ctx->maxCount * sizeof(struct kllineartrend_item_s));
	if (!ctx->list) {
		free(p);
		return NULL;
	}
	memcpy(p->list, ctx->list, ctx->maxCount * sizeof(struct kllineartrend_item_s));

	return p;
}

void kllineartrend_add(struct kllineartrend_context_s *ctx, double x, double y)
{
//printf("idx %d maxCount %d count %d\n", ctx->idx, ctx->maxCount, ctx->count);
	int ptr = SANITIZE(ctx, ctx->idx);
	struct kllineartrend_item_s *e = &ctx->list[ ptr ];
	
	e->x = x;
	e->y = y;

	if (ctx->count < ctx->maxCount)
		ctx->count++;
	
	ctx->idx = SANITIZE(ctx, ctx->idx + 1);
}

void kllineartrend_printf(struct kllineartrend_context_s *ctx)
{
	int a = ctx->idx;
	int b = 0;

	if (ctx->count < ctx->maxCount) {
		a = 0;
		b = ctx->count;
	} else
	if (ctx->count == ctx->maxCount) {
		a = ctx->idx;
		b = a + ctx->maxCount;
	}

	printf("linear trend: %s\n", ctx->name);
	for (int i = a; i < b; i++) {
		int ptr = SANITIZE(ctx, i);
		struct kllineartrend_item_s *e = &ctx->list[ ptr ];
		printf("%6d: %12.8f %12.8f\n", ptr, e->x, e->y);
	}
}

int kllineartrend_save_csv(struct kllineartrend_context_s *ctx, const char *fn)
{
	int a = ctx->idx;
	int b = 0;

	if (ctx->count < ctx->maxCount) {
		a = 0;
		b = ctx->count;
	} else
	if (ctx->count == ctx->maxCount) {
		a = ctx->idx;
		b = a + ctx->maxCount;
	}

	int fd = open(fn, O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd < 0) {
		return -1;
	}

	double slope, intersect, deviation, r2;
	kllineartrend_calculate(ctx, &slope, &intersect, &deviation);
	kllineartrend_calculate_r_squared(ctx, slope, intersect, &r2);

	char t[64];
	time_t now = time(NULL);
	sprintf(t, "%s", ctime(&now));
	t[ strlen(t) - 1] = 0;

	dprintf(fd, "# Created %s\n", t);
	dprintf(fd, "# Trend '%s', %8d entries, Slope %18.8f, Deviation is %12.2f, RSquared %18.8f\n",
		ctx->name,
		ctx->count,
		slope, deviation, r2);

	for (int i = a; i < b; i++) {
		int ptr = SANITIZE(ctx, i);
		struct kllineartrend_item_s *e = &ctx->list[ ptr ];
		dprintf(fd, "%8d,%18.8f,%12.2f,\n", ptr, e->x, e->y);
	}

	close(fd);

	return 0; /* Ssccess */
}

void kllineartrend_calculate_r_squared(struct kllineartrend_context_s *ctx, double slope, double intercept, double *r)
{
	double ss_total = 0, ss_residual = 0;
    double y_mean = 0, ret;

	int a = ctx->idx;
	int b = 0;

	if (ctx->count < ctx->maxCount) {
		a = 0;
		b = ctx->count;
	} else
	if (ctx->count == ctx->maxCount) {
		a = ctx->idx;
		b = a + ctx->maxCount;
	}

	// Calculate the mean of y
    for (int i = a; i < b; i++) {
		int ptr = SANITIZE(ctx, i);
		struct kllineartrend_item_s *e = &ctx->list[ ptr ];

        y_mean += e->x;
    }
    y_mean /= ctx->count;

	// Calculate SS_total and SS_residual
    for (int i = a; i < b; i++) {
		int ptr = SANITIZE(ctx, i);
		struct kllineartrend_item_s *e = &ctx->list[ ptr ];

        double y_pred = slope * e->x + intercept;
        ss_total += pow(e->y - y_mean, 2);
        ss_residual += pow(e->y - y_pred, 2);
    }

    ret = 1 - (ss_residual / ss_total);

	*r = ret;
}

void kllineartrend_calculate(struct kllineartrend_context_s *ctx, double *slope, double *intercept, double *deviation)
{
	int a = ctx->idx;
	int b = 0;

	if (ctx->count < ctx->maxCount) {
		a = 0;
		b = ctx->count;
	} else
	if (ctx->count == ctx->maxCount) {
		a = ctx->idx;
		b = a + ctx->maxCount;
	}

	double count = 0;
	double sumX = 0, sumX2 = 0, sumY = 0, sumXY = 0;

	for (int i = a; i < b; i++) {
		int ptr = SANITIZE(ctx, i);
		struct kllineartrend_item_s *e = &ctx->list[ ptr ];

		count++;

		sumX += e->x;
		sumX2 += (e->x * e->x);
		sumY += e->y;
		sumXY += (e->x * e->y);
	}

	*slope = (sumXY - ((sumX * sumY) / count)) / (sumX2 - ((sumX * sumX) / count));
	*intercept = (sumY / count) - (*slope * (sumX / count));
	*deviation = *slope * b;
}

