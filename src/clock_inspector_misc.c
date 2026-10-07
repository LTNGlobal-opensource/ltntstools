#include "clock_inspector_public.h"
#include <math.h>

int validateLinearTrend()
{
	//double vals[10] = { 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 1.0, 1.0 }; /* rsq = 1, slope = 1 */
	double vals[10] = { 2.0, 4.0, 6.0, 8.0, 10.0, 12.0, 14.0, 16.0, 1.0, 2.0 }; /* rsq = 1, slope = 2 */
	//double vals[10] = { 0.01, 0.02, 0.03, 0.04, 0.05, 0.06, 0.07, 0.08, 1.0, 0.01 };
	//double vals[10] = { 1.0, 0.0, 1.0, 0.2, 1.0, 0.4, 1.0, 0.6, 0.985348, -0.04761905 }; /// ?

	struct kllineartrend_context_s *tc = kllineartrend_alloc(128, "linear trend test");

	double counter = 0;
	for (int i = 0; i < 8; i++) {
		kllineartrend_add(tc, ++counter, vals[i]);
	}

	kllineartrend_printf(tc);

	double slope, intersect, deviation, r2;
	kllineartrend_calculate(tc, &slope, &intersect, &deviation);
	kllineartrend_calculate_r_squared(tc, slope, intersect, &r2);

	printf("Slope %17.8f Deviation is %12.2f, r is %f\n", slope, deviation, r2);
	if (r2 != vals[8]) {
		printf("Rsquared calculation doesn't match excel\n");
	}
	if (slope != vals[9]) {
		printf("slope calculation doesn't match excel\n");
	}

	kllineartrend_free(tc);

	return -1;
}

/* Unit test for kllineartrend against real 271 sample datasets: one with a steady
 * downward drift (strong fit), one noisy and close to flat (weak fit).
 * Expected values were computed independently (ordinary least squares, x = 1..N).
 * Case 1: buffer larger than the dataset (no ring wrap).
 * Case 2: 128 entry buffer, so the ring wraps and only the last 128 samples are fitted.
 * Deviation is expected to be the fitted change across the window, slope * (count - 1).
 * Run via -X 4.
 */
#include "testcase-lineartrend-drift.h"
#include "testcase-lineartrend-flat.h"

static int ci_lineartrend_check(const char *label, const char *field, double got, double expected, double tolerance)
{
	int ok = fabs(got - expected) <= tolerance;
	printf("validateLinearTrendDataset: %-13s %-9s got %18.10f expected %18.10f %s\n",
		label, field, got, expected, ok ? "ok" : "FAIL");
	return ok ? 0 : 1;
}

static int ci_lineartrend_run(const char *label, const double *data, int count, uint32_t maxItems,
	double expSlope, double expIntercept, double expR2, double expDeviation)
{
	int failed = 0;

	struct kllineartrend_context_s *tc = kllineartrend_alloc(maxItems, label);
	if (!tc || !tc->list) {
		printf("validateLinearTrendDataset: %s alloc failed\n", label);
		return 1;
	}

	for (int i = 0; i < count; i++) {
		kllineartrend_add(tc, (double)(i + 1), data[i]);
	}

	uint32_t expCount = (uint32_t)count < maxItems ? (uint32_t)count : maxItems;
	if (tc->count != expCount) {
		printf("validateLinearTrendDataset: %-13s count     got %u expected %u FAIL\n", label, tc->count, expCount);
		failed++;
	}

	double slope, intercept, deviation, r2;
	kllineartrend_calculate(tc, &slope, &intercept, &deviation);
	kllineartrend_calculate_r_squared(tc, slope, intercept, &r2);

	failed += ci_lineartrend_check(label, "slope", slope, expSlope, 1e-6);
	failed += ci_lineartrend_check(label, "intercept", intercept, expIntercept, 1e-4);
	failed += ci_lineartrend_check(label, "rsquared", r2, expR2, 1e-6);
	failed += ci_lineartrend_check(label, "deviation", deviation, expDeviation, 1e-4);

	kllineartrend_free(tc);

	return failed;
}

int validateLinearTrendDataset()
{
	int failed = 0;

	const double *drift = testcase_lineartrend_drift;
	int driftCount = sizeof(testcase_lineartrend_drift) / sizeof(testcase_lineartrend_drift[0]);
	const double *flat = testcase_lineartrend_flat;
	int flatCount = sizeof(testcase_lineartrend_flat) / sizeof(testcase_lineartrend_flat[0]);

	failed += ci_lineartrend_run("drift/full", drift, driftCount, 512, -0.0663302227, 439.6466962690, 0.9326983158, -17.9091601290);
	failed += ci_lineartrend_run("drift/last128", drift, driftCount, 128, -0.0665751551, 439.6776962410, 0.7301938700, -8.4550446977);
	failed += ci_lineartrend_run("flat/full", flat, flatCount, 512, -0.0070302300, 494.4171186552, 0.1295757639, -1.8981620903);
	failed += ci_lineartrend_run("flat/last128", flat, flatCount, 128, -0.0079211540, 494.5516160130, 0.0377117658, -1.0059865552);

	if (failed) {
		printf("validateLinearTrendDataset: FAILED (%d checks)\n", failed);
		return 1;
	}

	printf("validateLinearTrendDataset: PASSED\n");
	return 0;
}

/* Safety tests for kllineartrend alloc/free/clone argument handling, ring indexing
 * and save_csv. Allocation failure paths can't be forced here, run under a malloc
 * fault injector for those. Run via -X 5.
 */
#define CI_TREND_EXPECT(cond, msg) \
	do { \
		if (cond) { \
			printf("validateLinearTrendSafety: %-50s ok\n", msg); \
		} else { \
			printf("validateLinearTrendSafety: %-50s FAIL\n", msg); \
			failed++; \
		} \
	} while (0)

int validateLinearTrendSafety()
{
	int failed = 0;

	/* maxItems of zero would cause a modulo by zero in _add(). */
	struct kllineartrend_context_s *tc = kllineartrend_alloc(0, "zero");
	CI_TREND_EXPECT(tc == NULL, "alloc(0) returns NULL");
	kllineartrend_free(tc);

	/* NULL name is treated as an empty string. */
	tc = kllineartrend_alloc(8, NULL);
	CI_TREND_EXPECT(tc != NULL && tc->name[0] == 0, "alloc(8, NULL) succeeds with empty name");
	kllineartrend_free(tc);

	kllineartrend_free(NULL);
	CI_TREND_EXPECT(1, "free(NULL) is a no-op");

	CI_TREND_EXPECT(kllineartrend_clone(NULL) == NULL, "clone(NULL) returns NULL");

	struct kllineartrend_context_s nolist;
	memset(&nolist, 0, sizeof(nolist));
	nolist.maxCount = 8;
	CI_TREND_EXPECT(kllineartrend_clone(&nolist) == NULL, "clone(ctx without list) returns NULL");

	/* Wrap an 8 entry ring with 13 samples of y = 2x + 1, x = 1..13.
	 * Expect the ring to hold x = 6..13, oldest at slot 5.
	 */
	tc = kllineartrend_alloc(8, "wrap");
	if (!tc) {
		printf("validateLinearTrendSafety: alloc failed\n");
		return 1;
	}
	for (int i = 1; i <= 13; i++) {
		kllineartrend_add(tc, i, (2.0 * i) + 1.0);
	}
	CI_TREND_EXPECT(tc->count == 8 && tc->idx == 5, "13 adds into 8 entries: count 8, idx 5");
	CI_TREND_EXPECT(tc->list[5].x == 6.0 && tc->list[4].x == 13.0, "oldest x 6 at slot 5, newest x 13 at slot 4");

	double slope, intercept, deviation, r2;
	kllineartrend_calculate(tc, &slope, &intercept, &deviation);
	kllineartrend_calculate_r_squared(tc, slope, intercept, &r2);
	CI_TREND_EXPECT(fabs(slope - 2.0) < 1e-9 && fabs(intercept - 1.0) < 1e-9, "wrapped fit slope 2, intercept 1");
	CI_TREND_EXPECT(fabs(deviation - 14.0) < 1e-9, "wrapped deviation 14 (slope * (8 - 1))");
	CI_TREND_EXPECT(fabs(r2 - 1.0) < 1e-9, "wrapped rsquared 1");

	/* Clone is a deep, identical copy. */
	struct kllineartrend_context_s *dup = kllineartrend_clone(tc);
	CI_TREND_EXPECT(dup != NULL && dup->list != tc->list &&
		dup->count == tc->count && dup->idx == tc->idx && dup->maxCount == tc->maxCount &&
		strcmp(dup->name, tc->name) == 0 &&
		memcmp(dup->list, tc->list, tc->maxCount * sizeof(struct kllineartrend_item_s)) == 0,
		"clone is a deep identical copy");
	kllineartrend_free(dup);

	/* save_csv: timestamp line is populated, unsigned count, rows oldest first. */
	char fn[] = "/tmp/kllineartrend-test-XXXXXX";
	int fd = mkstemp(fn);
	if (fd < 0) {
		printf("validateLinearTrendSafety: mkstemp failed, skipping save_csv checks\n");
		failed++;
	} else {
		close(fd);
		CI_TREND_EXPECT(kllineartrend_save_csv(tc, fn) == 0, "save_csv returns 0");

		FILE *fh = fopen(fn, "r");
		char line[256];
		int lines = 0, rows = 0, createdOk = 0, entriesOk = 0, firstPtr = -1;
		while (fh && fgets(line, sizeof(line), fh)) {
			lines++;
			if (lines == 1) {
				createdOk = strncmp(line, "# Created ", 10) == 0 && strlen(line) > 11;
			} else if (lines == 2) {
				entriesOk = strstr(line, "       8 entries") != NULL;
			} else {
				if (rows++ == 0)
					firstPtr = atoi(line);
			}
		}
		if (fh)
			fclose(fh);
		unlink(fn);

		CI_TREND_EXPECT(createdOk, "save_csv '# Created <timestamp>' line");
		CI_TREND_EXPECT(entriesOk, "save_csv reports 8 entries");
		CI_TREND_EXPECT(rows == 8 && firstPtr == 5, "save_csv writes 8 rows, oldest (slot 5) first");
	}

	kllineartrend_free(tc);

	if (failed) {
		printf("validateLinearTrendSafety: FAILED (%d checks)\n", failed);
		return 1;
	}

	printf("validateLinearTrendSafety: PASSED\n");
	return 0;
}

int validateClockMath()
{
	/* Setup a PCR measurement unit as a 27MHz clock.
	 * We're going to simulate it moving forward in time and
	 * observe how we measure it as ir naturally wraps around
	 * it's upper value limit.
	 * */
	struct ltntstools_clock_s pcrclk;
	ltntstools_clock_initialize(&pcrclk);
	ltntstools_clock_establish_timebase(&pcrclk, 27 * 1e6);

	int64_t pcr_increment = 27 * 1e6; /* 1 second in a 27MHz clock */
	int64_t pcr = MAX_SCR_VALUE - (pcr_increment * 6); /* Start the PCR N frames behind the wrap */
	int64_t elapsed_us = 0;
	struct timeval t1, t2;

	while (1) {
		gettimeofday(&t1, NULL);

		if (ltntstools_clock_is_established_wallclock(&pcrclk) == 0) {
			/* Associate the current walltime to this PCR time (1 * 27), minus 10 frames of 59.94 */
			ltntstools_clock_establish_wallclock(&pcrclk, pcr);
		}

		/* PCR wraps across maximum value */
		ltntstools_clock_set_ticks(&pcrclk, pcr);

		int64_t us = ltntstools_clock_get_drift_us(&pcrclk);

		/* Negative drift indicates PCR falling behind walltime */
		char *s = NULL;
		ltntstools_pcr_to_ascii(&s, pcr);
		printf("pcr %13" PRIi64 " '%s', drift us: %5" PRIi64 ", sleep processing elapsed %7" PRIi64 "\n",
			pcr,
			s,
			us, elapsed_us);
		free(s);

		if (pcr >= MAX_SCR_VALUE) {
			printf("PCR has wrapped\n");
			pcr -= MAX_SCR_VALUE;
		}

		sleep(1);
		gettimeofday(&t2, NULL);

		elapsed_us = ltn_timeval_subtract_us(&t2, &t1);
		pcr += (elapsed_us * 27); /* one second in 27MHz clock */

		/* The PCR willnaturally fall behind wall time by 1 us every few seconds, 
		 * because all of this non-timed processing isn't accounted for, such as 
		 * subtarction, getting the time itself etc.
		 */

	}

	return 0;
}

/* Regression test for pid_s.clockLock (see clock_inspector_public.h / clock_inspector_ws.c).
 * One thread hammers the lock the way processSCRStats()/processPESHeader() do (mutate scr
 * and clk_pts under the lock, monotonically increasing); a second thread hammers it the way
 * the websocket snapshot thread does (copy the same fields out under the lock). If the lock
 * were missing or incorrect, the reader could observe a torn or momentarily-regressed value
 * (e.g. scr going backwards) despite the writer only ever incrementing it. Run via -X 3.
 */
struct ci_clocklock_test_ctx {
	struct pid_s pid;
	int iterations;
	int failed;
};

static void *ci_clocklock_test_writer(void *arg)
{
	struct ci_clocklock_test_ctx *t = arg;
	for (int i = 1; i <= t->iterations; i++) {
		pthread_mutex_lock(&t->pid.clockLock);
		t->pid.scr = (uint64_t)i * 300;
		t->pid.scr_updateCount++;
		ltntstools_clock_set_ticks(&t->pid.clk_pts, (int64_t)i * 90);
		pthread_mutex_unlock(&t->pid.clockLock);
	}
	return NULL;
}

static void *ci_clocklock_test_reader(void *arg)
{
	struct ci_clocklock_test_ctx *t = arg;
	uint64_t lastScr = 0;
	int64_t lastPtsTicks = -1;

	while (1) {
		pthread_mutex_lock(&t->pid.clockLock);
		uint64_t scr = t->pid.scr;
		uint64_t count = t->pid.scr_updateCount;
		int64_t ptsTicks = ltntstools_clock_get_ticks(&t->pid.clk_pts);
		pthread_mutex_unlock(&t->pid.clockLock);

		if (scr < lastScr || ptsTicks < lastPtsTicks) {
			t->failed = 1;
			fprintf(stderr, "validateClockLocking: FAIL - observed a torn/regressed read "
				"(scr %" PRIu64 " < last %" PRIu64 ", pts %" PRIi64 " < last %" PRIi64 ")\n",
				scr, lastScr, ptsTicks, lastPtsTicks);
		}
		lastScr = scr;
		lastPtsTicks = ptsTicks;

		if (count >= (uint64_t)t->iterations)
			break;
	}
	return NULL;
}

int validateClockLocking()
{
	struct ci_clocklock_test_ctx t;
	memset(&t, 0, sizeof(t));
	t.iterations = 200000;

	pthread_mutex_init(&t.pid.clockLock, NULL);
	ltntstools_clock_initialize(&t.pid.clk_pts);
	ltntstools_clock_establish_timebase(&t.pid.clk_pts, 90000);
	ltntstools_clock_establish_wallclock(&t.pid.clk_pts, 0);

	pthread_t writer, reader;
	pthread_create(&writer, NULL, ci_clocklock_test_writer, &t);
	pthread_create(&reader, NULL, ci_clocklock_test_reader, &t);

	pthread_join(writer, NULL);
	pthread_join(reader, NULL);

	pthread_mutex_destroy(&t.pid.clockLock);

	if (t.failed) {
		printf("validateClockLocking: FAILED\n");
		return 1;
	}

	printf("validateClockLocking: PASSED (%d iterations, no torn/regressed reads observed under contention)\n",
		t.iterations);
	return 0;
}

void kernel_check_socket_sizes(AVIOContext *i)
{
	printf("Kernel configured default/max socket buffer sizes:\n");

	char line[256];
	int val;
	FILE *fh = fopen("/proc/sys/net/core/rmem_default", "r");
	if (fh) {
		size_t l = fread(&line[0], 1, sizeof(line) - 1, fh);
		line[l] = 0;
		val = atoi(line);
		printf("/proc/sys/net/core/rmem_default = %d\n", val);
		fclose(fh);
	}

	fh = fopen("/proc/sys/net/core/rmem_max", "r");
	if (fh) {
		size_t l = fread(&line[0], 1, sizeof(line) - 1, fh);
		line[l] = 0;
		val = atoi(line);
		printf("/proc/sys/net/core/rmem_max = %d\n", val);
		if (i->buffer_size > val) {
			fprintf(stderr, "buffer_size %d exceeds rmem_max %d, aborting\n", i->buffer_size, val);
			exit(1);
		}
		fclose(fh);
	}

}

