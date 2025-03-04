#include "clock_inspector_public.h"

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

void kernel_check_socket_sizes(AVIOContext *i)
{
	printf("Kernel configured default/max socket buffer sizes:\n");

	char line[256];
	int val;
	FILE *fh = fopen("/proc/sys/net/core/rmem_default", "r");
	if (fh) {
		fread(&line[0], 1, sizeof(line), fh);
		val = atoi(line);
		printf("/proc/sys/net/core/rmem_default = %d\n", val);
		fclose(fh);
	}

	fh = fopen("/proc/sys/net/core/rmem_max", "r");
	if (fh) {
		fread(&line[0], 1, sizeof(line), fh);
		val = atoi(line);
		printf("/proc/sys/net/core/rmem_max = %d\n", val);
		if (i->buffer_size > val) {
			fprintf(stderr, "buffer_size %d exceeds rmem_max %d, aborting\n", i->buffer_size, val);
			exit(1);
		}
		fclose(fh);
	}

}

