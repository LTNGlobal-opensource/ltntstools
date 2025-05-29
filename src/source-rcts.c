#include <unistd.h>

#include "source-rcts.h"
#include "utils.h"

#define READ_SEG_SIZE (7 * 188)

struct source_rcts_ctx_s
{
	pthread_mutex_t    mutex;
	int                loop; /* Boolean, loop content at end of file? */

    pthread_t          threadId;
	int                threadRunning, threadTerminate, threadTerminated;

	void              *userContext;
	struct ltntstools_source_rcts_callbacks_s  callbacks;

	/* StreamModel */
	struct ltntstools_pat_s *pat;

	/* PCR smoother */
	void			  *smctx;

	/* File source */
	char 			  *filename;
	time_t			   lastPosCallback;
};

extern int ltnpthread_setname_np(pthread_t thread, const char *name);

static int sm_pcr_output_callback(void *userContext, unsigned char *pkts, int lengthBytes,
	struct ltntstools_pcr_position_s *array, int arrayLength)
{
	struct source_rcts_ctx_s *ctx = userContext;

        struct timeval current_time;
        gettimeofday(&current_time, NULL);

	if (ctx->callbacks.raw) {
		ctx->callbacks.raw(ctx->userContext, pkts, lengthBytes / 188, &current_time);
	}

	return 0;
}

static void *rcts_thread_func(void *p)
{
	struct source_rcts_ctx_s *ctx = p;
	struct timeval ts;

	ctx->threadRunning = 1;
	ctx->threadTerminate = 0;
	ctx->threadTerminated = 0;

	ltnpthread_setname_np(ctx->threadId, "tstools-rcts");

	pthread_detach(pthread_self());

	unsigned char *buf = malloc(READ_SEG_SIZE);
	if (!buf) {
		pthread_exit(NULL);
		return 0;
	}

	/* The basic processing model is this.
	 * Start a smoother_pcr queue, use a leaky bucket model to keep the queue at 1MB deep.
	 */
	FILE *fh = fopen(ctx->filename, "rb");
	fseek(fh, 0L, SEEK_END);
	long fileSizeBytes = ftell(fh);
	fseek(fh, 0L, SEEK_SET);

	while (fh && !ctx->threadTerminate) {

		/* Wait until the smoother queue is less then ideal deep */
		if (smoother_pcr_get_size(ctx->smctx) > 1048576) {
			usleep(2 * 1000);
			continue;
		}

		int rlen = fread(buf, 1, READ_SEG_SIZE, fh);
		if (rlen < READ_SEG_SIZE) {
			if (!ctx->loop) {
				break;
			}
			fseek(fh, 0L, SEEK_SET);
			if (ctx->callbacks.pos) {
				ctx->callbacks.pos(ctx->userContext, (uint64_t)fileSizeBytes, (uint64_t)fileSizeBytes, 100.0);
			}
			smoother_pcr_reset(ctx->smctx);
			continue;
		}

		time_t now = time(NULL);
		if (ctx->lastPosCallback != now) {
			ctx->lastPosCallback = now;
			if (ctx->callbacks.pos) {
				long pos = ftell(fh);
				double pct = ((double)pos / (double)fileSizeBytes) * 100.0;
				ctx->callbacks.pos(ctx->userContext, (uint64_t)pos, (uint64_t)fileSizeBytes, pct);
			}
		}
		gettimeofday(&ts, NULL);
		smoother_pcr_write(ctx->smctx, buf, READ_SEG_SIZE, &ts);

	}
	if (ctx->callbacks.pos) {
		ctx->callbacks.pos(ctx->userContext, (uint64_t)fileSizeBytes, (uint64_t)fileSizeBytes, 100.0);
	}
	fclose(fh);
	free(buf);
	ctx->threadTerminated = 1;

	pthread_exit(NULL);
	return 0;
}

int ltntstools_source_rcts_alloc(void **hdl, void *userContext, struct ltntstools_source_rcts_callbacks_s *callbacks, const char *filename, int fileLoop)
{
	if (!filename)
		return -1;

	struct source_rcts_ctx_s *ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return -1;

	pthread_mutex_init(&ctx->mutex, NULL);
	ctx->callbacks = *callbacks;
	ctx->userContext = userContext;
	ctx->filename = strdup(filename);
	ctx->loop = fileLoop;

#if 0
	/* Figure out the bps, we're assuming CBR.
	 * Bump it by 20% to keep the IATs from getting super bursty when we're assuming 400mbps
	 * through the bitrate smoother. The smooth can and will handle 400mbps, but it
	 * gets super lumpy of you declare 400mbps and then feet is 20mbps.
	 */
	uint32_t actual_bps = 400 * 1e6;
	uint32_t using_bps = actual_bps;
	if (ltntstools_file_estimate_bitrate(ctx->filename, &actual_bps) == 0) {
		using_bps = (double)actual_bps * 1.2L;
		if (using_bps < 20*1e6)
			using_bps = 20*1e6;
#if 1
		printf("%s() est... %s, bps = %d, using %d\n", __func__, ctx->filename, actual_bps, using_bps);
#endif
	}
	printf("%s() %s, bps = %d, using %d\n", __func__, ctx->filename, actual_bps, using_bps);
#endif

	/* Figure out the PCR Pid */
	if (ltntstools_streammodel_alloc_from_url(ctx->filename, &ctx->pat) < 0) {
		fprintf(stderr, "%s() Unable to detect stream PSIP model from file.\n", __func__);
		free(ctx);
		return -1;
	}

	int e = 0;
	struct ltntstools_pmt_s *pmt;
	if (ltntstools_pat_enum_services_video(ctx->pat, &e, &pmt) < 0) {
		fprintf(stderr, "%s() Unable to detect PCR PID from file.\n", __func__);
		free(ctx);
		return -1;
	}

	if (smoother_pcr_alloc(&ctx->smctx, ctx, &sm_pcr_output_callback,
		20000,
		7 * 188,
		pmt->PCR_PID,
		200 /* ms of jitter protection */) < 0)
	{
		fprintf(stderr, "%s() Unable to allocate smoother\n", __func__);
		free(ctx);
		return -1;
	}

	pthread_create(&ctx->threadId, 0, rcts_thread_func, ctx);

	*hdl = ctx;
	return 0;
}

void ltntstools_source_rcts_free(void *hdl)
{
	struct source_rcts_ctx_s *ctx = (struct source_rcts_ctx_s *)hdl;
	if (!ctx)
		return;

	/* Take the lock forever */
	pthread_mutex_lock(&ctx->mutex);

	ctx->threadTerminate = 1;
	while (!ctx->threadTerminated)
		usleep(1 * 1000);

	smoother_pcr_free(ctx->smctx);	
	ltntstools_pat_free(ctx->pat);	
	free(ctx->filename);
	free(ctx);
}

