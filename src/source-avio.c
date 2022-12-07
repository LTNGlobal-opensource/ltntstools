
/* If we push this into libltntstools, we push all the avioformat deps to.
   I don't like that, so leave the framework here.
 */

#include <unistd.h>
#include "source-avio.h"
#include "ffmpeg-includes.h"

#define READ_SEG_SIZE (4096)

struct source_avio_ctx_s
{
	pthread_mutex_t    mutex;
	int                verbose;

    pthread_t          threadId;
	int                threadRunning, threadTerminate, threadTerminated;

	void              *userContext;
	struct ltntstools_source_avio_callbacks_s  callbacks;

	/* libavformat */
	char 			  *url;
	AVIOContext       *puc;
};

extern int ltnpthread_setname_np(pthread_t thread, const char *name);

static void *avio_thread_func(void *p)
{
	struct source_avio_ctx_s *ctx = p;

	ctx->threadRunning = 1;
	ctx->threadTerminate = 0;
	ctx->threadTerminated = 0;

	ltnpthread_setname_np(ctx->threadId, "tstools-avio");

	pthread_detach(pthread_self());

	unsigned char *buf = malloc(READ_SEG_SIZE);
	if (!buf) {
		ctx->threadTerminated = 1;
		pthread_exit(NULL);
		return 0;
	}

	int isRTP = 0;
	int blen = 7 * 188;
	int boffset = 0;
	if (ctx->callbacks.status) {
		ctx->callbacks.status(ctx->userContext, AVIO_STATUS_MEDIA_START);
	}
	while (!ctx->threadTerminate) {
		int rlen = avio_read(ctx->puc, buf, blen);
		if (rlen == -EAGAIN) {
			usleep(2 * 1000);
			continue;
		}
		if (rlen < 0)
			break;

		if (buf[0] == 0x80 && isRTP == 0) {
			blen += 12;
			isRTP = 1;
			boffset = 12;
			continue;
		}
		if (ctx->verbose > 0) {
			printf("Read %4d : ", rlen);
			for (int i = 0; i < 16; i++)
				printf("%02x ", buf[i]);
			printf("\n");
		}
		if (ctx->callbacks.raw) {
			ctx->callbacks.raw(ctx->userContext, buf + boffset, (blen - boffset) / 188);
		}
	}
	if (ctx->callbacks.status) {
		ctx->callbacks.status(ctx->userContext, AVIO_STATUS_MEDIA_END);
	}

	free(buf);
	ctx->threadTerminated = 1;

	pthread_exit(NULL);
	return 0;
}

int ltntstools_source_avio_alloc(void **hdl, void *userContext, struct ltntstools_source_avio_callbacks_s *callbacks, const char *url)
{
	if (!url)
		return -1;

	struct source_avio_ctx_s *ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return -1;

	pthread_mutex_init(&ctx->mutex, NULL);
	ctx->callbacks = *callbacks;
	ctx->userContext = userContext;
	ctx->url = strdup(url);
	ctx->verbose = 0;

	avformat_network_init();
	
	int ret = avio_open2(&ctx->puc, ctx->url, AVIO_FLAG_READ | AVIO_FLAG_NONBLOCK | AVIO_FLAG_DIRECT, NULL, NULL);
	if (ret < 0) {
		fprintf(stderr, "%s() unable to open url\n", __func__);
		free(ctx);
		return 1;
	}

	pthread_create(&ctx->threadId, 0, avio_thread_func, ctx);

	*hdl = ctx;
	return 0;
}

void ltntstools_source_avio_free(void *hdl)
{
	struct source_avio_ctx_s *ctx = (struct source_avio_ctx_s *)hdl;
	if (!ctx)
		return;

	/* Take the lock forever */
	pthread_mutex_lock(&ctx->mutex);

	ctx->threadTerminate = 1;
	while (!ctx->threadTerminated)
		usleep(1 * 1000);

	if (ctx->puc) {
		avio_close(ctx->puc);
		ctx->puc = NULL;
	}

	free(ctx->url);
	free(ctx);
}

