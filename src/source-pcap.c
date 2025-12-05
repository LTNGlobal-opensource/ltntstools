#include <unistd.h>

#include "libltntstools/ltntstools.h"
#include "source-pcap.h"
#include "utils.h"

static int g_buffer_size_default = (64 * 1024 * 1024);
static int g_snaplen_default =
#ifdef __linux__
	BUFSIZ
#endif
#ifdef __APPLE__
	65535
#endif
;

struct source_pcap_ctx_s
{
	pthread_mutex_t    mutex;

    pthread_t          threadId;
	int                threadRunning, threadTerminate, threadTerminated;

	void              *userContext;
	struct ltntstools_source_pcap_callbacks_s  callbacks;

	/* PCAP */
	char             *ifname;
	char             *dev;
	char              errbuf[PCAP_ERRBUF_SIZE];
	pcap_t           *descr;
	bpf_u_int32       netp;
	bpf_u_int32       maskp;
	char             *pcap_filter;
	int               snaplen;
	int               bufferSize;
	struct pcap_stat  pcap_stats; /* network loss and drop statistics */
	struct pcap_stat  pcap_stats_startup; /* network loss and drop statistics */
	int64_t           pcap_free_miss;
	int64_t           pcap_dispatch_miss;
};

extern int ltnpthread_setname_np(pthread_t thread, const char *name);

static void pcap_callback(u_char *args, const struct pcap_pkthdr *h, const u_char *pkt) 
{
	struct source_pcap_ctx_s *ctx = (struct source_pcap_ctx_s *)args;

	if (ctx->callbacks.raw) {
		ctx->callbacks.raw(ctx->userContext, h, pkt, &ctx->pcap_stats);

	}
	//pcap_update_statistics(ctx, h, pkt); /* Update the stream stats realtime to avoid queue jitter */
	//pcap_queue_push(ctx, h, pkt); /* Push the packet onto a deferred queue for late IO processing. */
}

static void *pcap_thread_func(void *p)
{
	struct source_pcap_ctx_s *ctx = p;

	ctx->threadRunning = 1;
	ctx->threadTerminate = 0;
	ctx->threadTerminated = 0;

	int processed;

	ltnpthread_setname_np(ctx->threadId, "tstools-pcap");

	pthread_detach(pthread_self());

	time_t lastStatsCheck = 0;

	while (!ctx->threadTerminate) {

		processed = pcap_dispatch(ctx->descr, -1, pcap_callback, (u_char *)ctx);
		if (processed == 0) {
			ctx->pcap_dispatch_miss++;
			usleep(10 * 1000);
		}

		time_t now;
		time(&now);

		/* Querying stats repeatidly is cpu expensive, we only need it 30sec intervals. */
		if (lastStatsCheck == 0) {
			/* Collect pcap packet loss stats */
			if (pcap_stats(ctx->descr, &ctx->pcap_stats_startup) != 0) {
				/* Error */
			}
		}

		if (now > lastStatsCheck + 30) {
			lastStatsCheck = now;
			/* Collect pcap packet loss stats */
			struct pcap_stat tmp;
			if (pcap_stats(ctx->descr, &tmp) != 0) {
				/* Error */
			}

			ctx->pcap_stats.ps_recv = tmp.ps_recv - ctx->pcap_stats_startup.ps_recv;
			ctx->pcap_stats.ps_drop = tmp.ps_drop - ctx->pcap_stats_startup.ps_drop;
			ctx->pcap_stats.ps_ifdrop = tmp.ps_ifdrop - ctx->pcap_stats_startup.ps_ifdrop;
		}

	}
	ctx->threadTerminated = 1;

	pthread_exit(NULL);
	return 0;
}

int ltntstools_source_pcap_alloc(void **hdl, void *userContext, struct ltntstools_source_pcap_callbacks_s *callbacks, const char *ifname, const char *filter, int buffer_size_default)
{
	if (!ifname || !filter)
		return -1;

	struct source_pcap_ctx_s *ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return -1;

	pthread_mutex_init(&ctx->mutex, NULL);
	ctx->snaplen = g_snaplen_default;
	ctx->bufferSize = buffer_size_default == -1 ? g_buffer_size_default : buffer_size_default;
	ctx->callbacks = *callbacks;
	ctx->userContext = userContext;
	ctx->ifname = strdup(ifname);
	ctx->pcap_filter = strdup(filter);

	pcap_lookupnet(ctx->ifname, &ctx->netp, &ctx->maskp, ctx->errbuf);

	struct in_addr ip_net, ip_mask;
	ip_net.s_addr = ctx->netp;
	ip_mask.s_addr = ctx->maskp;

	printf("network: %s\n", inet_ntoa(ip_net));
	printf("   mask: %s\n", inet_ntoa(ip_mask));
	printf(" filter: %s\n", ctx->pcap_filter);
	printf("snaplen: %d\n", ctx->snaplen);
	printf("buffSiz: %d\n", ctx->bufferSize);

	ctx->descr = pcap_create(ctx->ifname, ctx->errbuf);
	if (ctx->descr == NULL) {
		fprintf(stderr, "Error, %s\n", ctx->errbuf);
		free(ctx);
		return -1;
	}

	pcap_set_immediate_mode(ctx->descr, 1); /* Ensure immediate packet callback delivery, later lib versions batch every 200ms */
	pcap_set_snaplen(ctx->descr, ctx->snaplen);
	pcap_set_promisc(ctx->descr,
#ifdef __linux__
		-1
#endif
#ifdef __APPLE__
		1
#endif
	);

	if (ctx->bufferSize != -1) {
		int ret = pcap_set_buffer_size(ctx->descr, ctx->bufferSize);
		if (ret == PCAP_ERROR_ACTIVATED) {
			fprintf(stderr, "%s() Unable to set -B buffersize to %d, already activated\n", __func__, ctx->bufferSize);
			free(ctx);
			return -1;
		}
		if (ret != 0) {
			fprintf(stderr, "%s() Unable to set -B buffersize to %d\n", __func__, ctx->bufferSize);
			free(ctx);
			return -1;
		}
	}

	int ret = pcap_activate(ctx->descr);
	if (ret != 0) {
		if (ret == PCAP_ERROR_PERM_DENIED) {
			fprintf(stderr, "%s() Error, permission denied.\n", __func__);
		}
		if (ret == PCAP_ERROR_NO_SUCH_DEVICE) {
			fprintf(stderr, "%s() Error, network interface '%s' not found.\n", __func__, ctx->ifname);
		}
		fprintf(stderr, "%s() Error, pcap_activate, %s\n", __func__, pcap_geterr(ctx->descr));
		printf("\nAvailable interfaces:\n");
		networkInterfaceList();
		free(ctx);
		return -1;
	}

	/* TODO: We should craft the filter to be udp dst 224.0.0.0/4 and then
	 * we don't need to manually filter in our callback.
	 */
	struct bpf_program fp;
	ret = pcap_compile(ctx->descr, &fp, ctx->pcap_filter, 0, ctx->netp);
	if (ret == -1) {
		fprintf(stderr, "Error, pcap_compile, %s\n", pcap_geterr(ctx->descr));
		free(ctx);
		return -1;
	}

	ret = pcap_setfilter(ctx->descr, &fp);
	if (ret == -1) {
		fprintf(stderr, "Error, pcap_setfilter\n");
		free(ctx);
		return -1;
	}

	pcap_setnonblock(ctx->descr, 1, ctx->errbuf);

	pthread_create(&ctx->threadId, 0, pcap_thread_func, ctx);

	*hdl = ctx;
	return 0;
}

void ltntstools_source_pcap_free(void *hdl)
{
	struct source_pcap_ctx_s *ctx = (struct source_pcap_ctx_s *)hdl;

	if (!ctx)
		return;

	/* Take the lock forever */
	pthread_mutex_lock(&ctx->mutex);

	ctx->threadTerminate = 1;
	while (!ctx->threadTerminated)
		usleep(1 * 1000);

	free(ctx);
}
