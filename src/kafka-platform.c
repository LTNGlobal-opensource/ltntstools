#include <unistd.h>
#include <inttypes.h>
#include <netdb.h>
#include <errno.h>

#if 0

#include <libltntstools/ltntstools.h>
#include <librdkafka/rdkafka.h>

/* On start then every 15 seconds afterwards:
{
	report_time: "YYYY-MM-DD HH:MM:SS.000", // iso 8601

	probename: "ltnp_cnbc-e1.task_enc-1",

	probe_starttime: "YYYY-MM-DD HH:MM:SS.000", // iso 8601
	probe_runtime: "YYYY-MM-DD HH:MM:SS.000", // iso 8601

	hostname_fqdn: "ltn245.ltnglobal.com",

	thermal_c: "62.2",
	uptime: "YYYY-MM-DD HH:MM:SS.000", // iso 8601
	"os", "Linux 3.10.0-957.5.1.el7.x86_64 (x86_64), #1 SMP Fri Feb 1 14:54:57 UTC 2019",

	"ram": {
		free: #bytes,
		used: #bytes
	},
	"load_averages": {
		1m: 1.03,
		5m: 1.21,
		15m: 1.16,
	},

	"udp_fd_sockets": [
			{
					"address": "227.1.20.80",
					"port": 4001,
					"pid": 15194,
					"comm": "srt-live-transmit",
					"inode": 4780523,
					"drops": 387,                   // units?
			},
			{
					"address": "227.1.20.80",
					"port": 4001,
					"pid": 27223,
					"comm": "gstlaunch-1.0",
					"inode": 5275987,
					"drops": 0,
			},
	],
	 "interfaces": [
                {
                        "name": "eth0",
                        "address": "192.168.2.15",
                        "udp_errors": 0,
                        "tcp_errors": 0,
                        "min_iat": 17,                  // us
                        "max_iat": 3211,                // us
                        "avg_iat": 866,                 // us
                        "rxb": 2829037857,              // bytes
                        "txb": 8723763,                 // bytes
                        "rx_drop": 0,
                        "tx_drop": 0,
                        "iat_histogram": (base64),
                },
                {
                        "name": "lo",
                        "address": "127.0.0.1",
                        "udp_errors": 4,
                        "tcp_errors": 0,
                        "min_iat_us": 17,
                        "max_iat_us": 3211,
                        "avg_iat_us": 866,
                        "rx_bytes": 37857,
                        "tx_bytes": 270,
                        "rx_drop": 0,
                        "tx_drop": 0,
                        "iat_histogram": (base64),
                },
        ],


}
*/

struct kafka_item_s
{
	struct xorg_list list;
	unsigned char *buf;
	int lengthBytes;
	int lengthBytesMax;
	struct kplatform_ctx_s *ctx;
};

struct kplatform_ctx_s {
	rd_kafka_conf_t       *conf;
	rd_kafka_topic_conf_t *topic_conf;
	rd_kafka_t            *rk;
	rd_kafka_topic_t      *rkt;
	char                   hostname[128];
	char                   errstr[512];
	char                   topicName[64];

	pthread_mutex_t        listLock;
	struct xorg_list       list;

	pthread_t              threadId;
	int                    threadTerminate, threadRunning, threadTerminated;

};

extern int ltnpthread_setname_np(pthread_t thread, const char *name);
static struct kafka_item_s *_queue_pop(struct kplatform_ctx_s *ctx);
static struct kafka_item_s *_queue_peek(struct kplatform_ctx_s *ctx);

static void _queue_delete(struct kplatform_ctx_s *ctx)
{
	struct kafka_item_s *item = _queue_pop(ctx);
	while (item) {
		ltntstools_kplatform_item_free(ctx, item);
		item = _queue_pop(ctx);
	}
}

static void _on_delivery(rd_kafka_t *rk, const rd_kafka_message_t *rkmessage, void *opaque)
{
	/* TODO: This isn't firing, why not? */
	//struct kplatform_ctx_s *ctx (struct kplatform_ctx_s *)opaque;

	printf("%s()\n", __func__);

	if (rkmessage->err) {
		fprintf(stderr, "%% Message delivery failed: %s\n", rd_kafka_message_errstr(rkmessage));
	}
}

static int _item_publish(struct kplatform_ctx_s *ctx, struct kafka_item_s *item)
{
	if (rd_kafka_produce(ctx->rkt, RD_KAFKA_PARTITION_UA, RD_KAFKA_MSG_F_COPY, item->buf, item->lengthBytes, NULL, 0, item) == -1) {
		printf("BAD!\n");
		fprintf(stderr, "Failed to produce to topic %s: %s\n", ctx->topicName, rd_kafka_err2str(rd_kafka_last_error()));
		return -1;
	}
	
	return 0; /* Success */
}

static int _queue_process(struct kplatform_ctx_s *ctx)
{
	if (ctx->rk == NULL)
		return 0;

	int failed = 0;

	struct kafka_item_s *item = _queue_peek(ctx);
	while (item) {
		if (_item_publish(ctx, item) == 0) {
			/* Success, remove the item from the list */
			item = _queue_pop(ctx);
			ltntstools_kplatform_item_free(ctx, item);
			item = NULL;

			failed = 0;
		} else {
			usleep(250 * 1000); /* Natural rate limit if the post fails */
			failed += 250;
		}

		/* Success, take this of the queue and destroy it */
		item = _queue_peek(ctx);
	}

	return 0; /* Success */
}

static void *kplatform_thread_func(void *p)
{
	struct kplatform_ctx_s *ctx = p;

	ctx->threadRunning = 1;
	ctx->threadTerminate = 0;
	ctx->threadTerminated = 0;

	ltnpthread_setname_np(ctx->threadId, "tstools-kplat");
	pthread_detach(pthread_self());

	while (!ctx->threadTerminate) {
		_queue_process(ctx);
		usleep(5 * 1000 * 1000);
	}
	ctx->threadTerminated = 1;

	pthread_exit(NULL);
	return 0;
}

int ltntstools_kplatform_alloc(void **hdl)
{
	struct kplatform_ctx_s *ctx = (struct kplatform_ctx_s *)calloc(1, sizeof(*ctx));
	if (!ctx)
		return -1;

	pthread_mutex_init(&ctx->listLock, NULL);
	xorg_list_init(&ctx->list);
	sprintf(ctx->topicName, "feed_%s", "something");

	printf("%s() topic '%s'\n", __func__, ctx->topicName);

	ctx->conf = rd_kafka_conf_new();

	rd_kafka_conf_set_dr_msg_cb(ctx->conf, _on_delivery);

	if (gethostname(ctx->hostname, sizeof(ctx->hostname))) {
		fprintf(stderr, "%% Failed to lookup hostname\n");
		return -1;
	}

	if (rd_kafka_conf_set(ctx->conf, "client.id", ctx->hostname, ctx->errstr, sizeof(ctx->errstr)) != RD_KAFKA_CONF_OK) {
		fprintf(stderr, "%% %s\n", ctx->errstr);
		return -1;
	}

	//if (rd_kafka_conf_set(k->conf, "bootstrap.servers", "192.168.2.41:9092,192.168.2.42:9092", k->errstr, sizeof(k->errstr)) != RD_KAFKA_CONF_OK) {
	//if (rd_kafka_conf_set(k->conf, "bootstrap.servers", "192.168.2.41:9092", k->errstr, sizeof(k->errstr)) != RD_KAFKA_CONF_OK) {
	if (rd_kafka_conf_set(ctx->conf, "bootstrap.servers", "170.187.147.164:9092", ctx->errstr, sizeof(ctx->errstr)) != RD_KAFKA_CONF_OK) {
		fprintf(stderr, "%% %s\n", ctx->errstr);
		return -1;
	}

	ctx->topic_conf = rd_kafka_topic_conf_new();

	if (rd_kafka_topic_conf_set(ctx->topic_conf, "acks", "all", ctx->errstr, sizeof(ctx->errstr)) != RD_KAFKA_CONF_OK) {
		fprintf(stderr, "%% %s\n", ctx->errstr);
		return -1;
	}

	/* Create Kafka producer handle */
	if (!(ctx->rk = rd_kafka_new(RD_KAFKA_PRODUCER, ctx->conf, ctx->errstr, sizeof(ctx->errstr)))) {
		fprintf(stderr, "%% Failed to create new producer: %s\n", ctx->errstr);
		return -1;
	}

	ctx->rkt = rd_kafka_topic_new(ctx->rk, ctx->topicName, ctx->topic_conf);
	if (!ctx->rkt) {
		fprintf(stderr, "%% Failed to create new topic: %s\n", ctx->errstr);
		return 0;
	}

	printf("%s() hostname: %s\n", __func__, ctx->hostname);
	
	pthread_create(&ctx->threadId, 0, kplatform_thread_func, ctx);

	*hdl = ctx;
	return 0; /* Success */
}

void ltntstools_kplatform_free(void *hdl)
{
	struct kplatform_ctx_s *ctx = hdl;

	_queue_delete(ctx);

	ctx->threadTerminate = 1;
	while (!ctx->threadTerminated)
		usleep(50 * 1000);

	if (ctx->rk)
		rd_kafka_destroy(ctx->rk);
	
//	if (ctx->topic_conf)
//		rd_kafka_topic_conf_destroy(ctx->topic_conf);

//	if (ctx->conf)
//		rd_kafka_conf_destroy(ctx->conf);

	free(ctx);
}

/* Peek the list, don't remove it because our post may fail, and I don't want to
 * push this back on the head of the queue.
 * Assume we'll fail on our post.
 */
static struct kafka_item_s *_queue_peek(struct kplatform_ctx_s *ctx)
{
	struct kafka_item_s *item = NULL;

	pthread_mutex_lock(&ctx->listLock);
	while (!xorg_list_is_empty(&ctx->list)) {
		item = xorg_list_first_entry(&ctx->list, struct kafka_item_s, list);
		break;
	}
	pthread_mutex_unlock(&ctx->listLock);

	return item;
}

/* Pop something off the list, called will delete the returned object lifespan. */
static struct kafka_item_s *_queue_pop(struct kplatform_ctx_s *ctx)
{
	struct kafka_item_s *item = NULL;

	pthread_mutex_lock(&ctx->listLock);
	while (!xorg_list_is_empty(&ctx->list)) {
		item = xorg_list_first_entry(&ctx->list, struct kafka_item_s, list);
		xorg_list_del(&item->list);
		break;
	}
	pthread_mutex_unlock(&ctx->listLock);

	return item;
}

/* Append to list */
int kafka_queue_push(struct kplatform_ctx_s *ctx, struct kafka_item_s *item)
{
	pthread_mutex_lock(&ctx->listLock);
	xorg_list_append(&item->list, &ctx->list);
	pthread_mutex_unlock(&ctx->listLock);

	return 0; /* Success */
}

struct kafka_item_s *ltntstools_kplatform_item_alloc(void *hdl, int lengthBytesMax)
{
	struct kplatform_ctx_s *ctx = hdl;

	struct kafka_item_s *item = calloc(1, sizeof(*item));
	if (!item)
		return NULL;

	item->lengthBytesMax = lengthBytesMax;
	item->buf = calloc(1, item->lengthBytesMax);
	item->ctx = ctx;

	return item;
}

void ltntstools_kplatform_item_free(void *hdl, struct kafka_item_s *item)
{
	//struct kplatform_ctx_s *ctx = hdl;
	free(item->buf);
	free(item);
}
#endif
