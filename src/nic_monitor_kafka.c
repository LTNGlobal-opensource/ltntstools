#include "nic_monitor.h"

/* See https://docs.confluent.io/clients-librdkafka/current/overview.html */

#if PROBE_REPORTER

#include <curl/curl.h>

#pragma message "WARNING: PROBE_REPORTER IS ACTIVE, remove before flight."

static void kafka_queue_delete(struct discovered_item_s *di);

static void on_delivery(rd_kafka_t *rk, const rd_kafka_message_t *rkmessage, void *opaque)
{
	/* TODO: This isn't firing, why not? */
	//struct kafka_item_s *item = (struct kafka_item_s *)opaque;
	//struct discovered_item_s *di = item->di;

	printf("%s()\n", __func__);

	if (rkmessage->err) {
		fprintf(stderr, "%% Message delivery failed: %s\n", rd_kafka_message_errstr(rkmessage));
	}
}

int kafka_initialize(struct discovered_item_s *di)
{
	struct kafka_ctx_s *k = &di->kafka;

	pthread_mutex_init(&k->listLock, NULL);
	xorg_list_init(&k->list);
	sprintf(k->topicName, "feed_%s", di->dstaddr);

	character_replace(k->topicName, ':', '_');
	printf("%s() topic '%s'\n", __func__, k->topicName);

	k->conf = rd_kafka_conf_new();

	rd_kafka_conf_set_dr_msg_cb(k->conf, on_delivery);

	if (gethostname(k->hostname, sizeof(di->kafka.hostname))) {
		fprintf(stderr, "%% Failed to lookup hostname\n");
		return -1;
	}

	if (rd_kafka_conf_set(di->kafka.conf, "client.id", k->hostname, k->errstr, sizeof(k->errstr)) != RD_KAFKA_CONF_OK) {
		fprintf(stderr, "%% %s\n", k->errstr);
		return -1;
	}

	//if (rd_kafka_conf_set(k->conf, "bootstrap.servers", "192.168.2.41:9092,192.168.2.42:9092", k->errstr, sizeof(k->errstr)) != RD_KAFKA_CONF_OK) {
	//if (rd_kafka_conf_set(k->conf, "bootstrap.servers", "192.168.2.41:9092", k->errstr, sizeof(k->errstr)) != RD_KAFKA_CONF_OK) {
	if (rd_kafka_conf_set(k->conf, "bootstrap.servers", "170.187.147.164:9092", k->errstr, sizeof(k->errstr)) != RD_KAFKA_CONF_OK) {
		fprintf(stderr, "%% %s\n", k->errstr);
		return -1;
	}

	k->topic_conf = rd_kafka_topic_conf_new();

	if (rd_kafka_topic_conf_set(k->topic_conf, "acks", "all", k->errstr, sizeof(k->errstr)) != RD_KAFKA_CONF_OK) {
		fprintf(stderr, "%% %s\n", k->errstr);
		return -1;
	}

	/* Create Kafka producer handle */
	if (!(k->rk = rd_kafka_new(RD_KAFKA_PRODUCER, k->conf, k->errstr, sizeof(k->errstr)))) {
		fprintf(stderr, "%% Failed to create new producer: %s\n", k->errstr);
		return -1;
	}

	k->rkt = rd_kafka_topic_new(k->rk, k->topicName, k->topic_conf);
	if (!k->rkt) {
		fprintf(stderr, "%% Failed to create new topic: %s\n", k->errstr);
		return 0;
	}

	printf("%s() hostname: %s\n", __func__, k->hostname);
	return 0; /* Success */
}

void kafka_free(struct discovered_item_s *di)
{
	struct kafka_ctx_s *k = &di->kafka;

	kafka_queue_delete(di);

	if (k->rk)
		rd_kafka_destroy(k->rk);
	
//	if (k->topic_conf)
//		rd_kafka_topic_conf_destroy(k->topic_conf);

//	if (k->conf)
//		rd_kafka_conf_destroy(k->conf);
}

struct kafka_item_s *kafka_item_alloc(struct discovered_item_s *di, int lengthBytesMax)
{
	struct kafka_item_s *item = calloc(1, sizeof(*item));
	if (!item)
		return NULL;

	item->lengthBytesMax = lengthBytesMax;
	item->buf = calloc(1, item->lengthBytesMax);
	item->di = di;

	return item;
}

void kafka_item_free(struct discovered_item_s *di, struct kafka_item_s *item)
{
	free(item->buf);
	free(item);
}

int kafka_item_publish(struct discovered_item_s *di, struct kafka_item_s *item)
{
	struct kafka_ctx_s *k = &di->kafka;

	if (rd_kafka_produce(k->rkt, RD_KAFKA_PARTITION_UA, RD_KAFKA_MSG_F_COPY, item->buf, item->lengthBytes, NULL, 0, item) == -1) {
		printf("BAD!\n");
		fprintf(stderr, "Failed to produce to topic %s: %s\n", k->topicName, rd_kafka_err2str(rd_kafka_errno2err(errno)));
		return -1;
	}
	
	return 0; /* Success */
}

/* Peek the list, don't remove it because our post may fail, and I don't want to
 * push this back on the head of the queue.
 * Assume we'll fail on our post.
 */
struct kafka_item_s *kafka_queue_peek(struct discovered_item_s *di)
{
	struct kafka_ctx_s *k = &di->kafka;
	struct kafka_item_s *item = NULL;

	pthread_mutex_lock(&k->listLock);
	while (!xorg_list_is_empty(&k->list)) {
		item = xorg_list_first_entry(&k->list, struct kafka_item_s, list);
		break;
	}
	pthread_mutex_unlock(&k->listLock);

	return item;
}

/* Pop something off the list, called will delete the returned object lifespan. */
struct kafka_item_s *kafka_queue_pop(struct discovered_item_s *di)
{
	struct kafka_ctx_s *k = &di->kafka;
	struct kafka_item_s *item = NULL;

	pthread_mutex_lock(&k->listLock);
	while (!xorg_list_is_empty(&k->list)) {
		item = xorg_list_first_entry(&k->list, struct kafka_item_s, list);
		xorg_list_del(&item->list);
		break;
	}
	pthread_mutex_unlock(&k->listLock);

	return item;
}

/* Append to list */
int kafka_queue_push(struct discovered_item_s *di, struct kafka_item_s *item)
{
	struct kafka_ctx_s *k = &di->kafka;

	pthread_mutex_lock(&k->listLock);
	xorg_list_append(&item->list, &k->list);
	pthread_mutex_unlock(&k->listLock);

	return 0; /* Success */
}

int kafka_queue_process(struct discovered_item_s *di)
{
	struct kafka_ctx_s *k = &di->kafka;

	if (k->rk == NULL)
		return 0;

	int failed = 0;

	struct kafka_item_s *item = kafka_queue_peek(di);
	while (item) {
		if (kafka_item_publish(di, item) == 0) {
			/* Success, remove the item from the list */
			item = kafka_queue_pop(di);
			kafka_item_free(di, item);
			item = NULL;

			failed = 0;
		} else {
			usleep(250 * 1000); /* Natural rate limit if the post fails */
			failed += 250;
		}

		/* Success, take this of the queue and destroy it */
		item = kafka_queue_peek(di);
	}

	return 0; /* Success */
}

static void kafka_queue_delete(struct discovered_item_s *di)
{
//	struct kafka_ctx_s *k = &di->kafka;

	struct kafka_item_s *item = kafka_queue_pop(di);
	while (item) {
		kafka_item_free(di, item);
		item = kafka_queue_pop(di);
	}
}

#endif
