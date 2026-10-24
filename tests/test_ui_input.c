#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/time.h>

#include "ui_test.h"
#include "nic_monitor_ui_input.h"

static void test_queue_basic(void)
{
	struct ui_event_queue_s q;
	struct ui_event_s e = { .type = UI_EVENT_KEY }, out[UI_EVENT_QUEUE_LEN * 2];

	CHECK_INT(ui_event_queue_init(NULL), UI_ERR_INVAL);
	CHECK_INT(ui_event_queue_init(&q), UI_OK);
	CHECK_INT(ui_event_queue_post(NULL, &e), UI_ERR_INVAL);
	CHECK_INT(ui_event_queue_post(&q, NULL), UI_ERR_INVAL);
	CHECK_INT(ui_event_queue_drain(&q, out, 4), 0);
	CHECK_INT(ui_event_queue_drain(NULL, out, 4), 0);
	CHECK_INT(ui_event_queue_drain(&q, NULL, 4), 0);
	CHECK_INT(ui_event_queue_drain(&q, out, 0), 0);

	for (int i = 0; i < 5; i++) {
		e.key = 'a' + i;
		CHECK_INT(ui_event_queue_post(&q, &e), UI_OK);
	}
	CHECK_INT(ui_event_queue_drain(&q, out, 2), 2);
	CHECK_INT(out[0].key, 'a');
	CHECK_INT(out[1].key, 'b');
	CHECK_INT(ui_event_queue_drain(&q, out, 10), 3);
	CHECK_INT(out[0].key, 'c');
	CHECK_INT(out[2].key, 'e');
	ui_event_queue_destroy(&q);
}

static void test_queue_overflow(void)
{
	struct ui_event_queue_s q;
	struct ui_event_s e = { .type = UI_EVENT_MOUSE }, out[UI_EVENT_QUEUE_LEN];

	ui_event_queue_init(&q);
	for (int i = 0; i < UI_EVENT_QUEUE_LEN; i++) {
		e.y = i;
		CHECK_INT(ui_event_queue_post(&q, &e), UI_OK);
	}
	e.y = 1000;
	CHECK_INT(ui_event_queue_post(&q, &e), UI_ERR_FULL);
	e.y = 1001;
	CHECK_INT(ui_event_queue_post(&q, &e), UI_ERR_FULL);
	CHECK_INT(ui_event_queue_dropped(&q), 2);

	CHECK_INT(ui_event_queue_drain(&q, out, UI_EVENT_QUEUE_LEN), UI_EVENT_QUEUE_LEN);
	CHECK_INT(out[0].y, 2);   /* The two oldest were dropped */
	CHECK_INT(out[UI_EVENT_QUEUE_LEN - 2].y, 1000);
	CHECK_INT(out[UI_EVENT_QUEUE_LEN - 1].y, 1001);
	ui_event_queue_destroy(&q);
}

/* Several producers, one consumer: every event is either received exactly
 * once or counted as dropped. Run under TSan for race detection.
 */
#define PRODUCERS 4
#define PER_PRODUCER 50000

static struct ui_event_queue_s g_q;
static volatile int g_producersDone = 0;

static void *producer(void *p)
{
	int id = (int)(intptr_t)p;
	for (int i = 0; i < PER_PRODUCER; i++) {
		struct ui_event_s e = { .type = UI_EVENT_KEY, .key = i, .y = id };
		ui_event_queue_post(&g_q, &e);
	}
	__atomic_fetch_add(&g_producersDone, 1, __ATOMIC_SEQ_CST);
	return NULL;
}

static void test_queue_threads(void)
{
	pthread_t t[PRODUCERS];
	int lastKey[PRODUCERS];
	uint64_t received = 0;
	int orderOk = 1;

	ui_event_queue_init(&g_q);
	for (int i = 0; i < PRODUCERS; i++) {
		lastKey[i] = -1;
		pthread_create(&t[i], NULL, producer, (void *)(intptr_t)i);
	}

	struct ui_event_s out[UI_EVENT_QUEUE_LEN];
	while (1) {
		int done = __atomic_load_n(&g_producersDone, __ATOMIC_SEQ_CST) == PRODUCERS;
		int n = ui_event_queue_drain(&g_q, out, UI_EVENT_QUEUE_LEN);
		for (int i = 0; i < n; i++) {
			int id = out[i].y;
			if (id < 0 || id >= PRODUCERS) {
				orderOk = 0;
				continue;
			}
			/* Per-producer order is preserved even when events are dropped. */
			if (out[i].key <= lastKey[id])
				orderOk = 0;
			lastKey[id] = out[i].key;
		}
		received += n;
		if (done && n == 0)
			break;
	}
	for (int i = 0; i < PRODUCERS; i++)
		pthread_join(t[i], NULL);

	CHECK(orderOk);
	CHECK_INT(received + ui_event_queue_dropped(&g_q), (uint64_t)PRODUCERS * PER_PRODUCER);
	ui_event_queue_destroy(&g_q);
}

static double now_ms(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
}

static struct ui_event_queue_s g_wq;

static void *late_poster(void *p)
{
	(void)p;
	usleep(50 * 1000);
	struct ui_event_s e = { .type = UI_EVENT_REDRAW };
	ui_event_queue_post(&g_wq, &e);
	return NULL;
}

static void test_queue_wait(void)
{
	struct ui_event_s e = { .type = UI_EVENT_KEY, .key = 'x' }, out[4];

	CHECK_INT(ui_event_queue_wait(NULL, 10), 0);
	ui_event_queue_init(&g_wq);

	/* Nothing queued: returns 0 after about the timeout. */
	double t0 = now_ms();
	CHECK_INT(ui_event_queue_wait(&g_wq, 120), 0);
	double waited = now_ms() - t0;
	CHECK(waited >= 110 && waited < 600);

	/* Already queued: returns at once, without removing the event. */
	ui_event_queue_post(&g_wq, &e);
	t0 = now_ms();
	CHECK_INT(ui_event_queue_wait(&g_wq, 1000), 1);
	CHECK(now_ms() - t0 < 50);
	CHECK_INT(ui_event_queue_drain(&g_wq, out, 4), 1);

	/* Posted by another thread while waiting: wakes well before the timeout. */
	pthread_t th;
	pthread_create(&th, NULL, late_poster, NULL);
	t0 = now_ms();
	CHECK_INT(ui_event_queue_wait(&g_wq, 2000), 1);
	waited = now_ms() - t0;
	CHECK(waited >= 30 && waited < 1000);
	pthread_join(th, NULL);
	CHECK_INT(ui_event_queue_drain(&g_wq, out, 4), 1);
	CHECK_INT(out[0].type, UI_EVENT_REDRAW);

	/* Timeouts over a second (tv_sec / tv_nsec carry). */
	t0 = now_ms();
	CHECK_INT(ui_event_queue_wait(&g_wq, 1100), 0);
	waited = now_ms() - t0;
	CHECK(waited >= 1050 && waited < 2000);

	ui_event_queue_destroy(&g_wq);
}

static void test_message(void)
{
	struct ui_message_s m;
	char out[UI_MESSAGE_LEN];

	CHECK_INT(ui_message_init(NULL), UI_ERR_INVAL);
	CHECK_INT(ui_message_init(&m), UI_OK);
	CHECK_INT(ui_message_get(&m, 100, out, sizeof(out)), 0);
	CHECK_STR(out, "");

	CHECK_INT(ui_message_post(NULL, 100, 5, "x"), UI_ERR_INVAL);
	CHECK_INT(ui_message_post(&m, 100, 5, "hello %d", 42), UI_OK);
	CHECK_INT(ui_message_get(&m, 100, out, sizeof(out)), 1);
	CHECK_STR(out, "hello 42");
	CHECK_INT(ui_message_get(&m, 104, out, sizeof(out)), 1);
	CHECK_INT(ui_message_get(&m, 105, out, sizeof(out)), 0);
	CHECK_STR(out, "");

	/* Minimum lifetime is one second. */
	ui_message_post(&m, 200, 0, "brief");
	CHECK_INT(ui_message_get(&m, 200, out, sizeof(out)), 1);
	CHECK_INT(ui_message_get(&m, 201, out, sizeof(out)), 0);

	/* Truncation to the caller's buffer. */
	ui_message_post(&m, 300, 5, "abcdefgh");
	char small[4];
	CHECK_INT(ui_message_get(&m, 300, small, sizeof(small)), 1);
	CHECK_STR(small, "abc");
	CHECK_INT(ui_message_get(&m, 300, NULL, 4), 0);
	ui_message_destroy(&m);
}

static struct ui_message_s g_m;

static void *poster(void *p)
{
	(void)p;
	for (int i = 0; i < 20000; i++)
		ui_message_post(&g_m, 1000, 5, "message %d from a worker thread", i);
	return NULL;
}

static void test_message_threads(void)
{
	pthread_t t[3];
	char out[UI_MESSAGE_LEN];
	int bad = 0;

	ui_message_init(&g_m);
	for (int i = 0; i < 3; i++)
		pthread_create(&t[i], NULL, poster, NULL);
	for (int i = 0; i < 20000; i++) {
		if (ui_message_get(&g_m, 1000, out, sizeof(out)) &&
			strncmp(out, "message ", 8) != 0)
			bad++;
	}
	for (int i = 0; i < 3; i++)
		pthread_join(t[i], NULL);

	CHECK_INT(bad, 0);
	CHECK_INT(g_m.seq, 60000);
	ui_message_destroy(&g_m);
}

int main(void)
{
	RUN(test_queue_basic);
	RUN(test_queue_overflow);
	RUN(test_queue_threads);
	RUN(test_queue_wait);
	RUN(test_message);
	RUN(test_message_threads);
	return TEST_RESULT();
}
