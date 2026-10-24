#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/time.h>

#include "nic_monitor_ui_input.h"

int ui_event_queue_init(struct ui_event_queue_s *q)
{
	if (!q)
		return UI_ERR_INVAL;

	memset(q, 0, sizeof(*q));
	if (pthread_mutex_init(&q->lock, NULL) != 0)
		return UI_ERR_NOMEM;
	if (pthread_cond_init(&q->cond, NULL) != 0) {
		pthread_mutex_destroy(&q->lock);
		return UI_ERR_NOMEM;
	}

	return UI_OK;
}

void ui_event_queue_destroy(struct ui_event_queue_s *q)
{
	if (q) {
		pthread_cond_destroy(&q->cond);
		pthread_mutex_destroy(&q->lock);
	}
}

int ui_event_queue_wait(struct ui_event_queue_s *q, int timeoutMs)
{
	if (!q)
		return 0;

	/* CLOCK_REALTIME deadline: macOS has no pthread_condattr_setclock().
	 * A wall-clock step can only lengthen or shorten one wait.
	 */
	struct timeval now;
	gettimeofday(&now, NULL);
	struct timespec deadline;
	long nsec = now.tv_usec * 1000L + (long)(timeoutMs % 1000) * 1000000L;
	deadline.tv_sec = now.tv_sec + timeoutMs / 1000 + nsec / 1000000000L;
	deadline.tv_nsec = nsec % 1000000000L;

	pthread_mutex_lock(&q->lock);
	while (q->count == 0) {
		/* Spurious wakeups loop back to re-check the predicate. */
		if (pthread_cond_timedwait(&q->cond, &q->lock, &deadline) == ETIMEDOUT)
			break;
	}
	int n = q->count;
	pthread_mutex_unlock(&q->lock);

	return n;
}

int ui_event_queue_post(struct ui_event_queue_s *q, const struct ui_event_s *ev)
{
	if (!q || !ev)
		return UI_ERR_INVAL;

	int ret = UI_OK;

	pthread_mutex_lock(&q->lock);
	if (q->count == UI_EVENT_QUEUE_LEN) {
		q->head = (q->head + 1) % UI_EVENT_QUEUE_LEN;
		q->count--;
		q->dropped++;
		ret = UI_ERR_FULL;
	}
	q->ev[(q->head + q->count) % UI_EVENT_QUEUE_LEN] = *ev;
	q->count++;
	pthread_cond_signal(&q->cond);
	pthread_mutex_unlock(&q->lock);

	return ret;
}

int ui_event_queue_drain(struct ui_event_queue_s *q, struct ui_event_s *out, int max)
{
	if (!q || !out || max <= 0)
		return 0;

	pthread_mutex_lock(&q->lock);
	int n = q->count < max ? q->count : max;
	for (int i = 0; i < n; i++) {
		out[i] = q->ev[q->head];
		q->head = (q->head + 1) % UI_EVENT_QUEUE_LEN;
	}
	q->count -= n;
	pthread_mutex_unlock(&q->lock);

	return n;
}

uint64_t ui_event_queue_dropped(struct ui_event_queue_s *q)
{
	if (!q)
		return 0;

	pthread_mutex_lock(&q->lock);
	uint64_t d = q->dropped;
	pthread_mutex_unlock(&q->lock);

	return d;
}

int ui_message_init(struct ui_message_s *m)
{
	if (!m)
		return UI_ERR_INVAL;

	memset(m, 0, sizeof(*m));
	if (pthread_mutex_init(&m->lock, NULL) != 0)
		return UI_ERR_NOMEM;

	return UI_OK;
}

void ui_message_destroy(struct ui_message_s *m)
{
	if (m)
		pthread_mutex_destroy(&m->lock);
}

int ui_message_post(struct ui_message_s *m, time_t now, int seconds, const char *fmt, ...)
{
	if (!m || !fmt)
		return UI_ERR_INVAL;

	if (seconds < 1)
		seconds = 1;

	char tmp[UI_MESSAGE_LEN];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(tmp, sizeof(tmp), fmt, ap);
	va_end(ap);

	pthread_mutex_lock(&m->lock);
	memcpy(m->text, tmp, sizeof(m->text));
	m->expires = now + seconds;
	m->seq++;
	pthread_mutex_unlock(&m->lock);

	return UI_OK;
}

int ui_message_get(struct ui_message_s *m, time_t now, char *out, size_t outSize)
{
	if (!m || !out || outSize == 0)
		return 0;

	int active = 0;

	pthread_mutex_lock(&m->lock);
	if (m->expires && now < m->expires) {
		snprintf(out, outSize, "%s", m->text);
		active = 1;
	}
	pthread_mutex_unlock(&m->lock);

	if (!active)
		out[0] = 0;

	return active;
}
