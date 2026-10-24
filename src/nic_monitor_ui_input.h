#ifndef NIC_MONITOR_UI_INPUT_H
#define NIC_MONITOR_UI_INPUT_H

/* Thread-safe hand-off between the main (keyboard) thread, worker threads
 * and the UI thread. No curses dependency.
 *
 * Both structures use their own mutex as a leaf lock: no other lock is
 * taken while it is held, so they may be used from any thread, including
 * while the caller holds ctx->lock or ui_threadLock.
 */

#include <stdint.h>
#include <time.h>
#include <pthread.h>

#include "nic_monitor_ui_buf.h"

/* Events from the main thread to the UI thread: navigation keys and mouse
 * events. Fixed size; when full, the oldest event is dropped and counted.
 */
#define UI_EVENT_QUEUE_LEN 32

enum ui_event_type_e
{
	UI_EVENT_KEY = 1,
	UI_EVENT_MOUSE,
	UI_EVENT_REDRAW,    /* Something changed (a command ran, the terminal resized): draw now */
};

/* Mouse buttons, translated from curses bstate by the main thread so the
 * UI thread doesn't depend on the curses mouse ABI version.
 */
#define UI_MOUSE_CLICK       (1 << 0)
#define UI_MOUSE_WHEEL_UP    (1 << 1)
#define UI_MOUSE_WHEEL_DOWN  (1 << 2)

struct ui_event_s
{
	enum ui_event_type_e type;
	uint64_t timeMs;    /* Monotonic, stamped when posted (double-click timing) */
	int key;            /* UI_EVENT_KEY: curses key code */
	int y, x;           /* UI_EVENT_MOUSE: screen position */
	unsigned int buttons; /* UI_EVENT_MOUSE: UI_MOUSE_* */
};

struct ui_event_queue_s
{
	pthread_mutex_t lock;
	pthread_cond_t cond;  /* Signalled on every post, for ui_event_queue_wait() */
	struct ui_event_s ev[UI_EVENT_QUEUE_LEN];
	int head;           /* Oldest event */
	int count;
	uint64_t dropped;
};

int  ui_event_queue_init(struct ui_event_queue_s *q);
void ui_event_queue_destroy(struct ui_event_queue_s *q);

/* Returns UI_OK, or UI_ERR_FULL when the oldest event was dropped to make
 * room (the new event is still queued). UI_ERR_INVAL on NULL arguments.
 */
int  ui_event_queue_post(struct ui_event_queue_s *q, const struct ui_event_s *ev);

/* Waits until an event is queued or timeoutMs passes. Returns the number of
 * queued events (0 on timeout). Does not remove them.
 */
int  ui_event_queue_wait(struct ui_event_queue_s *q, int timeoutMs);

/* Moves up to `max` events, oldest first, into out[]. Returns the count. */
int  ui_event_queue_drain(struct ui_event_queue_s *q, struct ui_event_s *out, int max);

uint64_t ui_event_queue_dropped(struct ui_event_queue_s *q);

/* The single-line MESSAGE area: the most recent message wins and expires
 * after a number of seconds.
 */
#define UI_MESSAGE_LEN 256

struct ui_message_s
{
	pthread_mutex_t lock;
	char text[UI_MESSAGE_LEN];
	time_t expires;     /* 0 = no message */
	uint64_t seq;       /* Incremented per post */
};

int  ui_message_init(struct ui_message_s *m);
void ui_message_destroy(struct ui_message_s *m);

/* Posts a message for `seconds` (minimum 1). Safe from any thread. */
int  ui_message_post(struct ui_message_s *m, time_t now, int seconds, const char *fmt, ...)
	__attribute__((format(printf, 4, 5)));

/* Copies the current message into out (NUL terminated). Returns 1 when a
 * message is active at `now`, else 0 (out is set to "").
 */
int  ui_message_get(struct ui_message_s *m, time_t now, char *out, size_t outSize);

#endif /* NIC_MONITOR_UI_INPUT_H */
