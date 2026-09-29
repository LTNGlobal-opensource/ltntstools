/* Realtime websocket PCR/PTS/DTS feed + embedded reference dashboard for
 * clock_inspector.
 *
 * One websocket message per real PCR/PTS/DTS tick observed, each carrying
 * that clock's raw ticks and its drift from walltime in ms -- the exact same
 * value already computed for the console's PCR/PTS/DTS "Drift" columns (see
 * clock_inspector_pcr.c / clock_inspector_pes.c). No periodic polling or
 * sampling: ws_notify_pcr()/ws_notify_pts()/ws_notify_dts() are called
 * directly from the packet-processing thread at the exact point each value is
 * computed, so every message corresponds to one real observation. A separate
 * ws_notify_pid_seen() event fires the first time a given (pid, clock) is
 * observed, so the dashboard's picker can populate live.
 *
 * Architecture:
 *  - One pthread (ws_thread_func) runs lws_service() in a loop. libwebsockets
 *    multiplexes any number of concurrent client connections on this single
 *    thread (unlike nic_monitor_rest.c's one-connection-at-a-time raw socket
 *    server).
 *  - There is no separate broadcaster thread: each ws_notify_*() call builds
 *    one small JSON message and pushes it into an lws_ring directly from the
 *    packet-processing thread, for broadcast to every connected client.
 *  - The lws_ring is a multi-consumer (one tail per connection) FIFO. Producing
 *    (the ws_notify_*() calls, from the packet-processing thread) and
 *    consuming (the lws service thread, inside ci_ws_callback) run on
 *    different threads, so all lws_ring_*() calls and the connected-session
 *    list are protected by ci_ws_priv.lock.
 */

#include "clock_inspector_public.h"
#include <libwebsockets.h>
#include <json-c/json.h>

extern int ltnpthread_setname_np(pthread_t thread, const char *name);

/* Generated at build time from clock_inspector_ws_html/index.html (see src/Makefile.am),
 * defines clock_inspector_ws_html_index_html[] / _len.
 */
#include "clock_inspector_ws_html.h"

#define CI_WS_RING_DEPTH 32

/* Defined further down; forward-declared so ci_ws_ring_push() can reference
 * the "clock-inspector" protocol slot without reaching into lws_context internals.
 */
static struct lws_protocols ci_ws_protocols[];

/* One entry in the broadcast ring. .json is heap-owned; freed either when the
 * ring retires it (ci_ws_msg_destroy) or, if lws_ring_insert() couldn't accept
 * it (ring full), immediately by the producer.
 */
struct ci_ws_msg {
	char *json;
	size_t len;
};

/* Per-connection state for the "clock-inspector" websocket protocol. */
struct ci_ws_session {
	struct ci_ws_session *next; /* intrusive singly-linked list, see ci_ws_priv.sessionList */
	uint32_t tail;
	int helloSent;
};

/* Per-connection state for the "http" (dashboard page) protocol. */
struct ci_http_session {
	size_t bodyOffset;
};

struct ci_ws_priv {
	struct lws_context *context;
	struct lws_ring *ring;             /* elements are struct ci_ws_msg */
	pthread_mutex_t lock;              /* guards ring + sessionList, see file header */
	struct ci_ws_session *sessionList;
};

static void ci_ws_msg_destroy(void *element)
{
	struct ci_ws_msg *m = element;
	free(m->json);
	m->json = NULL;
}

/* Takes ownership of `json` (must be a malloc()'d buffer). Frees it either by
 * handing it to the ring, or immediately if the ring is full (all consumers
 * already caught up to the ring's capacity, or nobody is connected yet).
 */
static void ci_ws_ring_push(struct tool_context_s *ctx, char *json, size_t len)
{
	struct ci_ws_priv *priv = ctx->ws_priv;
	struct ci_ws_msg m = { .json = json, .len = len };

	pthread_mutex_lock(&priv->lock);
	size_t inserted = lws_ring_insert(priv->ring, &m, 1);
	pthread_mutex_unlock(&priv->lock);

	if (inserted == 0) {
		/* Ring full -- drop this tick's message, the next one supersedes it. */
		free(json);
		return;
	}

	lws_callback_on_writable_all_protocol(priv->context, &ci_ws_protocols[1]);
}

static char *ci_ws_json_to_owned_string(json_object *obj)
{
	const char *s = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN);
	char *dup = s ? strdup(s) : NULL;
	json_object_put(obj);
	return dup;
}

/* Sent once per new connection: the full current picture (every pid with an
 * active PCR/PTS/DTS clock right now), so a client connecting mid-stream sees
 * everything already known. ws_notify_pid_seen() below keeps this up to date
 * live for already-connected clients as new pids/clocks appear afterward.
 * Scanning all 8192 pid slots is a one-time per-connection cost, not a
 * per-message one -- fine even though most slots are unused.
 */
static json_object *ci_ws_build_hello(struct tool_context_s *ctx)
{
	char hex[8];
	snprintf(hex, sizeof(hex), "0x%04x", ctx->scr_pid);

	json_object *root = json_object_new_object();
	json_object_object_add(root, "type", json_object_new_string("hello"));
	json_object_object_add(root, "version", json_object_new_string(GIT_VERSION));
	json_object_object_add(root, "streamName", json_object_new_string(ctx->iname ? ctx->iname : ""));
	json_object_object_add(root, "scrPid", json_object_new_int(ctx->scr_pid));
	json_object_object_add(root, "scrPidHex", json_object_new_string(hex));

	json_object *pids = json_object_new_array();
	json_object_object_add(root, "pids", pids);

	for (int i = 0; i <= 0x1fff; i++) {
		struct pid_s *p = &ctx->pids[i];

		pthread_mutex_lock(&p->clockLock);
		int hasPcr = (i == ctx->scr_pid) && p->scr_updateCount > 0;
		int hasPts = p->clk_pts_initialized;
		int hasDts = p->clk_dts_initialized;
		pthread_mutex_unlock(&p->clockLock);

		if (!hasPcr && !hasPts && !hasDts)
			continue;

		char pidHex[8];
		snprintf(pidHex, sizeof(pidHex), "0x%04x", i);

		json_object *item = json_object_new_object();
		json_object_object_add(item, "pid", json_object_new_int(i));
		json_object_object_add(item, "pidHex", json_object_new_string(pidHex));
		json_object_object_add(item, "hasPcr", json_object_new_boolean(hasPcr));
		json_object_object_add(item, "hasPts", json_object_new_boolean(hasPts));
		json_object_object_add(item, "hasDts", json_object_new_boolean(hasDts));
		json_object_array_add(pids, item);
	}

	return root;
}

/* Shared by ws_notify_pcr/pts/dts. driftMs is the same kind of quantity for all
 * three (drift from walltime in ms). intervalMs is the time since this pid's
 * previous tick of this same clock; negative means "no prior tick yet",
 * encoded as JSON null so the histogram chart doesn't mistake it for a real
 * (and wildly wrong) first-sample interval. Returns the still-open json_object
 * so ws_notify_pts()/ws_notify_dts() can add their extra "scrDriftMs" field
 * before it's serialized and sent.
 */
static json_object *ci_ws_build_clock_msg(const char *type, uint16_t pid,
	int64_t ticks, int64_t driftMs, double intervalMs, struct timeval ts)
{
	json_object *root = json_object_new_object();
	json_object_object_add(root, "type", json_object_new_string(type));
	json_object_object_add(root, "tsUnixMs",
		json_object_new_int64((int64_t)ts.tv_sec * 1000 + ts.tv_usec / 1000));
	json_object_object_add(root, "pid", json_object_new_int(pid));
	json_object_object_add(root, "ticks", json_object_new_int64(ticks));
	json_object_object_add(root, "driftMs", json_object_new_int64(driftMs));
	json_object_object_add(root, "intervalMs", intervalMs >= 0 ? json_object_new_double(intervalMs) : NULL);
	return root;
}

static void ci_ws_send(struct tool_context_s *ctx, json_object *root)
{
	char *json = ci_ws_json_to_owned_string(root);
	if (json)
		ci_ws_ring_push(ctx, json, strlen(json));
}

/* Called directly from processSCRStats() for each SCR tick observed on
 * ctx->scr_pid. One call in, at most one websocket message out -- no
 * sampling, no aliasing.
 */
void ws_notify_pcr(struct tool_context_s *ctx, uint16_t pid, uint64_t ticks27MHz,
	int64_t driftMs, double intervalMs, struct timeval ts)
{
	if (ctx->ws_port <= 0 || !ctx->ws_priv)
		return;
	ci_ws_send(ctx, ci_ws_build_clock_msg("pcr", pid, (int64_t)ticks27MHz, driftMs, intervalMs, ts));
}

/* Called directly from processPESHeader() for each PTS/DTS observed, reusing
 * the exact same ptsWalltimeDriftMs/dtsWalltimeDriftMs, pts_diff_ticks/
 * dts_diff_ticks, and d_pts_minus_scr_ticks/d_dts_minus_scr_ticks already
 * computed for the console report.
 */
void ws_notify_pts(struct tool_context_s *ctx, uint16_t pid, int64_t ticks90k,
	int64_t driftMs, double intervalMs, int haveScrDriftMs, double scrDriftMs, struct timeval ts)
{
	if (ctx->ws_port <= 0 || !ctx->ws_priv)
		return;
	json_object *root = ci_ws_build_clock_msg("pts", pid, ticks90k, driftMs, intervalMs, ts);
	json_object_object_add(root, "scrDriftMs", haveScrDriftMs ? json_object_new_double(scrDriftMs) : NULL);
	ci_ws_send(ctx, root);
}

void ws_notify_dts(struct tool_context_s *ctx, uint16_t pid, int64_t ticks90k,
	int64_t driftMs, double intervalMs, int haveScrDriftMs, double scrDriftMs, struct timeval ts)
{
	if (ctx->ws_port <= 0 || !ctx->ws_priv)
		return;
	json_object *root = ci_ws_build_clock_msg("dts", pid, ticks90k, driftMs, intervalMs, ts);
	json_object_object_add(root, "scrDriftMs", haveScrDriftMs ? json_object_new_double(scrDriftMs) : NULL);
	ci_ws_send(ctx, root);
}

void ws_notify_pid_seen(struct tool_context_s *ctx, uint16_t pid, const char *clockType)
{
	if (ctx->ws_port <= 0 || !ctx->ws_priv)
		return;

	char hex[8];
	snprintf(hex, sizeof(hex), "0x%04x", pid);

	json_object *root = json_object_new_object();
	json_object_object_add(root, "type", json_object_new_string("pid_seen"));
	json_object_object_add(root, "pid", json_object_new_int(pid));
	json_object_object_add(root, "pidHex", json_object_new_string(hex));
	json_object_object_add(root, "clock", json_object_new_string(clockType));

	char *json = ci_ws_json_to_owned_string(root);
	if (json)
		ci_ws_ring_push(ctx, json, strlen(json));
}

/* Writes a heap-owned JSON string directly to one connection (used for the
 * one-time per-connection hello, which bypasses the broadcast ring). Frees `json`.
 */
static int ci_ws_write_owned_string(struct lws *wsi, char *json, size_t len)
{
	if (!json)
		return -1;

	unsigned char *buf = malloc(LWS_PRE + len);
	if (!buf) {
		free(json);
		return -1;
	}
	memcpy(buf + LWS_PRE, json, len);
	free(json);

	int n = lws_write(wsi, buf + LWS_PRE, len, LWS_WRITE_TEXT);
	free(buf);
	return (n < 0 || (size_t)n < len) ? -1 : 0;
}

static int ci_ws_callback(struct lws *wsi, enum lws_callback_reasons reason,
	void *user, void *in, size_t len)
{
	struct ci_ws_session *pss = user;
	struct tool_context_s *ctx = lws_context_user(lws_get_context(wsi));
	struct ci_ws_priv *priv = ctx ? ctx->ws_priv : NULL;

	switch (reason) {
	case LWS_CALLBACK_ESTABLISHED:
		pss->helloSent = 0;
		pthread_mutex_lock(&priv->lock);
		pss->next = priv->sessionList;
		priv->sessionList = pss;
		pss->tail = lws_ring_get_oldest_tail(priv->ring);
		pthread_mutex_unlock(&priv->lock);
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		if (!pss->helloSent) {
			pss->helloSent = 1;
			char *hello = ci_ws_json_to_owned_string(ci_ws_build_hello(ctx));
			if (hello)
				ci_ws_write_owned_string(wsi, hello, strlen(hello));
			lws_callback_on_writable(wsi); /* drain any ring backlog next */
			break;
		}

		{
			int haveMore = 0;
			unsigned char *buf = NULL;
			size_t bufLen = 0;

			pthread_mutex_lock(&priv->lock);
			const struct ci_ws_msg *m = lws_ring_get_element(priv->ring, &pss->tail);
			if (m) {
				buf = malloc(LWS_PRE + m->len);
				if (buf) {
					memcpy(buf + LWS_PRE, m->json, m->len);
					bufLen = m->len;
				}
				lws_ring_consume_and_update_oldest_tail(priv->ring, struct ci_ws_session,
					&pss->tail, 1, priv->sessionList, tail, next);
				haveMore = lws_ring_get_count_waiting_elements(priv->ring, &pss->tail) > 0;
			}
			pthread_mutex_unlock(&priv->lock);

			if (buf) {
				lws_write(wsi, buf + LWS_PRE, bufLen, LWS_WRITE_TEXT);
				free(buf);
			}
			if (haveMore)
				lws_callback_on_writable(wsi);
		}
		break;

	case LWS_CALLBACK_CLOSED:
		pthread_mutex_lock(&priv->lock);
		{
			struct ci_ws_session **pp = &priv->sessionList;
			while (*pp) {
				if (*pp == pss) {
					*pp = pss->next;
					break;
				}
				pp = &(*pp)->next;
			}
		}
		pthread_mutex_unlock(&priv->lock);
		break;

	case LWS_CALLBACK_RECEIVE:
		/* No client->server control messages defined yet; ignore any input. */
		break;

	default:
		break;
	}

	return 0;
}

static int ci_http_callback(struct lws *wsi, enum lws_callback_reasons reason,
	void *user, void *in, size_t len)
{
	struct ci_http_session *pss = user;

	switch (reason) {
	case LWS_CALLBACK_HTTP:
	{
		unsigned char headers[LWS_PRE + 512];
		unsigned char *start = &headers[LWS_PRE];
		unsigned char *p = start;
		unsigned char *end = &headers[sizeof(headers) - 1];

		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK, "text/html",
				clock_inspector_ws_html_index_html_len, &p, end))
			return -1;
		if (lws_finalize_write_http_header(wsi, start, &p, end))
			return -1;

		pss->bodyOffset = 0;
		lws_callback_on_writable(wsi);
		return 0;
	}

	case LWS_CALLBACK_HTTP_WRITEABLE:
	{
		size_t remain = clock_inspector_ws_html_index_html_len - pss->bodyOffset;
		if (remain == 0)
			return lws_http_transaction_completed(wsi);

		size_t chunk = remain > 4096 ? 4096 : remain;
		unsigned char buf[LWS_PRE + 4096];
		memcpy(buf + LWS_PRE, clock_inspector_ws_html_index_html + pss->bodyOffset, chunk);

		int isFinal = (pss->bodyOffset + chunk) == clock_inspector_ws_html_index_html_len;
		int n = lws_write(wsi, buf + LWS_PRE, chunk, isFinal ? LWS_WRITE_HTTP_FINAL : LWS_WRITE_HTTP);
		if (n < 0)
			return -1;

		pss->bodyOffset += n;
		if (pss->bodyOffset < clock_inspector_ws_html_index_html_len) {
			lws_callback_on_writable(wsi);
			return 0;
		}
		if (isFinal)
			return lws_http_transaction_completed(wsi);
		return 0;
	}

	default:
		break;
	}

	return 0;
}

static struct lws_protocols ci_ws_protocols[] = {
	{ "http", ci_http_callback, sizeof(struct ci_http_session), 0, 0, NULL, 0 },
	{ "clock-inspector", ci_ws_callback, sizeof(struct ci_ws_session), 4096, 1, NULL, 0 },
	{ NULL, NULL, 0, 0, 0, NULL, 0 }
};

int ws_initialize(struct tool_context_s *ctx)
{
	if (ctx->ws_port <= 0)
		return 0;

	/* Keep libwebsockets' own logging out of this tool's console reports; only
	 * surface genuine errors/warnings from the websocket layer.
	 */
	lws_set_log_level(LLL_ERR | LLL_WARN, NULL);

	struct ci_ws_priv *priv = calloc(1, sizeof(*priv));
	if (!priv)
		return -1;

	pthread_mutex_init(&priv->lock, NULL);
	priv->ring = lws_ring_create(sizeof(struct ci_ws_msg), CI_WS_RING_DEPTH, ci_ws_msg_destroy);
	if (!priv->ring) {
		free(priv);
		return -1;
	}

	struct lws_context_creation_info info;
	memset(&info, 0, sizeof(info));
	info.port = ctx->ws_port;
	info.protocols = ci_ws_protocols;
	info.gid = -1;
	info.uid = -1;
	info.user = ctx;
	/* No .options / SSL fields set: plain ws:// and http:// only. */

	priv->context = lws_create_context(&info);
	if (!priv->context) {
		lws_ring_destroy(priv->ring);
		free(priv);
		return -1;
	}

	ctx->ws_priv = priv;
	return 0;
}

void ws_interrupt(struct tool_context_s *ctx)
{
	struct ci_ws_priv *priv = ctx->ws_priv;
	if (priv && priv->context)
		lws_cancel_service(priv->context);
}

void ws_free(struct tool_context_s *ctx)
{
	struct ci_ws_priv *priv = ctx->ws_priv;
	if (!priv)
		return;

	if (priv->context)
		lws_context_destroy(priv->context);
	if (priv->ring)
		lws_ring_destroy(priv->ring); /* frees any still-buffered .json via ci_ws_msg_destroy */
	pthread_mutex_destroy(&priv->lock);
	free(priv);
	ctx->ws_priv = NULL;
}

void *ws_thread_func(void *tool_context)
{
	struct tool_context_s *ctx = tool_context;
	struct ci_ws_priv *priv = ctx->ws_priv;

	ltnpthread_setname_np(ctx->ws_threadId, "tstools-ws");

	while (!__atomic_load_n(&ctx->ws_threadTerminate, __ATOMIC_RELAXED)) {
		lws_service(priv->context, 50);
	}

	ctx->ws_threadTerminated = 1;
	return NULL;
}
