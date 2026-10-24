
#include <stdio.h>
#include <stdarg.h>
#include <sys/resource.h>

#include "nic_monitor.h"
#include "nic_monitor_ui_screen.h"

/* Reduce this to 4 * 32768 to simulate loss on a NIC with 600Mbps */
/* Tuned to 64MB to support 2Gb/ps */
static int g_buffer_size_default = (64 * 1024 * 1024);
static int g_snaplen_default =
#ifdef __linux__
	BUFSIZ
#endif
#ifdef __APPLE__
	65535
#endif
;

static int gRunning = 0;
static int gQuitRequested = 0; /* Atomic. 'q' from the main or UI thread; ends the main loop. */

static struct tool_context_s g_ctx = { 0 };
static struct tool_context_s *ctx = &g_ctx;
static int g_max_iat_ms = 45;

#if defined(__linux__)
extern int pthread_setname_np(pthread_t thread, const char *name);
#endif

extern int ltnpthread_setname_np(pthread_t thread, const char *name);

static int igmp_joins_start(struct tool_context_s *ctx)
{
	for (int i = 0; i < ctx->igmpJoinCount; i++) {
		int ret = ltntstools_igmp_join(&ctx->igmpJoinHandle[i],
			ctx->igmpJoinAddress[i].address,
			ctx->igmpJoinAddress[i].port,
			ctx->ifname);
		if (ret < 0) {
			fprintf(stderr, "Unable to join address %s:%u on %s, aborting\n",
				ctx->igmpJoinAddress[i].address,
				ctx->igmpJoinAddress[i].port,
				ctx->ifname);
			return -1;
		}
	}

	return 0;
}

static void igmp_joins_stop(struct tool_context_s *ctx)
{
	for (int i = 0; i < ctx->igmpJoinCount; i++) {
		if (ctx->igmpJoinHandle[i]) {
			ltntstools_igmp_drop(ctx->igmpJoinHandle[i]);
			ctx->igmpJoinHandle[i] = NULL;
		}
	}
}

/* Seeing some crashes inside getch, five leves deep related to dorefresh
 * in ncurses. Make sure we don't call getch without ensuring
 * the ui thread isn't refreshing the display. The lock is held only for
 * the call itself; getch() is non-blocking (nodelay), so the UI thread is
 * never kept waiting for a key.
 */
static int ui_syncronized_getch(struct tool_context_s *ctx)
{
	pthread_mutex_lock(&ctx->ui_threadLock);
	int c = getch();
	pthread_mutex_unlock(&ctx->ui_threadLock);

	return c;
}

#if MEASURE_PCAP_CALLBACK_PERFORMANCE
extern int pcap_cb_intervals_reset;
#endif

static void stats_reset(struct tool_context_s *ctx)
{
	time(&ctx->lastResetTime);
	discovered_items_stats_reset(ctx);
	if (ctx->procNetUDPContext) {
		ltntstools_proc_net_udp_items_reset_drops(ctx->procNetUDPContext);
	}
#if MEASURE_PCAP_CALLBACK_PERFORMANCE
	pcap_cb_intervals_reset = 1;
#endif
}

static void ui_mouse_set(struct tool_context_s *ctx, int enable)
{
	pthread_mutex_lock(&ctx->ui_threadLock);
	if (enable) {
#if NCURSES_MOUSE_VERSION > 1
		mousemask(ALL_MOUSE_EVENTS, NULL);
#else
		/* Mouse ABI 1 (e.g. the macOS SDK ncurses) has no button 5: it
		 * reports wheel-down as REPORT_MOUSE_POSITION, and drops it unless
		 * that bit is in the mask.
		 */
		mousemask(ALL_MOUSE_EVENTS | REPORT_MOUSE_POSITION, NULL);
#endif
		mouseinterval(0); /* Report presses immediately, no click detection delay. */
	} else {
		mousemask(0, NULL);
	}
	pthread_mutex_unlock(&ctx->ui_threadLock);

	__atomic_store_n(&ctx->uiMouseEnabled, enable, __ATOMIC_RELEASE);
}

static void ui_post(struct tool_context_s *ctx, int seconds, const char *fmt, ...)
	__attribute__((format(printf, 3, 4)));

static void ui_post(struct tool_context_s *ctx, int seconds, const char *fmt, ...)
{
	char msg[UI_MESSAGE_LEN];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);

	ui_message_post(&ctx->uiMessage, time(NULL), seconds, "%s", msg);
}

/* Runs a per-stream command against the tagged streams, or the cursor stream. */
static void ui_stream_command(struct tool_context_s *ctx, void (*fn)(struct tool_context_s *), const char *what)
{
	int n = discovered_items_target_count(ctx);
	if (n == 0) {
		ui_post(ctx, 4, "No stream under the cursor: use Up/Down to choose one");
		return;
	}
	fn(ctx);
	ui_post(ctx, 3, "%s: %d stream%s", what, n, n == 1 ? "" : "s");
}

int nic_monitor_ui_command(struct tool_context_s *ctx, int key)
{
	/* 'F' was pressed: the next key picks a destination or cancels. */
	if (__atomic_load_n(&ctx->showForwardOptions, __ATOMIC_ACQUIRE)) {
		if (key == '7' || key == '8' || key == '9') {
			int n = discovered_items_target_count(ctx);
			discovered_items_select_forward_toggle(ctx, key - '0');
			__atomic_store_n(&ctx->showForwardOptions, 0, __ATOMIC_RELEASE);
			ui_post(ctx, 3, "Forwarding toggled to %s: %d stream%s",
				ctx->url_forwards[key - '7'].uilabel, n, n == 1 ? "" : "s");
			return 1;
		}
		if (key == 'q' || key == 27) {
			__atomic_store_n(&ctx->showForwardOptions, 0, __ATOMIC_RELEASE);
			ui_post(ctx, 2, "Forwarding cancelled");
			return 1;
		}
		return 1; /* Swallow other keys while the prompt is up. */
	}

	switch (key) {
	case 'q':
	case KEY_F(10):
		__atomic_store_n(&gQuitRequested, 1, __ATOMIC_RELEASE);
		return 1;
	case 'f': {
		int v = __atomic_add_fetch(&ctx->freezeDisplay, 1, __ATOMIC_RELAXED);
		if ((v & 1) == 0)
			ui_post(ctx, 2, "Display resumed");
		return 1;
	}
	case 'r':
		stats_reset(ctx);
		ui_post(ctx, 3, "Statistics reset");
		return 1;
	case 'C': ui_stream_command(ctx, discovered_items_select_show_clocks_toggle, "Clock report toggled"); return 1;
	case 'T': ui_stream_command(ctx, discovered_items_select_show_tr101290_toggle, "TR101290 report toggled"); return 1;
	case 'R': ui_stream_command(ctx, discovered_items_select_record_toggle, "Recording toggled"); return 1;
	case 's': ui_stream_command(ctx, discovered_items_select_show_processes_toggle, "Socket/process report toggled"); return 1;
	case 'P': ui_stream_command(ctx, discovered_items_select_show_pids_toggle, "PID report toggled"); return 1;
	case 'I': ui_stream_command(ctx, discovered_items_select_show_iats_toggle, "IAT histogram toggled"); return 1;
	case 'J': ui_stream_command(ctx, discovered_items_select_json_probe_toggle, "JSON probe toggled"); return 1;
	case 'L': ui_stream_command(ctx, discovered_items_select_show_stream_log_toggle, "Stream log toggled"); return 1;
	case 'H': ui_stream_command(ctx, discovered_items_select_hide, "Hidden (recording streams stay visible)"); return 1;
	case 'M': ui_stream_command(ctx, discovered_items_select_show_streammodel_toggle, "PSIP model report toggled"); return 1;
	case '3': ui_stream_command(ctx, discovered_items_select_scte35_toggle, "SCTE-35 report toggled"); return 1;
	case 'U':
		discovered_items_unhide_all(ctx);
		ui_post(ctx, 3, "All streams unhidden");
		return 1;
	case 'S':
		discovered_items_tag_all(ctx);
		ui_post(ctx, 3, "All streams tagged: commands now act on every stream (D or Esc clears)");
		return 1;
	case 'D':
		discovered_items_tag_none(ctx);
		ui_post(ctx, 3, "Tags cleared");
		return 1;
	case ' ': {
		int r = discovered_items_tag_toggle_id(ctx, __atomic_load_n(&ctx->uiCursorId, __ATOMIC_ACQUIRE));
		if (r >= 0)
			ui_post(ctx, 2, "Stream %s", r ? "tagged" : "untagged");
		return 1;
	}
	case 'F':
		if (discovered_items_target_count(ctx) == 0) {
			ui_post(ctx, 4, "No stream under the cursor: use Up/Down to choose one");
		} else {
			__atomic_store_n(&ctx->showForwardOptions, 1, __ATOMIC_RELEASE);
		}
		return 1;
	case '$':
		ctx->recordAsTS = (ctx->recordAsTS + 1) & 0x1;
		ui_post(ctx, 3, "Record format: %s", ctx->recordAsTS ? "MPEG-TS" : "PCAP");
		return 1;
	case '@':
		ctx->recordWithSegments = (ctx->recordWithSegments + 1) & 0x1;
		ui_post(ctx, 3, "Record mode: %s", ctx->recordWithSegments ? "Segments" : "Single File");
		return 1;
	case 'm': {
		int on = !__atomic_load_n(&ctx->uiMouseEnabled, __ATOMIC_ACQUIRE);
		ui_mouse_set(ctx, on);
		ui_post(ctx, 4, on ? "Mouse on: hold Shift (Option in some macOS terminals) to select text, m to turn off"
			: "Mouse off: drag selects text, m to turn on");
		return 1;
	}
	default:
		return 0;
	}
}

/* Reads every pending key (main thread). Navigation goes to the UI thread,
 * commands run here.
 */
/* Wake the UI thread to redraw now, after a command or a resize. */
static void ui_post_redraw(struct tool_context_s *ctx)
{
	struct ui_event_s ev = { .type = UI_EVENT_REDRAW };
	ui_event_queue_post(&ctx->uiEvents, &ev);
}

static void ui_process_input(struct tool_context_s *ctx)
{
	/* NIC_MONITOR_INPUT_LOG=/path: log every key code and mouse event, to
	 * diagnose what a terminal actually sends.
	 */
	static FILE *inputLog = NULL;
	static int inputLogChecked = 0;
	if (!inputLogChecked) {
		inputLogChecked = 1;
		const char *path = getenv("NIC_MONITOR_INPUT_LOG");
		if (path)
			inputLog = fopen(path, "a");
	}

	int c;
	while ((c = ui_syncronized_getch(ctx)) != ERR) {
		if (inputLog) {
			fprintf(inputLog, "%ld key %d (0x%x)%s%s\n", (long)time(NULL), c, c,
				c == KEY_MOUSE ? " KEY_MOUSE" : "", c == KEY_RESIZE ? " KEY_RESIZE" : "");
			fflush(inputLog);
		}
		if (c == KEY_RESIZE) {
			/* resizeterm() already ran inside getch(); wake the UI
			 * thread to lay out and draw at the new size.
			 */
			ui_post_redraw(ctx);
			continue;
		}
		if (c == KEY_MOUSE) {
			MEVENT me;
			pthread_mutex_lock(&ctx->ui_threadLock);
			int ret = getmouse(&me);
			pthread_mutex_unlock(&ctx->ui_threadLock);
			if (inputLog) {
				fprintf(inputLog, "%ld   getmouse %s y %d x %d bstate 0x%lx\n", (long)time(NULL),
					ret == OK ? "OK" : "ERR", me.y, me.x, (unsigned long)me.bstate);
				fflush(inputLog);
			}
			if (ret != OK)
				continue;

			struct timespec ts;
			clock_gettime(CLOCK_MONOTONIC, &ts);
			struct ui_event_s ev = { .type = UI_EVENT_MOUSE, .y = me.y, .x = me.x,
				.timeMs = (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000 };
			if (me.bstate & (BUTTON1_PRESSED | BUTTON1_CLICKED))
				ev.buttons |= UI_MOUSE_CLICK;
			if (me.bstate & BUTTON4_PRESSED)
				ev.buttons |= UI_MOUSE_WHEEL_UP;
#if NCURSES_MOUSE_VERSION > 1
			if (me.bstate & BUTTON5_PRESSED)
				ev.buttons |= UI_MOUSE_WHEEL_DOWN;
#else
			/* Mode 1000 reports no motion, so with ABI 1 this is wheel-down. */
			if (me.bstate == REPORT_MOUSE_POSITION)
				ev.buttons |= UI_MOUSE_WHEEL_DOWN;
#endif
			if (ev.buttons)
				ui_event_queue_post(&ctx->uiEvents, &ev);
			continue;
		}
		if (c == 27) {
			/* A lone Esc arrives by itself. Esc followed immediately by more
			 * bytes is an escape sequence ncurses didn't recognise (wrong
			 * TERM, unusual terminal): discard it rather than run its
			 * trailing letters as commands, e.g. "ESC [ H" would hide streams.
			 */
			int next = ui_syncronized_getch(ctx);
			if (next != ERR) {
				int n = 0;
				while (next != ERR && n++ < 16)
					next = ui_syncronized_getch(ctx);
				continue;
			}
		}
		if (__atomic_load_n(&ctx->showForwardOptions, __ATOMIC_ACQUIRE)) {
			nic_monitor_ui_command(ctx, c);
			ui_post_redraw(ctx);
			continue;
		}
		if (nic_monitor_ui_is_ui_key(c)) {
			struct ui_event_s ev = { .type = UI_EVENT_KEY, .key = c };
			ui_event_queue_post(&ctx->uiEvents, &ev);
			continue;
		}
		if (nic_monitor_ui_command(ctx, c))
			ui_post_redraw(ctx);
	}
}

static void *json_thread_func(void *p)
{
	struct tool_context_s *ctx = p;
	ctx->json_threadRunning = 1;
	ctx->json_threadTerminate = 0;
	ctx->json_threadTerminated = 0;

	ltnpthread_setname_np(ctx->json_threadId, "tstools-json");
	pthread_detach(pthread_self());

	time_t now;
	time(&now);
	if (ctx->json_next_write_time == 0) {
		ctx->json_next_write_time = now + ctx->json_write_interval;
	}

	int json_post_interval = 1; /* Seconds */
	time_t json_next_post_time = 0;

	int workdone = 0;
	while (!ctx->json_threadTerminate) {

		workdone = 0;

		time(&now);
		if (json_next_post_time <= now) {
			json_next_post_time = now + json_post_interval;

			/* Look at the queue, take everything off it, issue http post reqs. */
			int failed = 0;
			struct json_item_s *item = json_queue_peek(ctx);
			while (item && ctx->json_threadTerminate == 0) {
#if 1
				if (json_item_post_http(ctx, item) == 0) {
#else
				if (json_item_post_socket(ctx, item) == 0) {
#endif
					/* Success, remove the item from the list */
					item = json_queue_pop(ctx);
					json_item_free(ctx, item);
					item = NULL;

					failed = 0;
				} else {
					usleep(250 * 1000); /* Natural rate limit if the post fails */
					failed += 250;
				}
				workdone++;

				if (failed >= 2000) {
					/* Back off for 30 seconds before we try again. */
					json_next_post_time = now + 1;
					break;
				}

				/* Success, take this of the queue and destroy it */
				item = json_queue_peek(ctx);
			}
		}

		/* We don't want the thread thrashing when we have nothing to process. */
		if (!workdone)
			usleep(50 * 1000);
	}
	ctx->json_threadTerminated = 1;

	pthread_exit(NULL);
	return 0;
}

#if KAFKA_REPORTER
static void *kafka_thread_func(void *p)
{
	struct tool_context_s *ctx = p;
	ctx->kafka_threadRunning = 1;
	ctx->kafka_threadTerminate = 0;
	ctx->kafka_threadTerminated = 0;

	ltnpthread_setname_np(ctx->kafka_threadId, "tstools-kafka");
	pthread_detach(pthread_self());

	while (!ctx->kafka_threadTerminate) {
		//discovered_items_kafka_summary(ctx);
		usleep(500 * 1000);
	}
	ctx->kafka_threadTerminated = 1;

	pthread_exit(NULL);
	return 0;
}
#endif

static void *stats_thread_func(void *p)
{
	struct tool_context_s *ctx = p;
	ctx->stats_threadRunning = 1;
	ctx->stats_threadTerminate = 0;
	ctx->stats_threadTerminated = 0;
	int write_file_banner[2] = { 1, 1 };

	ltnpthread_setname_np(ctx->stats_threadId, "tstools-stats");
	pthread_detach(pthread_self());

	time_t now;
	time(&now);
	if (ctx->file_prefix_next_write_time == 0) {
		ctx->file_prefix_next_write_time = now + ctx->file_write_interval;
	}
	if (ctx->detailed_file_prefix_next_write_time == 0) {
		ctx->detailed_file_prefix_next_write_time = now + ctx->file_write_interval;
	}

	int workdone = 0;
	while (!ctx->stats_threadTerminate) {

		workdone = 0;
		int count = pcap_queue_service(ctx);
		if (count)
			workdone++;

		if (workdone) {
			/* Periodic housekeeping. */
			discovered_items_housekeeping(ctx);
		}

		time(&now);

		/* Once a second: model-driven PCR pids, H.264 slice pid, SCTE-35
		 * pruning. Runs with or without -M.
		 */
		discovered_items_periodic(ctx, now);

		if (ctx->file_prefix && ctx->file_prefix_next_write_time <= now) {
			ctx->file_prefix_next_write_time = now + ctx->file_write_interval;
			discovered_items_file_summary(ctx, write_file_banner[0]);
			write_file_banner[0] = 0;
			workdone++;
		}
		if (ctx->detailed_file_prefix && ctx->detailed_file_prefix_next_write_time <= now) {
			ctx->detailed_file_prefix_next_write_time = now + ctx->file_write_interval;
			discovered_items_file_detailed(ctx, write_file_banner[1]);
			write_file_banner[1] = 0;
			workdone++;
		}

		if (ctx->json_next_write_time <= now) {
			ctx->json_next_write_time = now + ctx->json_write_interval;
			discovered_items_json_summary(ctx);
			workdone++;
		}

		/* We don't want the thread thrashing when we have nothing to process. */
		if (!workdone)
			usleep(1 * 1000);
	}
	ctx->stats_threadTerminated = 1;

	pthread_exit(NULL);
	return 0;
}

#if MEASURE_PCAP_CALLBACK_PERFORMANCE
int pcap_cb_intervals_reset = 0;
struct ltn_histogram_s *pcap_cb_intervals[2] = { NULL, NULL };
#endif

static void pcap_callback(u_char *args, const struct pcap_pkthdr *h, const u_char *pkt) 
{
	if (!gRunning)
		return;

#if MEASURE_PCAP_CALLBACK_PERFORMANCE
		if (pcap_cb_intervals[0] == NULL) {
		ltn_histogram_alloc_video_defaults(&pcap_cb_intervals[0], "PCAP Callback Processing1");
		ltn_histogram_alloc_video_defaults(&pcap_cb_intervals[1], "PCAP Callback Processing2");
	}

	ltn_histogram_sample_begin(pcap_cb_intervals[0]);

	if (pcap_cb_intervals_reset) {
		pcap_cb_intervals_reset = 0;
		ltn_histogram_reset(pcap_cb_intervals[0]);
		ltn_histogram_reset(pcap_cb_intervals[1]);
	}
#endif

	pcap_update_statistics(ctx, h, pkt); /* Update the stream stats realtime to avoid queue jitter */

#if MEASURE_PCAP_CALLBACK_PERFORMANCE
	ltn_histogram_sample_end(pcap_cb_intervals[0]);
	ltn_histogram_sample_begin(pcap_cb_intervals[1]);
#endif
	pcap_queue_push(ctx, h, pkt); /* Push the packet onto a deferred queue for late IO processing. */

#if MEASURE_PCAP_CALLBACK_PERFORMANCE
	ltn_histogram_sample_end(pcap_cb_intervals[1]);
#endif
}

static struct pcap_pkthdr file_pkthdr;

static uint8_t file_pktdata[42 + (7 * 188)] = 
{
	0x01, 0x00, 0x5e, 0x01, 0x14, 0x50, 0xac, 0x1f,
	0x6b, 0x77, 0x81, 0xd3, 0x08, 0x00, 0x45, 0x00,
	0x05, 0x40, 0xeb, 0x0d, 0x40, 0x00, 0x05, 0x11,
	0xb9, 0x55, 0xc0, 0xa8, 0x14, 0x50, 0xe3, 0x01,
	0x14, 0x50, 0xd2, 0xb1, 0x0f, 0xa1, 0x05, 0x2c,
	0xf5, 0x29,
	/* Packet data to follow */
};

static void *sm_cb_pos(void *userContext, uint64_t pos, uint64_t max, double pct)
{
	struct tool_context_s *ctx = userContext;
	ctx->fileLoopPct = pct;
//	printf("%6.2f\n", pct);

	return NULL;
}

static void reformat_to_pcap(struct tool_context_s *ctx, const uint8_t *pkts, int packetCount)
{
	/* Convert a series of packets into a PCAP like structure */
	if (packetCount != 7) {
		/* Should never happen.
		 * Of the two possible callers:
		 * RCTS reframes to guarantee to 7 packets.
		 * SRT AVcodec reframes to guarantee to 7 packets.
		 * file_pktdata is a fixed-size buffer sized for exactly 7 packets --
		 * refuse anything else rather than writing past its bounds.
		 */
		printf("nic_monitor: file input, packetcount != 7, got %d, reframing not working.\n", packetCount);
		return;
	}

	gettimeofday(&file_pkthdr.ts, NULL);
	file_pkthdr.caplen = 42 + (packetCount * 188);
	file_pkthdr.len = file_pkthdr.caplen;

	memset(&file_pktdata[42], 0, 7 * 188);
	memcpy(&file_pktdata[42], pkts, packetCount * 188);
	file_pktdata[26] = 192;
	file_pktdata[27] = 168;
	file_pktdata[28] = 1;
	file_pktdata[29] = 1;
	file_pktdata[30] = 227;
	file_pktdata[31] = 1;
	file_pktdata[32] = 1;
	file_pktdata[33] = 1;
	file_pktdata[34] = 6502 >> 8;
	file_pktdata[35] = 6502 & 0xff;
	pcap_callback((u_char *)ctx, &file_pkthdr, (const u_char *)&file_pktdata[0]);
}

static void * sm_cb_raw(void *userContext, const uint8_t *pkts, int packetCount)
{
	struct tool_context_s *ctx = userContext;

	/* push to reframer */
	ltststools_reframer_write(ctx->reframer, pkts, packetCount * 188);
	
	return NULL;
}

static void *reframer_cb(void *userContext, const uint8_t *buf, int lengthBytes)
{
	struct tool_context_s *ctx = userContext;
	reformat_to_pcap(ctx, buf, lengthBytes / 188);

	return NULL;
}

static void *pcap_thread_func(void *p)
{
	struct tool_context_s *ctx = p;
	ctx->pcap_threadRunning = 1;
	ctx->pcap_threadTerminate = 0;
	ctx->pcap_threadTerminated = 0;

	int processed;
	void *sm = NULL;
	AVIOContext *puc = NULL;
	uint8_t *buf = NULL;

	/* Massive buffer, I know.
	 * We saw SRT buffer errors with high jitter/latency streams, super bursty.
	 * make the SRT input buffer big enough that our reads can absorb it.
	 */
	int buflen = 8192 * 188;

	struct ltntstools_source_rcts_callbacks_s sm_callbacks = { 0 };
	sm_callbacks.raw = (ltntstools_source_rcts_raw_callback)sm_cb_raw;
	sm_callbacks.pos = (ltntstools_source_rcts_pos_callback)sm_cb_pos;

	ltnpthread_setname_np(ctx->pcap_threadId, "tstools-pcap");
	pthread_detach(pthread_self());

	time_t lastStatsCheck = 0;

	if (ctx->iftype == IF_TYPE_PCAP) {
		ctx->descr = pcap_create(ctx->ifname, ctx->errbuf);
		if (ctx->descr == NULL) {
			fprintf(stderr, "Error, %s\n", ctx->errbuf);
			exit(1);
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
				fprintf(stderr, "Unable to set -B buffersize to %d, already activated\n", ctx->bufferSize);
				exit(0);
			}
			if (ret != 0) {
				fprintf(stderr, "Unable to set -B buffersize to %d\n", ctx->bufferSize);
				exit(0);
			}
		}

		int ret = pcap_activate(ctx->descr);
		if (ret != 0) {
			if (ctx->monitor) {
				endwin();
			}

			fprintf(stderr, "\n");
			if (ret == PCAP_ERROR_PERM_DENIED) {
				fprintf(stderr, "Error, permission denied.\n");
			}
			if (ret == PCAP_ERROR_NO_SUCH_DEVICE) {
				fprintf(stderr, "Error, network interface '%s' not found.\n", ctx->ifname);
			}
			fprintf(stderr, "Error, pcap_activate, %s\n", pcap_geterr(ctx->descr));
			printf("\nAvailable interfaces:\n");
			networkInterfaceList();
			printf("\n");
			exit(1);
		}

		/* TODO: We should craft the filter to be udp dst 224.0.0.0/4 and then
		* we don't need to manually filter in our callback.
		*/
		struct bpf_program fp;
		ret = pcap_compile(ctx->descr, &fp, ctx->pcap_filter, 0, ctx->netp);
		if (ret == -1) {
			fprintf(stderr, "Error, pcap_compile, %s\n", pcap_geterr(ctx->descr));
			exit(1);
		}

		ret = pcap_setfilter(ctx->descr, &fp);
		if (ret == -1) {
			fprintf(stderr, "Error, pcap_setfilter\n");
			exit(1);
		}

		pcap_setnonblock(ctx->descr, 1, ctx->errbuf);
	} else
	if (ctx->iftype == IF_TYPE_MPEGTS_FILE) {

		if (ltntstools_source_rcts_alloc(&sm, ctx, &sm_callbacks, ctx->ifname, ctx->fileLoops) < 0) {

		}
	} else
	if (ctx->iftype == IF_TYPE_MPEGTS_AVDEVICE) {
		buf = malloc(buflen);
		if (!buf) {
			ctx->pcap_threadRunning = 1;
			ctx->pcap_threadTerminated = 1;
			return NULL;
		}

		avformat_network_init();
	
		int ret = avio_open2(&puc, ctx->ifname, AVIO_FLAG_READ | AVIO_FLAG_NONBLOCK | AVIO_FLAG_DIRECT, NULL, NULL);
		if (ret < 0) {
			fprintf(stderr, "-i syntax error, invalid URL syntax, aborting.\n");
			exit(1);
		}
	}

	while (!ctx->pcap_threadTerminate) {

		if (ctx->iftype == IF_TYPE_PCAP) {
			processed = pcap_dispatch(ctx->descr, -1, pcap_callback, NULL);
			if (processed == 0) {
				ctx->pcap_dispatch_miss++;
				usleep(1 * 1000);
			}
		} else
		if (ctx->iftype == IF_TYPE_MPEGTS_FILE) {
			usleep(50 * 1000);
		} else
		if (ctx->iftype == IF_TYPE_MPEGTS_AVDEVICE) {
			/* TODO: Migrate this to use the source-avio.[ch] framework */

			/* Bulk reads of less than this (7 * 188 eg) cause the ffurl_read in libsrt
			 * to throw constant expcetions / warnings.
			 * Read larger buffer values to avoid the issue.
			 */
			int rlen = avio_read(puc, buf, buflen);
			if (rlen == -EAGAIN) {
				usleep(1 * 1000);
				continue;
			}
			if (rlen < 0) {
				// TODO: Do what if the URL breaks?
				break;
			}

			ltststools_reframer_write(ctx->reframer, buf, rlen);
		}

		time_t now;
		time(&now);

		/* Querying stats repeatidly is cpu expensive, we only need it 1sec intervals. */
		if (lastStatsCheck == 0) {
			if (ctx->iftype == IF_TYPE_PCAP) {
				/* Collect pcap packet loss stats */
				if (pcap_stats(ctx->descr, &ctx->pcap_stats_startup) != 0) {
					/* Error */
				}
			}
		}

		if (now != lastStatsCheck) {
			lastStatsCheck = now;

			if (ctx->iftype == IF_TYPE_PCAP) {
				/* Collect pcap packet loss stats */
				struct pcap_stat tmp;
				if (pcap_stats(ctx->descr, &tmp) != 0) {
					/* Error */
				}

				ctx->pcap_stats.ps_recv = tmp.ps_recv - ctx->pcap_stats_startup.ps_recv;
				ctx->pcap_stats.ps_drop = tmp.ps_drop - ctx->pcap_stats_startup.ps_drop;
				ctx->pcap_stats.ps_ifdrop = tmp.ps_ifdrop - ctx->pcap_stats_startup.ps_ifdrop;
			} else
			if (ctx->iftype == IF_TYPE_MPEGTS_FILE) {
				ctx->pcap_stats.ps_recv = 0;
				ctx->pcap_stats.ps_drop = 0;
				ctx->pcap_stats.ps_ifdrop = 0;
			} else
			if (ctx->iftype == IF_TYPE_MPEGTS_AVDEVICE) {
				/* TODO: Wire up the SRT loss stats these these? Show them in the UI? */
				ctx->pcap_stats.ps_recv = 0;
				ctx->pcap_stats.ps_drop = 0;
				ctx->pcap_stats.ps_ifdrop = 0;
			}

		}

		pcap_queue_rebalance(ctx);

		if (ctx->endTime) {
			if (now >= ctx->endTime) {
				//kill(getpid(), 0);
				gRunning = 0;
				break;
			}
		}
	}
	ctx->pcap_threadTerminated = 1;

	if (sm)
		ltntstools_source_rcts_free(sm);

	if (puc)
		avio_close(puc);

	if (buf) {
		free(buf);
		buf = NULL;
	}

	pthread_exit(NULL);
	return 0;
}

static void signal_handler(int signum)
{
	if (!ctx->monitor && signum == SIGINT)
		printf("\nUser requested terminate.\n");

	gRunning = 0;
}

static void usage(const char *progname)
{
	printf("A tool to monitor PCAP multicast ISO13818 traffic.\n");
	printf("Usage:\n");
	printf("  -i <iface | filename.ts | filename.ts:loop>\n");
	printf("  -v Increase level of verbosity.\n");
	printf("  -h Display command line help.\n");
	printf("  -t <#seconds>. Stop after N seconds [def: 0 - unlimited]\n");
	printf("  -M Display an interactive console with stats. Press h inside it for keys.\n");
	printf("  -a <url> Issue an IGMP join for this multicast UDP URL. May be repeated. Eg: udp://234.1.1.1:4160\n");
	printf("  -D <dir> Write any PCAP recordings in this target directory prefix. [def: %s else /tmp]\n", DEFAULT_STORAGE_LOCATION);
	printf("  -d <dir> Write summary stats per stream in this target directory prefix, every -n seconds.\n");
	printf("  -w <dir> Write detailed per pid stats per stream in this target directory prefix, every -n seconds.\n");
	printf("  -n <seconds> Interval to update -d file based stats [def: %d]\n", FILE_WRITE_INTERVAL);
	printf("  -F '<string>' Use a custom pcap filter. [def: '%s']\n", DEFAULT_PCAP_FILTER);
	printf("  -S <number> Packet buffer size [def: %d] (min: 2048)\n", g_snaplen_default);
	printf("  -B <number> Buffer size [def: %d]\n", g_buffer_size_default);
	printf("  -R Automatically record all discovered streams\n");
	printf("  -E Record in a single file, don't segment into 60sec files\n");
	printf("  -T Record int a TS format where possible [default is PCAP]\n");
	printf("  -I <#> (ms) max allowable IAT measured in ms [def: %d]\n", g_max_iat_ms);
	printf("\n");
	printf("  --udp-forwarder udp://a.b.c.d:port   Add up to %d url forwarders.\n", MAX_URL_FORWARDERS);
	printf("  --danger-skip-freespace-check        Skip the Disk Free space check, don't stop recording when disk has < 10pct free.\n");
	printf("  --measure-sei-latency-always         Look for the LTN SEI timing data, regardless of PMT version descriptoring.\n");
	printf("  --measure-scheduling-quanta          Test the scheduling quanta for 1000us sleep granularity.\n");
	printf("  --show-h264-metadata 0xnnnn          Analyze the given H264 PID (or detect it), show different codec stats (Experimental).\n");
	printf("  --report-rtp-headers                 For RTP UDP/TS streams, dump each RTP header to console.\n");
	printf("  --http-json-reporting http://url     Send 1sec json stats reports for all discovered streams [def: disabled] (Experimental).\n");
	printf("    Eg. http://127.0.0.1:13400/whatever_resource_name_you_want\n");
	printf("  --rest-api-port <port>               Serve REST API stats on this TCP port [def: disabled].\n");
	printf("  --report-memory-usage                Report memory usage and growth every 5 seconds.\n");
	printf("  --measure-scheduling-stalls          Test the scheduling system for 1000us sleeps that lasted more than 3000us.\n");
	printf("  --measure-microbursts                In the IAT report, show 10ms and 100ms microburst measurements.\n");
	printf("  --no-mouse                           -M: don't capture the mouse (m toggles it at runtime). While captured,\n");
	printf("                                       hold Shift (Option in some macOS terminals) to select text.\n");
}

static int processArguments(struct tool_context_s *ctx, int argc, char *argv[])
{
	int forwarder_idx = 0;
	struct option long_options[] =
	{
		// 0 - 4
		{ "struct-sizes",				no_argument,		0, '@' },
		{ "pcap-buffer-size",			required_argument,	0, 'B' },
		{ "stats-summary-dir",			required_argument,	0, 'd' },
		{ "pcap-filter",				required_argument,	0, 'F' },
		{ "help",						no_argument,		0, 'h' },

		// 5 - 9
		{ "help",						no_argument,		0, '?' },
		{ "input",						required_argument,	0, 'i' },
		{ "iat-max",					required_argument,	0, 'I' },
		{ "stats-write-interval",		required_argument,	0, 'n' },
		{ "terminate-after",			required_argument,	0, 't' },

		// 10 - 14
		{ "verbose",					no_argument,		0, 'v' },
		{ "ui",							no_argument,		0, 'M' },
		{ "danger-skip-freespace-check", no_argument,		0, 0 },
		{ "pcap-record-dir",			required_argument,	0, 'D' },
		{ "record-single-file",			no_argument,		0, 'E' },

		// 15 - 19
		{ "pcap-packet-size",			required_argument,	0, 'S' },
		{ "stats-detailed-dir",			required_argument,	0, 'w' },
		{ "record-as-transport",		no_argument,		0, 'T' },
		{ "record-on-startup",			no_argument,		0, 'R' },
		{ "test-arg-19",				no_argument,		0, 0 },

		// 20 - 24
		{ "udp-forwarder",				required_argument,	0, 0 },
		{ "measure-scheduling-quanta",	no_argument,		0, 0 },
		{ "show-h264-metadata",			required_argument,	0, 0 },
		{ "http-json-reporting",		required_argument,	0, 0 },
		{ "report-rtp-headers",			no_argument,		0, 0 },

		// 25 - 29
		{ "measure-sei-latency-always", no_argument,		0, 0 },
		{ "report-memory-usage", 		no_argument,		0, 0 },
		{ "measure-scheduling-stalls", 		no_argument,		0, 0 },
		{ "measure-microbursts", 		no_argument,		0, 0 },
		{ "rest-api-port",				required_argument,	0, 0 },
		{ "join",						required_argument,	0, 'a' },
		{ "no-mouse",					no_argument,		0, 0 },

		{ 0, 0, 0, 0 }
	};	

	int ch;
	while (1) {
		int option_index = 0;
		char *opts = "?ha:d:B:D:EF:i:I:t:vMn:w:RS:T@";
		ch = getopt_long(argc, argv, opts, long_options, &option_index);
		if (ch == -1)
			break;

//printf("ch = '%c', optidx %d\n", ch, option_index);

		switch (ch) {
		case '@':
			printf("\n");
			printf("sizeof(struct ltntstools_stream_statistics_s) = %lu\n", sizeof(struct ltntstools_stream_statistics_s));
			printf(" + 2x256KB for histograms per PCR pid\n");
			printf("sizeof(struct rtp_hdr_analyzer_s) = %lu\n", sizeof(struct rtp_hdr_analyzer_s));
			printf(" + 2x256KB for histograms\n");
			printf("\n");
			exit(1);
			break;
		case 'B':
			ctx->bufferSize = atoi(optarg);
			if (ctx->bufferSize < (2 * 1048576))
				ctx->bufferSize = 2 * 1048576;
			break;
		case 'a':
			if (ctx->igmpJoinCount == MAX_IGMP_JOIN_ADDRESSES) {
				fprintf(stderr, "\nError, too many IGMP joins defined, max is %d\n", MAX_IGMP_JOIN_ADDRESSES);
				exit(1);
			}
			if (parsers_ippid_parse(optarg, &ctx->igmpJoinAddress[ctx->igmpJoinCount]) < 0) {
				fprintf(stderr, "\n-a/--join syntax error, expected udp://a.b.c.d:port\n\n");
				exit(1);
			}
			ctx->igmpJoinCount++;
			break;
		case 'd':
			free(ctx->file_prefix);
			ctx->file_prefix = strdup(optarg);
			break;
		case 'F':
			ctx->pcap_filter = strdup(optarg);
			break;
		case '?':
		case 'h':
			usage(argv[0]);
			exit(1);
			break;
		case 'i':
			ctx->ifname = optarg;

			// Eg. hls+http://sportsgrid-vizio.amagi.tv/playlist.m3u8
			
			ctx->fileLoops = 0;
			if (strstr(ctx->ifname, "srt://")) {
				ctx->iftype = IF_TYPE_MPEGTS_AVDEVICE;
			} else
			if (strstr(ctx->ifname, "udp://")) {
				ctx->iftype = IF_TYPE_MPEGTS_AVDEVICE;
			} else
#if 0
			if (strstr(ctx->ifname, "http://")) {
				ctx->iftype = IF_TYPE_MPEGTS_AVDEVICE;
				printf("We have an HTTP input!!!\n");
				We might need to pcr the pcr and rate limit it, for example for a HTTP faster than realtime source
			} else
#endif
			if (strstr(ctx->ifname, ":loop")) {
				ctx->fileLoops = 1;
				ctx->ifname[strlen (ctx->ifname) - 5] = 0;
			}
			if (ctx->iftype == IF_TYPE_MPEGTS_AVDEVICE) {

			} else
			if (isValidTransportFile(ctx->ifname)) {
				ctx->iftype = IF_TYPE_MPEGTS_FILE;
			} else {

				if (networkInterfaceExistsByName(ctx->ifname) == 0) {
					fprintf(stderr, "\nNo such network interface '%s', available interfaces:\n", ctx->ifname);
					networkInterfaceList();
					printf("\n");
					exit(1);
				}

			}
			break;
		case 'I':
			ctx->iatMax = atoi(optarg);
			break;
		case 'n':
			ctx->file_write_interval = atoi(optarg);
			if (ctx->file_write_interval < 1)
				ctx->file_write_interval = 1;
			break;
		case 't':
			time(&ctx->endTime);
			ctx->endTime += atoi(optarg);
			break;
		case 'v':
			ctx->verbose++;
			break;
		case 'M':
			ctx->monitor = 1;
			break;
		case 'D':
			free(ctx->recordingDir);
			ctx->recordingDir = strdup(optarg);
			break;
		case 'E':
			ctx->recordWithSegments = 0;
			break;
		case 'S':
			ctx->snaplen = atoi(optarg);
			if (ctx->snaplen < 2048)
				ctx->snaplen = 2048;
			break;
		case 'w':
			free(ctx->detailed_file_prefix);
			ctx->detailed_file_prefix = strdup(optarg);
			break;
		case 'T':
			ctx->recordAsTS = 1;
			break;
		case 'R':
			ctx->automaticallyRecordStreams = 1;
			break;
		default:
			switch (option_index) {
			case 12: /* danger-skip-freespace-check */
				ctx->skipFreeSpaceCheck = 1;
				break;
			case 19: /* test-arg-19 */
				printf("Checking test-arg-19, success!\n");
				exit(1);
				break;
			case 20: /* udp-forwarder-url */
				if (forwarder_idx == MAX_URL_FORWARDERS) {
					fprintf(stderr, "\nError, too many forwarders defined, max is %d\n", MAX_URL_FORWARDERS);
					exit(1);
				}
				if (sscanf(optarg, "udp://%63[^:]:%d",
					&ctx->url_forwards[forwarder_idx].addr[0],
					&ctx->url_forwards[forwarder_idx].port) != 2)
				{
					fprintf(stderr, "\nError parsing forwarding url, check syntax. Must be udp://a.b.c.d:port\n");
					exit(1);
				}
				char tmp[sizeof(ctx->url_forwards[forwarder_idx].uilabel)];
				snprintf(tmp, sizeof(tmp), "%s:%d",
					ctx->url_forwards[forwarder_idx].addr,
					ctx->url_forwards[forwarder_idx].port);

				snprintf(ctx->url_forwards[forwarder_idx].uilabel, sizeof(ctx->url_forwards[forwarder_idx].uilabel), "%s", tmp);
				forwarder_idx++;
				break;
			case 21: /* measure-scheduling-quanta */
				{
					struct timeval a, b;
					gettimeofday(&a, NULL);
					usleep(1000);
					gettimeofday(&b, NULL);
					uint32_t diffUs = ltn_timeval_subtract_us(&b, &a);
					printf("\nSlept for 1000us, woke to find we'd spent %dus asleep.\n\n", diffUs);
					exit(1);
				}
				break;
			case 22: /* show-h264-metadata */
				ctx->gatherH264Metadata = 1;
				if ((sscanf(optarg, "0x%x", &ctx->gatherH264MetadataPID) != 1) || (ctx->gatherH264MetadataPID > 0x1fff)) {
					usage(argv[0]);
					exit(1);
				}
				break;
			case 23: /* http-json-reporting */
				ctx->automaticallyJSONProbeStreams = 1;
				snprintf(&ctx->json_http_url[0], sizeof(ctx->json_http_url), "%s", optarg);
				break;
			case 24: /* report-rtp-headers */
				ctx->reportRTPHeaders = 1;
				break;
			case 25: /* measure-sei-latency-always */
				ctx->measureSEILatencyAlways = 1;
				break;
			case 26: /* report-memory-usage */
				ctx->reportProcessMemoryUsage = 1;
				break;
			case 27: /* measure-scheduling-stalls */
				{
					void *ctx;
					if (ltntstools_probe_scheduler_alloc(&ctx) < 0) {
						fprintf(stderr, "Unable to allocate scheduler probe, aborting\n");
						exit(1);
					}

					signal(SIGINT, signal_handler);
					int cnt = 0;
					gRunning = 1;
					while (gRunning) {
						usleep(500 * 1000);
						if (cnt++ % 10) {
							continue;
						}
						char *buf = NULL;

						printf("Scheduler delayed our 1ms sleep request to more than 3ms %" PRIi64 " times.\n",
							ltntstools_probe_scheduler_get_3ms_error_count(ctx));

						ltntstools_probe_scheduler_get_histogram_report(ctx, &buf);
						if (buf) {
							printf("%s\n", buf);
							free(buf);
							buf = NULL;
						}
						
					}

					ltntstools_probe_scheduler_free(ctx);
					exit(1);
				}
				break;
			case 28: /* measure-microbursts */
				ctx->reportMicrobursts = 1;
				break;
			case 31: /* no-mouse */
				ctx->uiDisableMouse = 1;
				break;
			case 29: /* rest-api-port */
				ctx->rest_api_port = atoi(optarg);
				if (ctx->rest_api_port < 1 || ctx->rest_api_port > 65535) {
					fprintf(stderr, "\n--rest-api-port syntax error, expected a TCP port 1-65535\n\n");
					exit(1);
				}
				break;
			default:
				usage(argv[0]);
				exit(1);
			}
		}
	} 

	if (ctx->ifname == NULL) {
		usage(argv[0]);
		fprintf(stderr, "\nError, -i is mandatory.\n\n");
		exit(1);
	}
	if (ctx->igmpJoinCount && ctx->iftype != IF_TYPE_PCAP) {
		usage(argv[0]);
		fprintf(stderr, "\nError, -a/--join requires -i to name a pcap network interface.\n\n");
		exit(1);
	}

	return 0;
}

int nic_monitor(int argc, char *argv[])
{
	//int ch;

	pthread_mutex_init(&ctx->lock, NULL);
	xorg_list_init(&ctx->list);

	pthread_mutex_init(&ctx->ui_threadLock, NULL);
	pthread_mutex_init(&ctx->lockpcap, NULL);
	xorg_list_init(&ctx->listpcapFree);
	xorg_list_init(&ctx->listpcapUsed);

#if MEDIA_MONITOR
	media_init();
#endif

	pthread_mutex_init(&ctx->lockJSONPost, NULL);
	xorg_list_init(&ctx->listJSONPost);
	ctx->jsonSocket = -1;
	ctx->rest_api_socket = -1;

	ctx->reframer = ltntstools_reframer_alloc(ctx, 7 * 188, (ltntstools_reframer_callback)reframer_cb);

	if (pcap_queue_initialize(ctx) < 0) {
		exit(1);
	}
	ctx->file_write_interval = FILE_WRITE_INTERVAL;
	ctx->json_write_interval = JSON_WRITE_INTERVAL;
	ctx->pcap_filter = DEFAULT_PCAP_FILTER;
	ctx->snaplen = g_snaplen_default;
	ctx->bufferSize = g_buffer_size_default;
	ctx->recordWithSegments = 1;
	ctx->skipFreeSpaceCheck = 0;
	ctx->iatMax = g_max_iat_ms;
	ctx->iftype = IF_TYPE_PCAP;
	ctx->startTime = time(NULL);
	snprintf(ctx->json_http_url, sizeof(ctx->json_http_url), "http://127.0.0.1:13400/nicmonitor");

	for (int i = 0; i < 3; i++) {
		snprintf(&ctx->url_forwards[i].addr[0], sizeof(ctx->url_forwards[i].addr), "227.1.240.%d", i + 7);
		ctx->url_forwards[i].port = 4001;
		snprintf(&ctx->url_forwards[i].uilabel[0], sizeof(ctx->url_forwards[i].uilabel), "%s:%d", ctx->url_forwards[i].addr, ctx->url_forwards[i].port);
	}

	if (processArguments(ctx, argc, argv) < 0) {
		usage(argv[0]);
		exit(1);
	}

	ui_event_queue_init(&ctx->uiEvents);
	ui_message_init(&ctx->uiMessage);

	if (ctx->monitor) {
		/* Block SIGWINCH before any thread is created, so every thread
		 * inherits the mask. The main thread unblocks it once the UI is up
		 * (rule R3): worker threads never see EINTR from terminal resizes.
		 */
		sigset_t winch;
		sigemptyset(&winch);
		sigaddset(&winch, SIGWINCH);
		pthread_sigmask(SIG_BLOCK, &winch, NULL);

		/* Thousands separators in the UI. Process wide, so set before any
		 * thread exists (it was previously set by the UI thread at startup).
		 */
		setlocale(LC_NUMERIC, "");
	}

	if (ctx->verbose) {
		printf("  iface: %s\n", ctx->ifname);
	}

	/* Configure automatic core-dumps */
	struct rlimit core_limit;
	core_limit.rlim_cur = RLIM_INFINITY;
	core_limit.rlim_max = RLIM_INFINITY;
	if (setrlimit(RLIMIT_CORE, &core_limit) < 0) {
		fprintf(stderr, "setrlimit: unable to enable automatic core dumps, ignoring.\n");
	} else {
		printf("automatic core dumps enabled.\n");
	}

	if (ctx->iftype == IF_TYPE_PCAP) {
		pcap_lookupnet(ctx->ifname, &ctx->netp, &ctx->maskp, ctx->errbuf);

		struct in_addr ip_net, ip_mask;
		ip_net.s_addr = ctx->netp;
		ip_mask.s_addr = ctx->maskp;
		if (ctx->verbose) {
			printf("network: %s\n", inet_ntoa(ip_net));
			printf("   mask: %s\n", inet_ntoa(ip_mask));
			printf(" filter: %s\n", ctx->pcap_filter);
			printf("snaplen: %d\n", ctx->snaplen);
			printf("buffSiz: %d\n", ctx->bufferSize);
		}
	} else
	if (ctx->iftype == IF_TYPE_MPEGTS_FILE) {
	} else
	if (ctx->iftype == IF_TYPE_MPEGTS_AVDEVICE) {
	}

	if (ctx->verbose) {
		printf("file write interval: %d\n", ctx->file_write_interval);
		printf("json write interval: %d\n", JSON_WRITE_INTERVAL);
	}

	if (igmp_joins_start(ctx) < 0) {
		igmp_joins_stop(ctx);
		exit(1);
	}

	if (rest_api_initialize(ctx) < 0) {
		fprintf(stderr, "Unable to start REST API on port %d\n", ctx->rest_api_port);
		igmp_joins_stop(ctx);
		exit(1);
	}

	gRunning = 1;
	pthread_create(&ctx->stats_threadId, 0, stats_thread_func, ctx);
	if (ctx->iftype == IF_TYPE_PCAP || ctx->iftype == IF_TYPE_MPEGTS_FILE || ctx->iftype == IF_TYPE_MPEGTS_AVDEVICE) {
		pthread_create(&ctx->pcap_threadId, 0, pcap_thread_func, ctx);
	}
	pthread_create(&ctx->json_threadId, 0, json_thread_func, ctx);
	if (ctx->rest_api_port > 0) {
		pthread_create(&ctx->rest_api_threadId, 0, rest_api_thread_func, ctx);
		if (ctx->verbose) {
			printf("REST API listening on port %d\n", ctx->rest_api_port);
		}
	}
#if KAFKA_REPORTER
	pthread_create(&ctx->kafka_threadId, 0, kafka_thread_func, ctx);
#endif

	/* Framework to track the /proc/net/udp socket buffers stats - primarily for loss */
	ltntstools_proc_net_udp_alloc(&ctx->procNetUDPContext);

	if (ctx->monitor) {
		initscr();

		/* All curses setup happens here, before the UI thread exists and
		 * under the lock every later curses call uses.
		 */
		pthread_mutex_lock(&ctx->ui_threadLock);
		cbreak();
		noecho();
		curs_set(0);
		keypad(stdscr, TRUE);
		nodelay(stdscr, TRUE);   /* getch() never blocks; see ui_syncronized_getch() */
		set_escdelay(25);        /* Esc responds immediately */
		ui_screen_init_colors();
		pthread_mutex_unlock(&ctx->ui_threadLock);

		if (!ctx->uiDisableMouse) {
			ui_mouse_set(ctx, 1);
			ui_post(ctx, 8, "Mouse on: hold Shift (Option in some macOS terminals) to select text, m to turn off");
		}

		pthread_create(&ctx->ui_threadId, 0, nic_monitor_ui_thread_func, ctx);

		/* Every thread is created: SIGWINCH may now reach this thread only,
		 * the one that calls getch(), where ncurses handles the resize.
		 */
		sigset_t winch;
		sigemptyset(&winch);
		sigaddset(&winch, SIGWINCH);
		pthread_sigmask(SIG_UNBLOCK, &winch, NULL);
	}

	/* Start any threads, main loop processes keybaord. */
	signal(SIGINT, signal_handler);

	if (ctx->reportProcessMemoryUsage) {
		/* Measure the memory used by this process */
		process_memory_init(&ctx->memUsage);
	}

	time(&ctx->lastResetTime);
	int autoResetDone = 0;
	while (gRunning && !__atomic_load_n(&gQuitRequested, __ATOMIC_ACQUIRE)) {

		if (ctx->reportProcessMemoryUsage) {
			process_memory_update(&ctx->memUsage, 5);

			if (ctx->monitor == 0) {
				/* Report status to console */
				process_memory_dprintf(STDOUT_FILENO, &ctx->memUsage, 5);
			}
		}

		/* Start a fresh measurement period once startup settles. */
		if (!autoResetDone && time(NULL) >= ctx->startTime + 2) {
			autoResetDone = 1;
			stats_reset(ctx);
		}

		/* Without -M there is no terminal UI and no curses calls (rule H3). */
		if (ctx->monitor)
			ui_process_input(ctx);

		usleep(20 * 1000);
	}

	discovered_items_abort(ctx);

	/* discovered_items_abort() only sets DI_STATE_PCAP_RECORD_STOP /
	 * DI_STATE_STREAM_FORWARD_STOP -- those flags are observed and acted on
	 * (closing di->pcapRecorder / di->forwardAVIO) inside per-packet
	 * processing on the pcap/stats threads we are about to terminate below.
	 * Give any still-active stream a brief window to receive one more
	 * packet and gracefully close, rather than having its recorder/forwarder
	 * torn down uncleanly by the terminate flags set immediately after.
	 */
	usleep(250 * 1000);

	time_t periodEnds = time(NULL);

	/* Shutdown stats collection */
	__atomic_store_n(&ctx->ui_threadTerminate, 1, __ATOMIC_RELEASE);
	ctx->pcap_threadTerminate = 1;
	ctx->stats_threadTerminate = 1;
	ctx->json_threadTerminate = 1;
	ctx->rest_api_threadTerminate = 1;
	rest_api_free(ctx);
	while (!ctx->pcap_threadTerminated)
		usleep(50 * 1000);
	while (!ctx->stats_threadTerminated)
		usleep(50 * 1000);
	while (!ctx->json_threadTerminated)
		usleep(50 * 1000);
	while (ctx->rest_api_port > 0 && !ctx->rest_api_threadTerminated)
		usleep(50 * 1000);

	/* Shutdown ui */
	if (ctx->monitor) {
		while (!__atomic_load_n(&ctx->ui_threadTerminated, __ATOMIC_ACQUIRE)) {
			usleep(50 * 1000);
		}
		pthread_mutex_lock(&ctx->ui_threadLock);
		mousemask(0, NULL);
		endwin();
		pthread_mutex_unlock(&ctx->ui_threadLock);
	}

	/* Prepare stats window messages for later print. */
	char ts_b[64];
	snprintf(&ts_b[0], sizeof(ts_b), "%s", ctime(&ctx->lastResetTime));
	ts_b[ strlen(ts_b) - 1] = 0;

	char ts_e[64];
	snprintf(&ts_e[0], sizeof(ts_e), "%s", ctime(&periodEnds));
	ts_e[ strlen(ts_e) - 1] = 0;

	time_t d = periodEnds - ctx->lastResetTime;
	struct tm diff = { 0 };
	gmtime_r(&d, &diff);

	discovered_items_console_summary(ctx);

	struct ltntstools_proc_net_udp_item_s *items;
	int itemCount;
	if (ctx->procNetUDPContext && ltntstools_proc_net_udp_item_query(ctx->procNetUDPContext, &items, &itemCount) == 0) {
		printf("System wide UDP socket buffers\n");
		printf("-------------------------------------------------------------------------------------------->\n");
		ltntstools_proc_net_udp_item_dprintf(ctx->procNetUDPContext, STDOUT_FILENO, items, itemCount);
		printf("\n");

		ltntstools_proc_net_udp_item_free(ctx->procNetUDPContext, items);
	}

	if (ctx->procNetUDPContext) {
		ltntstools_proc_net_udp_free(ctx->procNetUDPContext);
	}

	if (ctx->verbose) {
		printf("pcap_free_miss %" PRIi64 "\n", ctx->pcap_free_miss);
		printf("pcap_dispatch_miss %" PRIi64 "\n", ctx->pcap_dispatch_miss);
		printf("pcap_malloc_miss %" PRIi64 "\n", ctx->pcap_malloc_miss);
		printf("pcap_mangled_list_items %" PRIi64 "\n", ctx->pcap_mangled_list_items);
		printf("ctx->listpcapFreeDepth %d\n", ctx->listpcapFreeDepth);
		printf("ctx->listpcapUsedDepth %d\n", ctx->listpcapUsedDepth);
		printf("ctx->rebalance_last_buffers_used %d\n", ctx->rebalance_last_buffers_used);
		printf("ctx->cacheHitRatio %.02f%% (%" PRIu64 ", %" PRIu64 ")\n", ctx->cacheHitRatio, ctx->cacheHit, ctx->cacheMiss);
	}

	if (ctx->iftype == IF_TYPE_PCAP) {
		printf("pcap nic '%s' stats: dropped: %d/%d\n",
			ctx->ifname, ctx->pcap_stats.ps_drop, ctx->pcap_stats.ps_ifdrop);
	}

	printf("Flushing the streams and recorders...\n");
	discovered_items_free(ctx);
	igmp_joins_stop(ctx);

	pcap_queue_free(ctx);

	printf("\nStats window:\n");
	printf("  from %s -> %s\n", ts_b, ts_e);
	printf("  duration %02d:%02d:%02d (HH:MM:SS)\n\n", diff.tm_hour, diff.tm_min, diff.tm_sec);

	free(ctx->file_prefix);
	free(ctx->detailed_file_prefix);

	ltntstools_reframer_free(ctx->reframer);

#if MEASURE_PCAP_CALLBACK_PERFORMANCE
	if (pcap_cb_intervals[0]) {
		ltn_histogram_interval_print(1, pcap_cb_intervals[0], 0);
		ltn_histogram_free(pcap_cb_intervals[0]);
		pcap_cb_intervals[0] = NULL;
	}
	if (pcap_cb_intervals[1]) {
		ltn_histogram_interval_print(1, pcap_cb_intervals[1], 0);
		ltn_histogram_free(pcap_cb_intervals[1]);
		pcap_cb_intervals[1] = NULL;
	}
#endif
	return 0;
}
