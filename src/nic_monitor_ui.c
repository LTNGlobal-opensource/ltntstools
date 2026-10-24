/* The nic_monitor interactive UI (-M).
 *
 * Each frame has three stages, run by the UI thread:
 *
 *   INPUT    Drain navigation keys and mouse events posted by the main
 *            thread, resolved against the frame currently on screen.
 *   BUILD    Hold ctx->lock just long enough to walk the streams and write
 *            text into two line buffers: LIST (one row per stream) and
 *            DETAIL (reports). No curses calls.
 *   PRESENT  Hold ctx->ui_threadLock, compute the layout from the terminal
 *            size, (re)create the area windows and draw them.
 *
 * ctx->lock and ctx->ui_threadLock are never held at the same time by this
 * thread. Everything in struct ui_state_s belongs to this thread; the only
 * UI state other threads see is in struct tool_context_s (uiCursorId,
 * uiEvents, uiMessage, showForwardOptions, freezeDisplay).
 */

#include <stdio.h>
#include <stdarg.h>
#include <sys/resource.h>

#include "nic_monitor.h"
#include "nic_monitor_ui_layout.h"
#include "nic_monitor_ui_screen.h"

extern int ltnpthread_setname_np(pthread_t thread, const char *name);

/* Redraw interval when nothing happens: 4 frames a second, for remote and
 * bandwidth-constrained sessions. Input (keys, mouse, commands, resizes)
 * wakes the UI and redraws at once.
 */
#define UI_FRAME_MS 250

static const char *scte35_command_name(int64_t commandType)
{
	switch (commandType) {
	case SCTE35_COMMAND_TYPE__SPLICE_NULL:
		return "splice_null";
	case SCTE35_COMMAND_TYPE__SPLICE_SCHEDULE:
		return "splice_schedule";
	case SCTE35_COMMAND_TYPE__SPLICE_INSERT:
		return "splice_insert";
	case SCTE35_COMMAND_TYPE__TIME_SIGNAL:
		return "time_signal";
	case SCTE35_COMMAND_TYPE__BW_RESERVATION:
		return "bandwidth_reservation";
	case SCTE35_COMMAND_TYPE__PRIVATE:
		return "private_command";
	default:
		return "unknown";
	}
}

static void scte35_format_age(char *dst, size_t dstSize, time_t age)
{
	if (age < 0)
		age = 0;

	snprintf(dst, dstSize, "%02ld:%02ld:%02ld",
		(long)(age / 3600),
		(long)((age / 60) % 60),
		(long)(age % 60));
}

static int scte35_json_int64(json_object *obj, const char *name, int64_t *value)
{
	json_object *child = NULL;
	if (!obj || !json_object_object_get_ex(obj, name, &child))
		return -1;

	*value = json_object_get_int64(child);
	return 0;
}

static int scte35_json_bool(json_object *obj, const char *name, int *value)
{
	json_object *child = NULL;
	if (!obj || !json_object_object_get_ex(obj, name, &child))
		return -1;

	*value = json_object_get_boolean(child);
	return 0;
}

static json_object *scte35_json_object(json_object *obj, const char *name)
{
	json_object *child = NULL;
	if (!obj || !json_object_object_get_ex(obj, name, &child))
		return NULL;
	if (!json_object_is_type(child, json_type_object))
		return NULL;

	return child;
}

static json_object *scte35_first_segmentation_descriptor(json_object *obj)
{
	json_object *descriptors = NULL;
	if (!obj || !json_object_object_get_ex(obj, "descriptors", &descriptors))
		return NULL;
	if (!json_object_is_type(descriptors, json_type_array))
		return NULL;

	int count = json_object_array_length(descriptors);
	for (int i = 0; i < count; i++) {
		json_object *desc = json_object_array_get_idx(descriptors, i);
		json_object *type = NULL;
		if (!desc || !json_object_object_get_ex(desc, "descriptor_type", &type))
			continue;
		if (strcmp(json_object_get_string(type), "segmentation_descriptor") == 0)
			return desc;
	}

	return NULL;
}

static void scte35_summary_append(char *dst, size_t dstSize, size_t *off, const char *fmt, ...)
{
	if (*off >= dstSize)
		return;

	va_list ap;
	va_start(ap, fmt);
	int ret = vsnprintf(dst + *off, dstSize - *off, fmt, ap);
	va_end(ap);

	if (ret < 0)
		return;
	if ((size_t)ret >= dstSize - *off) {
		*off = dstSize - 1;
	} else {
		*off += ret;
	}
}

static void scte35_message_summary(struct scte35_message_item_s *msg, char *dst, size_t dstSize)
{
	if (!msg->crcValid) {
		snprintf(dst, dstSize, "CRC INVALID section_len=%zu", msg->sectionLengthBytes);
		return;
	}
	if (!msg->parseOk || !msg->json) {
		snprintf(dst, dstSize, "parse failed section_len=%zu", msg->sectionLengthBytes);
		return;
	}

	json_object *root = json_tokener_parse(msg->json);
	if (!root) {
		snprintf(dst, dstSize, "decoded JSON unavailable section_len=%zu", msg->sectionLengthBytes);
		return;
	}

	size_t off = 0;
	int64_t commandType = -1;
	if (scte35_json_int64(root, "splice_command_type", &commandType) == 0) {
		scte35_summary_append(dst, dstSize, &off, "%s", scte35_command_name(commandType));
	} else {
		scte35_summary_append(dst, dstSize, &off, "unknown");
	}

	json_object *cmd = NULL;
	if (commandType == SCTE35_COMMAND_TYPE__SPLICE_INSERT) {
		cmd = scte35_json_object(root, "splice_insert");
		int64_t eventId = 0;
		int outOfNetwork = 0;
		if (scte35_json_int64(cmd, "splice_event_id", &eventId) == 0)
			scte35_summary_append(dst, dstSize, &off, " event=%" PRIi64, eventId);
		if (scte35_json_bool(cmd, "out_of_network_indicator", &outOfNetwork) == 0)
			scte35_summary_append(dst, dstSize, &off, " %s", outOfNetwork ? "OUT" : "IN");

		json_object *spliceTime = scte35_json_object(cmd, "splice_time");
		int64_t pts = 0;
		if (scte35_json_int64(spliceTime, "pts_time", &pts) == 0)
			scte35_summary_append(dst, dstSize, &off, " pts=%" PRIi64, pts);

		json_object *duration = scte35_json_object(cmd, "break_duration");
		int64_t dur = 0;
		if (scte35_json_int64(duration, "duration", &dur) == 0)
			scte35_summary_append(dst, dstSize, &off, " dur=%.3fs", (double)dur / 90000.0);
	} else if (commandType == SCTE35_COMMAND_TYPE__TIME_SIGNAL) {
		cmd = scte35_json_object(root, "time_signal");
		json_object *spliceTime = scte35_json_object(cmd, "splice_time");
		int64_t pts = 0;
		if (scte35_json_int64(spliceTime, "pts_time", &pts) == 0)
			scte35_summary_append(dst, dstSize, &off, " pts=%" PRIi64, pts);
	}

	json_object *seg = scte35_first_segmentation_descriptor(root);
	if (seg) {
		int64_t eventId = 0;
		int64_t typeId = 0;
		int64_t duration = 0;
		if (scte35_json_int64(seg, "segmentation_event_id", &eventId) == 0)
			scte35_summary_append(dst, dstSize, &off, " seg_event=%" PRIi64, eventId);
		if (scte35_json_int64(seg, "segmentation_type_id", &typeId) == 0)
			scte35_summary_append(dst, dstSize, &off, " seg_type=0x%02" PRIx64, typeId);
		if (scte35_json_int64(seg, "segmentation_duration", &duration) == 0)
			scte35_summary_append(dst, dstSize, &off, " seg_dur=%.3fs", (double)duration / 90000.0);
	}

	if (msg->videoPTS)
		scte35_summary_append(dst, dstSize, &off, " video_pts=%" PRIi64, msg->videoPTS);

	json_object_put(root);
}

enum ui_focus_e
{
	UI_FOCUS_LIST = 0,
	UI_FOCUS_DETAIL,   /* The single detail panel (no detail windows open) */
	UI_FOCUS_PANE,     /* A detail window: ui_state_s.focusPane */
};

/* A detail window: one stream's reports, opened by double-click or Enter. */
struct ui_pane_s
{
	uint32_t id;
	struct ui_buf_s buf;
	int top, left;
	int weight;        /* Share of the detail region, UI_PANE_WEIGHT_MIN..MAX (+/-) */
	int found;         /* Seen in the last BUILD; panes for vanished streams close */
};

struct ui_stream_info_s
{
	uint32_t id;
	char label[64];      /* "src -> dst" */
	char reports[24];    /* Reports switched on, e.g. "P C L" */
};

struct ui_state_s
{
	struct tool_context_s *ctx;
	struct ui_screen_s screen;
	struct ui_buf_s list;
	struct ui_buf_s detail;

	/* The frame on screen, used to resolve mouse clicks and size pages. */
	struct ui_layout_s layout;
	struct ui_view_s view;
	struct ui_hint_map_s hints;
	int overlayY, overlayX, overlayH, overlayW;
	int helpTop;                  /* First help line shown when it doesn't fit */
	struct ui_click_s lastClick;  /* Double-click pairing */

	/* Detail windows, top to bottom. While any are open they replace the
	 * single detail panel.
	 */
	struct ui_pane_s pane[UI_PANE_MAX];
	int paneCount;
	int focusPane;
	int panesShown;                         /* How many fit on screen last frame */
	struct ui_rect_s paneBar[UI_PANE_MAX];  /* Last frame, for mouse hits */
	struct ui_rect_s paneBody[UI_PANE_MAX];

	enum ui_focus_e focus;
	int detailPct;
	int helpOpen;
	int detailWanted;    /* Some visible stream has a report open: show DETAIL */
	int zoom;            /* Full-screen detail for the cursor stream (Enter / double-click) */

	/* DETAIL shows the tagged streams, one after another, or the cursor stream
	 * when nothing is tagged. The cursor view keeps a scroll position per
	 * stream; the tagged view has its own.
	 */
	struct ui_scroll_mem_s scrollMem;
	uint32_t detailSubject;  /* Stream id, or UI_DETAIL_TAGGED */
	int taggedCount;         /* Visible tagged streams in the last BUILD */
	int taggedTop, taggedLeft;

	/* Visible streams in display order, from the last BUILD. */
	struct ui_stream_info_s *streams;
	uint32_t *order;
	uint32_t *prevOrder;
	int *heights;
	int streamCount;
	int prevCount;
	int streamAlloc;

	/* Header and footer text from the last BUILD. */
	char titleA[160];
	char titleC[160];
	int titleAlert;
	char statusA[160];
	char statusC[96];
	char memStatus[96];

	struct ltntstools_proc_net_udp_item_s *items;
	int itemCount;
	time_t lastSocketReport;

	const char *dumpPath;    /* NIC_MONITOR_UI_DUMP: write the screen as text once a second */
	time_t lastDump;
};

#define UI_DETAIL_TAGGED UINT32_MAX  /* detailSubject: the combined tagged view */

#define UI_COLHDR "  <--------------------------------------------------- M/BIT <---------PACKETS <------CCErr <--IAT--Flags--------"

static const char *g_help[] = {
	"Moving around",
	"  Up Dn  j k      move the cursor / scroll the focused view",
	"  PgUp PgDn       page            Home End  g G   top / bottom",
	"  Left Right      scroll sideways Tab Shift-Tab   cycle focus: list, windows",
	"  Esc             back to the list (or clear tags when already there)",
	"",
	"Detail windows (one per stream, stacked under the list)",
	"  Enter           open a window for the cursor stream (or focus it)",
	"  double-click    open / close a stream's window (opens the model report)",
	"  x               close the focused window",
	"  + -             resize the focused window, else the list/detail split",
	"  z               full screen (z or Esc to leave)",
	"  With no windows open, the detail panel shows the tagged streams,",
	"  else the cursor stream.",
	"",
	"Reports (act on the tagged streams, else the cursor / focused window)",
	"  P PID traffic   C Clock   M PSIP model   L Stream log   I IAT histogram",
	"  s Socket/process          T TR101290     3 SCTE-35      J JSON probe",
	"",
	"Streams",
	"  Space tag/untag   S tag all   D clear tags   H hide   U unhide all",
	"  R record start/stop   @ segments/single file   $ TS/PCAP   F forward",
	"",
	"Other",
	"  r reset statistics   f freeze display   m mouse on/off",
	"  q quit               h ?  this help (Esc closes)",
	"  Mouse: click selects or focuses, wheel scrolls the view under it.",
	"  With the mouse on, hold Shift (Option in some macOS terminals) to select text.",
	NULL
};

/* ------------------------------------------------------------------ */
/* Keys                                                               */
/* ------------------------------------------------------------------ */

int nic_monitor_ui_is_ui_key(int key)
{
	switch (key) {
	case KEY_UP: case KEY_DOWN: case KEY_LEFT: case KEY_RIGHT:
	case KEY_PPAGE: case KEY_NPAGE: case KEY_HOME: case KEY_END:
	case KEY_BTAB: case KEY_ENTER: case KEY_F(1):
	case 'j': case 'k': case 'g': case 'G':
	case '\t': case '\n': case '\r': case 27:
	case '+': case '-': case 'h': case '?':
	case 'x': case 'z':
		return 1;
	default:
		return 0;
	}
}

/* ------------------------------------------------------------------ */
/* BUILD                                                              */
/* ------------------------------------------------------------------ */

static int ui_streams_reserve(struct ui_state_s *st, int n)
{
	if (n <= st->streamAlloc)
		return UI_OK;

	int alloc = st->streamAlloc ? st->streamAlloc : 64;
	while (alloc < n)
		alloc *= 2;

	struct ui_stream_info_s *s = realloc(st->streams, alloc * sizeof(*s));
	if (s)
		st->streams = s;
	uint32_t *o = realloc(st->order, alloc * sizeof(*o));
	if (o)
		st->order = o;
	uint32_t *p = realloc(st->prevOrder, alloc * sizeof(*p));
	if (p)
		st->prevOrder = p;
	int *h = realloc(st->heights, alloc * sizeof(*h));
	if (h)
		st->heights = h;

	if (!s || !o || !p || !h)
		return UI_ERR_NOMEM;

	st->streamAlloc = alloc;
	return UI_OK;
}

static unsigned int ui_report_flags(void)
{
	return DI_STATE_SHOW_PIDS | DI_STATE_SHOW_TR101290 | DI_STATE_SHOW_IAT_HISTOGRAM |
		DI_STATE_SHOW_STREAMMODEL | DI_STATE_SHOW_PROCESSES | DI_STATE_SHOW_SCTE35 |
		DI_STATE_SHOW_STREAM_LOG | DI_STATE_SHOW_CLOCKS;
}

static void ui_report_letters(struct discovered_item_s *di, char *out, size_t size)
{
	static const struct { unsigned int flag; const char *letter; } map[] = {
		{ DI_STATE_SHOW_PIDS, "P" }, { DI_STATE_SHOW_CLOCKS, "C" },
		{ DI_STATE_SHOW_STREAMMODEL, "M" }, { DI_STATE_SHOW_STREAM_LOG, "L" },
		{ DI_STATE_SHOW_IAT_HISTOGRAM, "I" }, { DI_STATE_SHOW_PROCESSES, "s" },
		{ DI_STATE_SHOW_TR101290, "T" }, { DI_STATE_SHOW_SCTE35, "3" },
	};

	out[0] = 0;
	for (size_t i = 0; i < sizeof(map) / sizeof(map[0]); i++) {
		if (discovered_item_state_get(di, map[i].flag)) {
			size_t len = strlen(out);
			snprintf(out + len, size - len, "%s%s", len ? " " : "", map[i].letter);
		}
	}
}

static void ui_dirname(const char *path, char *out, size_t size)
{
	snprintf(out, size, "%s", path);
	char *p = strrchr(out, '/');
	if (p == out)
		p[1] = 0;
	else if (p)
		*p = 0;
	else
		snprintf(out, size, ".");
}

struct ui_inline_s
{
	char text[UI_BUF_MAX_COLS];
	uint8_t pair;
};

/* One stream row in LIST, plus its indented recording / forwarding lines.
 * Caller holds ctx->lock.
 */
static void ui_build_stream(struct ui_state_s *st, struct discovered_item_s *di, uint32_t cursorId,
	double *totalRxMbps, double *totalTxMbps, double *totalMbps)
{
	struct tool_context_s *ctx = st->ctx;
	struct ui_buf_s *l = &st->list;
	int row = l->lineCount;

	ui_buf_set_owner(l, di->id);

	int ccError = ltntstools_pid_stats_stream_get_cc_errors(di->stats) > 0;
	int iatError = di->iat_hwm_us / 1000 > ctx->iatMax;
	int pair = 0;
	if (di->id == cursorId)
		pair = UI_PAIR_CURSOR;
	else if (discovered_item_state_get(di, DI_STATE_DST_DUPLICATE))
		pair = UI_PAIR_ALERT;
	else if (ccError || iatError)
		pair = UI_PAIR_ERROR;
	ui_buf_set_pair(l, pair);

	if (di->srcOriginRemoteHost) {
		*totalRxMbps += ltntstools_pid_stats_stream_get_mbps(di->stats);
	} else {
		*totalTxMbps += ltntstools_pid_stats_stream_get_mbps(di->stats);
	}
	*totalMbps = *totalRxMbps + *totalTxMbps;

	int recording = discovered_item_state_get(di, DI_STATE_PCAP_RECORDING) != 0;
	int forwarding = discovered_item_state_get(di, DI_STATE_STREAM_FORWARDING) != 0;
	char flags[32];
	snprintf(flags, sizeof(flags), "%s%s%s", di->warningIndicatorLabel,
		recording ? " REC" : "", forwarding ? " FWD" : "");

	char tag = discovered_item_state_get(di, DI_STATE_TAGGED) ? '*' : ' ';

	if ((di->payloadType == PAYLOAD_RTP_TS) || (di->payloadType == PAYLOAD_UDP_TS) || (di->payloadType == PAYLOAD_SRT_TS)) {
		ui_buf_printf(l, row, 0, "%c %s %21s -> %21s %7.2f  %'16" PRIu64 " %12" PRIu64 "   %4d  %s",
			tag,
			payloadTypeDesc(di->payloadType),
			di->srcaddr,
			di->dstaddr,
			ltntstools_pid_stats_stream_get_mbps(di->stats),
			ltntstools_pid_stats_stream_get_packet_count(di->stats),
			ltntstools_pid_stats_stream_get_cc_errors(di->stats),
			di->iat_hwm_us / 1000,
			flags);
	} else
	if ((di->payloadType == PAYLOAD_A324_CTP) ||
		(di->payloadType == PAYLOAD_SMPTE2110_20_VIDEO) ||
		(di->payloadType == PAYLOAD_SMPTE2110_30_AUDIO) ||
		(di->payloadType == PAYLOAD_SMPTE2110_40_ANC)) {
		ui_buf_printf(l, row, 0, "%c %s %21s -> %21s %7.2f  %'16" PRIu64 " %12" PRIu64 "   %4d  %s",
			tag,
			payloadTypeDesc(di->payloadType),
			di->srcaddr,
			di->dstaddr,
			ltntstools_ctp_stats_stream_get_mbps(di->stats),
			ltntstools_pid_stats_stream_get_packet_count(di->stats),
			ltntstools_pid_stats_stream_get_cc_errors(di->stats),
			di->iat_hwm_us / 1000,
			flags);
		*totalMbps += ltntstools_ctp_stats_stream_get_mbps(di->stats);
	} else {
		/* Byte streams, SRT control / encrypted, and streams not yet classified. */
		ui_buf_printf(l, row, 0, "%c %s %21s -> %21s %7.2f  %'16" PRIu64 " %12s   %4d  %s",
			tag,
			payloadTypeDesc(di->payloadType),
			di->srcaddr,
			di->dstaddr,
			ltntstools_bytestream_stats_stream_get_mbps(di->stats),
			ltntstools_pid_stats_stream_get_packet_count(di->stats),
			"-",
			di->iat_hwm_us / 1000,
			flags);
		*totalMbps += ltntstools_bytestream_stats_stream_get_mbps(di->stats);
	}

	/* Indented status lines that belong to this stream. */
	struct ui_inline_s lines[6];
	int n = 0;

	if (forwarding) {
		snprintf(lines[n].text, sizeof(lines[n].text), "Forwarding stream to %s", di->forwardURL);
		lines[n++].pair = 0;
	}

	if (recording && di->pcapRecorder) {
		char fn[512] = { 0 };
		if (ltntstools_segmentwriter_get_current_filename(di->pcapRecorder, &fn[0], sizeof(fn)) < 0)
			snprintf(fn, sizeof(fn), "pending open file");

		double fsusedpct = 100.0 - ltntstools_segmentwriter_get_freespace_pct(di->pcapRecorder);
		int segcount = ltntstools_segmentwriter_get_segment_count(di->pcapRecorder);
		double totalsize = ltntstools_segmentwriter_get_recording_size(di->pcapRecorder);
		totalsize /= 1048576; /* MB */
		int mb = 1;
		if (totalsize > 4000) {
			totalsize /= 1024; /* Convert to GB */
			mb = 0;
		}

		time_t startTime = ltntstools_segmentwriter_get_recording_start_time(di->pcapRecorder);
		char stime[64];
		ctime_r(&startTime, stime);
		stime[strcspn(stime, "\n")] = 0;

		char dir[512];
		ui_dirname(fn, dir, sizeof(dir));

		snprintf(lines[n].text, sizeof(lines[n].text), "%s to ... %s",
			ctx->recordWithSegments ? "Segmented recording" : "Recording", fn);
		lines[n++].pair = 0;

		if (ctx->recordWithSegments) {
			snprintf(lines[n].text, sizeof(lines[n].text), "  %d segment%s @ %'.02f%s, %s fs %5.02f%% full, since %s",
				segcount, segcount == 1 ? "" : "(s)", totalsize, mb == 1 ? "MB" : "GB", dir, fsusedpct, stime);
		} else {
			snprintf(lines[n].text, sizeof(lines[n].text), "  One file @ %'.02f%s, %s fs %5.02f%% full, since %s",
				totalsize, mb == 1 ? "MB" : "GB", dir, fsusedpct, stime);
		}
		lines[n++].pair = fsusedpct > 80.0 ? UI_PAIR_ERROR : 0;

		int qdepth = ltntstools_segmentwriter_get_queue_depth(di->pcapRecorder);
		if (qdepth > 300 * 1000) {
			snprintf(lines[n].text, sizeof(lines[n].text), "  Recorder I/O is falling behind realtime, %d items waiting", qdepth);
			lines[n++].pair = UI_PAIR_WARN;
		}
	}

	if (discovered_item_state_get(di, DI_STATE_JSON_PROBE_ACTIVE)) {
		snprintf(lines[n].text, sizeof(lines[n].text), "JSON Probe Active");
		lines[n++].pair = 0;
	}

	for (int i = 0; i < n; i++) {
		ui_buf_set_pair(l, lines[i].pair);
		ui_buf_printf(l, row + 1 + i, 0, "  %s %s", i == n - 1 ? "`-" : "|-", lines[i].text);
	}

	ui_buf_set_pair(l, 0);
	ui_buf_set_owner(l, 0);
}

/* SCTE-35 report, every message in the history, newest first.
 * Returns the number of lines written.
 */
static int ui_build_scte35(struct ui_buf_s *d, struct discovered_item_s *di, int row, time_t now)
{
	int lines = 0;
	int pidCount = 0;
	int messageCount = 0;

	pthread_mutex_lock(&di->scte35Lock);

	struct scte35_pid_item_s *pidItem = NULL;
	xorg_list_for_each_entry(pidItem, &di->listSCTE35Pids, list)
		pidCount++;

	struct scte35_message_item_s *msg = NULL;
	xorg_list_for_each_entry(msg, &di->listSCTE35Messages, list)
		messageCount++;

	ui_buf_printf(d, row + lines++, 0, " -> SCTE-35 Report, last %dh: %d message%s, %d PID%s",
		SCTE35_HISTORY_SECONDS / 3600,
		messageCount, messageCount == 1 ? "" : "s",
		pidCount, pidCount == 1 ? "" : "s");

	xorg_list_for_each_entry(pidItem, &di->listSCTE35Pids, list) {
		if (pidItem->lastVideoPTS) {
			ui_buf_printf(d, row + lines++, 4,
				"PID 0x%04x (%d), video 0x%04x (%d), messages %" PRIu64 ", last video PTS %" PRIi64,
				pidItem->pid, pidItem->pid,
				pidItem->videoPid, pidItem->videoPid,
				pidItem->messageCount,
				pidItem->lastVideoPTS);
		} else {
			ui_buf_printf(d, row + lines++, 4,
				"PID 0x%04x (%d), video 0x%04x (%d), messages %" PRIu64,
				pidItem->pid, pidItem->pid,
				pidItem->videoPid, pidItem->videoPid,
				pidItem->messageCount);
		}
	}

	if (messageCount == 0) {
		ui_buf_printf(d, row + lines++, 4, "No SCTE-35 messages decoded yet");
	}

	xorg_list_for_each_entry_reverse(msg, &di->listSCTE35Messages, list) {
		char age[16];
		char summary[256];
		scte35_format_age(age, sizeof(age), now - msg->receivedAt);
		scte35_message_summary(msg, summary, sizeof(summary));

		ui_buf_printf(d, row + lines++, 4,
			"#%" PRIu64 " age %s pid 0x%04x %s",
			msg->sequenceNumber,
			age,
			msg->pid,
			summary);
	}

	pthread_mutex_unlock(&di->scte35Lock);

	return lines;
}

/* Reports for one stream, into DETAIL. Caller holds ctx->lock. */
/* The first line of a stream's detail: its name when several streams share
 * one view (the combined tagged panel), else a blank line, because the
 * window's bar already names the stream.
 */
static void ui_build_stream_header(struct ui_buf_s *d, struct discovered_item_s *di, int row, int header)
{
	if (!header) {
		ui_buf_touch(d, row);
		return;
	}
	ui_buf_set_pair(d, UI_PAIR_HINT);
	ui_buf_printf(d, row, 0, "== %s %s -> %s ==", payloadTypeDesc(di->payloadType), di->srcaddr, di->dstaddr);
	ui_buf_set_pair(d, 0);
}

static void ui_build_reports(struct ui_state_s *st, struct ui_buf_s *d, struct discovered_item_s *di, time_t now, int header)
{
	struct tool_context_s *ctx = st->ctx;

	int dc = d->lineCount;
	if (dc > 0)
		dc++; /* Blank line between streams */

	ui_buf_set_owner(d, di->id);
	ui_build_stream_header(d, di, dc, header);

	if (discovered_item_state_get(di, DI_STATE_SHOW_CLOCKS)) {
		if (di->payloadType == PAYLOAD_SMPTE2110_20_VIDEO) {
			dc++;
			ui_buf_printf(d, dc, 0, " -> Clock Report not available for SMPTE2110-20 Video streams");
		}
		if (di->payloadType == PAYLOAD_SMPTE2110_30_AUDIO) {
			dc++;
			ui_buf_printf(d, dc, 0, " -> Clock Report not available for SMPTE2110-30 Audio streams");
		}
		if (di->payloadType == PAYLOAD_SMPTE2110_40_ANC) {
			dc++;
			ui_buf_printf(d, dc, 0, " -> Clock Report not available for SMPTE2110-40 Ancillary Data streams");
		}
		if (di->payloadType == PAYLOAD_A324_CTP) {
			dc++;
			ui_buf_printf(d, dc, 0, " -> Clock Report not available for A/324 Studio Transmitter Link CTP streams");
		}
		if (di->payloadType == PAYLOAD_BYTE_STREAM) {
			dc++;
			ui_buf_printf(d, dc, 0, " -> Clock Report not available for unidentified byte streams");
		}
		dc++;
		ui_buf_printf(d, dc, 0, " -> Clock Report (working)");
		int j = 0;

		struct ltntstools_pid_statistics_s *pid;
		ltntstools_stats_for_each_pid(di->stats, i, pid) {
			if (!pid->enabled)
				continue;

			if (!pid->enabled)
				continue;
			if (!pid->hasPCR)
				continue;
			if (!pid->pcrTickIntervals)
				continue;

			if (j++ == 0) {
				/* Replace the provisional '(working)' line above... */
				ui_buf_printf(d, dc, 0, " -> Clock Report for PID %04x", i);
				dc++;
			}
			

			/* The Model report starts the stream model analyzer, where the PCR pids are discovered.
			 * This only works if the stream model view is also enabled, else no PCR pids are found.
			 */

			char *s;
			ltn_histogram_interval_print_buf(&s, pid->pcrTickIntervals, 0);
			if (s) {
				char *buf = s;

				char *p = strtok(buf, "\n");
				while (p) {
					ui_buf_printf(d, dc, 4, "%s", p);
					p = strtok(NULL, "\n");
					if (p) {
						dc++;
					}
				}
				free(s);
				s = NULL;
				dc++;
			}
			dc++;

			if (pid->pcrWallDrift) {
				ltn_histogram_interval_print_buf(&s, pid->pcrWallDrift, 0);
				if (s) {
					char *buf = s;

					char *p = strtok(buf, "\n");
					while (p) {
						ui_buf_printf(d, dc, 4, "%s", p);
						p = strtok(NULL, "\n");
						if (p) {
							dc++;
						}
					}
					free(s);
					dc++;
				}
			}
		}
	} /* Show clocks */

	if (discovered_item_state_get(di, DI_STATE_SHOW_PIDS)) {
		if (di->payloadType == PAYLOAD_SRT_CTRL) {
			dc++;
			ui_buf_printf(d, dc, 0, " -> PID Report not available for SRT flow control channels");
		}
		if (di->payloadType == PAYLOAD_SRT_ENCRYPTED) {
			dc++;
			ui_buf_printf(d, dc, 0, " -> PID Report not available for SRT encrypted channels");
			ui_buf_printf(d, dc + 1, 0, "    Pkt ReTransmits %" PRIu64, di->srt_retransmittion_count);
		}
		if (di->payloadType == PAYLOAD_SMPTE2110_20_VIDEO) {
			dc++;
			ui_buf_printf(d, dc, 0, " -> PID Report not available for SMPTE2110-20 Video streams");
		}
		if (di->payloadType == PAYLOAD_SMPTE2110_30_AUDIO) {
			dc++;
			ui_buf_printf(d, dc, 0, " -> PID Report not available for SMPTE2110-30 Audio streams");
		}
		if (di->payloadType == PAYLOAD_SMPTE2110_40_ANC) {
			dc++;
			ui_buf_printf(d, dc, 0, " -> PID Report not available for SMPTE2110-40 Ancillary Data streams");
		}
		if (di->payloadType == PAYLOAD_A324_CTP) {
			dc++;
			ui_buf_printf(d, dc, 0, " -> PID Report not available for A/324 Studio Transmitter Link CTP streams");
		}
		if (di->payloadType == PAYLOAD_BYTE_STREAM) {
			dc++;
			ui_buf_printf(d, dc, 0, " -> PID Report not available for unidentified byte streams");
		}

		struct ltntstools_pid_statistics_s *pid;
		int pidRows = 0;
		ltntstools_stats_for_each_pid(di->stats, i, pid) {
			if (!pid->enabled)
				continue;

			if (pid->enabled) {
				dc++;
#if 0
				uint64_t oof_count = ltntstools_pid_stats_stream_get_reorder_errors(di->stats);
#endif
				/* Title on the first pid row (previously only when pid 0 was present). */
				if (pidRows++ == 0) {
					ui_buf_printf(d, dc, 0, " -> PID Report");
					if ((di->payloadType == PAYLOAD_SRT_ENCRYPTED) || (di->payloadType == PAYLOAD_SRT_TS)) {
						ui_buf_printf(d, dc + 1, 0, "    Pkt ReTransmits %" PRIu64, di->srt_retransmittion_count);
					}
#if 0
					ui_buf_printf(d, dc + 1, 0, "    Pkt Order Errors (POE) %" PRIu64, oof_count);
#endif
				}

				ui_buf_printf(d, dc, 37, "0x%04x (%4d) %7.2f %'17" PRIu64 " %12" PRIu64 "\n",
					i,
					i,
					ltntstools_pid_stats_pid_get_mbps(di->stats, i),
					ltntstools_pid_stats_pid_get_packet_count(di->stats, i),
					ltntstools_pid_stats_pid_get_cc_errors(di->stats, i));
			}
		}

		dc++;


		if (ltntstools_pid_stats_stream_get_notmultipleofseven_errors(di->stats) &&
			(di->payloadType != PAYLOAD_A324_CTP) &&
			(di->payloadType != PAYLOAD_SMPTE2110_20_VIDEO) &&
			(di->payloadType != PAYLOAD_SMPTE2110_30_AUDIO) &&
			(di->payloadType != PAYLOAD_SRT_CTRL) &&
			(di->payloadType != PAYLOAD_SRT_ENCRYPTED) &&
			(di->payloadType != PAYLOAD_SMPTE2110_40_ANC)) {
			ui_buf_set_pair(d, 4);
			ui_buf_printf(d, dc, 37, "Warning: %" PRIi64 " UDP packets that are less then 1316 bytes long",
				ltntstools_pid_stats_stream_get_notmultipleofseven_errors(di->stats));
			ui_buf_set_pair(d, 0);
			dc++;
		}
	}

	if (discovered_item_state_get(di, DI_STATE_SHOW_TR101290)) {
		if (di->payloadType == PAYLOAD_SMPTE2110_20_VIDEO) {
			dc++;
			ui_buf_printf(d, dc, 0, " -> TR101290 Status not available for SMPTE2110-20 Video streams");
			dc++;
		} else
		if (di->payloadType == PAYLOAD_SRT_CTRL) {
			dc++;
			ui_buf_printf(d, dc, 0, " -> TR101290 Status not available for SRT flow control channels");
			dc++;
		} else
		if (di->payloadType == PAYLOAD_SMPTE2110_30_AUDIO) {
			dc++;
			ui_buf_printf(d, dc, 0, " -> TR101290 Status not available for SMPTE2110-30 Audio streams");
			dc++;
		} else
		if (di->payloadType == PAYLOAD_SMPTE2110_40_ANC) {
			dc++;
			ui_buf_printf(d, dc, 0, " -> TR101290 Status not available for SMPTE2110-40 Ancillary Data streams");
			dc++;
		} else
		if (di->payloadType == PAYLOAD_A324_CTP) {
			dc++;
			ui_buf_printf(d, dc, 0, " -> TR101290 Status not available for A/324 Studio Transmitter Link CTP streams");
			dc++;
		} else
		if (di->payloadType == PAYLOAD_BYTE_STREAM) {
			dc++;
			ui_buf_printf(d, dc, 0, " -> TR101290 Status not available for unidentified byte streams");
			dc++;
		} else {
			dc++;
			ui_buf_printf(d, dc, 0, " -> TR101290 Status (Coming Soon.... Drum roll or sad trombone?)");
			dc++;
			int p1col = 10;
			int p2col = 45;
			//int p3col = 75;

			nic_monitor_tr101290_draw_ui(di, d, &dc, p1col, p2col);

		}
	}

	if (discovered_item_state_get(di, DI_STATE_SHOW_IAT_HISTOGRAM)) {
		dc++;
		ui_buf_printf(d, dc, 0, " -> ");

		char *s;
		ltn_histogram_interval_print_buf(&s, di->packetIntervals, 0);
		if (s) {
			char *buf = s;

			char *p = strtok(buf, "\n");
			while (p) {
				ui_buf_printf(d, dc, 4, "%s", p);
				p = strtok(NULL, "\n");
				if (p) {
					dc++;
				}
			}
			free(s);
			s = NULL;
			dc++;
		}

		if (ctx->reportMicrobursts) {
			double a = ((double)di->bitrate_hwm_us_10ms_last_nsecond * 100.0) / 1000000.0;
			double b = ((double)di->bitrate_hwm_us_100ms_last_nsecond * 10.0) / 1000000.0;
			ui_buf_printf(d, dc, 52, "%6.02f @ 10ms\n", a);
			dc++;
			ui_buf_printf(d, dc, 52, "%6.02f @ 100ms\n", b);
			dc++;
		}
	}

	if (discovered_item_state_get(di, DI_STATE_SHOW_PROCESSES)) {
		dc++;
		ui_buf_printf(d, dc, 0, " -> Socket / Process Report");

		if (ctx->procNetUDPContext && st->lastSocketReport + 2 < now) {
			st->lastSocketReport = now;

			if (st->items) {
				ltntstools_proc_net_udp_item_free(ctx->procNetUDPContext, st->items);
				st->items = NULL;
			}
			ltntstools_proc_net_udp_item_query(ctx->procNetUDPContext, &st->items, &st->itemCount);
		}

		if (st->itemCount) {
			ui_buf_printf(d, dc, 55, "PID           COMMAND        DROPS    TOTAL");
			dc++;
		} else {
			ui_buf_printf(d, dc, 55, "PID           COMMAND        DROPS   (discovery mode)");
			dc++;
		}

		if (st->items && st->itemCount) {
			for (int i = 0; i < st->itemCount; i++) {
				struct ltntstools_proc_net_udp_item_s *e = &st->items[i];

				// TODO: String compare is slow. Convert to uint32_t for a fast match.
				if (((e->local_addr.sin_addr.s_addr == INADDR_ANY) && (e->local_addr.sin_port == di->dstport)) ||
					(strcmp(e->locaddr, di->dstaddr) == 0))
				{
					if (e->drops_delta)
						ui_buf_set_pair(d, 4);

					ui_buf_printf(d, dc, 50, "%8" PRIu64 "  %16s    %9" PRIu64 "%9" PRIu64,
						e->pidList[0].pid,
						e->pidList[0].comm,
						e->drops_delta,
						e->drops);

					if (e->drops_delta)
						ui_buf_set_pair(d, 0);
					dc++;
				}
			}
			
		}
	}

	if (discovered_item_state_get(di, DI_STATE_SHOW_STREAMMODEL)) {
		dc++;
		if (di->payloadType == PAYLOAD_SMPTE2110_20_VIDEO) {
			ui_buf_printf(d, dc, 0, " -> Service Information Report not available for SMPTE2110-20 Video streams");
			dc++;
		} else
		if (di->payloadType == PAYLOAD_SRT_CTRL) {
			ui_buf_printf(d, dc, 0, " -> Service Information Report not available for SRT flow control channels");
			dc++;
		} else
		if (di->payloadType == PAYLOAD_SRT_ENCRYPTED) {
			ui_buf_printf(d, dc, 0, " -> Service Information Report not available for SRT encrypted channels");
			dc++;
		} else
		if (di->payloadType == PAYLOAD_SMPTE2110_30_AUDIO) {
			ui_buf_printf(d, dc, 0, " -> Service Information Report not available for SMPTE2110-30 Audio streams");
			dc++;
		} else
		if (di->payloadType == PAYLOAD_SMPTE2110_40_ANC) {
			ui_buf_printf(d, dc, 0, " -> Service Information Report not available for SMPTE2110-40 Ancillary Data streams");
			dc++;
		} else
		if (di->payloadType == PAYLOAD_A324_CTP) {
			ui_buf_printf(d, dc, 0, " -> Service Information Report not available for A/324 Studio Transmitter Link CTP streams");
			dc++;
		} else
		if (di->payloadType == PAYLOAD_BYTE_STREAM) {
			ui_buf_printf(d, dc, 0, " -> Service Information Report not available for unidentified byte streams");
			dc++;
		} else {
			ui_buf_printf(d, dc, 0, " -> Service Information Report");
		}

		struct ltntstools_pat_s *m = NULL;
		if (di->streamModel && ltntstools_streammodel_query_model(di->streamModel, &m) == 0) {

			/* Now that we have a working stream model, look PCR for each stream
			 * and establish a clock analyzer through the stats infrastructure.
			 * We'll do this during the program pid enumeration below.
			 */

			int mpts = ltntstools_streammodel_is_model_mpts(di->streamModel, m);

			ui_buf_printf(d, dc, 31, "%s", mpts ? "MPTS" : "SPTS");

			dc++;
			ui_buf_printf(d, dc, 4, "programs: %d  pat-tsid: 0x%04x  version: %d  CNI: %d",
				m->program_count,
				m->transport_stream_id,
				m->version_number,
				m->current_next_indicator);

			dc++;
			ui_buf_printf(d, dc, 4, "prog#  PMT_PID ----->  PCR_PID ----->  Streams  ES_PID ----->  TYPE  Description");

			for (unsigned int p = 0; p < m->program_count; p++) {

				int has_scte35 = ltntstools_descriptor_list_contains_scte35_cue_registration(&m->programs[p].pmt.descr_list);
				int has_smpte2038 = 0;

				dc++;
				if (m->programs[p].program_number == 0) {
					ui_buf_printf(d, dc, 1, "   %5d        -        -        -       -     -  Network Information Table",
						m->programs[p].program_number);
				} else {
					ui_buf_printf(d, dc, 1, "   %5d   0x%04x (%4d)   0x%04x (%4d)      %3d",
						m->programs[p].program_number,
						m->programs[p].program_map_PID,
						m->programs[p].program_map_PID,
						m->programs[p].pmt.PCR_PID,
						m->programs[p].pmt.PCR_PID,
						m->programs[p].pmt.stream_count);

					/* PCR pids are registered with the stats by discovered_items_periodic(). */
				}
				for (unsigned int s = 0; s < m->programs[p].pmt.stream_count; s++) {
					if (s > 0)
						dc++;

					char iso639_lang[64] = { 0 };
					unsigned int audio_type = 0;
					unsigned char lbl[16] = { 0 };
					int x = ltntstools_descriptor_list_contains_iso639_audio_descriptor(&m->programs[p].pmt.streams[s].descr_list, &lbl[0], &audio_type);
					if (x) {
						snprintf(&iso639_lang[0], sizeof(iso639_lang), "'%s' Type: %s",
							lbl,
							audio_type == 0 ? "None" :
							audio_type == 1 ? "Clean effects" :
							audio_type == 2 ? "Hearing impaired" :
							audio_type == 3 ? "Visual impaired commentary" : "Reserved");
					}

					const char *esDesc = ltntstools_GetESPayloadTypeDescription(m->programs[p].pmt.streams[s].stream_type);
					if (m->programs[p].pmt.streams[s].elementary_PID < 0x10) {
						ui_buf_set_pair(d, 4);
					}
					ui_buf_printf(d, dc, 52, "0x%04x (%4d)  0x%02x  %.*s%s",
						m->programs[p].pmt.streams[s].elementary_PID,
						m->programs[p].pmt.streams[s].elementary_PID,
						m->programs[p].pmt.streams[s].stream_type,
						52,
						esDesc,
						strlen(esDesc) >= 52 ? "..." : "");
					if (m->programs[p].pmt.streams[s].elementary_PID < 0x10) {
						ui_buf_set_pair(d, 0);
					}

					if (x) {
						dc++;
						ui_buf_printf(d, dc, 54, "lang: %s", iso639_lang);
					}

					if (m->programs[p].pmt.streams[s].stream_type  == 0x06 /* Private PES */) {
						has_smpte2038 = ltntstools_descriptor_list_contains_smpte2038_registration(&m->programs[p].pmt.streams[s].descr_list);
					}

					if (m->programs[p].pmt.streams[s].stream_type  == 0x1b /* H.264 */) {

						int slicesEnabled = 0;
						struct h264_slice_counter_results_s slices;

						pthread_mutex_lock(&di->h264_sliceLock);
						if (di->h264_slices) {
							/* discovered_items_periodic() points the counter at an H.264 pid. */
							if (h264_slice_counter_get_pid(di->h264_slices) == m->programs[p].pmt.streams[s].elementary_PID) {
								slicesEnabled = 1;
								h264_slice_counter_query(di->h264_slices, &slices);
							}
						}
						pthread_mutex_unlock(&di->h264_sliceLock);

						/* The strings are read under the lock that guards their writer. */
						pthread_mutex_lock(&di->h264_metadataLock);
						if (di->h264_metadata_parser) {
							dc++;
							ui_buf_printf(d, dc, 54, "%s", di->h264_video_colorspace);
							dc++;
							ui_buf_printf(d, dc, 54, "%s", di->h264_video_format);
						}
						pthread_mutex_unlock(&di->h264_metadataLock);

						if (slicesEnabled) {
							dc++;
							ui_buf_printf(d, dc, 54, "I: %'" PRIu64 " B: %'" PRIu64 " P: %'" PRIu64 " : %s...",
								slices.i, slices.b, slices.p,
								slices.sliceHistory);
						}

					} /* If H264 */

					if (m->programs[p].pmt.streams[s].stream_type  == 0x24 /* H.265 */) {

						/* The strings are read under the lock that guards their writer. */
						pthread_mutex_lock(&di->h265_metadataLock);
						if (di->h265_metadata_parser) {
							dc++;
							ui_buf_printf(d, dc, 54, "%s", di->h265_video_colorspace);
							dc++;
							ui_buf_printf(d, dc, 54, "%s", di->h265_video_format);
						}
						pthread_mutex_unlock(&di->h265_metadataLock);

					} /* If H.265 / HEVC */

				}

				if (m->programs[p].pmt.stream_count > 0) {
					dc++;
					ui_buf_printf(d, dc, 54, "SCTE35 Registration: %s", has_scte35 ? "Yes" : "No");
					dc++;
					ui_buf_printf(d, dc, 54, "SMPTE2038 Registration: %s", has_smpte2038 ? "Yes" : "No");
				}

				unsigned int major, minor, patch;
				int ret = ltntstools_descriptor_list_contains_ltn_encoder_sw_version(&m->programs[p].pmt.descr_list,
					&major, &minor, &patch);
				if (ret == 1) {
					dc++;
					ui_buf_printf(d, dc, 54, "LTN Encoder S/W: %d.%d.%d / Latency: ",
						major, minor, patch);

					int64_t ms = ltntstools_probe_ltnencoder_get_total_latency(di->LTNLatencyProbe);
					if (ms >= 0) {
						ui_buf_printf(d, dc, 89, "%" PRIi64 "ms", ms);
					} else {
						ui_buf_printf(d, dc, 89, "n/a");
					}
				} else {
					if (ctx->measureSEILatencyAlways) {
						/* Measure latency thorugh video transformers that strip the PMT ES encoder descriptor. */
						dc++;

						int64_t ms = ltntstools_probe_ltnencoder_get_total_latency(di->LTNLatencyProbe);
						if (ms >= 0) {
							ui_buf_printf(d, dc, 54, "Latency: %" PRIi64 "ms", ms);
						} else {
							ui_buf_printf(d, dc, 54, "Latency n/a");
						}
					}
				}

				if (m->programs[p].program_number > 0 && m->programs[p].pmt.PCR_PID) {
					int64_t pcr = ltntstools_pid_stats_pid_get_pcr(di->stats, m->programs[p].pmt.PCR_PID);
					char *ts = NULL;
					ltntstools_pcr_to_ascii(&ts, pcr);
					if (ts) {
						ui_buf_printf(d, dc - 1, 82, "PCR: %s", ts);
						free(ts);
					}
				}

				if (0) {
					dc++;
					struct ltntstools_pid_statistics_s *pid = ltntstools_pid_stats_get(di->stats, m->programs[p].pmt.PCR_PID);
					if (pid) {
						ui_buf_printf(d, dc, 52, "PCR Drift (us): %7" PRIi64 ", %" PRIi64 " %" PRIi64 " %" PRIi64,
							pid->clocks[ltntstools_CLOCK_PCR].drift_us,
							pid->clocks[ltntstools_CLOCK_PCR].drift_us_lwm,
							pid->clocks[ltntstools_CLOCK_PCR].drift_us_hwm,
							pid->clocks[ltntstools_CLOCK_PCR].drift_us_max
							);
					}
				}

				if (m->programs[p].service_name[0] && m->programs[p].service_provider[0]) {
					dc++;
					ui_buf_printf(d, dc, 52, "Service/Provider: '%s' / '%s'",
						m->programs[p].service_name,
						m->programs[p].service_provider);
				} else {
					if (m->programs[p].service_name[0]) {
						dc++;
						ui_buf_printf(d, dc, 52, "Service: '%s'",
							m->programs[p].service_name);
					}
					if (m->programs[p].service_name[0]) {
						dc++;
						ui_buf_printf(d, dc, 52, "Provider: '%s'",
							m->programs[p].service_provider);
					}
				}

			} /* For each program */

			ltntstools_pat_free(m);
			dc++;
		}
	}

	if (discovered_item_state_get(di, DI_STATE_SHOW_STREAM_LOG)) {
		dc = d->lineCount;
		pthread_mutex_lock(&di->doc_stream_log.lock);
		ui_buf_printf(d, dc, 0, " -> Stream Log / Report, %d line%s", di->doc_stream_log.lineCount,
			di->doc_stream_log.lineCount == 1 ? "" : "s");
		for (int i = 0; i < di->doc_stream_log.lineCount; i++) {
			dc++;
			ui_buf_printf(d, dc, 8, "%s", (const char *)di->doc_stream_log.lines[i]);
		}
		pthread_mutex_unlock(&di->doc_stream_log.lock);
	}

	if (discovered_item_state_get(di, DI_STATE_SHOW_SCTE35)) {
		ui_build_scte35(d, di, d->lineCount, now);
	}

	ui_buf_set_pair(d, 0);
	ui_buf_set_owner(d, 0);
}

/* DETAIL for a cursor stream with no reports open. Caller holds ctx->lock. */
static void ui_build_summary(struct ui_buf_s *d, struct discovered_item_s *di, int header)
{
	char first[64];

	time_t fs = di->firstSeen;
	ctime_r(&fs, first);
	first[strcspn(first, "\n")] = 0;

	int row = d->lineCount;
	if (row > 0)
		row++; /* Blank line between streams */

	ui_buf_set_owner(d, di->id);
	ui_build_stream_header(d, di, row, header);
	ui_buf_printf(d, row + 1, 1, "First seen %s   packets %'" PRIu64 "   CC errors %" PRIu64 "   IAT high-water %d ms   flags %s",
		first,
		ltntstools_pid_stats_stream_get_packet_count(di->stats),
		ltntstools_pid_stats_stream_get_cc_errors(di->stats),
		di->iat_hwm_us / 1000,
		di->warningIndicatorLabel);
	ui_buf_printf(d, row + 3, 1, "No reports open for this stream. Open one with:");
	ui_buf_printf(d, row + 4, 4, "P  PID traffic     C  Clock          M  PSIP model     L  Stream log");
	ui_buf_printf(d, row + 5, 4, "I  IAT histogram   s  Socket/process T  TR101290       3  SCTE-35");
	ui_buf_set_owner(d, 0);
}

static void ui_build_title(struct ui_state_s *st)
{
	struct tool_context_s *ctx = st->ctx;
	struct in_addr ip_net, ip_mask;
	char net[32], mask[32];

	ip_net.s_addr = ctx->netp;
	ip_mask.s_addr = ctx->maskp;
	inet_ntop(AF_INET, &ip_net, net, sizeof(net));
	inet_ntop(AF_INET, &ip_mask, mask, sizeof(mask));

	snprintf(st->titleA, sizeof(st->titleA), "%s", ctx->pcap_filter);
	st->titleC[0] = 0;

	if (ctx->iftype == IF_TYPE_PCAP) {
		snprintf(st->titleC, sizeof(st->titleC), "NIC: %s (%s/%s) Dropped: %d/%d", ctx->ifname, net, mask,
			ctx->pcap_stats.ps_drop,
			ctx->pcap_stats.ps_ifdrop);
	} else
	if (ctx->iftype == IF_TYPE_MPEGTS_FILE) {
		snprintf(st->titleC, sizeof(st->titleC), "%s: %s @ %6.2f%%", ctx->fileLoops ? "LOOP" : "FILE",
			ctx->ifname, ctx->fileLoopPct);
	} else
	if (ctx->iftype == IF_TYPE_MPEGTS_AVDEVICE) {
		snprintf(st->titleA, sizeof(st->titleA), "NIC Monitor");
		snprintf(st->titleC, sizeof(st->titleC), "URL: %s", ctx->ifname);
	}

	st->titleAlert = ctx->pcap_stats.ps_drop || ctx->pcap_stats.ps_ifdrop;
}

static void ui_build(struct ui_state_s *st, time_t now)
{
	struct tool_context_s *ctx = st->ctx;
	double totalMbps = 0, totalRxMbps = 0, totalTxMbps = 0;
	int totalStreams = 0;

	ui_buf_reset(&st->list);
	ui_buf_reset(&st->detail);
	for (int p = 0; p < st->paneCount; p++) {
		ui_buf_reset(&st->pane[p].buf);
		st->pane[p].found = 0;
	}
	ui_build_title(st);

	/* Keep the previous order for cursor repair. */
	if (st->streamCount && st->prevOrder)
		memcpy(st->prevOrder, st->order, st->streamCount * sizeof(uint32_t));
	st->prevCount = st->streamCount;
	st->streamCount = 0;
	st->detailWanted = 0;

	pthread_mutex_lock(&ctx->lock);

	/* Pass 1: visible streams, so the cursor can be repaired before drawing. */
	struct discovered_item_s *di = NULL;
	int visible = 0;
	xorg_list_for_each_entry(di, &ctx->list, list) {
		if (!discovered_item_state_get(di, DI_STATE_HIDDEN))
			visible++;
	}

	int count = 0;
	int tagged = 0;
	if (ui_streams_reserve(st, visible) == UI_OK) {
		xorg_list_for_each_entry(di, &ctx->list, list) {
			if (discovered_item_state_get(di, DI_STATE_HIDDEN))
				continue;
			st->order[count++] = di->id;
			if (discovered_item_state_get(di, DI_STATE_TAGGED))
				tagged++;
		}
	}
	st->taggedCount = tagged;
	if (tagged)
		st->detailWanted = 1;

	uint32_t cursorId = __atomic_load_n(&ctx->uiCursorId, __ATOMIC_ACQUIRE);
	cursorId = ui_cursor_repair(st->prevOrder, st->prevCount, st->order, count, cursorId);
	__atomic_store_n(&ctx->uiCursorId, cursorId, __ATOMIC_RELEASE);

	/* Pass 2: rows and reports. */
	int i = 0;
	xorg_list_for_each_entry(di, &ctx->list, list) {
		if (discovered_item_state_get(di, DI_STATE_HIDDEN))
			continue;
		if (i >= count)
			break;

		int first = st->list.lineCount;
		ui_build_stream(st, di, cursorId, &totalRxMbps, &totalTxMbps, &totalMbps);
		totalStreams++;

		struct ui_stream_info_s *info = &st->streams[i];
		info->id = di->id;
		snprintf(info->label, sizeof(info->label), "%s -> %s", di->srcaddr, di->dstaddr);
		ui_report_letters(di, info->reports, sizeof(info->reports));
		st->heights[i] = st->list.lineCount - first;
		i++;

		if (discovered_item_state_get(di, ui_report_flags()))
			st->detailWanted = 1;

		/* Detail windows: each open window shows its own stream. */
		for (int p = 0; p < st->paneCount; p++) {
			if (st->pane[p].id != di->id)
				continue;
			st->pane[p].found = 1;
			if (discovered_item_state_get(di, ui_report_flags()))
				ui_build_reports(st, &st->pane[p].buf, di, now, 0);
			else
				ui_build_summary(&st->pane[p].buf, di, 0);
		}

		/* The single panel (only without windows): every tagged stream, or
		 * the cursor stream when none are tagged.
		 */
		int inDetail = st->paneCount ? 0 :
			tagged ? discovered_item_state_get(di, DI_STATE_TAGGED) != 0 : di->id == cursorId;
		if (inDetail) {
			if (discovered_item_state_get(di, ui_report_flags()))
				ui_build_reports(st, &st->detail, di, now, tagged > 1);
			else
				ui_build_summary(&st->detail, di, tagged > 1);
		}
	}
	st->streamCount = i;
	ui_scroll_mem_prune(&st->scrollMem, st->order, st->streamCount);

	/* Close windows whose stream vanished or was hidden. */
	int w = 0;
	for (int p = 0; p < st->paneCount; p++) {
		if (st->pane[p].found) {
			if (w != p) {
				struct ui_buf_s keep = st->pane[w].buf;  /* Reuse the closed slot's allocations */
				st->pane[w] = st->pane[p];
				st->pane[p].buf = keep;
			}
			w++;
		} else if (st->focus == UI_FOCUS_PANE && st->focusPane >= w && st->focusPane > 0) {
			st->focusPane--;
		}
	}
	st->paneCount = w;
	if (st->paneCount == 0 && st->focus == UI_FOCUS_PANE)
		st->focus = UI_FOCUS_LIST;
	if (st->paneCount)
		st->detailWanted = 1;

	pthread_mutex_unlock(&ctx->lock);

	char s[64];
	ctime_r(&now, s);
	s[strcspn(s, "\n")] = 0;
	snprintf(st->statusA, sizeof(st->statusA), "%s       T:%7.02f R:%7.02f %7.02f / %d stream%s",
		s, totalTxMbps, totalRxMbps, totalMbps, totalStreams, totalStreams == 1 ? "" : "s");

	time_t reset = ctx->lastResetTime;
	ctime_r(&reset, s);
	s[strcspn(s, "\n")] = 0;
	snprintf(st->statusC, sizeof(st->statusC), "Since: %s", s);

	st->memStatus[0] = 0;
	if (ctx->reportProcessMemoryUsage) {
		if (process_memory_snprintf(&ctx->memUsageStatus[0], sizeof(ctx->memUsageStatus), &ctx->memUsage, 5, FALSE) == 0) {
			snprintf(st->memStatus, sizeof(st->memStatus), "Memory: %s", ctx->memUsageStatus);
		}
	}
}

/* ------------------------------------------------------------------ */
/* INPUT                                                              */
/* ------------------------------------------------------------------ */

/* Focus a detail window. The cursor follows it, so report keys (P, C, I, ...)
 * act on the stream of the window being looked at.
 */
static void ui_pane_focus(struct ui_state_s *st, int p)
{
	if (p < 0 || p >= st->paneCount)
		return;

	st->focus = UI_FOCUS_PANE;
	st->focusPane = p;
	__atomic_store_n(&st->ctx->uiCursorId, st->pane[p].id, __ATOMIC_RELEASE);
}

/* Opens a detail window for a stream (or focuses it if already open). */
static void ui_pane_open(struct ui_state_s *st, uint32_t id)
{
	if (!id)
		return;

	for (int p = 0; p < st->paneCount; p++) {
		if (st->pane[p].id == id) {
			ui_pane_focus(st, p);
			return;
		}
	}
	if (st->paneCount == UI_PANE_MAX) {
		ui_message_post(&st->ctx->uiMessage, time(NULL), 4, "At most %d detail windows: x closes the focused one", UI_PANE_MAX);
		return;
	}

	struct ui_pane_s *pn = &st->pane[st->paneCount];
	struct ui_buf_s keep = pn->buf;
	memset(pn, 0, sizeof(*pn));
	pn->buf = keep;
	pn->id = id;
	pn->weight = 1;
	pn->found = 1;
	st->paneCount++;
	ui_pane_focus(st, st->paneCount - 1);
}

static void ui_pane_close(struct ui_state_s *st, int p)
{
	if (p < 0 || p >= st->paneCount)
		return;

	struct ui_buf_s keep = st->pane[p].buf;
	for (int i = p; i < st->paneCount - 1; i++)
		st->pane[i] = st->pane[i + 1];
	st->pane[--st->paneCount].buf = keep;

	if (st->paneCount == 0) {
		st->focus = UI_FOCUS_LIST;
	} else {
		ui_pane_focus(st, st->focusPane >= st->paneCount ? st->paneCount - 1 : st->focusPane);
	}
}

static void ui_pane_scroll(struct ui_state_s *st, int p, enum ui_cursor_move_e move, int lines)
{
	if (p < 0 || p >= st->paneCount)
		return;

	struct ui_pane_s *pn = &st->pane[p];
	int rows = p < st->panesShown ? st->paneBody[p].h : 1;
	if (rows < 1)
		rows = 1;

	switch (move) {
	case UI_CURSOR_UP:        pn->top -= lines; break;
	case UI_CURSOR_DOWN:      pn->top += lines; break;
	case UI_CURSOR_PAGE_UP:   pn->top -= rows; break;
	case UI_CURSOR_PAGE_DOWN: pn->top += rows; break;
	case UI_CURSOR_HOME:      pn->top = 0; break;
	case UI_CURSOR_END:       pn->top = pn->buf.lineCount; break;
	default: break;
	}
	if (pn->top < 0)
		pn->top = 0;
}

static void ui_cursor_move(struct ui_state_s *st, enum ui_cursor_move_e move, int repeat)
{
	struct tool_context_s *ctx = st->ctx;
	uint32_t cursorId = __atomic_load_n(&ctx->uiCursorId, __ATOMIC_ACQUIRE);
	int rows = st->layout.area[UI_AREA_LIST].h;

	for (int i = 0; i < repeat; i++)
		cursorId = ui_cursor_apply(st->order, st->heights, st->streamCount, cursorId, move, rows);

	__atomic_store_n(&ctx->uiCursorId, cursorId, __ATOMIC_RELEASE);
}

static void ui_detail_scroll(struct ui_state_s *st, enum ui_cursor_move_e move, int lines)
{
	int rows = st->layout.area[UI_AREA_DETAIL].h;
	if (rows < 1)
		rows = 1;

	switch (move) {
	case UI_CURSOR_UP:        st->view.detailTop -= lines; break;
	case UI_CURSOR_DOWN:      st->view.detailTop += lines; break;
	case UI_CURSOR_PAGE_UP:   st->view.detailTop -= rows; break;
	case UI_CURSOR_PAGE_DOWN: st->view.detailTop += rows; break;
	case UI_CURSOR_HOME:      st->view.detailTop = 0; break;
	case UI_CURSOR_END:       st->view.detailTop = st->detail.lineCount; break;
	default: break;
	}
	/* Clamped against the content when the frame is presented. */
	if (st->view.detailTop < 0)
		st->view.detailTop = 0;
}

static void ui_navigate(struct ui_state_s *st, enum ui_cursor_move_e move)
{
	if (st->focus == UI_FOCUS_PANE)
		ui_pane_scroll(st, st->focusPane, move, 1);
	else
	if (st->focus == UI_FOCUS_DETAIL && st->layout.detailVisible)
		ui_detail_scroll(st, move, 1);
	else
		ui_cursor_move(st, move, 1);
}

static void ui_hscroll(struct ui_state_s *st, int delta)
{
	if (st->focus == UI_FOCUS_PANE && st->focusPane < st->paneCount) {
		st->pane[st->focusPane].left += delta;
		if (st->pane[st->focusPane].left < 0)
			st->pane[st->focusPane].left = 0;
	} else
	if (st->focus == UI_FOCUS_DETAIL && st->layout.detailVisible) {
		st->view.detailLeft += delta;
		if (st->view.detailLeft < 0)
			st->view.detailLeft = 0;
	} else {
		st->view.listLeft += delta;
		if (st->view.listLeft < 0)
			st->view.listLeft = 0;
	}
}

/* +/-: with a detail window focused, grow/shrink that window against the
 * other windows; otherwise move the split between the list and the detail
 * area. Says so when nothing can change.
 */
static void ui_resize(struct ui_state_s *st, int dir)
{
	struct tool_context_s *ctx = st->ctx;
	time_t now = time(NULL);

	if (st->focus == UI_FOCUS_PANE && st->focusPane < st->paneCount) {
		if (st->paneCount < 2) {
			ui_message_post(&ctx->uiMessage, now, 3, "Only one detail window: +/- from the list resizes the detail area");
			return;
		}
		struct ui_pane_s *pn = &st->pane[st->focusPane];
		int w = pn->weight + dir;
		if (w >= UI_PANE_WEIGHT_MIN && w <= UI_PANE_WEIGHT_MAX) {
			pn->weight = w;
			return;
		}
		/* Already at weight 1: shrinking it means growing the others. */
		if (dir < 0) {
			int grown = 0;
			for (int p = 0; p < st->paneCount; p++) {
				if (p != st->focusPane && st->pane[p].weight < UI_PANE_WEIGHT_MAX) {
					st->pane[p].weight++;
					grown++;
				}
			}
			if (grown)
				return;
		}
		ui_message_post(&ctx->uiMessage, now, 3, "Detail window is already at its %s size", dir > 0 ? "largest" : "smallest");
		return;
	}

	int pct = ui_detail_pct_adjust(st->detailPct, dir * UI_DETAIL_PCT_STEP);

	/* Would the screen change? Compare the layouts at both percentages. */
	struct ui_layout_s a, b;
	int lines = st->layout.lines, cols = st->layout.cols;
	ui_layout_compute_zoom(lines, cols, st->detailWanted, st->detailPct, st->zoom, &a);
	ui_layout_fit_list(&a, st->list.lineCount);
	ui_layout_compute_zoom(lines, cols, st->detailWanted, pct, st->zoom, &b);
	ui_layout_fit_list(&b, st->list.lineCount);
	st->detailPct = pct;

	if (ui_layout_equal(&a, &b)) {
		if (!a.detailVisible)
			ui_message_post(&ctx->uiMessage, now, 3, "No detail area open");
		else if (a.zoomed)
			ui_message_post(&ctx->uiMessage, now, 3, "Full screen: z or Esc to leave it first");
		else if (dir > 0)
			ui_message_post(&ctx->uiMessage, now, 3, "The detail area already has every row the stream list doesn't need");
		else
			ui_message_post(&ctx->uiMessage, now, 3, "The detail area is at its smallest%s",
				st->paneCount > 1 ? "; focus a window to resize the windows" : "");
	}
}

static void ui_handle_key(struct ui_state_s *st, int key)
{
	struct tool_context_s *ctx = st->ctx;

	if (st->helpOpen) {
		switch (key) {
		case 27: case 'h': case '?': case KEY_F(1):
			st->helpOpen = 0;
			return;
		/* Scroll the help when it doesn't fit (clamped when drawn). */
		case KEY_UP: case 'k':     st->helpTop--; return;
		case KEY_DOWN: case 'j':   st->helpTop++; return;
		case KEY_PPAGE:            st->helpTop -= 10; return;
		case KEY_NPAGE:            st->helpTop += 10; return;
		case KEY_HOME: case 'g':   st->helpTop = 0; return;
		case KEY_END: case 'G':    st->helpTop = 1000; return;
		default: break;
		}
	}

	switch (key) {
	case 'h':
	case '?':
	case KEY_F(1):
		st->helpOpen = !st->helpOpen;
		st->helpTop = 0;
		break;
	case '\t':
	case KEY_BTAB:
		if (st->panesShown > 0) {
			/* LIST -> window 1 -> ... -> window N -> LIST (Shift-Tab reverses). */
			int pos = st->focus == UI_FOCUS_PANE ? st->focusPane + 1 : 0;
			int n = st->panesShown + 1;
			pos = (pos + (key == KEY_BTAB ? n - 1 : 1)) % n;
			if (pos == 0) {
				st->focus = UI_FOCUS_LIST;
			} else {
				ui_pane_focus(st, pos - 1);
			}
		} else
		if (st->layout.detailVisible)
			st->focus = (st->focus == UI_FOCUS_LIST) ? UI_FOCUS_DETAIL : UI_FOCUS_LIST;
		break;
	case '\n':
	case '\r':
	case KEY_ENTER:
		/* A detail window for the cursor stream. */
		ui_pane_open(st, __atomic_load_n(&ctx->uiCursorId, __ATOMIC_ACQUIRE));
		break;
	case 'x':
		if (st->focus == UI_FOCUS_PANE)
			ui_pane_close(st, st->focusPane);
		else if (st->paneCount)
			ui_message_post(&ctx->uiMessage, time(NULL), 3, "Focus a detail window first (Tab or click), then x closes it");
		break;
	case 'z':
		/* Full screen: LIST shrinks to the cursor row, detail takes the rest. */
		st->zoom = !st->zoom;
		if (st->zoom && st->focus == UI_FOCUS_LIST)
			st->focus = st->paneCount ? UI_FOCUS_PANE : UI_FOCUS_DETAIL;
		break;
	case 27:
		if (st->zoom) {
			st->zoom = 0;
			st->focus = UI_FOCUS_LIST;
		} else
		if (st->focus == UI_FOCUS_DETAIL || st->focus == UI_FOCUS_PANE) {
			st->focus = UI_FOCUS_LIST;
		} else {
			pthread_mutex_lock(&ctx->lock);
			int anyTagged = discovered_items_any_tagged_locked(ctx);
			pthread_mutex_unlock(&ctx->lock);
			if (anyTagged) {
				discovered_items_tag_none(ctx);
				ui_message_post(&ctx->uiMessage, time(NULL), 3, "Tags cleared");
			}
		}
		break;
	case '+':
	case '-':
		ui_resize(st, key == '+' ? 1 : -1);
		break;
	case KEY_UP:
	case 'k':
		ui_navigate(st, UI_CURSOR_UP);
		break;
	case KEY_DOWN:
	case 'j':
		ui_navigate(st, UI_CURSOR_DOWN);
		break;
	case KEY_PPAGE:
		ui_navigate(st, UI_CURSOR_PAGE_UP);
		break;
	case KEY_NPAGE:
		ui_navigate(st, UI_CURSOR_PAGE_DOWN);
		break;
	case KEY_HOME:
	case 'g':
		ui_navigate(st, UI_CURSOR_HOME);
		break;
	case KEY_END:
	case 'G':
		ui_navigate(st, UI_CURSOR_END);
		break;
	case KEY_LEFT:
		ui_hscroll(st, -8);
		break;
	case KEY_RIGHT:
		ui_hscroll(st, 8);
		break;
	default:
		break;
	}
}

static void ui_handle_mouse(struct ui_state_s *st, const struct ui_event_s *ev)
{
	struct tool_context_s *ctx = st->ctx;

	if (st->helpOpen) {
		int inside = ev->y >= st->overlayY && ev->y < st->overlayY + st->overlayH &&
			ev->x >= st->overlayX && ev->x < st->overlayX + st->overlayW;
		if (!inside && (ev->buttons & UI_MOUSE_CLICK))
			st->helpOpen = 0;
		else if (ev->buttons & UI_MOUSE_WHEEL_UP)
			st->helpTop -= 3;
		else if (ev->buttons & UI_MOUSE_WHEEL_DOWN)
			st->helpTop += 3;   /* Clamped when drawn */
		return;
	}

	/* Detail windows first: they sit over the DETAIL area. */
	for (int p = 0; p < st->panesShown; p++) {
		const struct ui_rect_s *b = &st->paneBar[p], *d = &st->paneBody[p];
		if (ev->y < b->y || ev->y >= d->y + d->h)
			continue;
		ui_pane_focus(st, p);
		if (ev->buttons & UI_MOUSE_WHEEL_UP)
			ui_pane_scroll(st, p, UI_CURSOR_UP, 3);
		else if (ev->buttons & UI_MOUSE_WHEEL_DOWN)
			ui_pane_scroll(st, p, UI_CURSOR_DOWN, 3);
		return;
	}

	/* Resolved against the frame on screen when the user clicked. */
	struct ui_hit_s hit;
	if (ui_hit_test(&st->layout, &st->view, &st->list, &st->detail, &st->hints, ev->y, ev->x, &hit) != UI_OK)
		return;

	switch (hit.area) {
	case UI_AREA_LIST:
		st->focus = UI_FOCUS_LIST;
		if (ev->buttons & UI_MOUSE_WHEEL_UP) {
			ui_cursor_move(st, UI_CURSOR_UP, 3);
		} else
		if (ev->buttons & UI_MOUSE_WHEEL_DOWN) {
			ui_cursor_move(st, UI_CURSOR_DOWN, 3);
		} else
		if ((ev->buttons & UI_MOUSE_CLICK) && hit.ownerId) {
			__atomic_store_n(&ctx->uiCursorId, hit.ownerId, __ATOMIC_RELEASE);
			/* The tag column is the first two cells of the stream row. */
			if (ev->x + st->view.listLeft < 2 && ui_buf_line_owner(&st->list, hit.line - 1) != hit.ownerId) {
				discovered_items_tag_toggle_id(ctx, hit.ownerId);
				st->lastClick.ownerId = 0;   /* Tag clicks never pair into a double-click. */
			} else
			if (ui_click_register(&st->lastClick, hit.ownerId, ev->timeMs, UI_DOUBLE_CLICK_MS)) {
				/* Double-click toggles this stream's detail window: closes it
				 * if open, else opens one with the model report. Each
				 * double-clicked stream gets its own window.
				 */
				int open = -1;
				for (int p = 0; p < st->paneCount; p++) {
					if (st->pane[p].id == hit.ownerId)
						open = p;
				}
				if (open >= 0) {
					ui_pane_close(st, open);
					/* The double-click was in the list: focus and cursor stay there. */
					st->focus = UI_FOCUS_LIST;
					__atomic_store_n(&ctx->uiCursorId, hit.ownerId, __ATOMIC_RELEASE);
					return;
				}
				int r = discovered_items_show_streammodel_id(ctx, hit.ownerId);
				ui_pane_open(st, hit.ownerId);
				if (r == 1)
					ui_message_post(&ctx->uiMessage, time(NULL), 3, "PSIP model report opened (M closes it)");
			}
		}
		break;
	case UI_AREA_DETAIL:
	case UI_AREA_DETAIL_BAR:
		st->focus = UI_FOCUS_DETAIL;
		if (ev->buttons & UI_MOUSE_WHEEL_UP)
			ui_detail_scroll(st, UI_CURSOR_UP, 3);
		else if (ev->buttons & UI_MOUSE_WHEEL_DOWN)
			ui_detail_scroll(st, UI_CURSOR_DOWN, 3);
		break;
	case UI_AREA_HINTS:
		if ((ev->buttons & UI_MOUSE_CLICK) && hit.key) {
			if (nic_monitor_ui_is_ui_key(hit.key))
				ui_handle_key(st, hit.key);
			else
				nic_monitor_ui_command(ctx, hit.key);
		}
		break;
	default:
		break;
	}
}

static void ui_input(struct ui_state_s *st)
{
	struct ui_event_s ev[UI_EVENT_QUEUE_LEN];
	int n = ui_event_queue_drain(&st->ctx->uiEvents, ev, UI_EVENT_QUEUE_LEN);

	for (int i = 0; i < n; i++) {
		if (ev[i].type == UI_EVENT_KEY)
			ui_handle_key(st, ev[i].key);
		else if (ev[i].type == UI_EVENT_MOUSE)
			ui_handle_mouse(st, &ev[i]);
	}
}

/* ------------------------------------------------------------------ */
/* PRESENT (ctx->ui_threadLock held)                                  */
/* ------------------------------------------------------------------ */

static void ui_hint(char *buf, size_t size, struct ui_hint_map_s *map, const char *label, int key)
{
	size_t len = strlen(buf);
	if (len + strlen(label) + 2 >= size)
		return;
	if (key)
		ui_hint_map_add(map, (int)len, (int)(len + strlen(label)) - 1, key);
	snprintf(buf + len, size - len, "%s  ", label);
}

/* "label" followed by keys, each key its own click target: "reports PCMLIsT3". */
static void ui_hint_keys(char *buf, size_t size, struct ui_hint_map_s *map, const char *label, const char *keys)
{
	size_t len = strlen(buf);
	size_t need = strlen(label) + 1 + strlen(keys) + 2;
	if (len + need >= size)
		return;

	snprintf(buf + len, size - len, "%s ", label);
	len = strlen(buf);
	for (const char *k = keys; *k; k++) {
		ui_hint_map_add(map, (int)len, (int)len, *k);
		buf[len++] = *k;
	}
	snprintf(buf + len, size - len, "  ");
}

static const struct ui_stream_info_s *ui_stream_info(const struct ui_state_s *st, uint32_t id, int *index)
{
	for (int i = 0; i < st->streamCount; i++) {
		if (st->streams[i].id == id) {
			if (index)
				*index = i;
			return &st->streams[i];
		}
	}
	return NULL;
}

static void ui_compose_hints(struct ui_state_s *st, char *out, size_t size, int cols)
{
	struct tool_context_s *ctx = st->ctx;
	struct ui_hint_map_s *m = &st->hints;

	out[0] = 0;
	ui_hint_map_reset(m);

	if (__atomic_load_n(&ctx->showForwardOptions, __ATOMIC_ACQUIRE)) {
		ui_hint(out, size, m, "7", '7');
		ui_hint(out, size, m, "8", '8');
		ui_hint(out, size, m, "9", '9');
		ui_hint(out, size, m, "choose a forward destination", 0);
		ui_hint(out, size, m, "q cancel", 'q');
		return;
	}
	if (st->helpOpen) {
		ui_hint(out, size, m, "Esc close help", 27);
		ui_hint(out, size, m, "Up/Dn PgUp/PgDn scroll help", 0);
		return;
	}

	ui_hint(out, size, m, "q quit", 'q');
	ui_hint(out, size, m, "h help", 'h');
	if (st->focus == UI_FOCUS_PANE) {
		ui_hint(out, size, m, "Tab next", '\t');
		ui_hint(out, size, m, "Up/Dn PgUp/PgDn scroll", 0);
		ui_hint(out, size, m, "+/- size", '+');
		ui_hint(out, size, m, "x close", 'x');
		ui_hint(out, size, m, "z zoom", 'z');
		ui_hint(out, size, m, "Esc list", 27);
	} else
	if (st->focus == UI_FOCUS_DETAIL && st->layout.detailVisible) {
		ui_hint(out, size, m, "Tab list", '\t');
		ui_hint(out, size, m, "Up/Dn PgUp/PgDn scroll", 0);
		ui_hint(out, size, m, "+ grow", '+');
		ui_hint(out, size, m, "- shrink", '-');
		ui_hint(out, size, m, "Esc back", 27);
	} else {
		ui_hint(out, size, m, "Up/Dn PgUp/PgDn move", 0);
		ui_hint(out, size, m, "Space tag", ' ');
		ui_hint(out, size, m, "Enter window", '\n');
		ui_hint_keys(out, size, m, "reports", "PCMLIsT3");
	}
	if (__atomic_load_n(&ctx->uiMouseEnabled, __ATOMIC_ACQUIRE))
		ui_hint(out, size, m, "m mouse", 'm');

	/* Right-aligned: which streams are on screen. */
	int rows = st->layout.area[UI_AREA_LIST].h;
	if (st->streamCount && rows > 0) {
		int a = -1, b = -1;
		for (int r = 0; r < rows; r++) {
			int idx;
			uint32_t owner = ui_buf_line_owner(&st->list, st->view.listTop + r);
			if (owner && ui_stream_info(st, owner, &idx)) {
				if (a < 0)
					a = idx;
				b = idx;
			}
		}
		char pos[64];
		snprintf(pos, sizeof(pos), "%sstreams %d-%d of %d%s",
			st->view.listTop > 0 ? "^ " : "",
			a + 1, b + 1, st->streamCount,
			st->view.listTop + rows < st->list.lineCount ? " v" : "");
		int len = strlen(out);
		while (len > 0 && out[len - 1] == ' ')
			out[--len] = 0;
		int plen = strlen(pos);
		if (len + 1 + plen <= cols && a >= 0) {
			int pad = cols - len - plen;
			if (pad > 0 && len + pad + plen < (int)size) {
				memset(out + len, ' ', pad);
				snprintf(out + len + pad, size - len - pad, "%s", pos);
			}
		}
	}
}

static void ui_compose_status(struct ui_state_s *st, char *out, size_t size, int cols)
{
	/* Drop the least important parts first when the terminal is narrow. */
	int a = strlen(st->statusA);
	int c = strlen(st->statusC);
	int m = strlen(st->memStatus);

	if (a + c + m + 4 <= cols && m) {
		int pad = cols - a - c - m - 2;
		snprintf(out, size, "%s  %s%*s%s", st->statusA, st->memStatus, pad, "", st->statusC);
	} else
	if (a + c + 1 <= cols) {
		snprintf(out, size, "%s%*s%s", st->statusA, cols - a - c, "", st->statusC);
	} else {
		snprintf(out, size, "%s", st->statusA);
	}
}

static void ui_compose_title(struct ui_state_s *st, char *out, size_t size, int cols)
{
	int a = strlen(st->titleA);
	int c = strlen(st->titleC);
	if (a + c + 1 <= cols)
		snprintf(out, size, "%s%*s%s", st->titleA, cols - a - c, "", st->titleC);
	else
		snprintf(out, size, "%s  %s", st->titleA, st->titleC);
}

static void ui_compose_message(struct ui_state_s *st, char *out, size_t size, time_t now, int frozen, int *pair)
{
	struct tool_context_s *ctx = st->ctx;
	*pair = 0;

	if (__atomic_load_n(&ctx->showForwardOptions, __ATOMIC_ACQUIRE)) {
		snprintf(out, size, "Forward to: 7) %s  8) %s  9) %s",
			ctx->url_forwards[0].uilabel,
			ctx->url_forwards[1].uilabel,
			ctx->url_forwards[2].uilabel);
		*pair = UI_PAIR_FOCUS;
		return;
	}
	if (ui_message_get(&ctx->uiMessage, now, out, size)) {
		*pair = UI_PAIR_HINT;
		return;
	}
	if (frozen) {
		snprintf(out, size, "Display frozen, analysis continues. Press f to resume.");
		*pair = UI_PAIR_WARN;
		return;
	}
	if (st->list.truncated || st->detail.truncated) {
		snprintf(out, size, "Display truncated at %d lines; close some reports.", UI_BUF_MAX_LINES);
		*pair = UI_PAIR_WARN;
		return;
	}
	out[0] = 0;
}

static void ui_compose_detail_bar(struct ui_state_s *st, char *out, size_t size, int cols)
{
	int rows = st->layout.area[UI_AREA_DETAIL].h;
	uint32_t owner = ui_buf_line_owner(&st->detail, st->view.detailTop);
	const struct ui_stream_info_s *info = ui_stream_info(st, owner, NULL);

	char right[64];
	int last = st->view.detailTop + rows;
	if (last > st->detail.lineCount)
		last = st->detail.lineCount;
	snprintf(right, sizeof(right), " lines %d-%d of %d -- ",
		st->detail.lineCount ? st->view.detailTop + 1 : 0, last, st->detail.lineCount);

	char left[200];
	char what[32];
	if (st->taggedCount)
		snprintf(what, sizeof(what), "%d tagged stream%s -- ", st->taggedCount, st->taggedCount == 1 ? "" : "s");
	else
		what[0] = 0;
	snprintf(left, sizeof(left), "-- %s: %s%s -- %s ", st->layout.zoomed ? "Full screen (Esc back)" : "Detail",
		what, info ? info->label : "", info ? info->reports : "");

	int l = strlen(left), r = strlen(right);
	if (l + r <= cols && cols < (int)size) {
		memset(out, '-', cols);
		out[cols] = 0;
		memcpy(out, left, l);
		memcpy(out + cols - r, right, r);
	} else {
		snprintf(out, size, "%s", left);
	}
}

static void ui_compose_pane_bar(struct ui_state_s *st, int p, int shown, char *out, size_t size, int cols)
{
	struct ui_pane_s *pn = &st->pane[p];
	const struct ui_stream_info_s *info = ui_stream_info(st, pn->id, NULL);
	int rows = st->paneBody[p].h;

	char more[48] = "";
	if (p == shown - 1 && st->paneCount > shown)
		snprintf(more, sizeof(more), "+%d more -- ", st->paneCount - shown);

	char right[96];
	int last = pn->top + rows;
	if (last > pn->buf.lineCount)
		last = pn->buf.lineCount;
	snprintf(right, sizeof(right), " %slines %d-%d of %d -- ", more,
		pn->buf.lineCount ? pn->top + 1 : 0, last, pn->buf.lineCount);

	char left[200];
	snprintf(left, sizeof(left), "-- [%d/%d] %s -- %s ", p + 1, st->paneCount,
		info ? info->label : "", info ? info->reports : "");

	int l = strlen(left), r = strlen(right);
	if (l + r <= cols && cols < (int)size) {
		memset(out, '-', cols);
		out[cols] = 0;
		memcpy(out, left, l);
		memcpy(out + cols - r, right, r);
	} else {
		snprintf(out, size, "%s", left);
	}
}

static void ui_dump_frame(struct ui_state_s *st, time_t now)
{
	if (!st->dumpPath || st->lastDump == now)
		return;
	st->lastDump = now;

	FILE *fh = fopen(st->dumpPath, "w");
	if (!fh)
		return;

	fprintf(fh, "frame %ld size %dx%d tooSmall %d detailVisible %d focus %s help %d cursor %u\n",
		(long)now, st->layout.lines, st->layout.cols, st->layout.tooSmall,
		st->layout.detailVisible, st->focus == UI_FOCUS_DETAIL ? "detail" : "list", st->helpOpen,
		__atomic_load_n(&st->ctx->uiCursorId, __ATOMIC_ACQUIRE));

	static const char *names[UI_AREA_MAX] = {
		"TITLE", "COLHDR", "LIST", "DETAIL_BAR", "DETAIL", "MESSAGE", "STATUS", "HINTS"
	};
	char line[2048];
	for (int a = 0; a < UI_AREA_MAX; a++) {
		WINDOW *w = st->screen.win[a];
		if (!w)
			continue;
		int h, wd;
		getmaxyx(w, h, wd);
		if (wd >= (int)sizeof(line))
			wd = sizeof(line) - 1;
		for (int r = 0; r < h; r++) {
			mvwinnstr(w, r, 0, line, wd);
			fprintf(fh, "%-10s|%s\n", names[a], line);
		}
	}
	for (int p = 0; p < st->screen.paneCount; p++) {
		WINDOW *ws[2] = { st->screen.paneBar[p], st->screen.paneBody[p] };
		for (int k = 0; k < 2; k++) {
			int h, wd;
			getmaxyx(ws[k], h, wd);
			if (wd >= (int)sizeof(line))
				wd = sizeof(line) - 1;
			for (int r = 0; r < h; r++) {
				mvwinnstr(ws[k], r, 0, line, wd);
				fprintf(fh, "PANE%d%-5s|%s\n", p + 1, k ? "BODY" : "BAR", line);
			}
		}
	}
	fclose(fh);
}

static void ui_present(struct ui_state_s *st, time_t now, int frozen)
{
	struct tool_context_s *ctx = st->ctx;
	char text[1024];

	pthread_mutex_lock(&ctx->ui_threadLock);

	/* Layout from the current terminal size; resizeterm() runs in the main
	 * thread's getch() under this same lock (rule R1).
	 */
	int lines, cols;
	getmaxyx(stdscr, lines, cols);

	struct ui_layout_s l;
	ui_layout_compute_zoom(lines, cols, st->detailWanted, st->detailPct, st->zoom, &l);
	ui_layout_fit_list(&l, st->list.lineCount);

	/* Windows match the layout before anything is drawn (rule R2). */
	if (ui_screen_apply_layout(&st->screen, &l) != UI_OK)
		l.tooSmall = 1;

	st->layout = l;

	if (l.tooSmall) {
		ui_screen_draw_too_small(&st->screen, lines, cols);
		ui_screen_present(&st->screen);
		ui_hint_map_reset(&st->hints);
		pthread_mutex_unlock(&ctx->ui_threadLock);
		return;
	}

	if (!l.detailVisible && (st->focus == UI_FOCUS_DETAIL || st->focus == UI_FOCUS_PANE))
		st->focus = UI_FOCUS_LIST;

	/* LIST follows the cursor. */
	int listRows = l.area[UI_AREA_LIST].h;
	uint32_t cursorId = __atomic_load_n(&ctx->uiCursorId, __ATOMIC_ACQUIRE);
	int first, last;
	if (cursorId && ui_buf_find_owner_range(&st->list, cursorId, &first, &last) == UI_OK)
		st->view.listTop = ui_scroll_to_cursor(st->view.listTop, listRows, first, last);
	st->view.listTop = ui_scroll_clamp(st->view.listTop, st->list.lineCount, listRows);
	st->view.listLeft = ui_hscroll_clamp(st->view.listLeft, ui_buf_max_width(&st->list), cols);

	/* DETAIL shows the cursor stream: when the cursor moves, restore where
	 * that stream's detail was left.
	 */
	int detailRows = l.area[UI_AREA_DETAIL].h;
	uint32_t subject = st->taggedCount ? UI_DETAIL_TAGGED : cursorId;
	if (subject != st->detailSubject) {
		if (subject == UI_DETAIL_TAGGED) {
			st->view.detailTop = st->taggedTop;
			st->view.detailLeft = st->taggedLeft;
		} else {
			ui_scroll_mem_get(&st->scrollMem, subject, &st->view.detailTop, &st->view.detailLeft);
		}
		st->detailSubject = subject;
	}
	st->view.detailTop = ui_scroll_clamp(st->view.detailTop, st->detail.lineCount, detailRows);
	st->view.detailLeft = ui_hscroll_clamp(st->view.detailLeft, ui_buf_max_width(&st->detail), cols);
	if (subject == UI_DETAIL_TAGGED) {
		st->taggedTop = st->view.detailTop;
		st->taggedLeft = st->view.detailLeft;
	} else if (subject) {
		ui_scroll_mem_set(&st->scrollMem, subject, st->view.detailTop, st->view.detailLeft);
	}

	ui_compose_title(st, text, sizeof(text), cols);
	ui_screen_draw_line(st->screen.win[UI_AREA_TITLE], st->titleAlert ? UI_PAIR_ALERT : UI_PAIR_BAR, text);

	/* With two scrollable areas on screen, the focused one's bar is
	 * highlighted: COLHDR for LIST, DETAIL_BAR for DETAIL.
	 */
	const char *hdr = UI_COLHDR;
	int hl = strlen(hdr);
	ui_screen_draw_line(st->screen.win[UI_AREA_COLHDR],
		(l.detailVisible && st->focus == UI_FOCUS_LIST) ? UI_PAIR_FOCUS : UI_PAIR_BAR,
		st->view.listLeft < hl ? hdr + st->view.listLeft : "");

	ui_screen_draw_buf(st->screen.win[UI_AREA_LIST], &st->list, st->view.listTop, st->view.listLeft);

	/* Detail windows, stacked in the detail region. */
	struct ui_rect_s bars[UI_PANE_MAX], bodies[UI_PANE_MAX];
	int weights[UI_PANE_MAX];
	for (int p = 0; p < st->paneCount && p < UI_PANE_MAX; p++)
		weights[p] = st->pane[p].weight;
	int shown = ui_detail_split(&l, st->paneCount, weights, bars, bodies, UI_PANE_MAX);
	if (ui_screen_apply_panes(&st->screen, bars, bodies, shown) != UI_OK)
		shown = 0;
	st->panesShown = shown;
	memcpy(st->paneBar, bars, shown * sizeof(bars[0]));
	memcpy(st->paneBody, bodies, shown * sizeof(bodies[0]));
	if (st->focus == UI_FOCUS_PANE && st->focusPane >= shown) {
		if (shown)
			ui_pane_focus(st, shown - 1);
		else
			st->focus = UI_FOCUS_LIST;
	}

	for (int p = 0; p < shown; p++) {
		struct ui_pane_s *pn = &st->pane[p];
		pn->top = ui_scroll_clamp(pn->top, pn->buf.lineCount, bodies[p].h);
		pn->left = ui_hscroll_clamp(pn->left, ui_buf_max_width(&pn->buf), cols);
		ui_compose_pane_bar(st, p, shown, text, sizeof(text), cols);
		ui_screen_draw_line(st->screen.paneBar[p],
			(st->focus == UI_FOCUS_PANE && st->focusPane == p) ? UI_PAIR_FOCUS : UI_PAIR_BAR, text);
		ui_screen_draw_buf(st->screen.paneBody[p], &pn->buf, pn->top, pn->left);
	}

	if (l.detailVisible && shown == 0) {
		ui_compose_detail_bar(st, text, sizeof(text), cols);
		ui_screen_draw_line(st->screen.win[UI_AREA_DETAIL_BAR],
			st->focus == UI_FOCUS_DETAIL ? UI_PAIR_FOCUS : UI_PAIR_BAR, text);
		ui_screen_draw_buf(st->screen.win[UI_AREA_DETAIL], &st->detail, st->view.detailTop, st->view.detailLeft);
	}

	int pair;
	ui_compose_message(st, text, sizeof(text), now, frozen, &pair);
	ui_screen_draw_line(st->screen.win[UI_AREA_MESSAGE], pair, text);

	ui_compose_status(st, text, sizeof(text), cols);
	ui_screen_draw_line(st->screen.win[UI_AREA_STATUS], UI_PAIR_BAR, text);

	ui_compose_hints(st, text, sizeof(text), cols);
	ui_screen_draw_line(st->screen.win[UI_AREA_HINTS], UI_PAIR_HINT, text);

	if (st->helpOpen) {
		ui_screen_draw_overlay(&st->screen, "Help", g_help, &st->helpTop);
		if (st->screen.overlay) {
			getbegyx(st->screen.overlay, st->overlayY, st->overlayX);
			getmaxyx(st->screen.overlay, st->overlayH, st->overlayW);
		}
	} else {
		ui_screen_close_overlay(&st->screen);
		st->overlayH = st->overlayW = 0;
	}

	ui_screen_present(&st->screen);
	ui_dump_frame(st, now);

	pthread_mutex_unlock(&ctx->ui_threadLock);
}

/* ------------------------------------------------------------------ */
/* Thread                                                             */
/* ------------------------------------------------------------------ */

void *nic_monitor_ui_thread_func(void *p)
{
	struct tool_context_s *ctx = p;

	ltnpthread_setname_np(ctx->ui_threadId, "tstools-ui");
	pthread_detach(pthread_self());

	struct ui_state_s *st = calloc(1, sizeof(*st));
	if (!st) {
		__atomic_store_n(&ctx->ui_threadTerminated, 1, __ATOMIC_RELEASE);
		pthread_exit(NULL);
		return NULL;
	}

	st->ctx = ctx;
	st->detailPct = UI_DETAIL_PCT_DEFAULT;
	st->dumpPath = getenv("NIC_MONITOR_UI_DUMP");
	ui_buf_init(&st->list);
	ui_buf_init(&st->detail);
	ui_screen_init(&st->screen);

	ctx->ui_threadRunning = 1;

	while (!__atomic_load_n(&ctx->ui_threadTerminate, __ATOMIC_ACQUIRE)) {
		time_t now = time(NULL);

		ui_input(st);

		/* Frozen: keep the last frame's content, but still redraw it so
		 * scrolling and terminal resizes work (rule R4).
		 */
		int frozen = __atomic_load_n(&ctx->freezeDisplay, __ATOMIC_RELAXED) & 1;
		if (!frozen)
			ui_build(st, now);

		ui_present(st, now, frozen);

		/* Sleep until the next frame, or until input arrives. */
		ui_event_queue_wait(&ctx->uiEvents, UI_FRAME_MS);
	}

	pthread_mutex_lock(&ctx->ui_threadLock);
	ui_screen_free(&st->screen);
	pthread_mutex_unlock(&ctx->ui_threadLock);

	if (st->items) {
		ltntstools_proc_net_udp_item_free(ctx->procNetUDPContext, st->items);
		st->items = NULL;
	}
	ui_buf_free(&st->list);
	ui_buf_free(&st->detail);
	ui_scroll_mem_free(&st->scrollMem);
	for (int p = 0; p < UI_PANE_MAX; p++)
		ui_buf_free(&st->pane[p].buf);
	free(st->streams);
	free(st->order);
	free(st->prevOrder);
	free(st->heights);
	free(st);

	__atomic_store_n(&ctx->ui_threadTerminated, 1, __ATOMIC_RELEASE);

	pthread_exit(NULL);
	return NULL;
}
