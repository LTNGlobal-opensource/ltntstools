#ifndef NIC_MONITOR_UI_LAYOUT_H
#define NIC_MONITOR_UI_LAYOUT_H

/* Screen layout, scrolling, cursor movement and mouse hit testing for the
 * nic_monitor UI. Pure functions, no curses and no locking, so every rule
 * here can be unit tested without a terminal.
 */

#include <stdint.h>

#include "nic_monitor_ui_buf.h"

enum ui_area_e
{
	UI_AREA_TITLE = 0,
	UI_AREA_COLHDR,
	UI_AREA_LIST,
	UI_AREA_DETAIL_BAR,
	UI_AREA_DETAIL,
	UI_AREA_MESSAGE,
	UI_AREA_STATUS,
	UI_AREA_HINTS,
	UI_AREA_MAX,
	UI_AREA_NONE = UI_AREA_MAX,
};

#define UI_LAYOUT_FIXED_ROWS   5   /* TITLE, COLHDR, MESSAGE, STATUS, HINTS */
#define UI_LAYOUT_LIST_MIN     3
#define UI_LAYOUT_DETAIL_MIN   4
#define UI_LAYOUT_MIN_COLS     40
#define UI_LAYOUT_MIN_LINES    (UI_LAYOUT_FIXED_ROWS + UI_LAYOUT_LIST_MIN)

#define UI_DETAIL_PCT_DEFAULT  50
#define UI_DETAIL_PCT_MIN      20
#define UI_DETAIL_PCT_MAX      80
#define UI_DETAIL_PCT_STEP     10

struct ui_rect_s
{
	int y, x, h, w;   /* h == 0: area not shown */
};

struct ui_layout_s
{
	int lines, cols;  /* Terminal size this layout was computed for */
	struct ui_rect_s area[UI_AREA_MAX];
	int detailVisible;
	int zoomed;       /* Full-screen detail: LIST is reduced to one row */
	int tooSmall;
};

/* Smallest terminal that can show the zoomed (full-screen detail) layout:
 * fixed rows + one LIST row + DETAIL_BAR + DETAIL_MIN.
 */
#define UI_LAYOUT_ZOOM_MIN_LINES (UI_LAYOUT_FIXED_ROWS + 1 + 1 + UI_LAYOUT_DETAIL_MIN)

/* Fills *out from the terminal size. detailWanted: at least one visible
 * stream has a report switched on. detailPct is clamped to
 * UI_DETAIL_PCT_MIN..UI_DETAIL_PCT_MAX. Returns UI_OK or UI_ERR_INVAL.
 */
int ui_layout_compute(int lines, int cols, int detailWanted, int detailPct,
	struct ui_layout_s *out);

/* As ui_layout_compute(), with zoom: when set, LIST is one row (the cursor
 * stream) and DETAIL takes the rest, whatever detailWanted says. Falls back
 * to the normal layout when the terminal is shorter than
 * UI_LAYOUT_ZOOM_MIN_LINES (out->zoomed tells which was used).
 */
int ui_layout_compute_zoom(int lines, int cols, int detailWanted, int detailPct, int zoom,
	struct ui_layout_s *out);

/* When DETAIL is visible (not zoomed) and the stream list needs fewer rows
 * than LIST was given, shrink LIST to its content (at least
 * UI_LAYOUT_LIST_MIN rows) and give the spare rows to DETAIL. A few streams
 * then stay visible above a nearly full-screen detail.
 */
void ui_layout_fit_list(struct ui_layout_s *l, int listContentLines);

/* Detail windows: the detail region (DETAIL_BAR + DETAIL) split into
 * stacked panes, one per open stream, each a 1-row bar plus a body of at
 * least UI_PANE_MIN_BODY rows. Rows above the minimum are shared in
 * proportion to weights[] (NULL = equal; each weight clamped to
 * UI_PANE_WEIGHT_MIN..MAX); leftover rows go to the heaviest panes, then the
 * top ones. Returns how many panes fit (<= paneCount, <= max); fills bars[]
 * and bodies[] for those.
 */
#define UI_PANE_MAX         8
#define UI_PANE_MIN_BODY    3
#define UI_PANE_WEIGHT_MIN  1
#define UI_PANE_WEIGHT_MAX  8

int ui_detail_split(const struct ui_layout_s *l, int paneCount, const int *weights,
	struct ui_rect_s *bars, struct ui_rect_s *bodies, int max);

int ui_layout_equal(const struct ui_layout_s *a, const struct ui_layout_s *b);

/* Clamp a detail percentage after a +/- key. */
int ui_detail_pct_adjust(int pct, int delta);

/* Vertical: first visible line, kept within 0..max(0, totalLines - rows). */
int ui_scroll_clamp(int top, int totalLines, int rows);

/* The smallest change to `top` that keeps lines curFirst..curLast visible.
 * If the block is taller than `rows`, curFirst is aligned to the top.
 */
int ui_scroll_to_cursor(int top, int rows, int curFirst, int curLast);

/* Horizontal: first visible column, kept within 0..max(0, width - cols). */
int ui_hscroll_clamp(int left, int contentWidth, int cols);

/* Cursor movement over the visible streams, in on-screen order. */
enum ui_cursor_move_e
{
	UI_CURSOR_NONE = 0,
	UI_CURSOR_UP,
	UI_CURSOR_DOWN,
	UI_CURSOR_PAGE_UP,
	UI_CURSOR_PAGE_DOWN,
	UI_CURSOR_HOME,
	UI_CURSOR_END,
};

/* order[count]: stream ids in display order. heights[count]: lines each
 * stream occupies in LIST (may be NULL, meaning 1 each); used to size a
 * page. Returns the new cursor id, or 0 when count == 0. A cursorId that is
 * not in `order` behaves as if it were on the first stream.
 */
uint32_t ui_cursor_apply(const uint32_t *order, const int *heights, int count,
	uint32_t cursorId, enum ui_cursor_move_e move, int pageRows);

/* Keeps the cursor on a stream that still exists. If cursorId is still in
 * `order`, it is returned unchanged. Otherwise the cursor moves to the
 * nearest surviving stream, looking forward from its old position in
 * prevOrder first, then backward. With no previous position, the first
 * stream is used. Returns 0 when `order` is empty.
 */
uint32_t ui_cursor_repair(const uint32_t *prevOrder, int prevCount,
	const uint32_t *order, int count, uint32_t cursorId);

/* Per-stream DETAIL scroll positions, so returning to a stream restores
 * where its detail view was left. Owned by the UI thread.
 */
struct ui_scroll_mem_s
{
	struct {
		uint32_t id;
		int top, left;
	} *item;
	int count, alloc;
};

void ui_scroll_mem_free(struct ui_scroll_mem_s *m);
/* Returns UI_OK, UI_ERR_INVAL (id 0 / NULL) or UI_ERR_NOMEM. */
int  ui_scroll_mem_set(struct ui_scroll_mem_s *m, uint32_t id, int top, int left);
/* Fills top/left (0, 0 when the stream has no entry). Returns 1 if found. */
int  ui_scroll_mem_get(const struct ui_scroll_mem_s *m, uint32_t id, int *top, int *left);
/* Drops entries for streams not in ids[count], bounding memory to the
 * number of streams that exist.
 */
void ui_scroll_mem_prune(struct ui_scroll_mem_s *m, const uint32_t *ids, int count);

/* Double-click detection. The UI turns off ncurses' own click resolution
 * (mouseinterval(0)) so single clicks respond immediately, and pairs clicks
 * itself: two clicks on the same stream within UI_DOUBLE_CLICK_MS.
 */
#define UI_DOUBLE_CLICK_MS 400

struct ui_click_s
{
	uint32_t ownerId;   /* 0 = no previous click */
	uint64_t timeMs;
};

/* Records a click on ownerId at timeMs. Returns 1 if it completes a
 * double-click (the state is then cleared, so a third click starts over),
 * else 0. Clicks on no stream (ownerId 0) never pair.
 */
int ui_click_register(struct ui_click_s *prev, uint32_t ownerId, uint64_t timeMs, int intervalMs);

/* Column ranges of the key labels drawn in HINTS, filled when HINTS is drawn. */
#define UI_HINT_MAX 32
struct ui_hint_map_s
{
	int count;
	struct {
		int x0, x1;   /* Inclusive column range */
		int key;
	} item[UI_HINT_MAX];
};

void ui_hint_map_reset(struct ui_hint_map_s *m);
int  ui_hint_map_add(struct ui_hint_map_s *m, int x0, int x1, int key);

/* Result of mapping a screen position onto the last frame drawn. */
struct ui_hit_s
{
	enum ui_area_e area;   /* UI_AREA_NONE when outside every area */
	int line;              /* LIST / DETAIL: buffer line, -1 when past the end */
	uint32_t ownerId;      /* LIST / DETAIL: stream owning that line, 0 = none */
	int key;               /* HINTS: key under the pointer, 0 = none */
};

struct ui_view_s
{
	int listTop, listLeft;
	int detailTop, detailLeft;
};

int ui_hit_test(const struct ui_layout_s *l, const struct ui_view_s *view,
	const struct ui_buf_s *listBuf, const struct ui_buf_s *detailBuf,
	const struct ui_hint_map_s *hints, int y, int x, struct ui_hit_s *out);

#endif /* NIC_MONITOR_UI_LAYOUT_H */
