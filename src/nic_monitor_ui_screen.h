#ifndef NIC_MONITOR_UI_SCREEN_H
#define NIC_MONITOR_UI_SCREEN_H

/* The curses side of the nic_monitor UI: one WINDOW per screen area.
 *
 * Threading: ncurses is not thread safe. Every function here must be called
 * with ctx->ui_threadLock held, the same lock the main thread holds around
 * getch(). None of them take ctx->lock.
 */

#include <curses.h>

#include "nic_monitor_ui_buf.h"
#include "nic_monitor_ui_layout.h"

/* Color pairs, initialized once after initscr(). */
#define UI_PAIR_BAR        1   /* White on blue: title, column header, status */
#define UI_PAIR_HINT       2   /* Cyan on black: hints */
#define UI_PAIR_ERROR      3   /* Red on black: CC errors, IAT exceeded */
#define UI_PAIR_ALERT      4   /* White on red: duplicates, drops, warnings */
#define UI_PAIR_CURSOR     5   /* White on green: the cursor stream */
#define UI_PAIR_FOCUS      6   /* Black on cyan: the focused area's bar */
#define UI_PAIR_WARN       7   /* Yellow on black: recorder falling behind */

void ui_screen_init_colors(void);

struct ui_screen_s
{
	WINDOW *win[UI_AREA_MAX];      /* NULL when the area is not shown */
	WINDOW *small;                 /* "Terminal too small" window */
	WINDOW *overlay;               /* Help pop-up, NULL when closed */
	struct ui_layout_s layout;     /* Layout the windows were created for */
	int haveLayout;

	/* Detail windows (one per open stream), drawn over the DETAIL_BAR /
	 * DETAIL area windows when any are open.
	 */
	WINDOW *paneBar[UI_PANE_MAX];
	WINDOW *paneBody[UI_PANE_MAX];
	struct ui_rect_s paneBarRect[UI_PANE_MAX];
	struct ui_rect_s paneBodyRect[UI_PANE_MAX];
	int paneCount;
};

void ui_screen_init(struct ui_screen_s *s);

/* Recreates the windows when the layout differs from the current one.
 * Must run before anything is drawn in a frame. Returns UI_OK, or
 * UI_ERR_NOMEM when a window could not be created (all windows are then
 * deleted and the caller should treat the frame as too small).
 */
int  ui_screen_apply_layout(struct ui_screen_s *s, const struct ui_layout_s *l);

/* Recreates the pane windows when their rectangles changed. n == 0 removes
 * them. Returns UI_OK or UI_ERR_NOMEM (all panes are then removed).
 */
int  ui_screen_apply_panes(struct ui_screen_s *s, const struct ui_rect_s *bars,
	const struct ui_rect_s *bodies, int n);

/* Draw a buffer slice into an area window. */
void ui_screen_draw_buf(WINDOW *w, const struct ui_buf_s *b, int top, int left);

/* Draw a single line, padded across the window in `pair`. */
void ui_screen_draw_line(WINDOW *w, int pair, const char *text);

/* Draw a line of mixed colors: text and per-cell pairs, `width` cells. */
void ui_screen_draw_cells(WINDOW *w, int row, const char *text, const unsigned char *pairs, int width);

/* "Terminal too small" screen. */
void ui_screen_draw_too_small(struct ui_screen_s *s, int lines, int cols);

/* Help pop-up: `lines` NULL terminated, shown from line *top. Recreated on
 * every call. *top is clamped to what fits; returns the number of lines
 * that don't fit (0 when everything is visible).
 */
int  ui_screen_draw_overlay(struct ui_screen_s *s, const char *title, const char **lines, int *top);
void ui_screen_close_overlay(struct ui_screen_s *s);
/* 1 when (y, x) is inside the open overlay. */
int  ui_screen_overlay_contains(const struct ui_screen_s *s, int y, int x);

/* wnoutrefresh() every window, overlay last, then one doupdate(). */
void ui_screen_present(struct ui_screen_s *s);

void ui_screen_free(struct ui_screen_s *s);

#endif /* NIC_MONITOR_UI_SCREEN_H */
