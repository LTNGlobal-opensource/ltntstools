#include <string.h>
#include <stdlib.h>

#include "nic_monitor_ui_screen.h"

void ui_screen_init_colors(void)
{
	start_color();
	init_pair(UI_PAIR_BAR, COLOR_WHITE, COLOR_BLUE);
	init_pair(UI_PAIR_HINT, COLOR_CYAN, COLOR_BLACK);
	init_pair(UI_PAIR_ERROR, COLOR_RED, COLOR_BLACK);
	init_pair(UI_PAIR_ALERT, COLOR_WHITE, COLOR_RED);
	init_pair(UI_PAIR_CURSOR, COLOR_WHITE, COLOR_GREEN);
	init_pair(UI_PAIR_FOCUS, COLOR_BLACK, COLOR_CYAN);
	init_pair(UI_PAIR_WARN, COLOR_YELLOW, COLOR_BLACK);
}

void ui_screen_init(struct ui_screen_s *s)
{
	memset(s, 0, sizeof(*s));
}

static void delete_panes(struct ui_screen_s *s)
{
	for (int i = 0; i < s->paneCount; i++) {
		if (s->paneBar[i])
			delwin(s->paneBar[i]);
		if (s->paneBody[i])
			delwin(s->paneBody[i]);
		s->paneBar[i] = s->paneBody[i] = NULL;
	}
	s->paneCount = 0;
}

int ui_screen_apply_panes(struct ui_screen_s *s, const struct ui_rect_s *bars,
	const struct ui_rect_s *bodies, int n)
{
	if (n == s->paneCount &&
		memcmp(bars, s->paneBarRect, n * sizeof(*bars)) == 0 &&
		memcmp(bodies, s->paneBodyRect, n * sizeof(*bodies)) == 0)
		return UI_OK;

	delete_panes(s);
	for (int i = 0; i < n; i++) {
		s->paneBar[i] = newwin(bars[i].h, bars[i].w, bars[i].y, bars[i].x);
		s->paneBody[i] = newwin(bodies[i].h, bodies[i].w, bodies[i].y, bodies[i].x);
		s->paneCount = i + 1;
		if (!s->paneBar[i] || !s->paneBody[i]) {
			delete_panes(s);
			return UI_ERR_NOMEM;
		}
		scrollok(s->paneBar[i], FALSE);
		scrollok(s->paneBody[i], FALSE);
		leaveok(s->paneBar[i], TRUE);
		leaveok(s->paneBody[i], TRUE);
		s->paneBarRect[i] = bars[i];
		s->paneBodyRect[i] = bodies[i];
	}
	return UI_OK;
}

static void delete_windows(struct ui_screen_s *s)
{
	ui_screen_close_overlay(s);
	delete_panes(s);
	for (int a = 0; a < UI_AREA_MAX; a++) {
		if (s->win[a]) {
			delwin(s->win[a]);
			s->win[a] = NULL;
		}
	}
	if (s->small) {
		delwin(s->small);
		s->small = NULL;
	}
}

int ui_screen_apply_layout(struct ui_screen_s *s, const struct ui_layout_s *l)
{
	if (s->haveLayout && ui_layout_equal(&s->layout, l))
		return UI_OK;

	delete_windows(s);
	s->layout = *l;
	s->haveLayout = 1;

	if (l->tooSmall)
		return UI_OK;

	for (int a = 0; a < UI_AREA_MAX; a++) {
		const struct ui_rect_s *r = &l->area[a];
		if (r->h <= 0 || r->w <= 0)
			continue;
		s->win[a] = newwin(r->h, r->w, r->y, r->x);
		if (!s->win[a]) {
			delete_windows(s);
			s->layout.tooSmall = 1;
			return UI_ERR_NOMEM;
		}
		/* Writing the bottom-right cell must not scroll the window. */
		scrollok(s->win[a], FALSE);
		leaveok(s->win[a], TRUE);
	}

	/* The old windows' contents are gone from the screen model: repaint all. */
	clearok(curscr, TRUE);
	return UI_OK;
}

void ui_screen_draw_cells(WINDOW *w, int row, const char *text, const unsigned char *pairs, int width)
{
	int x = 0;
	while (x < width) {
		int pair = pairs ? pairs[x] : 0;
		int e = x + 1;
		while (e < width && (pairs ? pairs[e] : 0) == pair)
			e++;
		if (pair)
			wattron(w, COLOR_PAIR(pair));
		mvwaddnstr(w, row, x, text + x, e - x);
		if (pair)
			wattroff(w, COLOR_PAIR(pair));
		x = e;
	}
}

void ui_screen_draw_buf(WINDOW *w, const struct ui_buf_s *b, int top, int left)
{
	if (!w)
		return;

	int h, wd;
	getmaxyx(w, h, wd);
	werase(w);

	char text[UI_BUF_MAX_COLS + 1024];
	unsigned char pairs[UI_BUF_MAX_COLS + 1024];
	/* ui_buf_line_cells() NUL terminates text[wd]. */
	if (wd > (int)sizeof(text) - 1)
		wd = sizeof(text) - 1;

	for (int r = 0; r < h; r++) {
		int line = top + r;
		if (line >= b->lineCount)
			break;
		ui_buf_line_cells(b, line, left, wd, text, pairs);
		ui_screen_draw_cells(w, r, text, pairs, wd);
	}
}

void ui_screen_draw_line(WINDOW *w, int pair, const char *text)
{
	if (!w)
		return;

	int h, wd;
	getmaxyx(w, h, wd);
	(void)h;
	werase(w);

	if (pair)
		wattron(w, COLOR_PAIR(pair));
	for (int x = 0; x < wd; x++)
		mvwaddch(w, 0, x, ' ');
	mvwaddnstr(w, 0, 0, text, wd);
	if (pair)
		wattroff(w, COLOR_PAIR(pair));
}

void ui_screen_draw_too_small(struct ui_screen_s *s, int lines, int cols)
{
	if (lines < 1 || cols < 1)
		return;

	if (!s->small)
		s->small = newwin(lines, cols, 0, 0);
	if (!s->small)
		return;

	werase(s->small);
	char msg[80];
	snprintf(msg, sizeof(msg), "Terminal too small (need %dx%d)", UI_LAYOUT_MIN_LINES, UI_LAYOUT_MIN_COLS);
	int len = strlen(msg);
	int x = (cols - len) / 2;
	if (x < 0)
		x = 0;
	mvwaddnstr(s->small, lines / 2, x, msg, cols - x);
}

void ui_screen_close_overlay(struct ui_screen_s *s)
{
	if (s->overlay) {
		delwin(s->overlay);
		s->overlay = NULL;
	}
}

int ui_screen_draw_overlay(struct ui_screen_s *s, const char *title, const char **lines, int *top)
{
	ui_screen_close_overlay(s);
	if (!s->haveLayout || s->layout.tooSmall)
		return 0;

	int n = 0, wmax = (int)strlen(title) + 6;
	while (lines[n]) {
		int len = strlen(lines[n]);
		if (len > wmax)
			wmax = len;
		n++;
	}

	int sl = s->layout.lines, sc = s->layout.cols;
	int h = n + 2, w = wmax + 4;
	if (h > sl - 2)
		h = sl - 2;
	if (w > sc)
		w = sc;
	if (h < 3 || w < 10)
		return 0;

	int rows = h - 2;
	int hidden = n - rows;
	if (hidden < 0)
		hidden = 0;
	if (*top > hidden)
		*top = hidden;
	if (*top < 0)
		*top = 0;

	s->overlay = newwin(h, w, (sl - h) / 2, (sc - w) / 2);
	if (!s->overlay)
		return hidden;

	werase(s->overlay);
	box(s->overlay, 0, 0);
	mvwprintw(s->overlay, 0, 2, " %s ", title);
	for (int i = 0; i < rows && *top + i < n; i++)
		mvwaddnstr(s->overlay, i + 1, 2, lines[*top + i], w - 4);
	if (hidden) {
		char note[64];
		snprintf(note, sizeof(note), " %s%s Up/Dn PgUp/PgDn scroll ",
			*top > 0 ? "^ " : "", *top < hidden ? "v more," : "");
		int len = strlen(note);
		if (len < w - 2)
			mvwaddstr(s->overlay, h - 1, w - len - 2, note);
	}
	return hidden;
}

int ui_screen_overlay_contains(const struct ui_screen_s *s, int y, int x)
{
	if (!s->overlay)
		return 0;

	int by, bx, h, w;
	getbegyx(s->overlay, by, bx);
	getmaxyx(s->overlay, h, w);
	return y >= by && y < by + h && x >= bx && x < bx + w;
}

void ui_screen_present(struct ui_screen_s *s)
{
	if (s->small)
		wnoutrefresh(s->small);
	for (int a = 0; a < UI_AREA_MAX; a++) {
		if (s->win[a])
			wnoutrefresh(s->win[a]);
	}
	/* Panes cover the DETAIL area windows, so they go after them. */
	for (int i = 0; i < s->paneCount; i++) {
		wnoutrefresh(s->paneBar[i]);
		wnoutrefresh(s->paneBody[i]);
	}
	if (s->overlay) {
		touchwin(s->overlay);
		wnoutrefresh(s->overlay);
	}
	doupdate();
}

void ui_screen_free(struct ui_screen_s *s)
{
	delete_windows(s);
	s->haveLayout = 0;
}
