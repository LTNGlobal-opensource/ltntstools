#include <string.h>
#include <stdlib.h>

#include "nic_monitor_ui_layout.h"

static int clampi(int v, int lo, int hi)
{
	if (v < lo)
		return lo;
	if (v > hi)
		return hi;
	return v;
}

int ui_detail_pct_adjust(int pct, int delta)
{
	return clampi(pct + delta, UI_DETAIL_PCT_MIN, UI_DETAIL_PCT_MAX);
}

static void set_rect(struct ui_layout_s *out, enum ui_area_e a, int y, int h, int w)
{
	out->area[a].y = y;
	out->area[a].x = 0;
	out->area[a].h = h;
	out->area[a].w = w;
}

int ui_layout_compute(int lines, int cols, int detailWanted, int detailPct,
	struct ui_layout_s *out)
{
	if (!out)
		return UI_ERR_INVAL;

	memset(out, 0, sizeof(*out));
	out->lines = lines;
	out->cols = cols;

	if (lines < UI_LAYOUT_MIN_LINES || cols < UI_LAYOUT_MIN_COLS) {
		out->tooSmall = 1;
		return UI_OK;
	}

	detailPct = clampi(detailPct, UI_DETAIL_PCT_MIN, UI_DETAIL_PCT_MAX);

	int avail = lines - UI_LAYOUT_FIXED_ROWS;
	int listH = avail;
	int detailH = 0;

	if (detailWanted && avail >= UI_LAYOUT_LIST_MIN + 1 + UI_LAYOUT_DETAIL_MIN) {
		detailH = (avail * detailPct + 50) / 100;
		detailH = clampi(detailH, UI_LAYOUT_DETAIL_MIN, avail - 1 - UI_LAYOUT_LIST_MIN);
		listH = avail - 1 - detailH;
		out->detailVisible = 1;
	}

	int y = 0;
	set_rect(out, UI_AREA_TITLE, y, 1, cols);       y += 1;
	set_rect(out, UI_AREA_COLHDR, y, 1, cols);      y += 1;
	set_rect(out, UI_AREA_LIST, y, listH, cols);    y += listH;
	if (out->detailVisible) {
		set_rect(out, UI_AREA_DETAIL_BAR, y, 1, cols); y += 1;
		set_rect(out, UI_AREA_DETAIL, y, detailH, cols); y += detailH;
	} else {
		set_rect(out, UI_AREA_DETAIL_BAR, y, 0, cols);
		set_rect(out, UI_AREA_DETAIL, y, 0, cols);
	}
	set_rect(out, UI_AREA_MESSAGE, y, 1, cols);     y += 1;
	set_rect(out, UI_AREA_STATUS, y, 1, cols);      y += 1;
	set_rect(out, UI_AREA_HINTS, y, 1, cols);

	return UI_OK;
}

int ui_layout_compute_zoom(int lines, int cols, int detailWanted, int detailPct, int zoom,
	struct ui_layout_s *out)
{
	if (!zoom || lines < UI_LAYOUT_ZOOM_MIN_LINES)
		return ui_layout_compute(lines, cols, detailWanted, detailPct, out);

	int ret = ui_layout_compute(lines, cols, 0, detailPct, out);
	if (ret != UI_OK || out->tooSmall)
		return ret;

	int avail = lines - UI_LAYOUT_FIXED_ROWS;
	int y = 2;
	set_rect(out, UI_AREA_LIST, y, 1, cols);            y += 1;
	set_rect(out, UI_AREA_DETAIL_BAR, y, 1, cols);      y += 1;
	set_rect(out, UI_AREA_DETAIL, y, avail - 2, cols);
	out->detailVisible = 1;
	out->zoomed = 1;

	return UI_OK;
}

void ui_layout_fit_list(struct ui_layout_s *l, int listContentLines)
{
	if (!l || l->tooSmall || !l->detailVisible || l->zoomed)
		return;

	int want = listContentLines < UI_LAYOUT_LIST_MIN ? UI_LAYOUT_LIST_MIN : listContentLines;
	int spare = l->area[UI_AREA_LIST].h - want;
	if (spare <= 0)
		return;

	l->area[UI_AREA_LIST].h -= spare;
	l->area[UI_AREA_DETAIL_BAR].y -= spare;
	l->area[UI_AREA_DETAIL].y -= spare;
	l->area[UI_AREA_DETAIL].h += spare;
}

int ui_layout_equal(const struct ui_layout_s *a, const struct ui_layout_s *b)
{
	if (!a || !b)
		return 0;
	if (a->lines != b->lines || a->cols != b->cols)
		return 0;
	if (a->tooSmall != b->tooSmall || a->detailVisible != b->detailVisible || a->zoomed != b->zoomed)
		return 0;
	return memcmp(a->area, b->area, sizeof(a->area)) == 0;
}

int ui_scroll_clamp(int top, int totalLines, int rows)
{
	if (rows < 1)
		return 0;
	int max = totalLines - rows;
	if (max < 0)
		max = 0;
	return clampi(top, 0, max);
}

int ui_scroll_to_cursor(int top, int rows, int curFirst, int curLast)
{
	if (rows < 1 || curFirst < 0)
		return top < 0 ? 0 : top;
	if (curLast < curFirst)
		curLast = curFirst;

	if (curLast - curFirst + 1 > rows)
		return curFirst;
	if (curFirst < top)
		return curFirst;
	if (curLast >= top + rows)
		return curLast - rows + 1;
	return top < 0 ? 0 : top;
}

int ui_hscroll_clamp(int left, int contentWidth, int cols)
{
	if (cols < 1)
		return 0;
	int max = contentWidth - cols;
	if (max < 0)
		max = 0;
	return clampi(left, 0, max);
}

static int index_of(const uint32_t *order, int count, uint32_t id)
{
	if (!order)
		return -1;
	for (int i = 0; i < count; i++) {
		if (order[i] == id)
			return i;
	}
	return -1;
}

uint32_t ui_cursor_apply(const uint32_t *order, const int *heights, int count,
	uint32_t cursorId, enum ui_cursor_move_e move, int pageRows)
{
	if (!order || count <= 0)
		return 0;

	int i = index_of(order, count, cursorId);
	if (i < 0)
		i = 0;

	if (pageRows < 1)
		pageRows = 1;

	switch (move) {
	case UI_CURSOR_UP:
		if (i > 0)
			i--;
		break;
	case UI_CURSOR_DOWN:
		if (i < count - 1)
			i++;
		break;
	case UI_CURSOR_PAGE_UP: {
		int used = 0;
		while (i > 0) {
			int h = heights ? heights[i - 1] : 1;
			if (h < 1)
				h = 1;
			if (used + h > pageRows && used > 0)
				break;
			used += h;
			i--;
		}
		break;
	}
	case UI_CURSOR_PAGE_DOWN: {
		int used = 0;
		while (i < count - 1) {
			int h = heights ? heights[i] : 1;
			if (h < 1)
				h = 1;
			if (used + h > pageRows && used > 0)
				break;
			used += h;
			i++;
		}
		break;
	}
	case UI_CURSOR_HOME:
		i = 0;
		break;
	case UI_CURSOR_END:
		i = count - 1;
		break;
	case UI_CURSOR_NONE:
	default:
		break;
	}

	return order[i];
}

uint32_t ui_cursor_repair(const uint32_t *prevOrder, int prevCount,
	const uint32_t *order, int count, uint32_t cursorId)
{
	if (!order || count <= 0)
		return 0;

	if (cursorId && index_of(order, count, cursorId) >= 0)
		return cursorId;

	int p = cursorId ? index_of(prevOrder, prevCount, cursorId) : -1;
	if (p < 0)
		return order[0];

	/* Nearest survivor after the old position, then before it. */
	for (int k = p + 1; k < prevCount; k++) {
		if (index_of(order, count, prevOrder[k]) >= 0)
			return prevOrder[k];
	}
	for (int k = p - 1; k >= 0; k--) {
		if (index_of(order, count, prevOrder[k]) >= 0)
			return prevOrder[k];
	}

	return order[0];
}

void ui_hint_map_reset(struct ui_hint_map_s *m)
{
	if (m)
		m->count = 0;
}

int ui_hint_map_add(struct ui_hint_map_s *m, int x0, int x1, int key)
{
	if (!m || x1 < x0)
		return UI_ERR_INVAL;
	if (m->count >= UI_HINT_MAX)
		return UI_ERR_FULL;

	m->item[m->count].x0 = x0;
	m->item[m->count].x1 = x1;
	m->item[m->count].key = key;
	m->count++;
	return UI_OK;
}

static int in_rect(const struct ui_rect_s *r, int y, int x)
{
	return r->h > 0 && y >= r->y && y < r->y + r->h && x >= r->x && x < r->x + r->w;
}

int ui_hit_test(const struct ui_layout_s *l, const struct ui_view_s *view,
	const struct ui_buf_s *listBuf, const struct ui_buf_s *detailBuf,
	const struct ui_hint_map_s *hints, int y, int x, struct ui_hit_s *out)
{
	if (!l || !view || !out)
		return UI_ERR_INVAL;

	out->area = UI_AREA_NONE;
	out->line = -1;
	out->ownerId = 0;
	out->key = 0;

	if (l->tooSmall)
		return UI_OK;

	for (int a = 0; a < UI_AREA_MAX; a++) {
		const struct ui_rect_s *r = &l->area[a];
		if (!in_rect(r, y, x))
			continue;

		out->area = (enum ui_area_e)a;

		if (a == UI_AREA_LIST || a == UI_AREA_DETAIL) {
			const struct ui_buf_s *b = (a == UI_AREA_LIST) ? listBuf : detailBuf;
			int top = (a == UI_AREA_LIST) ? view->listTop : view->detailTop;
			int line = top + (y - r->y);
			if (b && line >= 0 && line < b->lineCount) {
				out->line = line;
				out->ownerId = ui_buf_line_owner(b, line);
			}
		} else
		if (a == UI_AREA_HINTS && hints) {
			for (int i = 0; i < hints->count; i++) {
				if (x >= hints->item[i].x0 && x <= hints->item[i].x1) {
					out->key = hints->item[i].key;
					break;
				}
			}
		}
		break;
	}

	return UI_OK;
}

int ui_click_register(struct ui_click_s *prev, uint32_t ownerId, uint64_t timeMs, int intervalMs)
{
	if (!prev)
		return 0;

	if (ownerId && prev->ownerId == ownerId && timeMs >= prev->timeMs &&
		timeMs - prev->timeMs <= (uint64_t)intervalMs) {
		prev->ownerId = 0;
		prev->timeMs = 0;
		return 1;
	}

	prev->ownerId = ownerId;
	prev->timeMs = timeMs;
	return 0;
}

void ui_scroll_mem_free(struct ui_scroll_mem_s *m)
{
	if (!m)
		return;
	free(m->item);
	m->item = NULL;
	m->count = m->alloc = 0;
}

static int scroll_mem_find(const struct ui_scroll_mem_s *m, uint32_t id)
{
	for (int i = 0; i < m->count; i++) {
		if (m->item[i].id == id)
			return i;
	}
	return -1;
}

int ui_scroll_mem_set(struct ui_scroll_mem_s *m, uint32_t id, int top, int left)
{
	if (!m || id == 0)
		return UI_ERR_INVAL;

	int i = scroll_mem_find(m, id);
	if (i < 0) {
		if (m->count == m->alloc) {
			int n = m->alloc ? m->alloc * 2 : 32;
			void *p = realloc(m->item, (size_t)n * sizeof(*m->item));
			if (!p)
				return UI_ERR_NOMEM;
			m->item = p;
			m->alloc = n;
		}
		i = m->count++;
		m->item[i].id = id;
	}
	m->item[i].top = top;
	m->item[i].left = left;
	return UI_OK;
}

int ui_scroll_mem_get(const struct ui_scroll_mem_s *m, uint32_t id, int *top, int *left)
{
	int i = (m && id) ? scroll_mem_find(m, id) : -1;
	if (top)
		*top = i < 0 ? 0 : m->item[i].top;
	if (left)
		*left = i < 0 ? 0 : m->item[i].left;
	return i >= 0;
}

void ui_scroll_mem_prune(struct ui_scroll_mem_s *m, const uint32_t *ids, int count)
{
	if (!m)
		return;

	int w = 0;
	for (int i = 0; i < m->count; i++) {
		int keep = 0;
		for (int k = 0; ids && k < count; k++) {
			if (ids[k] == m->item[i].id) {
				keep = 1;
				break;
			}
		}
		if (keep)
			m->item[w++] = m->item[i];
	}
	m->count = w;
}

int ui_detail_split(const struct ui_layout_s *l, int paneCount, const int *weights,
	struct ui_rect_s *bars, struct ui_rect_s *bodies, int max)
{
	if (!l || !bars || !bodies || l->tooSmall || !l->detailVisible || paneCount <= 0 || max <= 0)
		return 0;

	const struct ui_rect_s *b = &l->area[UI_AREA_DETAIL_BAR];
	int y = b->y;
	int h = b->h + l->area[UI_AREA_DETAIL].h;
	int minPane = 1 + UI_PANE_MIN_BODY;

	int n = paneCount < max ? paneCount : max;
	if (n > UI_PANE_MAX)
		n = UI_PANE_MAX;
	if (n > h / minPane)
		n = h / minPane;
	if (n <= 0)
		return 0;

	int w[UI_PANE_MAX], wsum = 0;
	for (int i = 0; i < n; i++) {
		w[i] = weights ? clampi(weights[i], UI_PANE_WEIGHT_MIN, UI_PANE_WEIGHT_MAX) : 1;
		wsum += w[i];
	}

	/* Everyone gets the minimum; the rest is shared by weight. */
	int spare = h - n * minPane;
	int ph[UI_PANE_MAX], given = 0;
	for (int i = 0; i < n; i++) {
		ph[i] = minPane + spare * w[i] / wsum;
		given += ph[i];
	}
	/* Rounding leftovers: heaviest first, top first among equals. */
	while (given < h) {
		int best = 0;
		for (int i = 1; i < n; i++) {
			if (w[i] > w[best])
				best = i;
		}
		for (int i = 0; i < n && given < h; i++) {
			if (w[i] == w[best]) {
				ph[i]++;
				given++;
			}
		}
	}

	for (int i = 0; i < n; i++) {
		bars[i].y = y;
		bars[i].x = 0;
		bars[i].h = 1;
		bars[i].w = b->w;
		bodies[i].y = y + 1;
		bodies[i].x = 0;
		bodies[i].h = ph[i] - 1;
		bodies[i].w = b->w;
		y += ph[i];
	}
	return n;
}
