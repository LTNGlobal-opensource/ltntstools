#include <stdlib.h>

#include "ui_test.h"
#include "nic_monitor_ui_layout.h"

/* Every visible area must be full width, areas must not overlap, and
 * together they must cover exactly `lines` rows.
 */
static void check_tiling(const struct ui_layout_s *l, int lines, int cols)
{
	if (l->tooSmall) {
		for (int a = 0; a < UI_AREA_MAX; a++)
			CHECK_INT(l->area[a].h, 0);
		return;
	}

	int covered[1024] = { 0 };
	int total = 0;
	for (int a = 0; a < UI_AREA_MAX; a++) {
		const struct ui_rect_s *r = &l->area[a];
		CHECK(r->h >= 0);
		if (r->h == 0)
			continue;
		CHECK_INT(r->x, 0);
		CHECK_INT(r->w, cols);
		for (int y = r->y; y < r->y + r->h; y++) {
			CHECK(y >= 0 && y < lines);
			if (y >= 0 && y < 1024) {
				CHECK_INT(covered[y], 0);
				covered[y] = 1;
			}
		}
		total += r->h;
	}
	CHECK_INT(total, lines);

	/* Fixed areas, in order, and always one row. */
	CHECK_INT(l->area[UI_AREA_TITLE].y, 0);
	CHECK_INT(l->area[UI_AREA_COLHDR].y, 1);
	CHECK_INT(l->area[UI_AREA_LIST].y, 2);
	CHECK_INT(l->area[UI_AREA_HINTS].y, lines - 1);
	CHECK_INT(l->area[UI_AREA_STATUS].y, lines - 2);
	CHECK_INT(l->area[UI_AREA_MESSAGE].y, lines - 3);
	if (l->zoomed)
		CHECK_INT(l->area[UI_AREA_LIST].h, 1);
	else
		CHECK(l->area[UI_AREA_LIST].h >= UI_LAYOUT_LIST_MIN);
	if (l->detailVisible) {
		CHECK_INT(l->area[UI_AREA_DETAIL_BAR].h, 1);
		CHECK(l->area[UI_AREA_DETAIL].h >= UI_LAYOUT_DETAIL_MIN);
	} else {
		CHECK_INT(l->area[UI_AREA_DETAIL_BAR].h, 0);
		CHECK_INT(l->area[UI_AREA_DETAIL].h, 0);
	}
}

static void test_layout_sweep(void)
{
	struct ui_layout_s l;

	for (int lines = 1; lines <= 200; lines++) {
		for (int cols = 20; cols <= 300; cols += 7) {
			for (int dw = 0; dw <= 1; dw++) {
				for (int pct = 0; pct <= 100; pct += 25) {
					CHECK_INT(ui_layout_compute(lines, cols, dw, pct, &l), UI_OK);
					int small = lines < UI_LAYOUT_MIN_LINES || cols < UI_LAYOUT_MIN_COLS;
					CHECK_INT(l.tooSmall, small);
					check_tiling(&l, lines, cols);
					if (!dw)
						CHECK_INT(l.detailVisible, 0);
				}
			}
		}
	}
	CHECK_INT(ui_layout_compute(24, 80, 0, 50, NULL), UI_ERR_INVAL);
}

static void test_layout_examples(void)
{
	struct ui_layout_s l;

	/* Plan mockup A: 24 rows, no reports. */
	ui_layout_compute(24, 112, 0, 50, &l);
	CHECK_INT(l.area[UI_AREA_LIST].y, 2);
	CHECK_INT(l.area[UI_AREA_LIST].h, 19);
	CHECK_INT(l.area[UI_AREA_MESSAGE].y, 21);

	/* Plan mockup B: 24 rows, reports on, 50%. */
	ui_layout_compute(24, 112, 1, 50, &l);
	CHECK_INT(l.detailVisible, 1);
	CHECK_INT(l.area[UI_AREA_LIST].h, 8);
	CHECK_INT(l.area[UI_AREA_DETAIL_BAR].y, 10);
	CHECK_INT(l.area[UI_AREA_DETAIL].y, 11);
	CHECK_INT(l.area[UI_AREA_DETAIL].h, 10);

	/* Smallest size that still shows DETAIL: 5 fixed + 3 list + 1 bar + 4 detail. */
	ui_layout_compute(13, 80, 1, 50, &l);
	CHECK_INT(l.detailVisible, 1);
	CHECK_INT(l.area[UI_AREA_LIST].h, 3);
	CHECK_INT(l.area[UI_AREA_DETAIL].h, 4);
	ui_layout_compute(12, 80, 1, 50, &l);
	CHECK_INT(l.detailVisible, 0);
	CHECK_INT(l.area[UI_AREA_LIST].h, 7);

	/* Too small boundaries. */
	ui_layout_compute(UI_LAYOUT_MIN_LINES, UI_LAYOUT_MIN_COLS, 0, 50, &l);
	CHECK_INT(l.tooSmall, 0);
	ui_layout_compute(UI_LAYOUT_MIN_LINES - 1, 200, 0, 50, &l);
	CHECK_INT(l.tooSmall, 1);
	ui_layout_compute(50, UI_LAYOUT_MIN_COLS - 1, 0, 50, &l);
	CHECK_INT(l.tooSmall, 1);
	ui_layout_compute(0, 0, 1, 50, &l);
	CHECK_INT(l.tooSmall, 1);
	ui_layout_compute(-5, -5, 1, 50, &l);
	CHECK_INT(l.tooSmall, 1);

	/* Percentage is clamped. */
	struct ui_layout_s a, b;
	ui_layout_compute(100, 120, 1, 0, &a);
	ui_layout_compute(100, 120, 1, UI_DETAIL_PCT_MIN, &b);
	CHECK(ui_layout_equal(&a, &b));
	ui_layout_compute(100, 120, 1, 100, &a);
	ui_layout_compute(100, 120, 1, UI_DETAIL_PCT_MAX, &b);
	CHECK(ui_layout_equal(&a, &b));
	ui_layout_compute(100, 121, 1, UI_DETAIL_PCT_MAX, &a);
	CHECK(!ui_layout_equal(&a, &b));
	CHECK(!ui_layout_equal(NULL, &b));
}

static void test_detail_pct_adjust(void)
{
	CHECK_INT(ui_detail_pct_adjust(50, 10), 60);
	CHECK_INT(ui_detail_pct_adjust(80, 10), 80);
	CHECK_INT(ui_detail_pct_adjust(20, -10), 20);
	CHECK_INT(ui_detail_pct_adjust(25, -10), 20);
}

static void test_scroll(void)
{
	CHECK_INT(ui_scroll_clamp(5, 0, 10), 0);      /* Empty buffer */
	CHECK_INT(ui_scroll_clamp(5, 8, 10), 0);      /* Content shorter than the screen */
	CHECK_INT(ui_scroll_clamp(50, 30, 10), 20);   /* Past the end after lines vanished */
	CHECK_INT(ui_scroll_clamp(-3, 30, 10), 0);
	CHECK_INT(ui_scroll_clamp(7, 30, 0), 0);      /* No rows */
	CHECK_INT(ui_scroll_clamp(7, 30, 10), 7);

	CHECK_INT(ui_scroll_to_cursor(0, 10, 3, 4), 0);    /* Already visible */
	CHECK_INT(ui_scroll_to_cursor(10, 10, 3, 4), 3);   /* Above */
	CHECK_INT(ui_scroll_to_cursor(0, 10, 12, 14), 5);  /* Below: last line at bottom */
	CHECK_INT(ui_scroll_to_cursor(0, 5, 20, 40), 20);  /* Taller than screen */
	CHECK_INT(ui_scroll_to_cursor(4, 10, 9, 8), 4);    /* last < first treated as one line */
	CHECK_INT(ui_scroll_to_cursor(4, 0, 9, 9), 4);
	CHECK_INT(ui_scroll_to_cursor(-2, 10, -1, -1), 0); /* No cursor */

	CHECK_INT(ui_hscroll_clamp(10, 100, 80), 10);
	CHECK_INT(ui_hscroll_clamp(30, 100, 80), 20);
	CHECK_INT(ui_hscroll_clamp(5, 60, 80), 0);
	CHECK_INT(ui_hscroll_clamp(-1, 200, 80), 0);
	CHECK_INT(ui_hscroll_clamp(5, 200, 0), 0);
}

static void test_cursor_apply(void)
{
	uint32_t order[] = { 11, 22, 33, 44, 55 };
	int heights[] = { 1, 3, 1, 1, 2 };

	CHECK_INT(ui_cursor_apply(NULL, NULL, 0, 11, UI_CURSOR_DOWN, 5), 0);
	CHECK_INT(ui_cursor_apply(order, NULL, 0, 11, UI_CURSOR_DOWN, 5), 0);

	CHECK_INT(ui_cursor_apply(order, NULL, 5, 11, UI_CURSOR_UP, 5), 11);
	CHECK_INT(ui_cursor_apply(order, NULL, 5, 11, UI_CURSOR_DOWN, 5), 22);
	CHECK_INT(ui_cursor_apply(order, NULL, 5, 55, UI_CURSOR_DOWN, 5), 55);
	CHECK_INT(ui_cursor_apply(order, NULL, 5, 33, UI_CURSOR_HOME, 5), 11);
	CHECK_INT(ui_cursor_apply(order, NULL, 5, 33, UI_CURSOR_END, 5), 55);
	CHECK_INT(ui_cursor_apply(order, NULL, 5, 33, UI_CURSOR_NONE, 5), 33);

	/* Unknown or no cursor behaves as the first stream. */
	CHECK_INT(ui_cursor_apply(order, NULL, 5, 0, UI_CURSOR_NONE, 5), 11);
	CHECK_INT(ui_cursor_apply(order, NULL, 5, 99, UI_CURSOR_DOWN, 5), 22);

	/* Single stream. */
	uint32_t one[] = { 7 };
	CHECK_INT(ui_cursor_apply(one, NULL, 1, 7, UI_CURSOR_PAGE_DOWN, 10), 7);
	CHECK_INT(ui_cursor_apply(one, NULL, 1, 7, UI_CURSOR_UP, 10), 7);

	/* Pages sized by line heights: from 11, 1 + 3 = 4 lines fit in 4 rows. */
	CHECK_INT(ui_cursor_apply(order, heights, 5, 11, UI_CURSOR_PAGE_DOWN, 4), 33);
	CHECK_INT(ui_cursor_apply(order, heights, 5, 11, UI_CURSOR_PAGE_DOWN, 100), 55);
	CHECK_INT(ui_cursor_apply(order, heights, 5, 55, UI_CURSOR_PAGE_UP, 2), 33);
	CHECK_INT(ui_cursor_apply(order, heights, 5, 55, UI_CURSOR_PAGE_UP, 100), 11);
	/* A page always moves at least one stream, even if it is taller than the page. */
	CHECK_INT(ui_cursor_apply(order, heights, 5, 22, UI_CURSOR_PAGE_UP, 0), 11);
	CHECK_INT(ui_cursor_apply(order, heights, 5, 22, UI_CURSOR_PAGE_DOWN, 1), 33);
}

static void test_cursor_repair(void)
{
	uint32_t prev[] = { 1, 2, 3, 4, 5 };
	uint32_t now1[] = { 1, 2, 4, 5 };     /* 3 vanished */
	uint32_t now2[] = { 1, 2 };           /* 3, 4, 5 vanished */
	uint32_t now3[] = { 9 };

	CHECK_INT(ui_cursor_repair(prev, 5, now1, 4, 2), 2);    /* Still there */
	CHECK_INT(ui_cursor_repair(prev, 5, now1, 4, 3), 4);    /* Next survivor */
	CHECK_INT(ui_cursor_repair(prev, 5, now2, 2, 5), 2);    /* Last removed: previous survivor */
	CHECK_INT(ui_cursor_repair(prev, 5, now2, 2, 4), 2);
	CHECK_INT(ui_cursor_repair(prev, 5, now3, 1, 3), 9);    /* No survivors from prev */
	CHECK_INT(ui_cursor_repair(prev, 5, now1, 4, 0), 1);    /* No cursor yet */
	CHECK_INT(ui_cursor_repair(NULL, 0, now1, 4, 77), 1);   /* Unknown, no history */
	CHECK_INT(ui_cursor_repair(prev, 5, NULL, 0, 3), 0);    /* Empty list */
	CHECK_INT(ui_cursor_repair(prev, 5, now1, 0, 3), 0);
}

static void test_hit(void)
{
	struct ui_layout_s l;
	struct ui_buf_s list, detail;
	struct ui_hint_map_s hints;
	struct ui_hit_s h;
	struct ui_view_s v = { .listTop = 2, .listLeft = 0, .detailTop = 1, .detailLeft = 0 };

	ui_buf_init(&list);
	ui_buf_init(&detail);
	for (int i = 0; i < 6; i++) {
		ui_buf_set_owner(&list, 100 + i);
		ui_buf_printf(&list, i, 0, "stream %d", i);
	}
	ui_buf_set_owner(&detail, 103);
	for (int i = 0; i < 3; i++)
		ui_buf_printf(&detail, i, 0, "report %d", i);

	ui_hint_map_reset(&hints);
	CHECK_INT(ui_hint_map_add(&hints, 0, 5, 'q'), UI_OK);
	CHECK_INT(ui_hint_map_add(&hints, 8, 14, 'h'), UI_OK);
	CHECK_INT(ui_hint_map_add(&hints, 5, 4, 'x'), UI_ERR_INVAL);
	CHECK_INT(ui_hint_map_add(NULL, 0, 1, 'x'), UI_ERR_INVAL);

	ui_layout_compute(24, 112, 1, 50, &l);    /* LIST rows 2-9, DETAIL rows 11-20 */

	CHECK_INT(ui_hit_test(NULL, &v, &list, &detail, &hints, 0, 0, &h), UI_ERR_INVAL);

	ui_hit_test(&l, &v, &list, &detail, &hints, 0, 3, &h);
	CHECK_INT(h.area, UI_AREA_TITLE);

	/* LIST edges: first row is buffer line listTop. */
	ui_hit_test(&l, &v, &list, &detail, &hints, 2, 0, &h);
	CHECK_INT(h.area, UI_AREA_LIST);
	CHECK_INT(h.line, 2);
	CHECK_INT(h.ownerId, 102);
	ui_hit_test(&l, &v, &list, &detail, &hints, 5, 111, &h);
	CHECK_INT(h.line, 5);
	CHECK_INT(h.ownerId, 105);
	/* Below the last line of content. */
	ui_hit_test(&l, &v, &list, &detail, &hints, 9, 0, &h);
	CHECK_INT(h.area, UI_AREA_LIST);
	CHECK_INT(h.line, -1);
	CHECK_INT(h.ownerId, 0);

	ui_hit_test(&l, &v, &list, &detail, &hints, 10, 0, &h);
	CHECK_INT(h.area, UI_AREA_DETAIL_BAR);

	/* Report lines resolve to the stream that owns them. */
	ui_hit_test(&l, &v, &list, &detail, &hints, 12, 40, &h);
	CHECK_INT(h.area, UI_AREA_DETAIL);
	CHECK_INT(h.line, 2);
	CHECK_INT(h.ownerId, 103);

	ui_hit_test(&l, &v, &list, &detail, &hints, 23, 3, &h);
	CHECK_INT(h.area, UI_AREA_HINTS);
	CHECK_INT(h.key, 'q');
	ui_hit_test(&l, &v, &list, &detail, &hints, 23, 7, &h);
	CHECK_INT(h.key, 0);
	ui_hit_test(&l, &v, &list, &detail, &hints, 23, 14, &h);
	CHECK_INT(h.key, 'h');

	/* Outside the screen. */
	ui_hit_test(&l, &v, &list, &detail, &hints, 30, 0, &h);
	CHECK_INT(h.area, UI_AREA_NONE);
	ui_hit_test(&l, &v, &list, &detail, &hints, 5, 200, &h);
	CHECK_INT(h.area, UI_AREA_NONE);

	/* Stale vs current frame: the same click maps through the layout it is given. */
	struct ui_layout_s small;
	ui_layout_compute(12, 112, 1, 50, &small);  /* Detail hidden at this size */
	ui_hit_test(&small, &v, &list, &detail, &hints, 9, 0, &h);
	CHECK_INT(h.area, UI_AREA_MESSAGE);
	ui_hit_test(&l, &v, &list, &detail, &hints, 9, 0, &h);
	CHECK_INT(h.area, UI_AREA_LIST);

	/* Too small screen: nothing is clickable. */
	ui_layout_compute(4, 112, 1, 50, &small);
	ui_hit_test(&small, &v, &list, &detail, &hints, 1, 1, &h);
	CHECK_INT(h.area, UI_AREA_NONE);

	ui_hint_map_reset(&hints);
	for (int i = 0; i < UI_HINT_MAX; i++)
		ui_hint_map_add(&hints, i, i, 'a');
	CHECK_INT(ui_hint_map_add(&hints, 99, 99, 'b'), UI_ERR_FULL);

	ui_buf_free(&list);
	ui_buf_free(&detail);
}

/* Random resize sequences: after every step the layout tiles the screen,
 * scroll positions stay in range and the cursor block stays visible.
 */
static void test_resize_sequences(void)
{
	srand(12345);
	int listTop = 0, detailTop = 0;
	int listLines = 120, detailLines = 300;

	for (int step = 0; step < 20000; step++) {
		int lines = rand() % 120;
		int cols = 20 + rand() % 260;
		int dw = rand() % 2;
		int pct = rand() % 101;
		int curFirst = rand() % listLines;
		int curLast = curFirst + rand() % 3;
		if (curLast >= listLines)
			curLast = listLines - 1;

		struct ui_layout_s l;
		ui_layout_compute(lines, cols, dw, pct, &l);
		check_tiling(&l, lines, cols);

		int listRows = l.area[UI_AREA_LIST].h;
		int detailRows = l.area[UI_AREA_DETAIL].h;

		listTop = ui_scroll_to_cursor(listTop, listRows, curFirst, curLast);
		listTop = ui_scroll_clamp(listTop, listLines, listRows);
		detailTop = ui_scroll_clamp(detailTop + (rand() % 21) - 10, detailLines, detailRows);

		CHECK(listTop >= 0);
		CHECK(detailTop >= 0);
		if (listRows > 0) {
			CHECK(listTop <= (listLines > listRows ? listLines - listRows : 0));
			/* Cursor visible, unless the block is taller than the area. */
			if (curLast - curFirst + 1 <= listRows) {
				CHECK(curFirst >= listTop);
				CHECK(curLast < listTop + listRows);
			} else {
				CHECK_INT(listTop, curFirst);
			}
		}
		if (detailRows > 0)
			CHECK(detailTop <= (detailLines > detailRows ? detailLines - detailRows : 0));

		if (g_test_failures > 20)
			break;
	}
}

static void test_double_click(void)
{
	struct ui_click_s c = { 0, 0 };

	CHECK_INT(ui_click_register(NULL, 5, 100, 400), 0);

	CHECK_INT(ui_click_register(&c, 5, 1000, 400), 0);   /* First click */
	CHECK_INT(ui_click_register(&c, 5, 1400, 400), 1);   /* Exactly at the limit */
	CHECK_INT(c.ownerId, 0);                              /* State cleared */
	CHECK_INT(ui_click_register(&c, 5, 1450, 400), 0);   /* Third click starts over */
	CHECK_INT(ui_click_register(&c, 5, 1900, 400), 0);   /* Too slow: 450 ms */
	CHECK_INT(ui_click_register(&c, 6, 1950, 400), 0);   /* Different stream */
	CHECK_INT(ui_click_register(&c, 6, 2000, 400), 1);
	CHECK_INT(ui_click_register(&c, 0, 3000, 400), 0);   /* No stream never pairs */
	CHECK_INT(ui_click_register(&c, 0, 3010, 400), 0);
	CHECK_INT(ui_click_register(&c, 7, 5000, 400), 0);
	CHECK_INT(ui_click_register(&c, 7, 4000, 400), 0);   /* Clock went backwards: no pair */
}

static void test_zoom(void)
{
	struct ui_layout_s l;

	/* Sweep: zoomed layouts tile the screen too. */
	for (int lines = 1; lines <= 120; lines++) {
		for (int cols = 20; cols <= 200; cols += 9) {
			for (int dw = 0; dw <= 1; dw++) {
				CHECK_INT(ui_layout_compute_zoom(lines, cols, dw, 50, 1, &l), UI_OK);
				check_tiling(&l, lines, cols);
				int canZoom = lines >= UI_LAYOUT_ZOOM_MIN_LINES && cols >= UI_LAYOUT_MIN_COLS;
				CHECK_INT(l.zoomed, canZoom);
				if (canZoom) {
					CHECK_INT(l.detailVisible, 1);
					CHECK_INT(l.area[UI_AREA_LIST].h, 1);
					CHECK_INT(l.area[UI_AREA_DETAIL].h, lines - UI_LAYOUT_FIXED_ROWS - 2);
				}
			}
		}
	}

	/* 24 rows: list row 2, bar row 3, detail rows 4-20. */
	ui_layout_compute_zoom(24, 112, 0, 50, 1, &l);
	CHECK_INT(l.area[UI_AREA_DETAIL_BAR].y, 3);
	CHECK_INT(l.area[UI_AREA_DETAIL].y, 4);
	CHECK_INT(l.area[UI_AREA_DETAIL].h, 17);

	/* Zoom off is the normal layout; zoomed and not zoomed differ. */
	struct ui_layout_s a, b;
	ui_layout_compute_zoom(24, 112, 1, 50, 0, &a);
	ui_layout_compute(24, 112, 1, 50, &b);
	CHECK(ui_layout_equal(&a, &b));
	ui_layout_compute_zoom(24, 112, 1, 50, 1, &a);
	CHECK(!ui_layout_equal(&a, &b));

	/* Too short to zoom: falls back. */
	ui_layout_compute_zoom(UI_LAYOUT_ZOOM_MIN_LINES - 1, 112, 1, 50, 1, &l);
	CHECK_INT(l.zoomed, 0);
}

static void test_fit_list(void)
{
	struct ui_layout_s l;

	/* Two streams, 24 rows, detail open: LIST shrinks to 3, DETAIL grows. */
	ui_layout_compute(24, 112, 1, 50, &l);
	CHECK_INT(l.area[UI_AREA_LIST].h, 8);
	ui_layout_fit_list(&l, 2);
	check_tiling(&l, 24, 112);
	CHECK_INT(l.area[UI_AREA_LIST].h, UI_LAYOUT_LIST_MIN);
	CHECK_INT(l.area[UI_AREA_DETAIL_BAR].y, 5);
	CHECK_INT(l.area[UI_AREA_DETAIL].y, 6);
	CHECK_INT(l.area[UI_AREA_DETAIL].h, 15);

	/* Five streams: exactly five rows. */
	ui_layout_compute(24, 112, 1, 50, &l);
	ui_layout_fit_list(&l, 5);
	CHECK_INT(l.area[UI_AREA_LIST].h, 5);

	/* More content than the share: unchanged. */
	struct ui_layout_s a;
	ui_layout_compute(24, 112, 1, 50, &l);
	a = l;
	ui_layout_fit_list(&l, 40);
	CHECK(ui_layout_equal(&a, &l));

	/* No detail, zoomed, too small: unchanged. */
	ui_layout_compute(24, 112, 0, 50, &l);
	a = l;
	ui_layout_fit_list(&l, 1);
	CHECK(ui_layout_equal(&a, &l));
	ui_layout_compute_zoom(24, 112, 1, 50, 1, &l);
	a = l;
	ui_layout_fit_list(&l, 1);
	CHECK(ui_layout_equal(&a, &l));
	ui_layout_compute(5, 112, 1, 50, &l);
	a = l;
	ui_layout_fit_list(&l, 1);
	CHECK(ui_layout_equal(&a, &l));
	ui_layout_fit_list(NULL, 1);

	/* Sweep: always tiles the screen. */
	for (int lines = 1; lines <= 100; lines++) {
		for (int content = 0; content <= 60; content += 3) {
			ui_layout_compute(lines, 120, 1, 50, &l);
			ui_layout_fit_list(&l, content);
			check_tiling(&l, lines, 120);
		}
	}
}

static void test_detail_split(void)
{
	struct ui_layout_s l;
	struct ui_rect_s bars[UI_PANE_MAX], bodies[UI_PANE_MAX];

	/* 24 rows, two streams, detail open, list fitted: region rows 5-20 (16 rows). */
	ui_layout_compute(24, 112, 1, 50, &l);
	ui_layout_fit_list(&l, 2);
	CHECK_INT(ui_detail_split(&l, 2, NULL, bars, bodies, UI_PANE_MAX), 2);
	CHECK_INT(bars[0].y, 5);
	CHECK_INT(bodies[0].y, 6);
	CHECK_INT(bodies[0].h, 7);
	CHECK_INT(bars[1].y, 13);
	CHECK_INT(bodies[1].y, 14);
	CHECK_INT(bodies[1].h, 7);
	CHECK_INT(bodies[1].y + bodies[1].h, l.area[UI_AREA_MESSAGE].y);

	/* Uneven split: spare rows go to the top panes. */
	CHECK_INT(ui_detail_split(&l, 3, NULL, bars, bodies, UI_PANE_MAX), 3);
	CHECK_INT(bodies[0].h, 5);   /* 16 rows / 3 = 5 r1: 6,5,5 per pane */
	CHECK_INT(bodies[1].h, 4);
	CHECK_INT(bodies[2].h, 4);

	/* Weights: 16 rows, two panes, 3:1 -> spare 8 rows split 6:2 -> 10 + 6. */
	int w31[] = { 3, 1 };
	CHECK_INT(ui_detail_split(&l, 2, w31, bars, bodies, UI_PANE_MAX), 2);
	CHECK_INT(bodies[0].h + 1, 10);
	CHECK_INT(bodies[1].h + 1, 6);
	CHECK_INT(bars[1].y, 5 + 10);
	int w13[] = { 1, 3 };
	ui_detail_split(&l, 2, w13, bars, bodies, UI_PANE_MAX);
	CHECK_INT(bodies[0].h + 1, 6);
	CHECK_INT(bodies[1].h + 1, 10);
	/* Extreme weights never push a pane below its minimum, and are clamped. */
	int w81[] = { 99, -5 };
	ui_detail_split(&l, 2, w81, bars, bodies, UI_PANE_MAX);
	CHECK(bodies[1].h >= UI_PANE_MIN_BODY);
	CHECK_INT(bodies[0].h + bodies[1].h + 2, 16);

	/* More panes than fit: 16 rows / 4 per pane = 4. */
	CHECK_INT(ui_detail_split(&l, 7, NULL, bars, bodies, UI_PANE_MAX), 4);
	CHECK_INT(ui_detail_split(&l, 7, NULL, bars, bodies, 2), 2);   /* Caller's max */

	/* Nothing to do. */
	CHECK_INT(ui_detail_split(&l, 0, NULL, bars, bodies, UI_PANE_MAX), 0);
	CHECK_INT(ui_detail_split(NULL, 2, NULL, bars, bodies, UI_PANE_MAX), 0);
	ui_layout_compute(24, 112, 0, 50, &l);
	CHECK_INT(ui_detail_split(&l, 2, NULL, bars, bodies, UI_PANE_MAX), 0);   /* Detail hidden */

	/* Sweep: panes never overlap, stay inside the region, bodies >= minimum. */
	for (int lines = 8; lines <= 120; lines++) {
		for (int n = 1; n <= UI_PANE_MAX + 2; n++) {
			ui_layout_compute(lines, 120, 1, 50, &l);
			ui_layout_fit_list(&l, lines % 7);
			int wts[UI_PANE_MAX + 2];
			for (int k = 0; k < n; k++)
				wts[k] = 1 + (lines + k) % UI_PANE_WEIGHT_MAX;
			int shown = ui_detail_split(&l, n, (lines & 1) ? wts : NULL, bars, bodies, UI_PANE_MAX);
			CHECK(shown <= n && shown <= UI_PANE_MAX);
			if (!l.detailVisible)
				continue;
			int top = l.area[UI_AREA_DETAIL_BAR].y;
			int end = l.area[UI_AREA_DETAIL].y + l.area[UI_AREA_DETAIL].h;
			int y = top;
			for (int i = 0; i < shown; i++) {
				CHECK_INT(bars[i].y, y);
				CHECK_INT(bodies[i].y, y + 1);
				CHECK(bodies[i].h >= UI_PANE_MIN_BODY);
				y = bodies[i].y + bodies[i].h;
			}
			if (shown)
				CHECK_INT(y, end);
		}
	}
}

static void test_scroll_mem(void)
{
	struct ui_scroll_mem_s m = { 0 };
	int top = -1, left = -1;

	CHECK_INT(ui_scroll_mem_get(&m, 5, &top, &left), 0);
	CHECK_INT(top, 0);
	CHECK_INT(left, 0);
	CHECK_INT(ui_scroll_mem_set(&m, 0, 1, 1), UI_ERR_INVAL);
	CHECK_INT(ui_scroll_mem_set(NULL, 5, 1, 1), UI_ERR_INVAL);

	for (uint32_t id = 1; id <= 100; id++)
		CHECK_INT(ui_scroll_mem_set(&m, id, (int)id * 2, (int)id), UI_OK);
	CHECK_INT(m.count, 100);
	CHECK_INT(ui_scroll_mem_set(&m, 7, 70, 3), UI_OK);    /* Update, no new entry */
	CHECK_INT(m.count, 100);
	CHECK_INT(ui_scroll_mem_get(&m, 7, &top, &left), 1);
	CHECK_INT(top, 70);
	CHECK_INT(left, 3);
	CHECK_INT(ui_scroll_mem_get(&m, 50, &top, NULL), 1);
	CHECK_INT(top, 100);

	uint32_t alive[] = { 7, 50, 999 };
	ui_scroll_mem_prune(&m, alive, 3);
	CHECK_INT(m.count, 2);
	CHECK_INT(ui_scroll_mem_get(&m, 8, &top, &left), 0);
	CHECK_INT(ui_scroll_mem_get(&m, 7, &top, &left), 1);
	CHECK_INT(top, 70);
	ui_scroll_mem_prune(&m, NULL, 0);
	CHECK_INT(m.count, 0);
	ui_scroll_mem_free(&m);
	ui_scroll_mem_free(NULL);
	ui_scroll_mem_prune(NULL, alive, 3);
}

int main(void)
{
	RUN(test_zoom);
	RUN(test_fit_list);
	RUN(test_detail_split);
	RUN(test_scroll_mem);
	RUN(test_double_click);
	RUN(test_layout_sweep);
	RUN(test_layout_examples);
	RUN(test_detail_pct_adjust);
	RUN(test_scroll);
	RUN(test_cursor_apply);
	RUN(test_cursor_repair);
	RUN(test_hit);
	RUN(test_resize_sequences);
	return TEST_RESULT();
}
