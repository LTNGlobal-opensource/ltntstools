#include <stdlib.h>

#include "ui_test.h"
#include "nic_monitor_ui_buf.h"

static void line(const struct ui_buf_s *b, int row, int width, char *out)
{
	ui_buf_line_cells(b, row, 0, width, out, NULL);
	/* Trim trailing spaces to keep expectations readable. */
	int n = width;
	while (n > 0 && out[n - 1] == ' ')
		n--;
	out[n] = 0;
}

static void test_null_args(void)
{
	struct ui_buf_s b;
	char t[8];

	CHECK_INT(ui_buf_init(NULL), UI_ERR_INVAL);
	CHECK_INT(ui_buf_init(&b), UI_OK);
	CHECK_INT(ui_buf_puts(NULL, 0, 0, "x"), UI_ERR_INVAL);
	CHECK_INT(ui_buf_puts(&b, 0, 0, NULL), UI_ERR_INVAL);
	CHECK_INT(ui_buf_puts(&b, -1, 0, "x"), UI_ERR_INVAL);
	CHECK_INT(ui_buf_puts(&b, 0, -1, "x"), UI_ERR_INVAL);
	CHECK_INT(ui_buf_printf(NULL, 0, 0, "x"), UI_ERR_INVAL);
	CHECK_INT(ui_buf_touch(&b, -1), UI_ERR_INVAL);
	CHECK_INT(ui_buf_line_cells(NULL, 0, 0, 4, t, NULL), UI_ERR_INVAL);
	CHECK_INT(ui_buf_line_cells(&b, 0, 0, 4, NULL, NULL), UI_ERR_INVAL);
	CHECK_INT(ui_buf_line_owner(NULL, 0), 0);
	CHECK_INT(ui_buf_max_width(NULL), 0);
	int f, l;
	CHECK_INT(ui_buf_find_owner_range(&b, 0, &f, &l), UI_ERR_INVAL);
	CHECK_INT(b.lineCount, 0);
	ui_buf_free(&b);
	ui_buf_free(NULL);
	ui_buf_reset(NULL);
}

static void test_sparse_rows(void)
{
	struct ui_buf_s b;
	char t[64];

	ui_buf_init(&b);
	CHECK_INT(ui_buf_printf(&b, 3, 2, "row%d", 3), UI_OK);
	CHECK_INT(b.lineCount, 4);
	line(&b, 0, 20, t); CHECK_STR(t, "");
	line(&b, 3, 20, t); CHECK_STR(t, "  row3");
	line(&b, 9, 20, t); CHECK_STR(t, "");   /* Past the end: blank */

	CHECK_INT(ui_buf_printf(&b, 1, 0, "one"), UI_OK);
	CHECK_INT(b.lineCount, 4);
	line(&b, 1, 20, t); CHECK_STR(t, "one");

	CHECK_INT(ui_buf_touch(&b, 6), UI_OK);
	CHECK_INT(b.lineCount, 7);
	ui_buf_free(&b);
}

static void test_overlap_order(void)
{
	struct ui_buf_s b;
	char t[64];
	uint8_t p[64];

	ui_buf_init(&b);
	ui_buf_set_pair(&b, 1);
	ui_buf_puts(&b, 0, 0, "aaaaaaaaaa");
	ui_buf_set_pair(&b, 3);
	ui_buf_puts(&b, 0, 4, "BB");
	ui_buf_line_cells(&b, 0, 0, 12, t, p);
	CHECK_STR(t, "aaaaBBaaaa  ");
	CHECK_INT(p[0], 1);
	CHECK_INT(p[4], 3);
	CHECK_INT(p[5], 3);
	CHECK_INT(p[6], 1);
	CHECK_INT(p[11], 0);
	CHECK_INT(ui_buf_max_width(&b), 10);
	ui_buf_free(&b);
}

static void test_control_chars_and_clip(void)
{
	struct ui_buf_s b;
	char t[UI_BUF_MAX_COLS + 8];

	ui_buf_init(&b);
	ui_buf_puts(&b, 0, 0, "a\tb\nc\n");
	line(&b, 0, 10, t);
	CHECK_STR(t, "a b c");

	char longtext[UI_BUF_MAX_COLS * 2];
	memset(longtext, 'x', sizeof(longtext) - 1);
	longtext[sizeof(longtext) - 1] = 0;
	CHECK_INT(ui_buf_puts(&b, 1, 10, longtext), UI_OK);
	CHECK_INT(ui_buf_max_width(&b), UI_BUF_MAX_COLS);

	/* Starting beyond the maximum width writes nothing but is not an error. */
	CHECK_INT(ui_buf_puts(&b, 2, UI_BUF_MAX_COLS, "zz"), UI_OK);
	CHECK_INT(b.lineCount, 3);
	line(&b, 2, 10, t);
	CHECK_STR(t, "");
	ui_buf_free(&b);
}

static void test_horizontal_window(void)
{
	struct ui_buf_s b;
	char t[16];

	ui_buf_init(&b);
	ui_buf_puts(&b, 0, 2, "0123456789");
	ui_buf_line_cells(&b, 0, 5, 6, t, NULL);
	CHECK_STR(t, "345678");
	ui_buf_line_cells(&b, 0, 20, 4, t, NULL);
	CHECK_STR(t, "    ");
	ui_buf_free(&b);
}

static void test_owner(void)
{
	struct ui_buf_s b;
	int f = -1, l = -1;

	ui_buf_init(&b);
	ui_buf_set_owner(&b, 7);
	ui_buf_puts(&b, 2, 0, "x");
	ui_buf_puts(&b, 4, 0, "y");
	ui_buf_set_owner(&b, 9);
	ui_buf_puts(&b, 4, 5, "z");  /* First owner of a line wins */
	ui_buf_touch(&b, 5);
	ui_buf_set_owner(&b, 0);
	ui_buf_puts(&b, 6, 0, "none");

	CHECK_INT(ui_buf_line_owner(&b, 2), 7);
	CHECK_INT(ui_buf_line_owner(&b, 3), 0);
	CHECK_INT(ui_buf_line_owner(&b, 4), 7);
	CHECK_INT(ui_buf_line_owner(&b, 5), 9);
	CHECK_INT(ui_buf_line_owner(&b, 6), 0);
	CHECK_INT(ui_buf_line_owner(&b, 99), 0);

	CHECK_INT(ui_buf_find_owner_range(&b, 7, &f, &l), UI_OK);
	CHECK_INT(f, 2);
	CHECK_INT(l, 4);
	CHECK_INT(ui_buf_find_owner_range(&b, 9, &f, &l), UI_OK);
	CHECK_INT(f, 5);
	CHECK_INT(l, 5);
	CHECK_INT(ui_buf_find_owner_range(&b, 42, &f, &l), UI_ERR_INVAL);
	ui_buf_free(&b);
}

static void test_full(void)
{
	struct ui_buf_s b;

	ui_buf_init(&b);
	CHECK_INT(ui_buf_puts(&b, UI_BUF_MAX_LINES - 1, 0, "last"), UI_OK);
	CHECK_INT(b.truncated, 0);
	CHECK_INT(ui_buf_puts(&b, UI_BUF_MAX_LINES, 0, "over"), UI_ERR_FULL);
	CHECK_INT(b.truncated, 1);
	CHECK_INT(ui_buf_touch(&b, UI_BUF_MAX_LINES + 5), UI_ERR_FULL);
	CHECK_INT(b.lineCount, UI_BUF_MAX_LINES);
	ui_buf_free(&b);
}

static void test_reset_keeps_capacity(void)
{
	struct ui_buf_s b;
	char t[16];

	ui_buf_init(&b);
	for (int i = 0; i < 1000; i++)
		ui_buf_printf(&b, i, 0, "line %d", i);
	int la = b.lineAlloc;
	uint32_t sa = b.spanAlloc;
	size_t aa = b.arenaAlloc;
	CHECK(la >= 1000);

	ui_buf_set_pair(&b, 4);
	ui_buf_set_owner(&b, 3);
	ui_buf_reset(&b);
	CHECK_INT(b.lineCount, 0);
	CHECK_INT(b.spanCount, 0);
	CHECK_INT(b.arenaUsed, 0);
	CHECK_INT(b.curPair, 0);
	CHECK_INT(b.curOwner, 0);
	CHECK_INT(b.lineAlloc, la);
	CHECK_INT(b.spanAlloc, sa);
	CHECK_INT(b.arenaAlloc, aa);

	ui_buf_puts(&b, 0, 0, "again");
	ui_buf_line_cells(&b, 0, 0, 5, t, NULL);
	CHECK_STR(t, "again");
	CHECK_INT(ui_buf_line_owner(&b, 0), 0);
	ui_buf_free(&b);
}

int main(void)
{
	RUN(test_null_args);
	RUN(test_sparse_rows);
	RUN(test_overlap_order);
	RUN(test_control_chars_and_clip);
	RUN(test_horizontal_window);
	RUN(test_owner);
	RUN(test_full);
	RUN(test_reset_keeps_capacity);
	return TEST_RESULT();
}
