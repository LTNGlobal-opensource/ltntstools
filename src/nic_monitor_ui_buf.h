#ifndef NIC_MONITOR_UI_BUF_H
#define NIC_MONITOR_UI_BUF_H

/* A frame's worth of text for one scrollable screen area (LIST or DETAIL).
 *
 * Text is written at (row, col) positions, the same way mvprintw() places it,
 * but into memory rather than onto the screen. Later writes that overlap
 * earlier ones on the same row win, matching curses overwrite behaviour.
 * The buffer has no curses dependency, so it can be built and tested
 * without a terminal.
 *
 * Threading: a buffer is owned by a single thread (the UI thread). None of
 * these functions lock.
 */

#include <stdint.h>
#include <stddef.h>

enum ui_result_e {
	UI_OK        =  0,
	UI_ERR_INVAL = -1, /* NULL argument, or a negative row / column */
	UI_ERR_NOMEM = -2, /* Allocation failed, the write was dropped */
	UI_ERR_FULL  = -3, /* UI_BUF_MAX_LINES reached, the write was dropped */
};

#define UI_BUF_MAX_LINES 20000
#define UI_BUF_MAX_COLS  256

#define UI_BUF_NO_SPAN   UINT32_MAX

struct ui_span_s
{
	uint16_t col;
	uint16_t len;
	uint8_t  pair;        /* curses color pair, 0 = default */
	uint32_t textOffset;  /* Into ui_buf_s.arena */
	uint32_t next;        /* Next span on the same line, or UI_BUF_NO_SPAN */
};

struct ui_line_s
{
	uint32_t ownerId;     /* Stream that owns this line, 0 = none */
	uint32_t firstSpan;   /* UI_BUF_NO_SPAN when the line is empty */
	uint32_t lastSpan;
};

struct ui_buf_s
{
	struct ui_line_s *lines;
	int lineCount;        /* Highest row written + 1 */
	int lineAlloc;

	struct ui_span_s *spans;
	uint32_t spanCount;
	uint32_t spanAlloc;

	char *arena;
	size_t arenaUsed;
	size_t arenaAlloc;

	uint8_t  curPair;     /* Pair applied to subsequent writes */
	uint32_t curOwner;    /* Owner applied to lines touched by subsequent writes */
	int truncated;        /* Set when a write was dropped (UI_ERR_FULL / UI_ERR_NOMEM) */
};

int  ui_buf_init(struct ui_buf_s *buf);
void ui_buf_free(struct ui_buf_s *buf);

/* Empties the buffer but keeps its allocations for the next frame. */
void ui_buf_reset(struct ui_buf_s *buf);

void ui_buf_set_pair(struct ui_buf_s *buf, uint8_t pair);
void ui_buf_set_owner(struct ui_buf_s *buf, uint32_t ownerId);

/* Print at (row, col). Newlines and other control characters are replaced
 * with spaces (a single trailing newline is dropped). Text beyond
 * UI_BUF_MAX_COLS is clipped. Returns enum ui_result_e.
 */
int  ui_buf_printf(struct ui_buf_s *buf, int row, int col, const char *fmt, ...)
	__attribute__((format(printf, 4, 5)));
int  ui_buf_puts(struct ui_buf_s *buf, int row, int col, const char *text);

/* Ensures lineCount > row, adding empty lines if needed. Used to reserve a
 * blank row. Returns enum ui_result_e.
 */
int  ui_buf_touch(struct ui_buf_s *buf, int row);

/* Flatten one line into cells: text[0..width-1] (space filled, NUL
 * terminated at text[width]) and pairs[0..width-1]. Cells left of `left`
 * are skipped (horizontal scroll). `text` must hold width + 1 bytes;
 * `pairs` may be NULL. Returns enum ui_result_e.
 */
int  ui_buf_line_cells(const struct ui_buf_s *buf, int row, int left, int width,
	char *text, uint8_t *pairs);

/* Widest line, in columns. */
int  ui_buf_max_width(const struct ui_buf_s *buf);

uint32_t ui_buf_line_owner(const struct ui_buf_s *buf, int row);

/* First and last line owned by ownerId. Returns UI_OK, or UI_ERR_INVAL when
 * the owner has no lines.
 */
int  ui_buf_find_owner_range(const struct ui_buf_s *buf, uint32_t ownerId,
	int *first, int *last);

#endif /* NIC_MONITOR_UI_BUF_H */
