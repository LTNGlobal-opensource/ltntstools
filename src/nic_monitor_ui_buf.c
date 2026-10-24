#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "nic_monitor_ui_buf.h"

int ui_buf_init(struct ui_buf_s *buf)
{
	if (!buf)
		return UI_ERR_INVAL;

	memset(buf, 0, sizeof(*buf));
	return UI_OK;
}

void ui_buf_free(struct ui_buf_s *buf)
{
	if (!buf)
		return;

	free(buf->lines);
	free(buf->spans);
	free(buf->arena);
	memset(buf, 0, sizeof(*buf));
}

void ui_buf_reset(struct ui_buf_s *buf)
{
	if (!buf)
		return;

	buf->lineCount = 0;
	buf->spanCount = 0;
	buf->arenaUsed = 0;
	buf->curPair = 0;
	buf->curOwner = 0;
	buf->truncated = 0;
}

void ui_buf_set_pair(struct ui_buf_s *buf, uint8_t pair)
{
	if (buf)
		buf->curPair = pair;
}

void ui_buf_set_owner(struct ui_buf_s *buf, uint32_t ownerId)
{
	if (buf)
		buf->curOwner = ownerId;
}

static int grow_lines(struct ui_buf_s *buf, int row)
{
	if (row >= UI_BUF_MAX_LINES)
		return UI_ERR_FULL;

	if (row >= buf->lineAlloc) {
		int n = buf->lineAlloc ? buf->lineAlloc : 64;
		while (n <= row)
			n *= 2;
		if (n > UI_BUF_MAX_LINES)
			n = UI_BUF_MAX_LINES;

		struct ui_line_s *p = realloc(buf->lines, (size_t)n * sizeof(*p));
		if (!p)
			return UI_ERR_NOMEM;
		buf->lines = p;
		buf->lineAlloc = n;
	}

	while (buf->lineCount <= row) {
		struct ui_line_s *l = &buf->lines[buf->lineCount++];
		l->ownerId = 0;
		l->firstSpan = UI_BUF_NO_SPAN;
		l->lastSpan = UI_BUF_NO_SPAN;
	}

	return UI_OK;
}

int ui_buf_touch(struct ui_buf_s *buf, int row)
{
	if (!buf || row < 0)
		return UI_ERR_INVAL;

	int ret = grow_lines(buf, row);
	if (ret != UI_OK) {
		buf->truncated = 1;
		return ret;
	}

	if (buf->curOwner && buf->lines[row].ownerId == 0)
		buf->lines[row].ownerId = buf->curOwner;

	return UI_OK;
}

int ui_buf_puts(struct ui_buf_s *buf, int row, int col, const char *text)
{
	if (!buf || !text || row < 0 || col < 0)
		return UI_ERR_INVAL;

	int ret = grow_lines(buf, row);
	if (ret != UI_OK) {
		buf->truncated = 1;
		return ret;
	}

	struct ui_line_s *line = &buf->lines[row];
	if (buf->curOwner && line->ownerId == 0)
		line->ownerId = buf->curOwner;

	if (col >= UI_BUF_MAX_COLS)
		return UI_OK;

	size_t len = strlen(text);
	if (len && text[len - 1] == '\n')
		len--;
	if (len > (size_t)(UI_BUF_MAX_COLS - col))
		len = UI_BUF_MAX_COLS - col;
	if (len == 0)
		return UI_OK;

	if (buf->spanCount == buf->spanAlloc) {
		uint32_t n = buf->spanAlloc ? buf->spanAlloc * 2 : 256;
		struct ui_span_s *p = realloc(buf->spans, (size_t)n * sizeof(*p));
		if (!p) {
			buf->truncated = 1;
			return UI_ERR_NOMEM;
		}
		buf->spans = p;
		buf->spanAlloc = n;
	}

	if (buf->arenaUsed + len > buf->arenaAlloc) {
		size_t n = buf->arenaAlloc ? buf->arenaAlloc : 16384;
		while (n < buf->arenaUsed + len)
			n *= 2;
		char *p = realloc(buf->arena, n);
		if (!p) {
			buf->truncated = 1;
			return UI_ERR_NOMEM;
		}
		buf->arena = p;
		buf->arenaAlloc = n;
	}

	char *dst = buf->arena + buf->arenaUsed;
	for (size_t i = 0; i < len; i++) {
		unsigned char c = (unsigned char)text[i];
		dst[i] = (c < 0x20 || c == 0x7f) ? ' ' : (char)c;
	}

	uint32_t idx = buf->spanCount++;
	struct ui_span_s *s = &buf->spans[idx];
	s->col = (uint16_t)col;
	s->len = (uint16_t)len;
	s->pair = buf->curPair;
	s->textOffset = (uint32_t)buf->arenaUsed;
	s->next = UI_BUF_NO_SPAN;
	buf->arenaUsed += len;

	if (line->firstSpan == UI_BUF_NO_SPAN) {
		line->firstSpan = idx;
	} else {
		buf->spans[line->lastSpan].next = idx;
	}
	line->lastSpan = idx;

	return UI_OK;
}

int ui_buf_printf(struct ui_buf_s *buf, int row, int col, const char *fmt, ...)
{
	if (!buf || !fmt)
		return UI_ERR_INVAL;

	char tmp[UI_BUF_MAX_COLS + 1];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(tmp, sizeof(tmp), fmt, ap);
	va_end(ap);

	return ui_buf_puts(buf, row, col, tmp);
}

int ui_buf_line_cells(const struct ui_buf_s *buf, int row, int left, int width,
	char *text, uint8_t *pairs)
{
	if (!buf || !text || width < 0 || left < 0)
		return UI_ERR_INVAL;

	memset(text, ' ', (size_t)width);
	text[width] = 0;
	if (pairs)
		memset(pairs, 0, (size_t)width);

	if (row < 0 || row >= buf->lineCount)
		return UI_OK;

	const struct ui_line_s *line = &buf->lines[row];
	for (uint32_t i = line->firstSpan; i != UI_BUF_NO_SPAN; i = buf->spans[i].next) {
		const struct ui_span_s *s = &buf->spans[i];
		for (int k = 0; k < s->len; k++) {
			int x = s->col + k - left;
			if (x < 0)
				continue;
			if (x >= width)
				break;
			text[x] = buf->arena[s->textOffset + k];
			if (pairs)
				pairs[x] = s->pair;
		}
	}

	return UI_OK;
}

int ui_buf_max_width(const struct ui_buf_s *buf)
{
	if (!buf)
		return 0;

	int w = 0;
	for (uint32_t i = 0; i < buf->spanCount; i++) {
		int e = buf->spans[i].col + buf->spans[i].len;
		if (e > w)
			w = e;
	}
	return w;
}

uint32_t ui_buf_line_owner(const struct ui_buf_s *buf, int row)
{
	if (!buf || row < 0 || row >= buf->lineCount)
		return 0;

	return buf->lines[row].ownerId;
}

int ui_buf_find_owner_range(const struct ui_buf_s *buf, uint32_t ownerId,
	int *first, int *last)
{
	if (!buf || !first || !last || ownerId == 0)
		return UI_ERR_INVAL;

	int f = -1, l = -1;
	for (int i = 0; i < buf->lineCount; i++) {
		if (buf->lines[i].ownerId == ownerId) {
			if (f < 0)
				f = i;
			l = i;
		}
	}
	if (f < 0)
		return UI_ERR_INVAL;

	*first = f;
	*last = l;
	return UI_OK;
}
