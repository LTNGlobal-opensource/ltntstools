#include "pes.h"
#include "klbitstream_readwriter.h"
#include <inttypes.h>

#define DISPLAY_U32(indent, fn) printf("%s%s = %d (0x%x)\n", indent, #fn, fn, fn);
#define DISPLAY_U64(indent, fn) printf("%s%s = %" PRIu64 " (0x%" PRIx64 ")\n", indent, #fn, fn, fn);
#define DISPLAY_U32_SUFFIX(indent, fn, str) printf("%s%s = %d (0x%x) %s\n", indent, #fn, fn, fn, str);

struct ltn_pes_packet_s *ltn_pes_packet_alloc()
{
	struct ltn_pes_packet_s *pkt = calloc(1, sizeof(*pkt));
	return pkt;
}

void ltn_pes_packet_init(struct ltn_pes_packet_s *pkt)
{
	memset(pkt, 0, sizeof(*pkt));
}

void ltn_pes_packet_free(struct ltn_pes_packet_s *pkt)
{
	free(pkt);
}

static int64_t read33bit_ts(struct klbs_context_s *bs)
{
        int64_t a = (uint64_t)klbs_read_bits(bs, 3) << 30;
        if (klbs_read_bits(bs, 1) != 1)
                return -1;

        int64_t b = (uint64_t)klbs_read_bits(bs, 15) << 15;
        if (klbs_read_bits(bs, 1) != 1)
                return -1;

        int64_t c = (uint64_t)klbs_read_bits(bs, 15);
        if (klbs_read_bits(bs, 1) != 1)
                return -1;

	int64_t ts = a | b | c;

	return ts;
}

ssize_t ltn_pes_packet_parse(struct ltn_pes_packet_s *pkt, struct klbs_context_s *bs)
{
	ssize_t bits = 0;

	pkt->packet_start_code_prefix = klbs_read_bits(bs, 24);
	pkt->stream_id = klbs_read_bits(bs, 8);
	pkt->PES_packet_length = klbs_read_bits(bs, 16);

	klbs_read_bits(bs, 2); /* reserved */

	pkt->PES_scrambling_control = klbs_read_bits(bs, 2);
	pkt->PES_priority = klbs_read_bits(bs, 1);
	pkt->data_alignment_indicator = klbs_read_bits(bs, 1);
	pkt->copyright = klbs_read_bits(bs, 1);
	pkt->original_or_copy = klbs_read_bits(bs, 1);
	pkt->PTS_DTS_flags = klbs_read_bits(bs, 2);
	pkt->ESCR_flag = klbs_read_bits(bs, 1);
	pkt->ES_rate_flag = klbs_read_bits(bs, 1);
	pkt->DSM_trick_mode_flag = klbs_read_bits(bs, 1);
	pkt->additional_copy_info_flag = klbs_read_bits(bs, 1);
	pkt->PES_CRC_flag = klbs_read_bits(bs, 1);
	pkt->PES_extension_flag = klbs_read_bits(bs, 1);
	pkt->PES_header_data_length = klbs_read_bits(bs, 8);

	bits += 72;

	if (pkt->PTS_DTS_flags == 2) {
		klbs_read_bits(bs, 4); /* 0010 */
		pkt->PTS = read33bit_ts(bs);
		bits += 40;
	} else
	if (pkt->PTS_DTS_flags == 3) {
		klbs_read_bits(bs, 4); /* 0011 */
		pkt->PTS = read33bit_ts(bs);
		bits += 40;

		klbs_read_bits(bs, 4); /* 0001 */
		pkt->DTS = read33bit_ts(bs);
		bits += 40;
	}
	return bits;
}

void ltn_pes_packet_dump(struct ltn_pes_packet_s *pkt, const char *indent)
{
	char i[32];
	sprintf(i, "%s    ", indent);

	DISPLAY_U32(indent, pkt->packet_start_code_prefix);
	DISPLAY_U32_SUFFIX(i, pkt->stream_id,
		ltn_pes_packet_is_video(pkt) ? "[VIDEO]" :
		ltn_pes_packet_is_audio(pkt) ? "[AUDIO]" : "[OTHER]");

	DISPLAY_U32(i, pkt->PES_packet_length);
	DISPLAY_U32(i, pkt->PES_scrambling_control);
	DISPLAY_U32(i, pkt->PES_priority);
	DISPLAY_U32(i, pkt->data_alignment_indicator);
	DISPLAY_U32(i, pkt->copyright);
	DISPLAY_U32(i, pkt->original_or_copy);
	DISPLAY_U32(i, pkt->PTS_DTS_flags);
	DISPLAY_U32(i, pkt->ESCR_flag);
	DISPLAY_U32(i, pkt->ES_rate_flag);
	DISPLAY_U32(i, pkt->DSM_trick_mode_flag);
	DISPLAY_U32(i, pkt->additional_copy_info_flag);
	DISPLAY_U32(i, pkt->PES_CRC_flag);
	DISPLAY_U32(i, pkt->PES_extension_flag);
	DISPLAY_U32(i, pkt->PES_header_data_length);
	if (pkt->PTS_DTS_flags == 2) {
		DISPLAY_U64(i, pkt->PTS);
	} else
	if (pkt->PTS_DTS_flags == 3) {
		DISPLAY_U64(i, pkt->PTS);
		DISPLAY_U64(i, pkt->DTS);
	}
}

void ltn_pes_packet_copy(struct ltn_pes_packet_s *dst, struct ltn_pes_packet_s *src)
{
	memcpy(dst, src, sizeof(*src));
}

int ltn_pes_packet_is_audio(struct ltn_pes_packet_s *pes)
{
	if ((pes->stream_id >= 0xc0) && (pes->stream_id <= 0xdf)) {
		return 1;
	}

	/* AC3 / private */
	if (pes->stream_id >= 0xfd) {
		return 1;
	}

	return 0;
}

int ltn_pes_packet_is_video(struct ltn_pes_packet_s *pes)
{
	if ((pes->stream_id >= 0xe0) && (pes->stream_id <= 0xef)) {
		return 1;
	}

	return 0;
}
