#include "pes.h"
#include "klbitstream_readwriter.h"

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

static uint64_t read33bit_ts(struct klbs_context_s *bs)
{
	uint64_t ts = 0, a, b, c;

	klbs_read_bits(bs, 4); /* 0010 */

	a = klbs_read_bits(bs, 3);
	klbs_read_bit(bs); /* marker */

	b = klbs_read_bits(bs, 15);
	klbs_read_bit(bs); /* marker */

	c = klbs_read_bits(bs, 15);
	klbs_read_bit(bs); /* marker */

	ts = (a << 30) | (b << 15) | c;

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

