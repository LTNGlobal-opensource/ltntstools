#ifndef PES_H
#define PES_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct klbs_context_s;

/* See ISO13818 table 2.18 */
/* Implement enough of a PES header and parsing funcs
 * that we can extract PTS/DTS fields.
 * Struct is created for optimal cpu register speed, not for memory efficiency.
 */
struct ltn_pes_packet_s
{
	uint32_t packet_start_code_prefix;
	uint32_t stream_id;
	uint32_t PES_packet_length;

	uint32_t PES_scrambling_control;
	uint32_t PES_priority;
	uint32_t data_alignment_indicator;
	uint32_t copyright;
	uint32_t original_or_copy;
	uint32_t PTS_DTS_flags;
	uint32_t ESCR_flag;
	uint32_t ES_rate_flag;
	uint32_t DSM_trick_mode_flag;
	uint32_t additional_copy_info_flag;
	uint32_t PES_CRC_flag;
	uint32_t PES_extension_flag;
	uint32_t PES_header_data_length;

	int64_t PTS;
	int64_t DTS;
};

struct ltn_pes_packet_s *ltn_pes_packet_alloc();
void ltn_pes_packet_init(struct ltn_pes_packet_s *pkt);
void ltn_pes_packet_free(struct ltn_pes_packet_s *pkt);

/* Parse an existing bitstream into an existing pkt, returning the number of bits parsed,
 * or < 0 on error.
 */
ssize_t ltn_pes_packet_parse(struct ltn_pes_packet_s *pkt, struct klbs_context_s *bs);
void ltn_pes_packet_dump(struct ltn_pes_packet_s *pkt, const char *indent);
void ltn_pes_packet_copy(struct ltn_pes_packet_s *dst, struct ltn_pes_packet_s *src);

int ltn_pes_packet_is_audio(struct ltn_pes_packet_s *pes);
int ltn_pes_packet_is_video(struct ltn_pes_packet_s *pes);

#endif /* PES_H */
