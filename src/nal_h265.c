#include "libltntstools/ts.h"
#include "nal_h265.h"
#include "nal_h264.h"
#include <inttypes.h>

#include <libltntstools/nal_bitreader.h>


int ltn_nal_h265_find_headers(const uint8_t *buf, int lengthBytes, struct ltn_nal_headers_s **array, int *arrayLength)
{
	int idx = 0;
	int maxitems = 64;
	struct ltn_nal_headers_s *a = malloc(sizeof(struct ltn_nal_headers_s) * maxitems);
	if (!a)
		return -1;

	int offset = -1;
	struct ltn_nal_headers_s *curr = a, *prev = a;
	while (ltn_nal_h265_findHeader(buf, lengthBytes, &offset) == 0) {
		curr->ptr = buf + offset;
		curr->nalType = (buf[offset + 3] >> 1) & 0x3f;
		curr->nalName = h265Nals_lookupName(curr->nalType);
		if (curr != prev) {
			prev->lengthBytes = curr->ptr - prev->ptr;
		}
		
		prev = curr;
		curr++;
		idx++;
	}
	prev->lengthBytes = (buf + lengthBytes) - prev->ptr;

	*array = a;
	*arrayLength = idx;
	return 0; /* Success */
}

/*
 * TRAIL_N and TRAIL_R Nals
 *   slice_segment_layer_rbsp()
 *      slice_segment_header()
 *        (contains slice_type)
 */

int ltn_nal_h265_findHeader(const uint8_t *buffer, int lengthBytes, int *offset)
{
	const uint8_t sig[] = { 0, 0, 1 };

	for (int i = (*offset + 1); i < lengthBytes - (int)sizeof(sig); i++) {
		if (memcmp(buffer + i, sig, sizeof(sig)) == 0) {

			/* Check for the forbidden zero bit, it's illegal to be high in a nal (conflicts with PES headers. */
			if (*(buffer + i + 3) & 0x80)
				continue;

			*offset = i;
			return 0; /* Success */
		}
	}

	return -1; /* Not found */
}

static struct hevcNal_s {
	const char *name;
	const char *type;
} hevcNals[] = {
	[ 0] = { "TRAIL_N", .type = "AUTO" },
	[ 1] = { "TRAIL_R", .type = "IDR" },
	[ 2] = {   "TSA_N", .type = "I" },
	[ 3] = {   "TSA_R", .type = "P" },
	[ 4] = {  "STSA_N", .type = "BREF" },
	[ 5] = {  "STSA_R", .type = "B" },
	[ 6] = { "RADL_N" },
	[ 7] = { "RADL_R" },
	[ 8] = { "RASL_N" },
	[ 9] = { "RASL_R" },
	[10] = { "RSV_VCL_N10" },
	[11] = { "RSV_VCL_R11" },
	[12] = { "RSV_VCL_N12" },
	[13] = { "RSV_VCL_R13" },
	[14] = { "RSV_VCL_N14" },
	[15] = { "RSV_VCL_R15" },

	[16] = { "BLA_W_LP" },
	[17] = { "BLA_W_RADL" },
	[18] = { "BLA_N_LP" },

	[19] = { "IDR_W_RADL", .type = "IDR" },
	[20] = { "IDR_N_LP" },

	[21] = { "CRA" },

	[22] = { "RSV_IRAP_VCL22" },
	[23] = { "RSV_IRAP_VCL23" },

	[32] = { "VPS" },
	[33] = { "SPS" },
	[34] = { "PPS" },
	[35] = { "AUD" },
	[36] = { "EOS" },
	[37] = { "EOB" },
	[38] = { "FD filler_data_rbsp()" },
	[39] = { "PREFIX_SEI" },
	[40] = { "SUFFIX_SEI" },
};

const char *h265Nals_lookupName(int nalType)
{
	return hevcNals[nalType].name;
}

const char *h265Nals_lookupType(int nalType)
{
	return hevcNals[nalType].type;
}

char *ltn_nal_h265_findNalTypes(const uint8_t *buffer, int lengthBytes)
{
	char *arr = calloc(1, 128);
	arr[0] = 0;

	int items = 0;
	int offset = -1;
	while (ltn_nal_h265_findHeader(buffer, lengthBytes, &offset) == 0) {
		unsigned int nalType = (buffer[offset + 3] >> 1) & 0x3f;
		const char *nalName = h265Nals_lookupName(nalType);
		//const char *nalTypeDesc = h265Nals_lookupType(nalType);

		if (items++ > 0)
			sprintf(arr + strlen(arr), ", ");

		sprintf(arr + strlen(arr), "%s", nalName);
#if 0
		printf("%6d: %02x %02x %02x %02x : type %2d (%s)\n",
			offset,
			buffer[offset + 0],
			buffer[offset + 1],
			buffer[offset + 2],
			buffer[offset + 3],
			nalType,
			nalName);
#endif
	}
	
	if (items == 0) {
		free(arr);
		return NULL;
	}

	return arr;
}


struct h265_slice_data_s
{
	uint32_t  slice_type;
	uint64_t  count;
	char     *name;
};

#define MAX_H265_SLICE_TYPES 3
static struct h265_slice_data_s slice_defaults[MAX_H265_SLICE_TYPES] = {
	{ 0, 0, "B", },
	{ 1, 0, "P", },
	{ 2, 0, "I", },
};

const char *h265_slice_name_ascii(int slice_type)
{
	return &slice_defaults[ slice_type % MAX_H265_SLICE_TYPES ].name[0];
}

struct h265_slice_counter_s
{
	uint16_t pid;
	struct h265_slice_data_s slice[MAX_H265_SLICE_TYPES];

	int nextHistoryPos;
    char sliceHistory[H265_SLICE_COUNTER_HISTORY_LENGTH];

	/* SPS */
	uint32_t spsValid;
	uint32_t sps_video_parameter_set_id;
	uint32_t sps_max_sub_layers_minus1;
	uint32_t sps_temporal_id_nesting_flag;

	/* PPS */
	uint32_t ppsValid;
	uint32_t pps_pic_parameter_set_id;
	uint32_t pps_seq_parameter_set_id;
	uint32_t dependent_slice_segments_enabled_flag;
	uint32_t output_flag_present_flag;
	uint32_t num_extra_slice_header_bits;

};

void h265_slice_counter_reset(void *ctx)
{
	struct h265_slice_counter_s *s = (struct h265_slice_counter_s *)ctx;
	memcpy(s->slice, slice_defaults, sizeof(slice_defaults));
	for (int i = 0; i < H265_SLICE_COUNTER_HISTORY_LENGTH; i++) {
		s->sliceHistory[i] = ' ';
	}
	s->sliceHistory[H265_SLICE_COUNTER_HISTORY_LENGTH - 1] = 0;
}

void *h265_slice_counter_alloc(uint16_t pid)
{
	struct h265_slice_counter_s *s = malloc(sizeof(*s));
	s->pid = pid;
	h265_slice_counter_reset(s);
	return (void *)s;
}

void h265_slice_counter_free(void *ctx)
{
	struct h265_slice_counter_s *s = (struct h265_slice_counter_s *)ctx;
	free(s);
}

void h265_slice_counter_update(void *ctx, int slice_type)
{
	struct h265_slice_counter_s *s = (struct h265_slice_counter_s *)ctx;
	s->slice[ slice_type ].count++;

    s->sliceHistory[s->nextHistoryPos++ % H265_SLICE_COUNTER_HISTORY_LENGTH] = s->slice[ slice_type ].name[0];
}

void h265_slice_counter_dprintf(void *ctx, int fd, int printZeroCounts)
{
	struct h265_slice_counter_s *s = (struct h265_slice_counter_s *)ctx;
	dprintf(fd, "Type  Name  Count (H265 slice types for pid 0x%04x)\n", s->pid);
	for (int i = MAX_H265_SLICE_TYPES - 1; i >= 0 ; i--) {
		struct h265_slice_data_s *sl = &s->slice[i];
		if (sl->count == 0 && !printZeroCounts)
			continue;
		dprintf(fd, "%4d  %4s  %" PRIu64 "\n", sl->slice_type, sl->name, sl->count);
	}
}

static void h265_slice_counter_write_packet(void *ctx, const unsigned char *pkt)
{
	struct h265_slice_counter_s *s = (struct h265_slice_counter_s *)ctx;
	NALBitReader br;

	int offset = -1;
	while (offset < ((1 * 188) - 5)) {
		if (ltn_nal_h265_findHeader(pkt, 188, &offset) == 0) {
			unsigned int nalType = (*(pkt + offset + 3) >> 1) & 0x3f;
#if 0
			printf("H265 nal at 0x%04x: ", offset);
			for (int i = 0; i < 6; i++)
				printf("%02x ", *(pkt + offset + i));

			printf("NalType : %02x - %s ", nalType, h265Nals_lookupName(nalType));
#endif

#if 1
			switch (nalType) {
			case 33: /* SPS - 7.3.2.2.1 General sequence parameter set RBSP syntax */
				/* We need to query a couple of fields before we can decode
				 * a slice segment header to extract the slice type.
				 */
				if (s->spsValid)
					break; /* Already have the data */

				NALBitReader_init(&br, pkt + offset + 4, 4);

				s->sps_video_parameter_set_id = NALBitReader_read_bits(&br, 4);
				s->sps_max_sub_layers_minus1 = NALBitReader_read_bits(&br, 3);
				s->sps_temporal_id_nesting_flag = NALBitReader_read_bits(&br, 1);

				s->spsValid = 1;
				/* Abort parsing from here */

				break;

			case 34: /* PPS - 7.3.2.3.1 General picture parameter set RBSP syntax */
				/* We need to query a couple of fields before we can decode
				 * a slice segment header to extract the slice type.
				 * Find the num_extra_slice_header_bits field.
				 */
				if (s->ppsValid)
					break; /* Already have the data */

				NALBitReader_init(&br, pkt + offset + 4, 4);

				s->pps_pic_parameter_set_id = NALBitReader_read_ue(&br);
				s->pps_seq_parameter_set_id = NALBitReader_read_ue(&br);
				s->dependent_slice_segments_enabled_flag = NALBitReader_read_bits(&br, 1);
				s->output_flag_present_flag = NALBitReader_read_bits(&br, 1);
				s->num_extra_slice_header_bits = NALBitReader_read_bits(&br, 3);
				s->ppsValid = 1;
				/* Abort parsing from here */
				break;
			case 0: /* TRAIL_N - slice_segment_layer_rbsp */
			case 1: /* TRAIL_R - slice_segment_layer_rbsp */
			case 2: /* TSA_N - slice_segment_layer_rbsp */
			case 3: /* TSA_R - slice_segment_layer_rbsp */
			case 4: /* STSA_N - slice_segment_layer_rbsp */
			case 5: /* STSA_R - slice_segment_layer_rbsp */
			case 6: /* RADL_N - slice_segment_layer_rbsp */
			case 7: /* RADL_R - slice_segment_layer_rbsp */
			case 8: /* RASL_N - slice_segment_layer_rbsp */
			case 9: /* RASL_R - slice_segment_layer_rbsp */
			case 16:
			case 17:
			case 18:
			case 19:
			case 20:
			case 21:
				if (s->ppsValid == 0)
					break;

				NALBitReader_init(&br, pkt + offset + 4, 4);
				int first_slice_segment_in_pic_flag = NALBitReader_read_bits(&br, 1);
				if ((nalType >= 16) && (nalType <= 23)) {
					int no_output_of_prior_pics_flag = NALBitReader_read_bits(&br, 1);
					printf("no_output_of_prior_pics_flag = %d\n", no_output_of_prior_pics_flag);
				}

				int slice_pic_parameter_set_id = NALBitReader_read_ue(&br);
				printf("slice_pic_parameter_set_id = %d\n", slice_pic_parameter_set_id);

				int dependent_slice_segment_flag = 0;
				if (!first_slice_segment_in_pic_flag) {
					if (s->dependent_slice_segments_enabled_flag) {
						dependent_slice_segment_flag = NALBitReader_read_bits(&br, 1);
					}
					//int slice_address_length = 0; //av_ceil_log2(s->ps.sps->ctb_width * s->ps.sps->ctb_height);
					int slice_segment_address = NALBitReader_read_bits(&br, 1);
					printf("slice_segment_address = %d\n", slice_segment_address);
				}

				int slice_type = -1;
				if (!dependent_slice_segment_flag) {
					for (unsigned int i = 0; i < s->num_extra_slice_header_bits; i++) {
						NALBitReader_skip_bits(&br, 1); /* Reserved */
					}
					slice_type = NALBitReader_read_ue(&br);
					printf("slice_type = %d\n", slice_type);
					// End of parsing */
				}
				// End of parsing */

				if (slice_type < MAX_H265_SLICE_TYPES) {
					h265_slice_counter_update(s, slice_type);
					//h265_slice_counter_dprintf(s, 0, 0);
				} else {
					/* Malformed stream, not a video stream probably.
					 * in 0x2000 mode we catch audio using this filter
					 * and we need to ignore it.
					 */
					printf("PKT : ");
					for (int i = 0; i < 8; i++)
						printf("%02x ", *(pkt + i));
					printf("\n  -> offset %3d, nal? %2d slice %2d: ", offset, nalType, slice_type);
					for (int i = 0; i < 12; i++)
						printf("%02x ", *(pkt + offset + i));
					printf("\n");
				}
				break;
			}
#endif
#if 1
			printf("\n");
#endif
		} else
			break;
	}
}

void h265_slice_counter_write(void *ctx, const unsigned char *pkts, int pktCount)
{
	struct h265_slice_counter_s *s = (struct h265_slice_counter_s *)ctx;
	for (int i = 0; i < pktCount; i++) {
		uint16_t pid = ltntstools_pid(pkts + (i * 188));
		if (s->pid == 0x2000 || pid == s->pid) {
			h265_slice_counter_write_packet(s, pkts + (i * 188));
		}
	}
}

void h265_slice_counter_query(void *ctx, struct h265_slice_counter_results_s *results)
{
	struct h265_slice_counter_s *s = (struct h265_slice_counter_s *)ctx;
	results->i = s->slice[2].count;
	results->b = s->slice[0].count;
	results->p = s->slice[1].count;

	int p = s->nextHistoryPos;
	for (int i = 0; i < H265_SLICE_COUNTER_HISTORY_LENGTH; i++) {
		results->sliceHistory[i] = s->sliceHistory[p++ % H265_SLICE_COUNTER_HISTORY_LENGTH];
	}
	results->sliceHistory[H265_SLICE_COUNTER_HISTORY_LENGTH] = 0x0;
}

uint16_t h265_slice_counter_get_pid(void *ctx)
{
	struct h265_slice_counter_s *s = (struct h265_slice_counter_s *)ctx;
	return s->pid;
}

void h265_slice_counter_reset_pid(void *ctx, uint16_t pid)
{
	struct h265_slice_counter_s *s = (struct h265_slice_counter_s *)ctx;
	s->pid = pid;
	h265_slice_counter_reset(ctx);
}

/* HEVC */
