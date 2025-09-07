#include <libltntstools/ts.h>
#include "nal_h264.h"
#include <inttypes.h>
#include "memmem.h"

#include <libltntstools/nal_bitreader.h>

int ltn_nal_h264_find_headers(const uint8_t *buf, int lengthBytes, struct ltn_nal_headers_s **array, int *arrayLength)
{
	int idx = 0;
	int maxitems = 64;
	struct ltn_nal_headers_s *a = malloc(sizeof(struct ltn_nal_headers_s) * maxitems);
	if (!a) {
		return -1;
	}
	const uint8_t start_code[3] = {0, 0, 1};
	const uint8_t *end = buf + lengthBytes;
	const uint8_t *p = buf;

	while (p < end - 3) {
		p = ltn_memmem(p, end - p, start_code, sizeof(start_code));
		if (!p)
				break;

		if (idx >= maxitems) {
				maxitems *= 2;
				struct ltn_nal_headers_s *temp = realloc(a, sizeof(struct ltn_nal_headers_s) * maxitems);
				if (!temp)
				{
						free(a);
						return -1;
				}
				a = temp;
		}

		a[idx].ptr = p;
		a[idx].nalType = p[3] & 0x1f;
		a[idx].nalName = h264Nals_lookupName(a[idx].nalType);
		if (idx > 0) {
				a[idx - 1].lengthBytes = p - a[idx - 1].ptr;
		}

		idx++;
		p += 3; // Move past start code
	}

	if (idx > 0) {
		a[idx - 1].lengthBytes = end - a[idx - 1].ptr;
	}

	*array = a;
	*arrayLength = idx;
	return 0; /* Success */
}

int ltn_nal_h264_findHeader(const uint8_t *buffer, int lengthBytes, int *offset)
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

#define NAL_TYPE_SEI 0x06

static struct h264Nal_s {
	const char *name;
	const char *type;
} h264Nals[] = {
	[ 0] = { "UNSPECIFIED", .type = "AUTO" },
	[ 1] = { "slice_layer_without_partitioning_rbsp non-IDR", .type = "P" },
	[ 2] = { "slice_data_partition_a_layer_rbsp(", .type = "P" },
	[ 3] = { "slice_data_partition_b_layer_rbsp(", .type = "P" },
	[ 4] = { "slice_data_partition_c_layer_rbsp(", .type = "P" },
	[ 5] = { "slice_layer_without_partitioning_rbsp IDR", .type = "IDR" },
	[ 6] = { "SEI", .type = "" },
	[ 7] = { "SPS", .type = "" },
	[ 8] = { "PPS", .type = "" },
	[ 9] = { "AUD", .type = "" },
	[10] = { "EO SEQ", .type = "" },
	[11] = { "EO STREAM", .type = "" },
	[12] = { "FILLER", .type = "" },
	[13] = { "SPS-EX", .type = "" },
	[14] = { "PNU", .type = "" },
	[15] = { "SSPS", .type = "" },
	[16] = { "DPS", .type = "" },
	[19] = { "ACP", .type = "" },
	[20] = { "CSE", .type = "" },
	[21] = { "CSEDV", .type = "" },
};

const char *h264Nals_lookupName(int nalType)
{
	return h264Nals[nalType].name;
}

const char *h264Nals_lookupType(int nalType)
{
	return h264Nals[nalType].type;
}

char *ltn_nal_h264_findNalTypes(const uint8_t *buffer, int lengthBytes)
{
	char *arr = calloc(1, 128);
	arr[0] = 0;

	int items = 0;
	int offset = -1;
	while (ltn_nal_h264_findHeader(buffer, lengthBytes, &offset) == 0) {
		unsigned int nalType = buffer[offset + 3] & 0x1f;
		const char *nalName = h264Nals_lookupName(nalType);
		//const char *nalTypeDesc = h264Nals_lookupType(nalType);

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


struct h264_slice_data_s
{
	uint32_t  slice_type;
	uint64_t  count;
	char     *name;
};

#define MAX_H264_SLICE_TYPES 10
static struct h264_slice_data_s slice_defaults[MAX_H264_SLICE_TYPES] = {
	{ 0, 0, "P", },
	{ 1, 0, "B", },
	{ 2, 0, "I", },
	{ 3, 0, "p", },
	{ 4, 0, "i", },
	{ 5, 0, "P", },
	{ 6, 0, "B", },
	{ 7, 0, "I", },
	{ 8, 0, "p", },
	{ 9, 0, "i", },
};

const char *h264_slice_name_ascii(int slice_type)
{
	return &slice_defaults[ slice_type % MAX_H264_SLICE_TYPES ].name[0];
}

struct h264_slice_counter_s
{
	uint16_t pid;
	struct h264_slice_data_s slice[MAX_H264_SLICE_TYPES];

	int nextHistoryPos;
	char sliceHistory[H264_SLICE_COUNTER_HISTORY_LENGTH + 1];
};

void h264_slice_counter_reset(void *ctx)
{
	struct h264_slice_counter_s *s = (struct h264_slice_counter_s *)ctx;
	memcpy(s->slice, slice_defaults, sizeof(slice_defaults));
	for (int i = 0; i < H264_SLICE_COUNTER_HISTORY_LENGTH; i++) {
		s->sliceHistory[i] = ' ';
	}
	s->sliceHistory[H264_SLICE_COUNTER_HISTORY_LENGTH] = 0;
}

void *h264_slice_counter_alloc(uint16_t pid)
{
	struct h264_slice_counter_s *s = malloc(sizeof(*s));
	s->pid = pid;
	h264_slice_counter_reset(s);
	return (void *)s;
}

void h264_slice_counter_free(void *ctx)
{
	struct h264_slice_counter_s *s = (struct h264_slice_counter_s *)ctx;
	free(s);
}

void h264_slice_counter_update(void *ctx, int slice_type)
{
	struct h264_slice_counter_s *s = (struct h264_slice_counter_s *)ctx;
	s->slice[ slice_type ].count++;

    s->sliceHistory[s->nextHistoryPos++ % H264_SLICE_COUNTER_HISTORY_LENGTH] = s->slice[ slice_type ].name[0];
}

void h264_slice_counter_dprintf(void *ctx, int fd, int printZeroCounts)
{
	struct h264_slice_counter_s *s = (struct h264_slice_counter_s *)ctx;
	dprintf(fd, "Type  Name  Count (H264 slice types for pid 0x%04x)\n", s->pid);
	for (int i = MAX_H264_SLICE_TYPES - 1; i >= 0 ; i--) {
		struct h264_slice_data_s *sl = &s->slice[i];
		if (sl->count == 0 && !printZeroCounts)
			continue;
		dprintf(fd, "%4d  %4s  %" PRIu64 "\n", sl->slice_type, sl->name, sl->count);
	}
}

int h264_nal_get_slice_type(const struct ltn_nal_headers_s *hdr, char *sliceType)
{
	NALBitReader br;
	int offset = -1;

	if (ltn_nal_h264_findHeader(hdr->ptr, hdr->lengthBytes, &offset) == 0) {
	
		unsigned int nalType = *(hdr->ptr + offset + 3) & 0x1f;

		switch (nalType) {
		case 1: /* slice_layer_without_partitioning_rbsp */
		case 2: /* slice_data_partition_a_layer_rbsp */
		case 5: /* slice_layer_without_partitioning_rbsp */
		case 19: /* slice_layer_without_partitioning_rbsp */
			NALBitReader_init(&br, hdr->ptr + 4, 4);
			NALBitReader_read_ue(&br); /* first_mb_in_slice */
			int slice_type = NALBitReader_read_ue(&br);
			if (slice_type < MAX_H264_SLICE_TYPES) {
				strcpy(sliceType, h264_slice_name_ascii(slice_type));
			} else {
				/* Malformed stream, not a video stream probably.
					* in 0x2000 mode we catch audio using this filter
					* and we need to ignore it.
					*/
#if 0
				printf("PKT : ");
				for (int i = 0; i < 8; i++)
					printf("%02x ", *(pkt + i));
				printf("\n  -> offset %3d, nal? %2d slice %2d: ", offset, nalType, slice_type);
				for (int i = 0; i < 12; i++)
					printf("%02x ", *(pkt + offset + i));
				printf("\n");
#endif
			}
			return 0; /* Success */
		}
	}
#if 0
		printf("\n");
#endif

	return -1; /* error */
}

static void h264_slice_counter_write_packet(void *ctx, const unsigned char *pkt)
{

	struct h264_slice_counter_s *s = (struct h264_slice_counter_s *)ctx;
	NALBitReader br;

	int offset = -1;
	while (offset < ((1 * 188) - 5)) {
		if (ltn_nal_h264_findHeader(pkt, 188, &offset) == 0) {
			unsigned int nalType = *(pkt + offset + 3) & 0x1f;
#if 0
			printf("nal at 0x%04x: ", offset);
			for (int i = 0; i < 6; i++)
				printf("%02x ", *(pkt + offset + i));

			printf("NalType : %02x - %s ", nalType, h264Nals_lookupName(nalType));
#endif
			switch (nalType) {
			case 1: /* slice_layer_without_partitioning_rbsp */
			case 2: /* slice_data_partition_a_layer_rbsp */
#if 0
			/* No slice headers at the beginnig of these structs */
			case 3: /* slice_data_partition_b_layer_rbsp */
			case 4: /* slice_data_partition_c_layer_rbsp */

			// Problems from audio packets that were mi-interpreted in 0x2000 mode.
			offset  52, nal? 19 slice 10: 00 00 01 13 8b 3c f3 55 51 45 58 61
			offset  76, nal? 19 slice 14: 00 00 01 53 8f 4c f3 d6 55 25 94 49
			offset 100, nal? 19 slice 14: 00 00 01 13 8f 44 f3 90 41 24 10 44
			offset 100, nal?  1 slice 27: 00 00 01 01 87 1b 88 7c 80 ec 17 8b
#endif
			case 5: /* slice_layer_without_partitioning_rbsp */
			case 19: /* slice_layer_without_partitioning_rbsp */
				NALBitReader_init(&br, pkt + offset + 4, 4);
				NALBitReader_read_ue(&br); /* first_mb_in_slice */
				int slice_type = NALBitReader_read_ue(&br);
				if (slice_type < MAX_H264_SLICE_TYPES) {
					h264_slice_counter_update(s, slice_type);
					//h264_slice_counter_dprintf(s, 0, 0);
				} else {
					/* Malformed stream, not a video stream probably.
					 * in 0x2000 mode we catch audio using this filter
					 * and we need to ignore it.
					 */
#if 0
					printf("PKT : ");
					for (int i = 0; i < 8; i++)
						printf("%02x ", *(pkt + i));
					printf("\n  -> offset %3d, nal? %2d slice %2d: ", offset, nalType, slice_type);
					for (int i = 0; i < 12; i++)
						printf("%02x ", *(pkt + offset + i));
					printf("\n");
#endif
				}
				break;
			}
#if 0
			printf("\n");
#endif
		} else
			break;
	}
}

void h264_slice_counter_write(void *ctx, const unsigned char *pkts, int pktCount)
{
	struct h264_slice_counter_s *s = (struct h264_slice_counter_s *)ctx;
	for (int i = 0; i < pktCount; i++) {
		uint16_t pid = ltntstools_pid(pkts + (i * 188));
		if (s->pid == 0x2000 || pid == s->pid) {
			h264_slice_counter_write_packet(s, pkts + (i * 188));
		}
	}
}

void h264_slice_counter_query(void *ctx, struct h264_slice_counter_results_s *results)
{
	struct h264_slice_counter_s *s = (struct h264_slice_counter_s *)ctx;
	results->i = s->slice[2].count + s->slice[7].count;
	results->b = s->slice[1].count + s->slice[6].count;
	results->p = s->slice[0].count + s->slice[5].count;
	results->si = s->slice[4].count + s->slice[9].count;
	results->sp = s->slice[3].count + s->slice[8].count;

	int p = s->nextHistoryPos;
	for (int i = 0; i < H264_SLICE_COUNTER_HISTORY_LENGTH; i++) {
		results->sliceHistory[i] = s->sliceHistory[p++ % H264_SLICE_COUNTER_HISTORY_LENGTH];
	}
	results->sliceHistory[H264_SLICE_COUNTER_HISTORY_LENGTH] = 0x0;
}

uint16_t h264_slice_counter_get_pid(void *ctx)
{
	struct h264_slice_counter_s *s = (struct h264_slice_counter_s *)ctx;
	return s->pid;
}

void h264_slice_counter_reset_pid(void *ctx, uint16_t pid)
{
	struct h264_slice_counter_s *s = (struct h264_slice_counter_s *)ctx;
	s->pid = pid;
	h264_slice_counter_reset(ctx);
}

/* See ISO 14496-10 Appened D.1 2004 Page 231 */
#define MAX_H264_SEI (18)
static struct h264SEI_s {
	const char *name;
	const char *type;
} h264SEIs[] = {
	[ 0] = { "buffer_period",							.type = 0 },
	[ 1] = { "pic_timing",								.type = 0 },
	[ 2] = { "pan_scan_rect",							.type = 0 },
	[ 3] = { "filler_payload",							.type = 0 },
	[ 4] = { "user_data_registered_itu_t_t35",			.type = 0 },
	[ 5] = { "user_data_unregistered",					.type = 0 },
	[ 6] = { "recovery_point",							.type = 0 },
	[ 7] = { "dec_ref_pic_marking_repetition",			.type = 0 },
	[ 8] = { "spare_pic",								.type = 0 },
	[ 9] = { "scene_info",								.type = 0 },
	[10] = { "sub_seq_info",							.type = 0 },
	[11] = { "sub_seq_layer_characteristics",			.type = 0 },
	[12] = { "sub_seq_characteristics",					.type = 0 },
	[13] = { "full_frame_freeze",						.type = 0 },
	[14] = { "full_frame_freeze_release",				.type = 0 },
	[15] = { "full_frame_snapshot",						.type = 0 },
	[16] = { "progressive_refinement_segment_start",	.type = 0 },
	[17] = { "progressive_refinement_segment_end",		.type = 0 },
	[18] = { "motion_constrained_slice_group_set",		.type = 0 },
	[64] = { "undefined in spec 2004",					.type = 0 },
};

const char *ltn_sei_h264_lookupName(int seiType)
{
	if (seiType <= MAX_H264_SEI) {
		return h264SEIs[seiType].name;
	} else {
		return h264SEIs[64].name;
	}
}

int ltn_sei_h264_find_headers(struct ltn_nal_headers_s *nals, int nalArrayLength, struct ltn_sei_headers_s **array, int *arrayLength)
{
	if (!arrayLength) {
		return -1;
	}

	if (nals == 0) {
		return -1;
	}

	int idx = 0;
	int maxitems = 64;
	*array = malloc(sizeof(struct ltn_sei_headers_s) * maxitems);
	if (!array) {
		return -1;
	}

	struct ltn_sei_headers_s *hdr = *array;

	for (int i = 0; i < nalArrayLength; i++) {
		if (nals[i].nalType == NAL_TYPE_SEI) {

			uint8_t seiType = nals[i].ptr[4]; /* SEI Sub Type, buffer_period 0, PIC_TIMING 1, etc */

			hdr->lengthBytes	= nals[i].lengthBytes;
			hdr->ptr			= nals[i].ptr;
			hdr->seiType		= seiType;
			hdr->seiName		= ltn_sei_h264_lookupName(hdr->seiType);

			hdr++;
			idx++;
		}
	}

	*arrayLength = idx;

	return 0; /* Success */
}
