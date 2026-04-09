/* Copyright LiveTimeNet, Inc. 2026. All Rights Reserved. */

#include "switcher-types.h"


/* For a given pes, look at the vars and stream content.
 * determine of the pes begins with a MP2 sync marker.
 * Returns 1 on success else 0.
 */
int pes_contains_start_of_mp2_sync(const struct ltn_pes_packet_s *pes)
{
	if (!ltn_pes_packet_is_audio((struct ltn_pes_packet_s *)pes))
		return 0;

	if (pes->dataLengthBytes < 2)
		return 0;

	/* MP2 sync word 0xFFF */
	if (pes->data[0] != 0xff)
		return 0;
	/* C = MPEG Version == MP2*/
	if (pes->data[1] != 0xfc)
		return 0;

	return 1; /* MP1/L2 sync found */
}

/* For a given pes, look at the vars and stream content.
 * determine of the pes begins with a MP2 sync marker.
 * Returns 1 on success else 0.
 */
int pes_contains_start_of_ac3_sync(const struct ltn_pes_packet_s *pes)
{
	if (!ltn_pes_packet_is_audio((struct ltn_pes_packet_s *)pes))
		return 0;

	if (pes->dataLengthBytes < 2)
		return 0;

	/* Fixed sync 0x0B77 */
	if (pes->data[0] != 0x0B)
		return 0;
	if (pes->data[1] != 0x77)
		return 0;

	return 1; /* AC3 sync found */
}

int pes_contains_start_of_aac_sync(const struct ltn_pes_packet_s *pes)
{
	/* FFFn
	adts_fixed_header() {
    syncword                         12 bits  // 0xFFF
    ID                                1 bit   // 0=MPEG-4, 1=MPEG-2
    layer                             2 bits  // always 00
    protection_absent                 1 bit   // 1=no CRC

    profile                           2 bits  // 1 = AAC-LC
    sampling_frequency_index          4 bits
    private_bit                       1 bit
    channel_configuration             3 bits
    original_copy                     1 bit
    home                              1 bit
	}
	*/
	if (!ltn_pes_packet_is_audio((struct ltn_pes_packet_s *)pes))
		return 0;

	if (pes->dataLengthBytes < 2)
		return 0;

	/* Fixed sync 0xFFF1 */
	if (pes->data[0] != 0xff)
		return 0;
	if (pes->data[1] != 0xf1)
		return 0;

	return 1; /* AAC ADTS sync found */
}


void pes_item_nals_dump(struct pes_item_s *item)
{
	for (int i = 0; i < item->nalArrayLength; i++) {
		struct ltn_nal_headers_s *nal = &item->nals[i];
		printf(" nal: %02x [%s]\n", nal->nalType, nal->nalName);
	}
}

void pes_item_nals_free(struct pes_item_s *item)
{
	if (item->nals) {
		free(item->nals);
		item->nals = NULL;
	}
	item->nalArrayLength = 0;
}

int pes_item_nals_alloc(struct pes_item_s *item)
{
	//struct tool_ctx_s *ctx = item->pid->stream->ctx;
	struct pid_s *pid = item->pid;

	unsigned int sliceType;

	/* Free any existing nals */
	pes_item_nals_free(item);

	/* Turn the PES into a series of NALS */
	if (ltn_nal_h264_find_headers(item->pes->data, item->pes->dataLengthBytes, &item->nals, &item->nalArrayLength) < 0) {
		return -1;
	}

/*
	printf("AVC: I/B/P = %" PRIu64 "/%" PRIu64 "/%" PRIu64 ", %" PRIu64 " slices.\n",
		ctx->count_frames_i, ctx->count_frames_b, ctx->count_frames_p,
		ctx->count_frames_i + ctx->count_frames_b + ctx->count_frames_p);
*/

	/* TODO: THIS IS AVC ONLY */
	for (int i = 0; i < item->nalArrayLength; i++) {
		struct ltn_nal_headers_s *nal = &item->nals[i];
		switch (nal->nalType) {
		case 1: /* slice_layer_without_partitioning_rbsp */
		case 2: /* slice_data_partition_a_layer_rbsp */
		case 5: /* slice_layer_without_partitioning_rbsp */
		case 19: /* slice_layer_without_partitioning_rbsp */
			if (h264_nal_get_slice_type_for_nal(nal, &sliceType) == 0) {
				//printf("SLICE TYPE %d, %s\n", sliceType, h264_slice_name_ascii(sliceType));
				if (h264_is_slice_type_iframe(sliceType)) {
					item->video.sliceType = SLICE_I;
					pid->count_frames_i++;
				} else
				if (h264_is_slice_type_bframe(sliceType)) {
					item->video.sliceType = SLICE_B;
					pid->count_frames_b++;
				} else
				if (h264_is_slice_type_pframe(sliceType)) {
					item->video.sliceType = SLICE_P;
					pid->count_frames_p++;
				}
			}
			break;
		case 7:
			item->video.has_avc_sps = 1;
			break;
		case 8:
			item->video.has_avc_pps = 1;
			break;
		case 9:
			item->video.has_avc_aud = 1;
			break;
		}
	}

	return 0; /* Success */
}

struct pes_item_s *pes_item_alloc(struct pid_s *pid, struct ltn_pes_packet_s *pes, struct output_stream_s *os)
{
    struct pes_item_s *item = calloc(1, sizeof(*item));
    if (!item) {
        return item;
    }

    item->pes = pes;
    item->pid = pid;
    item->created = time(NULL);
    item->arrivalSTC = output_get_computed_stc(os); /* We got the pes at the current STC */

    if (pid->type == PID_VIDEO) {
        item->outputSTC = output_get_computed_stc(os) + (27000 * 200); /* We'll schedule for output in 200ms */
    } else 
    if (pid->type == PID_AUDIO) {
        item->outputSTC = 0; // get_computed_stc(os);
    }

    if (ltn_pes_packet_is_video((struct ltn_pes_packet_s *)item->pes)) {
        //printf("pes contains video\n");
        item->type = PID_VIDEO;

        if (pes_item_nals_alloc(item) < 0) {
            fprintf(stderr, "asked to find nals, no nals found.... unusual, continuiting...\n");
        }
        /* item->video.has_XYZ are now set correctly */

    } else
    if (ltn_pes_packet_is_audio((struct ltn_pes_packet_s *)item->pes)) {
        item->type = PID_AUDIO;
        //printf("pes contains audio\n");
        if (pes_contains_start_of_mp2_sync(pes) == 1) {
            //printf("Contains MP1/L2 sync\n");
            item->audio.hasSync_MP1L2 = 1;
        } else
        if (pes_contains_start_of_ac3_sync(pes) == 1) {
            //printf("Contains AC3 sync\n");
            item->audio.hasSync_AC3 = 1;
        } else
        if (pes_contains_start_of_aac_sync(pes) == 1) {
            //printf("Contains AAC/ADTS sync\n");
            item->audio.hasSync_AAC = 1;
        }
    } else {
        item->type = PID_OTHER;
    }

    return item;
}

void pes_item_free(struct pes_item_s *item)
{
    if (item->pes) {
        ltn_pes_packet_free(item->pes);
        item->pes = NULL;
    }

    pes_item_nals_free(item);

    free(item);
}
