
/* Copyright Kernel Labs Inc 2015-2018 */

#include "avc-types.h"

#include <libltntstools/nal_bitreader.h>

struct avc_slice_header_s *avc_slice_header_alloc()
{
    return calloc(1, sizeof(struct avc_slice_header_s));
}

void avc_slice_header_free(struct avc_slice_header_s *sh)
{
    free(sh);
}

/* This ALWAYS assumes the RBP stripped has taken place BEFORE hand,
 * See ltn_nal_h264_strip_emulation_prevention(struct ltn_nal_headers_s *h) if you need that.
 */
/* See ISO/IEC 14496-10:2014(E) - 7.3.3 Slice header syntax */
int avc_slice_header_parse(struct avc_seq_parameter_set_s *sps,
    struct avc_pic_parameter_set_s *pps,
    struct avc_slice_header_s *sh, int nal_unit_type, const uint8_t *buf, int lengthBytes)
{
    NALBitReader sbr, *br = &sbr;

    NALBitReader_init(br, buf, lengthBytes);

    memset(sh, 0, sizeof(*sh));

    int IdrPicFlag = ((nal_unit_type == 5 ) ? 1 : 0 ); 

    sh->first_mb_in_slice = NALBitReader_read_ue(br);
    sh->slice_type = NALBitReader_read_ue(br);
    sh->pic_parameter_set_id = NALBitReader_read_ue(br);

    if (sps->separate_colour_plane_flag == 1) {
        sh->colour_plane_id = NALBitReader_read_bits(br, 2);
    }

    sh->frame_num = NALBitReader_read_bits(br, sps->log2_max_frame_num_minus4 + 4); /* Maybe */

    if (!sps->frame_mbs_only_flag) {
        sh->field_pic_flag = NALBitReader_read_bits(br, 1);
        if (sh->field_pic_flag) {
            sh->bottom_field_flag = NALBitReader_read_bits(br, 1);
        }
    }

    if (IdrPicFlag) {
        sh->idr_pic_id = NALBitReader_read_ue(br);
    }

    if (sps->pic_order_cnt_type == 0) {
        sh->pic_order_cnt_lsb = NALBitReader_read_bits(br, sps->log2_max_pic_order_cnt_lab_minus4 + 4); /* Maybe */
        if (pps->bottom_field_pic_order_in_frame_present_flag && !sh->field_pic_flag) {
            sh->delta_pic_order_cnt_bottom = NALBitReader_read_se(br);
        }
    }

    return 0; /* Success */
}
