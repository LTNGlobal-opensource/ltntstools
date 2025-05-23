#ifndef H264_CODEC_METADATA_H
#define H264_CODEC_METADATA_H

/* A framework to demux h264 nals from transport streams,
 * pull apart some lightwight structures and bitfirsts and
 * expose core metadata such as width, height, colorspace.
 * 
 * Designed to be significantly lighter performance wise
 * than mediainfo or ffmpeg.
 * 
 * Usage:
 *   _allocate a context and pass the pid of interest.
 *   _write the entire mux
 *   Wait for the write call to return the 'complete' flag.
 *   _query the metadata
 *  _free the context.
 */
#include <time.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

struct h264_aud_s
{
    uint32_t primary_pic_type;
};

struct h264_slice_s
{
    uint32_t first_mb_in_slice;
    uint32_t slice_type;
};

struct h264_seq_parameter_set_rbsp_s
{
    /* ASCII labels */
    char     video_colorspace_ascii[64];
    char     video_format_ascii[64];
    char     profile_idc_ascii[16];
    char     level_idc_ascii[16];
    char     chroma_format_idc_ascii[16];
    char     bit_depth_luma_ascii[8];
    char     timing_info_fps_ascii[24];

    char reserved[256];

    /* SPS */
    uint32_t profile_idc;
    uint32_t constraint_set0_flag;
    uint32_t constraint_set1_flag;
    uint32_t constraint_set2_flag;
    uint32_t constraint_set3_flag;
    uint32_t constraint_set4_flag;
    uint32_t constraint_set5_flag;
    uint32_t level_idc;
    uint32_t seq_parameter_set_id;

    /* http://mmlab.knu.ac.kr/Lecture/hci/avc/H.264_AVC_syntax.pdf */
    uint32_t chroma_format_idc;
    uint32_t separate_colour_plane_flag;
    uint32_t bit_depth_luma_minus8;
    uint32_t bit_depth_chroma_minus8;
    uint32_t qpprime_y_zero_transform_bypass_flag;
    uint32_t seq_scaling_matrix_present_flag;
    struct {
        uint32_t seq_scaling_matrix_present_flag;
        uint32_t scaling_list_4x4[16];
        uint32_t scaling_list_8x8[16];
    } seq_scaling_matrix_present_array[8];

    uint32_t log2_max_frame_num_minus4;
    uint32_t pict_order_cnt_type;

    uint32_t log2_max_pic_order_cnt_lab_minus4;
    uint32_t delta_pic_order_always_zero_flag;
    uint32_t offset_for_non_ref_pic;
    uint32_t offset_for_top_to_bottom_field;

    uint32_t num_ref_frames;
    uint32_t gaps_in_frame_num_value_allowed_flag;
    uint32_t pic_width_in_mbs_minus1;
    uint32_t pic_height_in_map_minus1;
    uint32_t pic_width;
    uint32_t pic_height;

    uint32_t frame_mbs_only_flag;
    uint32_t mb_adaptive_frame_field_flag;

    uint32_t direct_8x8_inference_flag;
    uint32_t frame_cropping_flag;
    uint32_t frame_cropping_left_offset;
    uint32_t frame_cropping_right_offset;
    uint32_t frame_cropping_top_offset;
    uint32_t frame_cropping_bottom_offset;

    uint32_t aspect_ratio_info_present_flag;
    uint32_t aspect_ratio_idc;
    uint32_t sar_width;
    uint32_t sar_height;

    uint32_t overscan_info_present_flag;
    uint32_t overscan_appropriate_flag;

    uint32_t video_signal_type_present_flag;
    uint32_t video_format;
    uint32_t video_full_range_flag;

    uint32_t colour_description_present_flag;
    uint32_t colour_primaries;
    uint32_t transfer_characteristics;
    uint32_t matrix_coefficients;

    uint32_t chroma_loc_info_present_flag;
    uint32_t chroma_sample_loc_type_top_field;
    uint32_t chroma_sample_loc_type_bottom_field;

    uint32_t timing_info_present_flag;
    uint32_t num_units_in_tick;
    uint32_t time_scale;
    uint32_t fixed_frame_rate_flag;

    uint32_t vui_parameters_present_flag;

    uint32_t nal_hrd_parameters_present_flag;
    uint32_t vcl_hrd_parameters_present_flag;
    uint32_t pic_struct_present_flag;

    uint32_t bitstream_restriction_flag;
    uint32_t motion_vectors_over_pic_boundaries_flag;
    uint32_t max_bytes_per_pic_denom;
    uint32_t max_bits_per_mb_denom;
    uint32_t log2_max_mv_length_vertical;
    uint32_t log2_max_mv_length_horizontal;
    uint32_t num_reorder_frames;
    uint32_t max_dec_frame_buffering;

};

struct h264_codec_metadata_results_s
{
    struct h264_aud_s aud;
    struct h264_seq_parameter_set_rbsp_s sps;
    struct h264_slice_s slice;
};

int     ltntstools_h264_codec_metadata_alloc(void **hdl, uint16_t pid, uint8_t streamId);
ssize_t ltntstools_h264_codec_metadata_write(void *hdl, const uint8_t *pkt, size_t packetCount, int *complete);
void    ltntstools_h264_codec_metadata_free(void *hdl);
int     ltntstools_h264_codec_metadata_query(void *hdl, struct h264_codec_metadata_results_s *result);

#ifdef __cplusplus
};
#endif

#endif /* H264_CODEC_METADATA_H */

