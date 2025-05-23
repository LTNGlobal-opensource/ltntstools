#ifndef H265_CODEC_METADATA_H
#define H265_CODEC_METADATA_H

/* - DON'T USE ANY OF THIS YET - */

/* A framework to demux h265 nals from transport streams,
 * pull apart some lightweight structures and bitfields and
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

struct h265_profile_tier_level_sub_layer_s
{
    uint32_t sub_layer_profile_present_flag;
    uint32_t sub_layer_level_present_flag;

    uint32_t sub_layer_profile_space;
    uint32_t sub_layer_tier_flag;
    uint32_t sub_layer_profile_idc;
    uint32_t sub_layer_profile_compatibility_flag[32];
    uint32_t sub_layer_progressive_source_flag;
    uint32_t sub_layer_interlaced_source_flag;
    uint32_t sub_layer_non_packed_constraint_flag;
    uint32_t sub_layer_frame_only_constraint_flag;
    uint32_t sub_layer_max_12bit_constraint_flag;
    uint32_t sub_layer_max_10bit_constraint_flag;
    uint32_t sub_layer_max_8bit_constraint_flag;
    uint32_t sub_layer_max_422chroma_constraint_flag;
    uint32_t sub_layer_max_420chroma_constraint_flag;
    uint32_t sub_layer_max_monochrome_constraint_flag;
    uint32_t sub_layer_intra_constraint_flag;
    uint32_t sub_layer_one_picture_only_constraint_flag;
    uint32_t sub_layer_lower_bit_rate_constraint_flag;
    uint32_t sub_layer_max_14bit_constraint_flag;
    uint32_t sub_layer_inbld_flag;
    uint32_t sub_layer_level_idc;
};

struct h265_profile_tier_level_s
{
    uint32_t general_profile_space;
    uint32_t general_tier_flag;
    uint32_t general_profile_idc;
    uint8_t  general_profile_compatibility_flag[32];
    uint32_t general_progressive_source_flag;
    uint32_t general_interlaced_source_flag;
    uint32_t general_non_packed_constraint_flag;
    uint32_t general_frame_only_constraint_flag;

    uint32_t general_max_12bit_constraint_flag;
    uint32_t general_max_10bit_constraint_flag;
    uint32_t general_max_8bit_constraint_flag;
    uint32_t general_max_422chroma_constraint_flag;
    uint32_t general_max_420chroma_constraint_flag;
    uint32_t general_max_monochrome_constraint_flag;
    uint32_t general_intra_constraint_flag;
    uint32_t general_one_picture_only_constraint_flag;
    uint32_t general_lower_bit_rate_constraint_flag;
    uint32_t general_max_14bit_constraint_flag;
    uint32_t general_inbld_flag;

    
    uint32_t general_level_idc;
    struct h265_profile_tier_level_sub_layer_s sublayer[8];
};

struct h265_slice_s
{
    uint32_t slice_type;
};

struct access_unit_delimiter_rbsp
{
    uint32_t pic_type;
};

struct h265_video_parameter_set_rbsp_s
{
	uint32_t valid;
    uint32_t vps_video_parameter_set_id;
    uint32_t vps_base_layer_internal_flag;
    uint32_t vps_base_layer_available_flag;
    uint32_t vps_max_layers_minus1;
    uint32_t vps_max_sub_layers_minus1;
    uint32_t vps_temporal_id_nesting_flag;

    struct h265_profile_tier_level_s ptl;

    uint32_t vps_sub_layer_ordering_info_present_flag;

    uint32_t vps_max_dec_pic_buffering_minus1[8];
    uint32_t vps_max_num_reorder_pics[8];
    uint32_t vps_max_latency_increase_plus1[8];

    uint32_t vps_max_layer_id;
    uint32_t vps_num_layer_sets_minus1;
    uint8_t  layer_id_included_flag[16];

    uint32_t vps_timing_info_present_flag;
    uint32_t vps_num_units_in_tick;
    uint32_t vps_time_scale;
    uint32_t vps_poc_proportional_to_timing_flag;
    uint32_t vps_num_ticks_poc_diff_one_minus1;
    uint32_t vps_num_hrd_parameters;
    /* No more support, parsing aborts beyond this */
};

struct h265_seq_parameter_set_rbsp_s
{
	uint32_t valid;
	uint32_t sps_video_parameter_set_id;
	uint32_t sps_max_sub_layers_minus1;
	uint32_t sps_temporal_id_nesting_flag;

    struct h265_profile_tier_level_s ptl;

    uint32_t sps_seq_parameter_set_id;
    uint32_t chroma_format_idc;
    uint32_t separate_colour_plane_flag;
    uint32_t pic_width_in_luma_samples;
    uint32_t pic_height_in_luma_samples;
    uint32_t conformance_window_flag;
    uint32_t conf_win_left_offset;
    uint32_t conf_win_right_offset;
    uint32_t conf_win_top_offset;
    uint32_t conf_win_bottom_offset;
    uint32_t bit_depth_luma_minus8;
    uint32_t bit_depth_chroma_minus8;

    uint32_t log2_max_pic_order_cnt_lsb_minus4;
    uint32_t sps_sub_layer_ordering_info_present_flag;
    uint32_t sps_max_dec_pic_buffering_minus1[16];
    uint32_t sps_max_num_reorder_pics[16];
    uint32_t sps_max_latency_increase_plus1[16];

    uint32_t log2_min_luma_coding_block_size_minus3;
    uint32_t log2_diff_max_min_luma_coding_block_size;
    uint32_t log2_min_luma_transform_block_size_minus2;
    uint32_t log2_diff_max_min_luma_transform_block_size;
    uint32_t max_transform_hierarchy_depth_inter;
    uint32_t max_transform_hierarchy_depth_intra;
    uint32_t scaling_list_enabled_flag;
    uint32_t sps_scaling_list_data_present_flag;

    //
    uint32_t scaling_list_pred_mode_flag[4][6];
    uint32_t scaling_list_pred_matrix_id_delta[4][6];
    uint32_t scaling_list_dc_coef_minus8[4][6];
    //

    uint32_t amp_enabled_flag;
    uint32_t sample_adaptive_offset_enabled_flag;
    uint32_t pcm_enabled_flag;
    uint32_t pcm_sample_bit_depth_luma_minus1;
    uint32_t pcm_sample_bit_depth_chroma_minus1;
    uint32_t log2_min_pcm_luma_coding_block_size_minus3;
    uint32_t log2_diff_max_min_pcm_luma_coding_block_size;
    uint32_t pcm_loop_filter_disabled_flag;

    uint32_t num_short_term_ref_pic_sets;

    //
    uint32_t inter_ref_pic_set_prediction_flag;
    uint32_t delta_idx_minus1;
    uint32_t delta_rps_sign;
    uint32_t abs_delta_rps_minus1;
    uint32_t used_by_curr_pic_flag; // TODO; This should be an array
    uint32_t use_delta_flag;
    uint32_t num_negative_pics;
    uint32_t num_positive_pics;
    uint32_t delta_poc_s0_minus1; // TODO; This should be an array
    uint32_t used_by_curr_pic_s0_flag; // TODO; This should be an array
    uint32_t delta_poc_s1_minus1; // TODO; This should be an array
    uint32_t used_by_curr_pic_s1_flag; // TODO; This should be an array

    uint32_t long_term_ref_pics_present_flag;
    uint32_t num_long_term_ref_pics_sps;
    uint32_t lt_ref_pic_poc_lsb_sps[16];
    uint32_t used_by_curr_pic_lt_sps_flag[16];

    uint32_t sps_temporal_mvp_enabled_flag;
    uint32_t strong_intra_smoothing_enabled_flag;
    uint32_t vui_parameters_present_flag;

    //
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
    uint32_t matrix_coeffs;

    uint32_t chroma_loc_info_present_flag;
    uint32_t chroma_sample_loc_type_top_field;
    uint32_t chroma_sample_loc_type_bottom_field;
    uint32_t neutral_chroma_indication_flag;
    uint32_t field_seq_flag;
    uint32_t frame_field_info_present_flag;
    uint32_t default_display_window_flag;
    uint32_t def_disp_win_left_offset;
    uint32_t def_disp_win_right_offset;
    uint32_t def_disp_win_top_offset;
    uint32_t def_disp_win_bottom_offset;

    uint32_t vui_timing_info_present_flag;
    uint32_t vui_num_units_in_tick;
    uint32_t vui_time_scale;
    uint32_t vui_poc_proportional_to_timing_flag;
    uint32_t vui_num_ticks_poc_diff_one_minus1;
};

struct h265_pic_parameter_set_rbsp_s
{
	uint32_t valid;
	uint32_t pps_pic_parameter_set_id;
	uint32_t pps_seq_parameter_set_id;
	uint32_t dependent_slice_segments_enabled_flag;
	uint32_t output_flag_present_flag;
	uint32_t num_extra_slice_header_bits;
};

struct h265_codec_metadata_results_s
{
    struct h265_video_parameter_set_rbsp_s vps;
    struct h265_pic_parameter_set_rbsp_s pps;
    struct h265_seq_parameter_set_rbsp_s sps;
    struct access_unit_delimiter_rbsp aud;
    struct h265_slice_s slice;

    /* ASCII labels */
    char     video_colorspace_ascii[64];
    char     video_format_ascii[64];
    char     profile_idc_ascii[16];
    char     level_idc_ascii[16];
    char     chroma_format_idc_ascii[16];
    char     bit_depth_luma_ascii[8];
    char     timing_info_fps_ascii[16];
};

int     ltntstools_h265_codec_metadata_alloc(void **hdl, uint16_t pid, uint8_t streamId);
ssize_t ltntstools_h265_codec_metadata_write(void *hdl, const uint8_t *pkt, size_t packetCount, int *complete);
void    ltntstools_h265_codec_metadata_free(void *hdl);
int     ltntstools_h265_codec_metadata_query(void *hdl, struct h265_codec_metadata_results_s *result);

#ifdef __cplusplus
};
#endif

#endif /* H265_CODEC_METADATA_H */

