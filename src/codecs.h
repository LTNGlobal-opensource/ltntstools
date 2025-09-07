#ifndef LTNTSTOOLS_CODECS_H
#define LTNTSTOOLS_CODECS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "h264_codec_metadata.h"
#include "h265_codec_metadata.h"
#include "audioanalyzer.h"

/* golomb.c */
extern const uint8_t ff_golomb_vlc_len[512];
extern const int8_t ff_se_golomb_vlc_code[512];

#ifdef __cplusplus
};
#endif

#endif /* LTNTSTOOLS_CODECS_H */
