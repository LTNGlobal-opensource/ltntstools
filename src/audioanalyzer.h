#ifndef _AUDIOANALYZER_H
#define _AUDIOANALYZER_H

/* A minimalistic implemenation of a bulk audio decoder.
 * limitations, namely:
 * 1. Only stereo pairs are currently support.
 * 2. Only MP2, AAC and AC3 stereo pairs are currently supported.
 *
 * Currently functionality:
 * 1) Nielsen audio codes are detected and dumped to console.
 * 
 */

#include <time.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

/* specifically matching avcodecs id */
#define LTN_CODEC_ID_MP2 (0x15000 + 0) 
#define LTN_CODEC_ID_AAC (0x15000 + 2)
#define LTN_CODEC_ID_AC3 (0x15000 + 3)

/* specifically matching avcodecs formats */
#define LTN_SAMPLE_FMT_S16P (6) 
#define LTN_SAMPLE_FMT_FLTP (8) 

int     ltntstools_audioanalyzer_stream_add(void *hdl, uint16_t pid, uint8_t streamID, unsigned int codecID, unsigned int sampleFormat, int enableNielsen);
void    ltntstools_audioanalyzer_stream_remove(void *hdl, uint16_t pid);

int     ltntstools_audioanalyzer_alloc(void **hdl);
ssize_t ltntstools_audioanalyzer_write(void *hdl, const uint8_t *pkt, unsigned int packetCount);
void    ltntstools_audioanalyzer_free(void *hdl);

int     ltntstools_audioanalyzer_has_feature_nielsen(void *hdl);
void    ltntstools_audioanalyzer_set_verbosity(void *hdl, int level);

#ifdef __cplusplus
};
#endif

#endif /* _AUDIOANALYZER_H */
