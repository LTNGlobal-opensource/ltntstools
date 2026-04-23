/* Copyright Kernel Labs Inc 2015-2018 */

#include "avc-types.h"

#include <pthread.h>

struct avc_core_s
{
    pthread_mutex_t sps_lock; /* protection */
    struct avc_seq_parameter_set_s *sps;

    pthread_mutex_t pps_lock; /* protection */
    struct avc_pic_parameter_set_s *pps;
};

int avc_core_alloc(void **handle)
{
    struct avc_core_s *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        return -1; /* Failure */
    }

    *handle = ctx;
    pthread_mutex_init(&ctx->sps_lock, NULL);
    pthread_mutex_init(&ctx->pps_lock, NULL);

    //pthread_mutex_lock(&ctx->sps_lock);
    //pthread_mutex_unlock(&ctx->sps_lock);

    return 0; /* Success */
}

void avc_core_free(void *handle)
{
    struct avc_core_s *ctx = (struct avc_core_s *)handle;

    pthread_mutex_lock(&ctx->sps_lock);
    pthread_mutex_lock(&ctx->pps_lock);
    if (ctx->pps) {
        avc_pic_parameter_set_free(ctx->pps);
        ctx->pps = NULL;
    }

    if (ctx->sps) {
        avc_seq_parameter_set_free(ctx->sps);
        ctx->sps = NULL;
    }
    pthread_mutex_lock(&ctx->pps_lock);
    pthread_mutex_lock(&ctx->sps_lock);

    free(ctx);
}

int avc_core_decode(void *handle, struct ltn_nal_headers_s *h)
{
    struct avc_core_s *ctx = (struct avc_core_s *)handle;

    switch (h->nalType) {
    case 1: /* slice_layer_without_partitioning_rbsp */
    case 2: /* slice_data_partition_a_layer_rbsp */
    case 5: /* slice_layer_without_partitioning_rbsp */
    case 19: /* slice_layer_without_partitioning_rbsp */
        break;
    case 7: /* SPS */
        {
            ltn_nal_h264_strip_emulation_prevention(h);

            struct avc_seq_parameter_set_s *sps = avc_seq_parameter_set_alloc();
            if (sps) {
                if (avc_seq_parameter_parse(sps, h->ptr, h->lengthBytes) == 0) {
                    pthread_mutex_lock(&ctx->sps_lock);
                    if (ctx->sps) {
                        avc_seq_parameter_set_free(ctx->sps);
                        ctx->sps = NULL;
                    }
                    ctx->sps = sps;
                    pthread_mutex_unlock(&ctx->sps_lock);
                }
            }
        }
        break;
    case 8: /* PPS */
        {
            pthread_mutex_lock(&ctx->sps_lock);
            if (ctx->sps == NULL) {
                pthread_mutex_unlock(&ctx->sps_lock);
            } else {

                ltn_nal_h264_strip_emulation_prevention(h);

                struct avc_pic_parameter_set_s *pps = avc_pic_parameter_set_alloc();
                if (pps) {
                    if (avc_pic_parameter_parse(ctx->sps, pps, h->ptr, h->lengthBytes) == 0) {
                        pthread_mutex_lock(&ctx->pps_lock);
                        if (ctx->pps) {
                            avc_pic_parameter_set_free(ctx->pps);
                            ctx->pps = NULL;
                        }
                        ctx->pps = pps;
                        pthread_mutex_unlock(&ctx->pps_lock);
                    }
                }
                pthread_mutex_unlock(&ctx->sps_lock);
            }
        }
        break;
    case 9: /* AUD */
        break;
    }

    return 0;
}
