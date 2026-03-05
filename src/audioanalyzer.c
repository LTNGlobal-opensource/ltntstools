
#include <libltntstools/ltntstools.h>
#include <unistd.h>
#include <libavformat/avformat.h>
#include <libavutil/dict.h>
#include <libavutil/fifo.h>

#include "codecs.h"

#include "nielsen-bindings.h"

#define LOCAL_DEBUG 0

#define MIN_PES_EXTRACTOR (1 * 1048576)
#define MAX_PES_EXTRACTOR (2 * 1048576)

extern int ltnpthread_setname_np(pthread_t thread, const char *name);

struct ltntstools_audioanalyzer_stream_s
{
    struct ltntstools_audioanalyzer_ctx_s *ctx;
    uint16_t                               pid;
    uint8_t                                streamID;

    enum AVCodecID       codecID;
    enum AVSampleFormat  sampleFormat;
    const AVCodec        *codec;
    AVCodecParserContext *parser;
    AVCodecContext       *codecContext;
    AVFrame              *decoded_frame;
    AVPacket             *pkt;

#define ES_FIFO_PROC_SIZE (2048)
#define ES_FIFO_MAX_SIZE (32768)
    unsigned char  *esbuf;
    AVFifoBuffer   *esfifo;

#define TS_FIFO_MAX_SIZE (128 * 188)
#define TS_BUF_MAX_SIZE (32 * 188)
    pthread_mutex_t tsmutex;
    AVFifoBuffer   *tsfifo;
    unsigned char  *tsbuf;   /* Disconnect the writer from the reader thread via this fifo */

    void           *pesExtractor;
    uint64_t        pesCallbackCount;

    int enableNielsen;
#if HAVE_IMONITORSDKPROCESSOR_H
    struct nielsen_bindings_decoder_s *nielsen;
#endif

    /* Up to 8 channels of PCM (7.1) for any single audio codec */
    struct {
        double     pcm_dbFS;
        const char pcm_dbFSDescription[8];
        int        decodeCounterOptimize;
    } pcm[16];
};

struct ltntstools_audioanalyzer_ctx_s
{
    int verbose;

	pthread_t threadId;
    int threadRunning, threadTerminate, threadTerminated;
    int doWork;

    pthread_mutex_t mutex;
    struct ltntstools_audioanalyzer_stream_s *streams[8192];
};

static void _compute_dbFS_s16p(struct ltntstools_audioanalyzer_stream_s *stream, int channelNr, int16_t *samples, int sampleCount)
{
    /* I don't need dbFS for every sample, because these that's arent that timely,
     * instead process every 8th sample.
     */
    if (++stream->pcm[channelNr].decodeCounterOptimize < 16)
        return;
    stream->pcm[channelNr].decodeCounterOptimize = 0;

    /* Find the largest sample in the series of samples, for a given channel */
    int bits = 16;

    double x = 0.0;
    int16_t *p = samples;
    for (int i = 0; i < sampleCount; i++) {
        if (*p > x)
            x = *p;
        p++;
    }

    /* Generate a dbFS measurement. Where maximum power is 0dbFS, and minimum is -90dbFS. */
    if (bits <= 16) {
        stream->pcm[channelNr].pcm_dbFS = 20 * log10( x / 32767.0);
    } else
    if (bits <= 20) {
        stream->pcm[channelNr].pcm_dbFS = 20 * log10( x / 524287.0);
    } else
    if (bits <= 24) {
        stream->pcm[channelNr].pcm_dbFS = 20 * log10( x / 8388607.0);
    } else
    if (bits <= 32) {
        stream->pcm[channelNr].pcm_dbFS = 20 * log10( x / 2147483647.0);
    }

    if (isinf(stream->pcm[channelNr].pcm_dbFS)) {
        sprintf((char *)stream->pcm[channelNr].pcm_dbFSDescription, "N/A");
    } else {
        sprintf((char *)stream->pcm[channelNr].pcm_dbFSDescription, "% 04.02f", stream->pcm[channelNr].pcm_dbFS);
    }
#if 0
    printf("S16P pid 0x%04x/ch#%d: %s\n", stream->pid, channelNr, stream->pcm[channelNr].pcm_dbFSDescription);
#endif
}

static void _compute_dbFS_fltp(struct ltntstools_audioanalyzer_stream_s *stream, int channelNr, int16_t *samples, int sampleCount)
{
    /* I don't need dbFS for every sample, because these that's arent that timely,
     * instead process every 8th sample.
     */
    if (++stream->pcm[channelNr].decodeCounterOptimize < 16)
        return;
    stream->pcm[channelNr].decodeCounterOptimize = 0;

    /* Find the largest sample in the series of samples, for a given channel */

    float x = 0.0;
    float *p = (float *)samples;
    for (int i = 0; i < sampleCount; i++) {
        if (*p > x)
            x = *p;
        p++;
    }

printf("x %f\n", x);
    stream->pcm[channelNr].pcm_dbFS = 20 * log10(abs(x));

    if (isinf(stream->pcm[channelNr].pcm_dbFS)) {
        sprintf((char *)stream->pcm[channelNr].pcm_dbFSDescription, "N/A");
    } else {
        sprintf((char *)stream->pcm[channelNr].pcm_dbFSDescription, "% 04.02f", stream->pcm[channelNr].pcm_dbFS);
    }
#if 1
    printf("FLPT pid 0x%04x/ch#%d: %s\n", stream->pid, channelNr, stream->pcm[channelNr].pcm_dbFSDescription);
#endif
}

static void compute_dbFS(struct ltntstools_audioanalyzer_stream_s *stream, int channelNr, int16_t *samples, int sampleCount)
{
    switch(stream->sampleFormat) {
    case AV_SAMPLE_FMT_S16P:
        return _compute_dbFS_s16p(stream, channelNr, samples, sampleCount);
    case AV_SAMPLE_FMT_FLTP:
        return _compute_dbFS_fltp(stream, channelNr, samples, sampleCount);
    default:
        break;
    }
}

static void decode(struct ltntstools_audioanalyzer_ctx_s *ctx, struct ltntstools_audioanalyzer_stream_s *stream)
{
    /* send the packet with the compressed data to the decoder */
    int ret = avcodec_send_packet(stream->codecContext, stream->pkt);
    if (ret < 0) {
        fprintf(stderr, "Error submitting the packet to the decoder\n");
        return;
    }

    /* read all the output frames (in general there may be any number of them */
    while (ret >= 0) {
        ret = avcodec_receive_frame(stream->codecContext, stream->decoded_frame);
        if (ret == AVERROR(EAGAIN) || ret == AVERROR_EOF)
            return;
        else if (ret < 0) {
            fprintf(stderr, "Error during decoding\n");
            exit(1);
        }
        int sample_size = av_get_bytes_per_sample(stream->codecContext->sample_fmt);
        if (sample_size < 0) {
            /* This should not occur, checking just for paranoia */
            fprintf(stderr, "Failed to calculate data size\n");
            exit(1);
        }

        /* Flip endian */
#if 0
        for (int i = 0; i < 2; i++) {
            uint16_t *ptr = (uint16_t *)stream->decoded_frame->data[i];
            for (int s = 0; s < stream->decoded_frame->nb_samples; s++) {
                uint16_t d = *ptr;
                uint16_t v = d << 8;
                v = v | (d >> 8);
                *ptr = v;
                ptr++;
            }
        }
#endif

        if (ctx->verbose >= 2) {
            int bytes = stream->decoded_frame->nb_samples * sample_size * stream->codecContext->channels;
            printf("pid 0x%04x decoded %d bytes\n", stream->pid, bytes);

            for (int i = 0; i < 2; i++) {
                printf("pid 0x%04x plane%d: ", stream->pid, i);
                uint8_t *p = (uint8_t *)stream->decoded_frame->data[i];
                for (int j = 0; j < stream->decoded_frame->nb_samples * sample_size; j++) {
                    printf("%02x ", *(p++));
                    if (j > 31)
                        break;
                }
                printf("\n");
            }
        }

        if (stream->sampleFormat == AV_SAMPLE_FMT_FLTP) {
            /* Stereo planes */
            for (int ch = 0; ch < 2; ch++) {
                /* Measure dbFS across every PCM channel, this is planer so the samples are just a massive array. */
                compute_dbFS(stream, ch, (int16_t *)stream->decoded_frame->data[ch], stream->decoded_frame->nb_samples);
            }
        } else
        if (stream->sampleFormat == AV_SAMPLE_FMT_S16P) {
            /* Stereo planes */
            for (int ch = 0; ch < 2; ch++) {
                //printf("ch%d planes = %p/%p/%p\n", i, stream->decoded_frame->data[0], stream->decoded_frame->data[1], stream->decoded_frame->data[2]);
#if HAVE_IMONITORSDKPROCESSOR_H
                /* Its fairly expensive to compute Nielson, skip it if the user doesn't want it. */
                if (stream->enableNielsen) {
                    nielsen_bindings_write_silent(stream->nielsen, 0);
                    nielsen_bindings_write_plane(stream->nielsen, ch, (uint8_t *)stream->decoded_frame->data[ch], stream->decoded_frame->nb_samples * sample_size);
                }
#endif /* HAVE_IMONITORSDKPROCESSOR_H */

                /* Measure dbFS across every PCM channel, this is planer so the samples are just a massive array. */
                compute_dbFS(stream, ch, (int16_t *)stream->decoded_frame->data[ch], stream->decoded_frame->nb_samples);
            }
        }

    }
}

static void *ltntstools_audioanalyzer_stream_threadfunc(void *p)
{
    struct ltntstools_audioanalyzer_ctx_s *ctx = (struct ltntstools_audioanalyzer_ctx_s *)p;
#if LOCAL_DEBUG
    printf("%s()\n", __func__);
#endif

    pthread_detach(ctx->threadId);
    ltnpthread_setname_np(ctx->threadId, "thread-nielsen");

    ctx->threadTerminate = 0;
	ctx->threadRunning = 1;
	while (!ctx->threadTerminate) {

        if (ctx->doWork == 0)
            usleep(100 * 1000);

        ctx->doWork = 0;
        for (int i = 0; i < 8192; i++) {
            struct ltntstools_audioanalyzer_stream_s *stream = ctx->streams[i];
            if (!stream)
                continue;

            pthread_mutex_lock(&stream->tsmutex);
            while (av_fifo_size(stream->tsfifo) >= TS_BUF_MAX_SIZE) {
                av_fifo_generic_read(stream->tsfifo, stream->tsbuf, TS_BUF_MAX_SIZE, NULL);
                ltntstools_pes_extractor_write(stream->pesExtractor, stream->tsbuf, TS_BUF_MAX_SIZE / 188);
            }
            pthread_mutex_unlock(&stream->tsmutex);

        }
    }

	ctx->threadTerminated = 1;
	ctx->threadRunning = 0;
	pthread_exit(0);
}

/* We're called in the running context of the audioanalyzer thread. */
static void *pes_callback(void *userContext, struct ltn_pes_packet_s *pes)
{
    struct ltntstools_audioanalyzer_stream_s *stream = (struct ltntstools_audioanalyzer_stream_s *)userContext;
    struct ltntstools_audioanalyzer_ctx_s *ctx = stream->ctx;
#if LOCAL_DEBUG
    printf("%s(0x%04x)\n", __func__, stream->pid);
#endif

    stream->pesCallbackCount++;

    /* Push the PES data into a fifo */
    av_fifo_generic_write(stream->esfifo, pes->data, pes->dataLengthBytes, NULL);

    while (av_fifo_size(stream->esfifo) >= ES_FIFO_PROC_SIZE) {
        if (!stream->decoded_frame) {
            if (!(stream->decoded_frame = av_frame_alloc())) {
                fprintf(stderr, "Could not allocate audio frame\n");
                exit(1);
            }
        }

        /* Copy the es into a buffer, we don't know how much data the parser needs.
         * we'll drain the fifo later by the read amount.
         */
        av_fifo_generic_peek(stream->esfifo, stream->esbuf, ES_FIFO_PROC_SIZE, NULL);

        /* Submit to the parser/codec for decompression. */
        int plen = av_parser_parse2(stream->parser, stream->codecContext,
            &stream->pkt->data, &stream->pkt->size,
            stream->esbuf, ES_FIFO_PROC_SIZE,
            AV_NOPTS_VALUE, AV_NOPTS_VALUE, 0);
        if (plen < 0) {
            fprintf(stderr, "%s() Error while parsing, continuing\n", __func__);
        }

        av_fifo_drain(stream->esfifo, plen);

        if (stream->pkt->size) {
            decode(ctx, stream);
        }

    }

    if (ctx->verbose > 3) {
	    ltn_pes_packet_dump(pes, "");
    }

	ltn_pes_packet_free(pes);

    return NULL;
}

int ltntstools_audioanalyzer_stream_add(void *hdl, uint16_t pid, uint8_t streamID, unsigned int codecID, unsigned int sampleFormat, int enableNielsen)
{
#if LOCAL_DEBUG
    printf("%s(%p, 0x%04x, 0x%02x, 0x%08x, fmt %d)\n", __func__, hdl, pid, streamID, codecID, sampleFormat);
#endif
    struct ltntstools_audioanalyzer_ctx_s *ctx = (struct ltntstools_audioanalyzer_ctx_s *)hdl;
    pid &= 0x1fff;

    switch (sampleFormat) {
    //case AV_SAMPLE_FMT_FLTP:
    case AV_SAMPLE_FMT_S16P:
        break;
    default:
        return -1;
    }

    pthread_mutex_lock(&ctx->mutex);
    if (ctx->streams[pid]) {
        pthread_mutex_unlock(&ctx->mutex);
        return -1; /* Already exists */
    }

    struct ltntstools_audioanalyzer_stream_s *stream = calloc(1, sizeof(*stream));
    ctx->streams[pid] = stream;

    stream->ctx = ctx;
    stream->codecID = codecID;
    stream->sampleFormat = sampleFormat;
    stream->pid = pid;
    stream->streamID = streamID;
    stream->enableNielsen = enableNielsen;
    pthread_mutex_init(&stream->tsmutex, NULL);

    /* Bring up the PES extractor */
    int ret = ltntstools_pes_extractor_alloc(&stream->pesExtractor, pid, streamID, (pes_extractor_callback)pes_callback, stream, MIN_PES_EXTRACTOR, MAX_PES_EXTRACTOR);
    if (ret < 0) {
        pthread_mutex_unlock(&ctx->mutex);
        fprintf(stderr, "%s() unable to allocate a pes extractor, aborting.\n", __func__);
        return -1;
    }
    ltntstools_pes_extractor_set_skip_data(stream->pesExtractor, 0); /* ask for all data to be added to the pes headers. */
    /* End: Bring up the PES extractor */

    stream->esbuf = malloc(ES_FIFO_PROC_SIZE);
    stream->tsbuf = malloc(TS_BUF_MAX_SIZE);
    stream->tsfifo = av_fifo_alloc(TS_FIFO_MAX_SIZE);
    stream->esfifo = av_fifo_alloc(ES_FIFO_MAX_SIZE);

    /* Bring up libavcodec */
    stream->codec = avcodec_find_decoder(stream->codecID);
    stream->parser = av_parser_init(stream->codec->id);
    stream->codecContext = avcodec_alloc_context3(stream->codec);
    if (avcodec_open2(stream->codecContext, stream->codec, NULL) < 0) {
        pthread_mutex_unlock(&ctx->mutex);
        fprintf(stderr, "%s() Could not open codec\n", __func__);
        exit(1);
    }
    stream->pkt = av_packet_alloc();
    /* end: libavcodec */

#if HAVE_IMONITORSDKPROCESSOR_H
    if (stream->enableNielsen) {
        stream->nielsen = nielsen_bindings_alloc(pid, 2); /* TODO Two channels only currently */
    }
#endif /* HAVE_IMONITORSDKPROCESSOR_H */

    pthread_mutex_unlock(&ctx->mutex);
    return 0;
}

void ltntstools_audioanalyzer_stream_remove(void *hdl, uint16_t pid)
{
#if LOCAL_DEBUG
    printf("%s(%p, 0x%04x)\n", __func__, hdl, pid);
#endif
    struct ltntstools_audioanalyzer_ctx_s *ctx = (struct ltntstools_audioanalyzer_ctx_s *)hdl;
    pid &= 0x1fff;

    pthread_mutex_lock(&ctx->mutex);
    if (!ctx->streams[pid]) {
        pthread_mutex_unlock(&ctx->mutex);
        return; /* doesn't exist */
    }

    struct ltntstools_audioanalyzer_stream_s *stream = ctx->streams[pid];

    ltntstools_pes_extractor_free(stream->pesExtractor);

    free(stream->esbuf);
    free(stream->tsbuf);
    av_fifo_free(stream->tsfifo);
    av_fifo_free(stream->esfifo);
    avcodec_free_context(&stream->codecContext);
    av_frame_free(&stream->decoded_frame);
    av_packet_free(&stream->pkt);

    if (stream->enableNielsen) {
#if HAVE_IMONITORSDKPROCESSOR_H
        nielsen_bindings_free(stream->nielsen);
#endif
    }
    memset(stream, 0, sizeof(*stream));
    free(stream);

    pthread_mutex_unlock(&ctx->mutex);
}

ssize_t ltntstools_audioanalyzer_write(void *hdl, const uint8_t *pkts, unsigned int packetCount)
{
    struct ltntstools_audioanalyzer_ctx_s *ctx = (struct ltntstools_audioanalyzer_ctx_s *)hdl;
    int count = 0;

    for (unsigned int i = 0; i < packetCount; i++) {
        const unsigned char *pkt = &pkts[i * 188];
        uint16_t pid = ltntstools_pid(pkt);

        struct ltntstools_audioanalyzer_stream_s *stream = ctx->streams[pid];
        if (!stream)
            continue;

#if LOCAL_DEBUG
        printf("%s(%p, pid 0x%04x writing %d packets)\n", __func__, hdl, stream->pid, packetCount);
#endif

        /* We don't want the foreground thread blocked by thread work,
         * feed a fifo and return quickly. The thread will take care of the rest.
         */
        pthread_mutex_lock(&stream->tsmutex);
        while (av_fifo_space(stream->tsfifo) < TS_BUF_MAX_SIZE) {
            pthread_mutex_unlock(&stream->tsmutex);
            usleep(1000);
            pthread_mutex_lock(&stream->tsmutex);
	}
        av_fifo_generic_write(stream->tsfifo, (void *)pkt, 188, NULL);
        pthread_mutex_unlock(&stream->tsmutex);
        count++;
    }

    if (count) {
        ctx->doWork = 1;
    }

    return 0;
}

int ltntstools_audioanalyzer_has_feature_nielsen(void *hdl)
{
    //struct ltntstools_audioanalyzer_ctx_s *ctx = (struct ltntstools_audioanalyzer_ctx_s *)hdl;
    return
#if HAVE_IMONITORSDKPROCESSOR_H
        1
#else
        0
#endif
        ;
}

void ltntstools_audioanalyzer_set_verbosity(void *hdl, int level)
{
#if LOCAL_DEBUG
    printf("%s(%p, %d)\n", __func__, hdl, level);
#endif
    struct ltntstools_audioanalyzer_ctx_s *ctx = (struct ltntstools_audioanalyzer_ctx_s *)hdl;
    ctx->verbose = level;
}

void ltntstools_audioanalyzer_free(void *hdl)
{
#if LOCAL_DEBUG
    printf("%s(%p)\n", __func__, hdl);
#endif
    struct ltntstools_audioanalyzer_ctx_s *ctx = (struct ltntstools_audioanalyzer_ctx_s *)hdl;
    if (ctx->threadRunning) {
        ctx->threadTerminate = 1;
        while (!ctx->threadTerminated)
            usleep(20 * 1000);
    }

    for (int i = 0; i < 8192; i++) {
        if (ctx->streams[i]) {
            ltntstools_audioanalyzer_stream_remove(ctx, i);
        }
    }
    free(ctx);
}

int ltntstools_audioanalyzer_alloc(void **hdl)
{
#if LOCAL_DEBUG
    printf("%s()\n", __func__);
#endif

    struct ltntstools_audioanalyzer_ctx_s *ctx = calloc(1, sizeof(*ctx));

    pthread_mutex_init(&ctx->mutex, NULL);

    pthread_create(&ctx->threadId, 0, ltntstools_audioanalyzer_stream_threadfunc, ctx);

    *hdl = ctx;

    return 0;
}
