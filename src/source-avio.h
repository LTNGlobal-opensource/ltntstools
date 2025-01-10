/**
 * @file        source-avio.h
 * @author      Steven Toth <steven.toth@ltnglobal.com>
 * @copyright   Copyright (c) 2022 LTN Global,Inc. All Rights Reserved.
 * @brief       Collect mpegts-ts from ffmpeg URL inputs, regarldess of whether they're RTP, UDP or something else
 *              we knowingly support.
 * 
 * Supported urls:
 *   udp://      any number of packet sizes
 *   rtp://      Automatically removed 12 byte header, FEC is not supported.
 *   hls+http://
 * 
 * **** If you pass any other kind of url, the behaviour is undefined. ****
 *   srt://      (with or without RTP headers - without FEC)
 */

#ifndef SOURCE_AVIO_H
#define SOURCE_AVIO_H

#include <libltntstools/ltntstools.h>

#ifdef __cplusplus
extern "C" {
#endif

enum source_avio_status_e
{
    AVIO_STATUS_UNDEFINED = 0,
    AVIO_STATUS_MEDIA_START,
    AVIO_STATUS_MEDIA_END,
};

typedef void (*ltntstools_source_avio_raw_callback)(void *userContext, const uint8_t *pkts, int packetCount, struct timeval *capture_time);
typedef void (*ltntstools_source_avio_raw_callback_status)(void *userContext, enum source_avio_status_e status);

struct ltntstools_source_avio_callbacks_s
{
    ltntstools_source_rcts_raw_callback raw;
    ltntstools_source_avio_raw_callback_status status;
};

/**
 * @brief       Allocate a new source context, for use with all other calls.
 *              Transport Packets will be returned to your application via one or more callbacks.
 *              Don't stall the callback or you'll start blocking the primary receive thread.
 *              Be swift in your callback handling.
 * @param[out]  void **handle - returned object.
 * @param[in]   void *userContext - user specific value returned during callbacks
 * @param[in]   struct ltntstools_source_rcts_callbacks_s *callbacks - array of callbacks used to push data from filename into your application.
 * @param[in]   const char *url - ffmpeg formatted url (and appropriate args)
 * @return      0 - Success, else < 0 on error.
 */
int  ltntstools_source_avio_alloc(void **hdl, void *userContext, struct ltntstools_source_avio_callbacks_s *callbacks, const char *url);

/**
 * @brief       Free a previously allocated context.
 * @param[in]   void *handle - ltntstools_source_rcts_alloc()
 */
void ltntstools_source_avio_free(void *hdl);

#ifdef __cplusplus
};
#endif

#endif /* SOURCE_AVIO_H */
