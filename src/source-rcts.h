/**
 * @file        source-rate-controlled-ts.h
 * @author      Steven Toth <steven.toth@ltnglobal.com>
 * @copyright   Copyright (c) 2022 LTN Global,Inc. All Rights Reserved.
 * @brief       Collect mpegts-ts from file, rate control it out based on PCR.
 */

#ifndef SOURCE_RATE_CONTROLLED_TS_H
#define SOURCE_RATE_CONTROLLED_TS_H

#include <time.h>
#include <inttypes.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*ltntstools_source_rcts_raw_callback)(void *userContext, const uint8_t *pkts, int packetCount, struct timeval *timestamp);
typedef void (*ltntstools_source_rcts_pos_callback)(void *userContext, uint64_t pos, uint64_t max, double pct);

struct ltntstools_source_rcts_callbacks_s
{
    ltntstools_source_rcts_raw_callback raw;
    ltntstools_source_rcts_pos_callback pos;
};

/**
 * @brief       Allocate a new source context, for use with all other calls.
 *              Traffic form the NIC will be returned to your application via one or more callbacks.
 *              Don't stall the callback or you'll start blocking the primary receive thread.
 *              Be swift in your callback handling.
 * @param[out]  void **handle - returned object.
 * @param[in]   void *userContext - user specific value returned during callbacks
 * @param[in]   struct ltntstools_source_rcts_callbacks_s *callbacks - array of callbacks used to push data from filename into your application.
 * @param[in]   const char *filename - MPEG-TS input filename
 * @param[in]   int fileLoop - Boolean. At end of file should the source stop, or rewind and repeat?
 * @return      0 - Success, else < 0 on error.
 */
int  ltntstools_source_rcts_alloc(void **hdl, void *userContext, struct ltntstools_source_rcts_callbacks_s *callbacks, const char *filename, int fileLoop);

/**
 * @brief       Free a previously allocated context.
 * @param[in]   void *handle - ltntstools_source_rcts_alloc()
 */
void ltntstools_source_rcts_free(void *hdl);

#ifdef __cplusplus
};
#endif

#endif /* SOURCE_RATE_CONTROLLED_TS_H */
