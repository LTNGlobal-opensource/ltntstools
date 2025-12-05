/**
 * @file        source-pcap.h
 * @author      Steven Toth <steven.toth@ltnglobal.com>
 * @copyright   Copyright (c) 2022 LTN Global,Inc. All Rights Reserved.
 * @brief       Collect UDP-TS, RTP-TS, RTP-A324 and arbitrary byte streams from udp.
 */

#ifndef SOURCE_PCAP_H
#define SOURCE_PCAP_H

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

typedef void (*ltntstools_source_pcap_raw_callback)(void *userContext, const struct pcap_pkthdr *hdr, const u_char *pkt, const struct pcap_stat *stats);

struct ltntstools_source_pcap_callbacks_s
{
    ltntstools_source_pcap_raw_callback raw;
};

/**
 * @brief       Allocate a new source context, for use with all other calls.
 *              Traffic form the NIC will be returned to your application via one or more callbacks.
 *              Don't stall the callback or you'll start blocking the primary receive thread.
 *              Be swift in your callback handling.
 * @param[out]  void **handle - returned object.
 * @param[in]   void *userContext - user specific value returned during callbacks
 * @param[in]   struct ltntstools_source_pcap_callbacks_s *callbacks - array of callbacks used to push data from PCAP into your application.
 * @param[in]   const char *ifname - Eg. eno2
 * @param[in]   const char *filter - Eg. 'host 227.1.20.80 && udp port 4001'
 * @return      0 - Success, else < 0 on error.
 */
int  ltntstools_source_pcap_alloc(void **hdl, void *userContext, struct ltntstools_source_pcap_callbacks_s *callbacks, const char *ifname, const char *filter, int buffer_size_default);

/**
 * @brief       Free a previously allocated context.
 * @param[in]   void *handle - ltntstools_source_pcap_alloc()
 */
void ltntstools_source_pcap_free(void *hdl);

#ifdef __cplusplus
};
#endif

#endif /* SOURCE_PCAP_H */
