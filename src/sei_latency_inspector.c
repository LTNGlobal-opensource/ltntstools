/* Copyright LiveTimeNet, Inc. 2023. All Rights Reserved. */

/* For a given pair of input streams,
 * that are expected to contain LTN SEI timing information,
 * extract that timing information (and other PES stats).
 * Compute the time delta between the two SEI timing clocks
 * and output that to a mulcicast port as a JSON object.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <math.h>
#include <inttypes.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <libltntstools/ltntstools.h>
#include "ffmpeg-includes.h"
#include "source-avio.h"
#include "xorg-list.h"
#include "utils.h"

#define DEFAULT_STREAMID 0xe0
#define DEFAULT_PID 0x31
#define DEFAULT_ELEMENTS (60 * 120)
#define DEFAULT_INSTANCE_NAME "INSTANCE_NAME"

static int g_running = 1;

struct tool_ctx_s;

char *strcasestr(const char *haystack, const char *needle);

struct timing_element_s
{
	struct xorg_list list;

	uint32_t nr;
	int64_t PTS;
	int64_t DTS;

	/* The raw SEI data */
	uint8_t data[128];

	uint32_t sei_framenumber;

	struct timeval ts_seen; /* Timestamp from walltime when we saw this frame from the network */

	int64_t trueLatency;
};

#define MAX_STREAM_SOURCES 2
struct stream_s {
	struct tool_ctx_s *ctx;
	int nr;
	char *iname;
	int pid;
	int streamId;
	void *pe;

	/* we suse libavformats udp and general AVIO input mechanism */
	void *avio_ctx;
	struct ltntstools_source_avio_callbacks_s avio_cbs;

	void *src_pcap; /* Source-pcap context */
	char *pcap_filter;

	/* We have a list of 'previously seen' sei ojects, for referencing over time.
	 * A fixed length list where the oldest SEI object is at the top of the list
	 */
	pthread_mutex_t lockElements;
	struct xorg_list listElements;
	uint32_t maxListElements;

	/* We use the library probe to find the SEI objects in our PES headers,
	 * and as helpers to extract details form them.
	 */
	void *probe_hdl;
	uint32_t lastFrameNumber;

	/* Time is an illusion, lunchtime doubly so.... Let's measure some stream clocks vs Walltime */
	struct ltntstools_clock_s clkPTS;
	struct ltntstools_clock_s clkDTS;

	/* Some true latency and high/low watermarks */
	int64_t trueLatency, trueLatency_hwm, trueLatency_lwm;
	time_t trueLatencyComputeAfter;

	int64_t driftPTS_ms;
	int64_t driftDTS_ms;
	int64_t drift_ms;

#define MODE_SOURCE_AVIO 0
#define MODE_SOURCE_PCAP 1
	int mode;

	int isRTP;
};

struct tool_ctx_s
{
	struct stream_s src[MAX_STREAM_SOURCES];
	int verbose;
	int totalElements;
	int compareMode;

	char *instanceName;

	pthread_mutex_t console_mutex;

	/* UDP transmit output */
	int udpOutput;
	int tx_skt;
	struct sockaddr_in tx_sa;
	char tx_ip[32];
	int tx_port;	
};

static void signal_handler(int signum)
{
	g_running = 0;
}

/* Seach the elements in stream for e->sei_framenumber */
void _printList(struct tool_ctx_s *ctx, struct stream_s *stream)
{
	struct timing_element_s *e = NULL;

	int i = 0;
	xorg_list_for_each_entry_reverse(e, &stream->listElements, list) {

		printf("list 2 framenumber %d, DTS %" PRIi64 " PTS %" PRIi64 ", seen %d.%6d\n", e->sei_framenumber, e->DTS, e->PTS,
			(uint32_t)e->ts_seen.tv_sec, (uint32_t)e->ts_seen.tv_usec);

		if (i++ > 10)
			break;
	}
}

/* Seach the elements in stream for e->sei_framenumber */
static void _compareStreams(struct tool_ctx_s *ctx, struct stream_s *stream, struct timing_element_s *element)
{
	struct timing_element_s *e = NULL;

	xorg_list_for_each_entry_reverse(e, &stream->listElements, list) {

		//printf("framenumber %d, wanted %d\n", e->sei_framenumber, element->sei_framenumber);
		if (e->sei_framenumber == element->sei_framenumber) {
			int ms = ltn_timeval_subtract_ms(&element->ts_seen, &e->ts_seen);

			if (ctx->verbose) {

				printf("Frame %12d taking %5d ms between sampling points, P1->vPTS %13" PRIi64 ", P1->vDTS %13" PRIi64 ", P2->vPTS %13" PRIi64 ", P2->vDTS %13" PRIi64
					", 1:%" PRIi64 " 2:%" PRIi64 "\n",
					element->sei_framenumber,
					ms,
					e->PTS,
					e->DTS,
					element->PTS,
					element->DTS,
					element->trueLatency,
					e->trueLatency);
			}

			char *msg = malloc(512);

			int64_t finalLatency_ms = element->trueLatency - e->trueLatency;

			char *t1, *t2;
			ISO8601_UTC_CreateTimestamp(&e->ts_seen, &t1);
			ISO8601_UTC_CreateTimestamp(&element->ts_seen, &t2);

			// { "instance": "BBC1", "upstream":{ "uri": "udp://233.1.1.1:11111", "pts":12345, "timestamp":"2023-01-02T12:23:34.12345Z" }, "downstream":{ "uri": "udp://233.1.1.2:22222", "pts":23456, "timestamp":"2023-01-02T12:23:34.22345Z" }, "latency": 1000 }
			sprintf(msg, "{ \"instance\": \"%s\", \"upstream\":{ \"uri\": \"%s\", \"pts\":%" PRIi64
					", \"timestamp\":\"%s\" }, \"downstream\":{ \"uri\": \"%s\", \"pts\":%" PRIi64
					", \"timestamp\":\"%s\" }, \"latency\":%" PRIi64 " }\n",
				ctx->instanceName,
				ctx->src[0].iname,
				e->PTS,
				t1,
				ctx->src[1].iname,
				element->PTS,
				t2,
				finalLatency_ms);

			if (ctx->verbose) {
				printf("%s", msg);
			}

			if (ctx->udpOutput) {
				if (sendto(ctx->tx_skt, msg, strlen(msg), 0, (struct sockaddr *)&ctx->tx_sa, sizeof(ctx->tx_sa)) < 0) {
					fprintf(stderr, "Error transmitting to UDP\n");
				}
			}

			free(msg);
			free(t1);
			free(t2);

			//_printList(ctx, &ctx->src[1]);

			return;
		}

	}

}

static void _maintain_clocks(struct stream_s *stream, struct ltn_pes_packet_s *pes, int64_t *trueLatency_ms)
{
	struct tool_ctx_s *ctx = stream->ctx;
	*trueLatency_ms = -1;

	/* Establish PTS vs walltime if needed, ideally on an iframe - pick a large pes to do this on. */
	if (ltntstools_clock_is_established_wallclock(&stream->clkPTS) == 0) {
		int sync = 0;

		/* Find an iframe before we establish walltime to PTS syncronization */
		struct ltn_nal_headers_s *narray = NULL;
		int narray_length = 0;
		int ret = ltn_nal_h264_find_headers(pes->data, pes->dataLengthBytes, &narray, &narray_length);
		if (ret == 0) {
			for (int i = 0; i < narray_length; i++) {
				char st[256];
				if (h264_nal_get_slice_type(&narray[i], &st[0]) != 0) {
					st[0] = '?';
					st[1] = 0;
				}

				if (ctx->verbose) {
					printf("%d. %s, %s\n", i, narray[i].nalName, st);
				}

				switch(st[0]) {
				case 'i':
				case 'I':
					sync = 1;
					break;
				}

				if (sync)
					break;
			}
		}

		if (sync) {
			ltntstools_clock_establish_wallclock(&stream->clkPTS, pes->PTS);
		}
		if (narray) {
			free(narray);
			narray = NULL;
		}
	}
	
	if (ltntstools_clock_is_established_wallclock(&stream->clkPTS)) {
		ltntstools_clock_set_ticks(&stream->clkPTS, pes->PTS);
	}

	/* If we're expecting a DTS, and the DTS is present, establish DTS bs walltime if needed. */
	if ((pes->PTS_DTS_flags == 3) && (pes->DTS)) {
		if (ltntstools_clock_is_established_wallclock(&stream->clkDTS) == 0) {
			ltntstools_clock_establish_wallclock(&stream->clkDTS, pes->DTS);
		} else {
			ltntstools_clock_set_ticks(&stream->clkDTS, pes->DTS);
		}
	}

	stream->drift_ms = ltntstools_probe_ltnencoder_get_total_latency(stream->probe_hdl);

	/* A positive number indicates the clock is ahead of walltime.
	 * A negative number therefore indicates the ticks are behind walltime.
	 */
	stream->driftPTS_ms = ltntstools_clock_get_drift_ms(&stream->clkPTS);
	stream->driftDTS_ms = ltntstools_clock_get_drift_ms(&stream->clkDTS);

	stream->trueLatency = stream->drift_ms + stream->driftPTS_ms; /* Latency corrected by walltime to remove bursting and PTS B frame jitter. */

	*trueLatency_ms = stream->trueLatency;

#if 1
	printf("stream%d: drift_ms %6" PRIi64 ", driftPTS_ms %6" PRIi64 ", trueLatency %6" PRIi64 "\n",
		stream->nr,
		stream->drift_ms,
		stream->driftPTS_ms,
		stream->trueLatency);
#endif
}

static void *pe_callback(void *userContext, struct ltn_pes_packet_s *pes)
{
	struct stream_s *stream = (struct stream_s *)userContext;
	struct tool_ctx_s *ctx = stream->ctx;

	if (ctx->verbose > 1) {
		printf("PES Extractor callback stream %d\n", stream->nr);
		/* Else, dump all the PES packets */
		ltn_pes_packet_dump(pes, "");
	}

	int ret = ltntstools_probe_ltnencoder_sei_timestamp_query(stream->probe_hdl, pes->data, pes->dataLengthBytes);
	if (ret != 0) {
		if (ctx->verbose) {
			printf("PES Extractor callback stream %d, no timestamp found - skipping\n", stream->nr);
		}
		ltn_pes_packet_free(pes);
		return NULL; /* No timing information, skip this pes */
	}

	/* Establish walltimes vs PTS,s and keep them current. */
	int64_t trueLatency_ms;
	_maintain_clocks(stream, pes, &trueLatency_ms);

	/* -------- */
	/* Found the timing data, extract throw the details on a list */
	pthread_mutex_lock(&stream->lockElements);
	struct timing_element_s *e = xorg_list_first_entry(&stream->listElements, struct timing_element_s, list);
	if (!e) {
		pthread_mutex_unlock(&stream->lockElements);
		ltn_pes_packet_free(pes);
		return NULL; /* No items on the list. Not sure this could ever happen. */
	}

	e->trueLatency = trueLatency_ms;
	e->PTS = pes->PTS;
	e->DTS = pes->DTS;
#if 0
	if (stream->lastFrameNumber + 1 != e->sei_framenumber) {
		printf("! Frame discontinuity, wanted %d got %d\n", stream->lastFrameNumber + 1, e->sei_framenumber);
	}
#endif
	stream->lastFrameNumber = e->sei_framenumber;

	gettimeofday(&e->ts_seen, NULL);

	xorg_list_del(&e->list);


#if 1
	/* Search the list backwards, insert into the list but keep the list sorted by framenumber */
	/* Order by PTS, framenumber will have dups but be correctly ordered */
	/* Order by DTS, framenumber will have dups but be INcorrectly ordered */
	struct timing_element_s *item = NULL;
	xorg_list_for_each_entry_reverse(item, &stream->listElements, list) {
		/* TODO: THis fails when the frame number wraps */
		if (e->sei_framenumber >= item->sei_framenumber) {
		//if (e->PTS >= item->PTS) {
			__xorg_list_add(&e->list, &item->list, item->list.next);
			break;
		}
	}
#else
	xorg_list_append(&e->list, &stream->listElements);
#endif

#if 0
	pthread_mutex_lock(&ctx->console_mutex);
	printf("stream#%d: nr %4d, frame %d, PTS %13" PRIi64 ", DTS %13" PRIi64 ", seen %9u.%06u\n",
		stream->nr,
		e->nr,
		e->sei_framenumber,
		pes->PTS,
		pes->DTS,
		(uint32_t)e->ts_seen.tv_sec,
		(uint32_t)e->ts_seen.tv_usec);
	pthread_mutex_unlock(&ctx->console_mutex);
#endif

	if (ctx->compareMode && stream->nr == 2) {
		/* Comparing times between two probe stream 1 and probe stream 2 */

		if (time(NULL) >= stream->trueLatencyComputeAfter) {

			if (stream->trueLatency < stream->trueLatency_lwm)
				stream->trueLatency_lwm = stream->trueLatency;
			if (stream->trueLatency > stream->trueLatency_hwm)
				stream->trueLatency_hwm = stream->trueLatency;

			/* Lookup framenumber in cached list for stream 1 */
			_compareStreams(ctx, &ctx->src[0], e);
		}

	} else
	if (!ctx->compareMode && stream->nr == 1) {
		/* Single probe measurement, from probe stream 1 */
		
		if (time(NULL) >= stream->trueLatencyComputeAfter) {
			if (stream->trueLatency < stream->trueLatency_lwm)
				stream->trueLatency_lwm = stream->trueLatency;
			if (stream->trueLatency > stream->trueLatency_hwm)
				stream->trueLatency_hwm = stream->trueLatency;

			int64_t latencySpan = stream->trueLatency_hwm - stream->trueLatency_lwm;
			int64_t latency =  stream->trueLatency_lwm + (latencySpan / 2);
			printf("stream#%d: nr %4d, frame %d, bytes %7d, latency %" PRIi64 "ms +- %" PRIi64 "ms\n",
				stream->nr,
				e->nr,
				e->sei_framenumber,
				pes->dataLengthBytes,
				latency, latencySpan / 2);

		}

		if (ctx->verbose)
		{
			printf("stream#%d: nr %4d, frame %d, bytes %7d, PTS %13" PRIi64 ", DTS %13" PRIi64 ", seen %9u.%06u, latency %6" PRIi64 "ms, PTS drift %8" PRIi64 " DTS drift %8" PRIi64 ", truelatency %" PRIi64 "ms +- %" PRIi64 "ms\n",
				stream->nr,
				e->nr,
				e->sei_framenumber,
				pes->dataLengthBytes,
				pes->PTS,
				pes->DTS,
				(uint32_t)e->ts_seen.tv_sec,
				(uint32_t)e->ts_seen.tv_usec,
				stream->drift_ms,
				stream->driftPTS_ms,
				stream->driftDTS_ms, stream->trueLatency, stream->trueLatency_hwm - stream->trueLatency_lwm);			
		}

	} /* (!ctx->compareMode && stream->nr == 1) */

	pthread_mutex_unlock(&stream->lockElements);
	ltn_pes_packet_free(pes);

	return NULL;
}

static void *_avio_raw_callback(void *userContext, const uint8_t *pkts, int packetCount)
{
	struct stream_s *stream = (struct stream_s *)userContext;
	//struct tool_ctx_s *ctx = stream->ctx;
	
	ltntstools_pes_extractor_write(stream->pe, pkts, packetCount);

	return NULL;
}

static void *_avio_raw_callback_status(void *userContext, enum source_avio_status_e status)
{
	switch (status) {
	case AVIO_STATUS_MEDIA_START:
		printf("AVIO media starts\n");
		break;
	case AVIO_STATUS_MEDIA_END:
		printf("AVIO media ends\n");
		g_running = 0;
		break;
	default:
		fprintf(stderr, "unsupported avio state %d\n", status);
	}
	return NULL;
}


#ifdef __APPLE__
#define iphdr ip
#endif

static void *source_pcap_raw_cb(void *userContext, const struct pcap_pkthdr *hdr, const u_char *pkt)
{
	struct stream_s *src = (struct stream_s *)userContext;
	struct tool_ctx_s *ctx = src->ctx;

	if (hdr->len < sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr))
		return NULL;

	struct ether_header *ethhdr = (struct ether_header *)pkt;
	if (ntohs(ethhdr->ether_type) == ETHERTYPE_IP) {
		struct iphdr *iphdr = (struct iphdr *)((u_char *)ethhdr + sizeof(struct ether_header));

#ifdef __APPLE__
		if (iphdr->ip_p != IPPROTO_UDP)
			return NULL;
#endif
#ifdef __linux__
		if (iphdr->protocol != IPPROTO_UDP)
			return NULL;
#endif

		struct udphdr *udphdr = (struct udphdr *)((u_char *)iphdr + sizeof(struct iphdr));
		uint8_t *ptr = (uint8_t *)((uint8_t *)udphdr + sizeof(struct udphdr));

		if (ctx->verbose > 2) {
			struct in_addr dstaddr, srcaddr;
#ifdef __APPLE__
			srcaddr.s_addr = iphdr->ip_src.s_addr;
			dstaddr.s_addr = iphdr->ip_dst.s_addr;
#endif
#ifdef __linux__
			srcaddr.s_addr = iphdr->saddr;
			dstaddr.s_addr = iphdr->daddr;
#endif

			char src[24], dst[24];
			sprintf(src, "%s:%d", inet_ntoa(srcaddr), ntohs(udphdr->source));
			sprintf(dst, "%s:%d", inet_ntoa(dstaddr), ntohs(udphdr->dest));

			printf("%s -> %s : %4d : %02x %02x %02x %02x\n",
				
				src, dst,
				ntohs(udphdr->len),
				ptr[0], ptr[1], ptr[2], ptr[3]);
		}

		int lengthPayloadBytes = ntohs(udphdr->len) - sizeof(struct udphdr);
		
		if ((lengthPayloadBytes > 12) && ((lengthPayloadBytes - 12) % 188 == 0)) {
			/* It's RTP */
			ptr += 12;
			lengthPayloadBytes -= 12;
		}

		ltntstools_pes_extractor_write(src->pe, ptr, lengthPayloadBytes / 188);
	}

	return NULL;
}

static struct ltntstools_source_pcap_callbacks_s pcap_callbacks = 
{
    .raw = (ltntstools_source_pcap_raw_callback)source_pcap_raw_cb,
};

static void process_pcap_input(struct stream_s *src)
{
	//struct tool_ctx_s *ctx = src->ctx;

	if (ltntstools_source_pcap_alloc(&src->src_pcap, src, &pcap_callbacks, src->iname, src->pcap_filter) < 0) {
		fprintf(stderr, "Failed to open source_pcap interface, check permissions (sudo) or syntax.\n");
		return;
	}

}

static void process_avio_input(struct stream_s *src)
{
	//struct tool_ctx_s *ctx = src->ctx;

	if (strcasestr(src->iname, "rtp://")) {
		src->isRTP = 1;
	}

	struct ltntstools_source_avio_callbacks_s cbs = { 0 };
	cbs.raw = (ltntstools_source_avio_raw_callback)_avio_raw_callback;
	cbs.status = (ltntstools_source_avio_raw_callback_status)_avio_raw_callback_status;

	void *srcctx = NULL;
	int ret = ltntstools_source_avio_alloc(&srcctx, src, &cbs, src->iname);
	if (ret < 0) {
		fprintf(stderr, "-i syntax error\n");
		return;
	}

}

static void usage(const char *progname)
{
	printf("\nA tool to extract LTN SEI timing information from live transport streams, measuring the overall latency.\n");
	printf("Usage:\n");
	printf("  -i <url#1> Eg: rtp|udp://227.1.20.45:4001?localaddr=192.168.20.45\n"
               "             192.168.20.45 is the IP addr where we'll issue a IGMP join\n");
	printf("  -I <url#2> Eg: rtp|udp://227.1.20.45:4001?localaddr=192.168.20.45\n"
               "             192.168.20.45 is the IP addr where we'll issue a IGMP join\n");
	printf("  -v Increase level of verbosity.\n");
	printf("  -h Display command line help.\n");
	printf("  -n <instancename> [def: %s]\n", DEFAULT_INSTANCE_NAME);
	printf("  -N <framecachesize> measure in frames [def: %d]\n", DEFAULT_ELEMENTS);
	printf("  -p 0xnnnn PID containing the program elementary stream #1 [def: 0x%02x]\n", DEFAULT_PID);
	printf("  -s PES #1 Stream Id. Eg. 0xe0 or 0xc0 [def: 0x%02x]\n", DEFAULT_STREAMID);
	printf("  -P 0xnnnn PID containing the program elementary stream #2 [def: 0x%02x]\n", DEFAULT_PID);
	printf("  -S PES #2 Stream Id. Eg. 0xe0 or 0xc0 [def: 0x%02x]\n", DEFAULT_STREAMID);
	printf("  -U <udp://addr:port> Push timing messages to a UDP destination [def: disabled]\n\n");
	printf("  -f exact pcap filter. Eg 'host 227.1.20.80 && udp port 4001'\n");
	printf("  -F exact pcap filter. Eg 'host 227.1.20.90 && udp port 4100'\n");
	printf("     DON'T PASS A FILTER WITH MPTS or something with multiple different streams - be very specific, one stream one program\n");
	printf("\nExample:\n");
	printf("  sudo ./tstools_sei_latency_inspector -i eno2 \\ \n"
		   "     -i  net2.401 \\ \n"
		   "     -f 'host 227.1.20.80 && udp port 4001' -p 0x31  -s 0xe0 \\ \n"
		   "     -F 'host 227.1.20.90 && udp port 4100' -P 0x101 -S 0xe0 \\ \n"
		);
}

static int init_source(struct tool_ctx_s *ctx, int nr)
{
	if (nr > MAX_STREAM_SOURCES)
		return -1;

	struct stream_s *src = &ctx->src[nr - 1];

	src->nr = nr;
	src->ctx = ctx;
	src->avio_cbs.raw = (ltntstools_source_avio_raw_callback)_avio_raw_callback;
	src->avio_cbs.status = (ltntstools_source_avio_raw_callback_status)_avio_raw_callback_status;
	src->streamId = DEFAULT_STREAMID;
	src->pid = DEFAULT_PID;
	src->maxListElements = ctx->totalElements;
	src->trueLatency_hwm = 0;
	src->trueLatency_lwm = 150000000; /* unfeasable huge number */
	src->trueLatencyComputeAfter = time(NULL) + 3;
	src->mode = MODE_SOURCE_AVIO;

	ltntstools_probe_ltnencoder_alloc(&src->probe_hdl);

	ltntstools_clock_initialize(&src->clkPTS);
	ltntstools_clock_establish_timebase(&src->clkPTS, 90000);

	ltntstools_clock_initialize(&src->clkDTS);
	ltntstools_clock_establish_timebase(&src->clkDTS, 90000);

	pthread_mutex_init(&src->lockElements, NULL);
	xorg_list_init(&src->listElements);

	pthread_mutex_lock(&src->lockElements);
	for (int i = 0; i < src->maxListElements; i++) {
		struct timing_element_s *e = calloc(1, sizeof(*e));
		e->nr = i;
		xorg_list_append(&e->list, &src->listElements);
	}
	pthread_mutex_unlock(&src->lockElements);

	return 0;
}

static int start_source(struct tool_ctx_s *ctx, int nr)
{
	if (nr > MAX_STREAM_SOURCES)
		return -1;

	struct stream_s *src = &ctx->src[nr - 1];

	/* PES Extractor for the first input stream */
	if (ltntstools_pes_extractor_alloc(&src->pe, src->pid, src->streamId, (pes_extractor_callback)pe_callback, src) < 0) {
		fprintf(stderr, "\nUnable to allocate src pes_extractor object.\n\n");
		exit(1);
	}
	ltntstools_pes_extractor_set_skip_data(src->pe, 0);

	if (src->mode == MODE_SOURCE_AVIO) {
		printf("Mode: AVIO\n");
		process_avio_input(src);
	} else
	if (src->mode == MODE_SOURCE_PCAP) {
		printf("Mode: PCAP\n");
		process_pcap_input(src);
	}

	return 0;
}

static void destroy_source(struct tool_ctx_s *ctx, int nr)
{
	if (nr > MAX_STREAM_SOURCES)
		return;

	struct stream_s *src = &ctx->src[nr - 1];

	if (src->mode == MODE_SOURCE_AVIO) {
		ltntstools_source_avio_free(src->avio_ctx);
	} else
	if (src->mode == MODE_SOURCE_PCAP) {
		ltntstools_source_pcap_free(src->src_pcap);
	}

	pthread_mutex_lock(&src->lockElements);
	while(!xorg_list_is_empty(&src->listElements)) {
		struct timing_element_s *e = xorg_list_first_entry(&src->listElements, struct timing_element_s, list);
		xorg_list_del(&e->list);
		free(e);
	}
	pthread_mutex_unlock(&src->lockElements);

	ltntstools_pes_extractor_free(src->pe);
	ltntstools_probe_ltnencoder_free(src->probe_hdl);
	free(src->iname);
}

int sei_latency_inspector(int argc, char *argv[])
{
	struct tool_ctx_s myctx, *ctx;
	ctx = &myctx;
	memset(ctx, 0, sizeof(*ctx));
	ctx->totalElements = DEFAULT_ELEMENTS;
	ctx->compareMode = 0;
	ctx->instanceName = strdup(DEFAULT_INSTANCE_NAME);

	pthread_mutex_init(&ctx->console_mutex, NULL);

	init_source(ctx, 1);
	init_source(ctx, 2);

	struct stream_s *src = &ctx->src[0];
	struct stream_s *dst = &ctx->src[1];

	int ch, ret;
	while ((ch = getopt(argc, argv, "?hvi:f:F:I:n:N:p:P:s:S:U:")) != -1) {
		switch (ch) {
		case '?':
		case 'h':
			usage(argv[0]);
			exit(1);
			break;
		case 'i':
			src->iname = strdup(optarg);
			break;
		case 'I':
			dst->iname = strdup(optarg);
			ctx->compareMode = 1;
			break;
		case 'N':
			ctx->totalElements = atoi(optarg);
			break;
		case 'f':
			src->pcap_filter = strdup(optarg);
			src->mode = MODE_SOURCE_PCAP;
			break;
		case 'F':
			dst->pcap_filter = strdup(optarg);
			dst->mode = MODE_SOURCE_PCAP;
			break;
		case 'n':
			free(ctx->instanceName);
			ctx->instanceName = strdup(optarg);
			break;
		case 'p':
			if ((sscanf(optarg, "0x%x", &src->pid) != 1) || (src->pid > 0x1fff)) {
				usage(argv[0]);
				exit(1);
			}
			break;
		case 'P':
			if ((sscanf(optarg, "0x%x", &dst->pid) != 1) || (dst->pid > 0x1fff)) {
				usage(argv[0]);
				exit(1);
			}
			break;
		case 's':
			if ((sscanf(optarg, "0x%x", &src->streamId) != 1) || (src->streamId > 0xff)) {
				usage(argv[0]);
				exit(1);
			}
			break;
		case 'S':
			if ((sscanf(optarg, "0x%x", &dst->streamId) != 1) || (dst->streamId > 0xff)) {
				usage(argv[0]);
				exit(1);
			}
			break;
		case 'U':
			ret = sscanf(optarg, "udp://%99[^:]:%99d", &ctx->tx_ip[0], &ctx->tx_port);
			if (ret != 2) {
				fprintf(stderr, "Error parsing -U args, aborting ret %d\n", ret);
				exit(1);
			}
			ctx->udpOutput = 1;
			break;
		case 'v':
			ctx->verbose++;
			break;
		default:
			usage(argv[0]);
			exit(1);
		}
	}

	if (src->pid == 0) {
		usage(argv[0]);
		fprintf(stderr, "\n-s is mandatory.\n\n");
		exit(1);
	}

	if (src->iname == NULL) {
		usage(argv[0]);
		fprintf(stderr, "\n-i is mandatory.\n\n");
		exit(1);
	}

	if (getuid() == 0 && getenv("SUDO_UID") && getenv("SUDO_GID") && src->mode != MODE_SOURCE_PCAP) {
		usage(argv[0]);
		fprintf(stderr, "\n**** Don't use SUDO against file or udp socket sources, ONLY nic/pcap sources ****.\n\n");
		exit(1);
	}
	
	printf("Building a timing cache of %d frames\n", ctx->totalElements);

	if (ctx->compareMode) {
		printf("Between urls:\n");
		printf("\t%s\n", src->iname);
		printf("\t%s\n", dst->iname);
	} else {
		printf("From url to local walltime:\n");
		printf("\t%s\n", src->iname);
	}

	if (ctx->udpOutput) {
		ctx->tx_skt = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if(ctx->tx_skt < 0){
        	fprintf(stderr, "Error creating UDP output socket\n");
        	return -1;
    	}

		ctx->tx_sa.sin_family = AF_INET;
		ctx->tx_sa.sin_addr.s_addr = inet_addr(ctx->tx_ip);
		ctx->tx_sa.sin_port = htons(ctx->tx_port);
	}

	signal(SIGINT, signal_handler);

	start_source(ctx, 1);

	if (ctx->compareMode) {
		start_source(ctx, 2);
	}

	while (g_running) {
		usleep(50 * 1000);
	}

	destroy_source(ctx, 1);

	if (ctx->compareMode) {
		destroy_source(ctx, 2);
	}

	if (ctx->udpOutput) {
		close(ctx->tx_skt);
	}

	free(ctx->instanceName);

	return 0;
}
