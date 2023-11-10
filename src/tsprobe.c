
#include <stdio.h>
#include <sys/resource.h>
#include <zmq.h>

#include "nic_monitor.h"

/* Reduce this to 4 * 32768 to simulate loss on a NIC with 600Mbps */
/* Tuned to 64MB to support 2Gb/ps */
static int g_buffer_size_default = (64 * 1024 * 1024);
static int g_snaplen_default = 
#ifdef __linux__
	BUFSIZ
#endif
#ifdef __APPLE__
	65535
#endif
;

static int gRunning = 0;

static struct tool_context_s g_ctx = { 0 };
static struct tool_context_s *ctx = &g_ctx;
static int g_max_iat_ms = 45;

#if defined(__linux__)
extern int pthread_setname_np(pthread_t thread, const char *name);
#endif

extern int ltnpthread_setname_np(pthread_t thread, const char *name);

// Global ZMQ context and publisher declaration
void *zmq_context = NULL;
void *zmq_publisher = NULL;

// Initialization function for ZMQ, call this in initialization routine
void initialize_zmq_publisher(struct tool_context_s *ctx) {
    zmq_context = zmq_ctx_new();
    zmq_publisher = zmq_socket(zmq_context, ZMQ_PUB);
    int rc = zmq_bind(zmq_publisher, ctx->json_http_url); // Replace with your desired endpoint
    if (rc != 0) {
        fprintf(stderr, "Error occurred during zmq_bind: %s\n", zmq_strerror(errno));
        exit(-1); // Exit if bind fails
    }
}

// Cleanup function for ZMQ, call this during application shutdown routine
void cleanup_zmq_publisher() {
    zmq_close(zmq_publisher);
    zmq_ctx_destroy(zmq_context);
}

// Function to publish JSON message using ZMQ
int publish_json_message(const char *json_message) {
    int rc = zmq_send(zmq_publisher, json_message, strlen(json_message), 0);
    if (rc == -1) {
        fprintf(stderr, "Error occurred during zmq_send of %s: %s\n", json_message, zmq_strerror(errno));
		return -1;
    }
    return 0;
}

int zmq_item_send(struct tool_context_s *ctx, struct json_item_s *item)
{
        printf("sending json to %s:\n%s\n", ctx->json_http_url, item->buf);
        return publish_json_message((const char *)item->buf);
}

static void *json_thread_func(void *p)
{
	struct tool_context_s *ctx = p;
	ctx->json_threadRunning = 1;
	ctx->json_threadTerminate = 0;
	ctx->json_threadTerminated = 0;

	ltnpthread_setname_np(ctx->json_threadId, "tstools-json");
	pthread_detach(pthread_self());

	time_t now;
	time(&now);
	if (ctx->json_next_write_time == 0) {
		ctx->json_next_write_time = now + ctx->json_write_interval;
	}

	int json_post_interval = 1; /* Seconds */
	time_t json_next_post_time = 0;

	/* Initialize ZeroMQ */
	initialize_zmq_publisher(ctx);

	int workdone = 0;
	while (!ctx->json_threadTerminate) {

		workdone = 0;

		time(&now);
		if (json_next_post_time <= now) {
			json_next_post_time = now + json_post_interval;

			/* Look at the queue, take everything off it, issue zmq send. */
			int failed = 0;
			struct json_item_s *item = json_queue_peek(ctx);
			int loop = 0;
			while (item && ctx->json_threadTerminate == 0) {
				if (zmq_item_send(ctx, item) == 0) {
					/* Success, remove the item from the list */
					item = json_queue_pop(ctx);
					json_item_free(ctx, item);
					item = NULL;

					failed = 0;
				} else {
					fprintf(stderr, "json send failed, retrying in 250ms\n");
					usleep(250 * 1000); /* Natural rate limit if the post fails */
					failed += 250;
				}
				workdone++;

				if (failed >= 2000) {
					/* Back off for 30 seconds before we try again. */
					json_next_post_time = now + 1;
					break;
				}

				/* Success, take this of the queue and destroy it */
				item = json_queue_peek(ctx);

				fprintf(stdout, "json loop count: %d\n", ++loop);
			}
		}

		/* We don't want the thread thrashing when we have nothing to process. */
		if (!workdone)
			usleep(50 * 1000);
	}
	ctx->json_threadTerminated = 1;

	/* Cleanup ZeroMQ */
	cleanup_zmq_publisher();

	pthread_exit(NULL);
	return 0;
}

static void *stats_thread_func(void *p)
{
	struct tool_context_s *ctx = p;
	ctx->stats_threadRunning = 1;
	ctx->stats_threadTerminate = 0;
	ctx->stats_threadTerminated = 0;
	int write_file_banner[2] = { 1, 1 };

	ltnpthread_setname_np(ctx->stats_threadId, "tstools-stats");
	pthread_detach(pthread_self());

	time_t now;
	time(&now);
	if (ctx->file_prefix_next_write_time == 0) {
		ctx->file_prefix_next_write_time = now + ctx->file_write_interval;
	}
	if (ctx->detailed_file_prefix_next_write_time == 0) {
		ctx->detailed_file_prefix_next_write_time = now + ctx->file_write_interval;
	}

	int workdone = 0;
	while (!ctx->stats_threadTerminate) {

		workdone = 0;
		int count = pcap_queue_service(ctx);
		if (count)
			workdone++;

		if (workdone) {
			/* Periodic housekeeping. */
			discovered_items_housekeeping(ctx);
		}

		time(&now);
		if (ctx->file_prefix && ctx->file_prefix_next_write_time <= now) {
			ctx->file_prefix_next_write_time = now + ctx->file_write_interval;
			discovered_items_file_summary(ctx, write_file_banner[0]);
			write_file_banner[0] = 0;
			workdone++;
		}
		if (ctx->detailed_file_prefix && ctx->detailed_file_prefix_next_write_time <= now) {
			ctx->detailed_file_prefix_next_write_time = now + ctx->file_write_interval;
			discovered_items_file_detailed(ctx, write_file_banner[1]);
			write_file_banner[1] = 0;
			workdone++;
		}

		if (ctx->json_next_write_time <= now) {
			ctx->json_next_write_time = now + ctx->json_write_interval;
			discovered_items_json_summary(ctx);
			workdone++;
		}

		/* We don't want the thread thrashing when we have nothing to process. */
		if (!workdone)
			usleep(1 * 1000);
	}
	ctx->stats_threadTerminated = 1;

	pthread_exit(NULL);
	return 0;
}


static void pcap_callback(u_char *args, const struct pcap_pkthdr *h, const u_char *pkt) 
{
	pcap_update_statistics(ctx, h, pkt); /* Update the stream stats realtime to avoid queue jitter */
	pcap_queue_push(ctx, h, pkt); /* Push the packet onto a deferred queue for late IO processing. */
}

static struct pcap_pkthdr file_pkthdr;

static uint8_t file_pktdata[42 + (7 * 188)] = 
{
	0x01, 0x00, 0x5e, 0x01, 0x14, 0x50, 0xac, 0x1f,
	0x6b, 0x77, 0x81, 0xd3, 0x08, 0x00, 0x45, 0x00,
	0x05, 0x40, 0xeb, 0x0d, 0x40, 0x00, 0x05, 0x11,
	0xb9, 0x55, 0xc0, 0xa8, 0x14, 0x50, 0xe3, 0x01,
	0x14, 0x50, 0xd2, 0xb1, 0x0f, 0xa1, 0x05, 0x2c,
	0xf5, 0x29,
	/* Packet data to follow */
};

static void *sm_cb_pos(void *userContext, uint64_t pos, uint64_t max, double pct)
{
	struct tool_context_s *ctx = userContext;
	ctx->fileLoopPct = pct;
//	printf("%6.2f\n", pct);

	return NULL;
}

static void * sm_cb_raw(void *userContext, const uint8_t *pkts, int packetCount)
{
	struct tool_context_s *ctx = userContext;

	/* Convert a series of packets into a PCAP like structure */
	if (packetCount == 7) {
		gettimeofday(&file_pkthdr.ts, NULL);
		file_pkthdr.caplen = 42 + (packetCount * 188);
		file_pkthdr.len = file_pkthdr.caplen;

		memcpy(&file_pktdata[42], pkts, packetCount * 188);
		file_pktdata[26] = 192;
		file_pktdata[27] = 168;
		file_pktdata[28] = 1;
		file_pktdata[29] = 1;
		file_pktdata[30] = 227;
		file_pktdata[31] = 1;
		file_pktdata[32] = 1;
		file_pktdata[33] = 1;
		file_pktdata[34] = 6502 >> 8;
		file_pktdata[35] = 6502 & 0xff;
		pcap_callback((u_char *)ctx, &file_pkthdr, (const u_char *)&file_pktdata[0]);
	} else {
		/* Should never happen.
		 * Of the two possible callers:
		 * RCTS reframes to guarantee to 7 packets.
		 * SRT AVcodec reframes to guarantee to 7 packets.
		 */
	}

	return NULL;
}

static void *reframer_cb(void *userContext, const uint8_t *buf, int lengthBytes)
{
	struct tool_context_s *ctx = userContext;
	sm_cb_raw(ctx, buf, lengthBytes / 188);

	return NULL;
}

static void *pcap_thread_func(void *p)
{
	struct tool_context_s *ctx = p;
	ctx->pcap_threadRunning = 1;
	ctx->pcap_threadTerminate = 0;
	ctx->pcap_threadTerminated = 0;

	int processed;
	void *sm = NULL;
	AVIOContext *puc = NULL;
	uint8_t *buf = NULL;

	/* Massive buffer, I know.
	 * We saw SRT buffer errors with high jitter/latency streams, super bursty.
	 * make the SRT input buffer big enough that our reads can absorb it.
	 */
	int buflen = 8192 * 188;

	struct ltntstools_source_rcts_callbacks_s sm_callbacks = { 0 };
	sm_callbacks.raw = (ltntstools_source_rcts_raw_callback)sm_cb_raw;
	sm_callbacks.pos = (ltntstools_source_rcts_pos_callback)sm_cb_pos;

	ltnpthread_setname_np(ctx->pcap_threadId, "tstools-pcap");
	pthread_detach(pthread_self());

	time_t lastStatsCheck = 0;

	if (ctx->iftype == IF_TYPE_PCAP) {
		ctx->descr = pcap_create(ctx->ifname, ctx->errbuf);
		if (ctx->descr == NULL) {
			fprintf(stderr, "Error, %s\n", ctx->errbuf);
			exit(1);
		}
	
		pcap_set_immediate_mode(ctx->descr, 1); /* Ensure immediate packet callback delivery, later lib versions batch every 200ms */
		pcap_set_snaplen(ctx->descr, ctx->snaplen);
		pcap_set_promisc(ctx->descr,
#ifdef __linux__
			-1
#endif
#ifdef __APPLE__
			1
#endif
		);

		if (ctx->bufferSize != -1) {
			int ret = pcap_set_buffer_size(ctx->descr, ctx->bufferSize);
			if (ret == PCAP_ERROR_ACTIVATED) {
				fprintf(stderr, "Unable to set -B buffersize to %d, already activated\n", ctx->bufferSize);
				exit(0);
			}
			if (ret != 0) {
				fprintf(stderr, "Unable to set -B buffersize to %d\n", ctx->bufferSize);
				exit(0);
			}
		}

		int ret = pcap_activate(ctx->descr);
		if (ret != 0) {
			if (ret == PCAP_ERROR_PERM_DENIED) {
				fprintf(stderr, "Error, permission denied.\n");
			}
			if (ret == PCAP_ERROR_NO_SUCH_DEVICE) {
				fprintf(stderr, "Error, network interface '%s' not found.\n", ctx->ifname);
			}
			fprintf(stderr, "Error, pcap_activate, %s\n", pcap_geterr(ctx->descr));
			printf("\nAvailable interfaces:\n");
			networkInterfaceList();
			exit(1);
		}

		/* TODO: We should craft the filter to be udp dst 224.0.0.0/4 and then
		* we don't need to manually filter in our callback.
		*/
		struct bpf_program fp;
		ret = pcap_compile(ctx->descr, &fp, ctx->pcap_filter, 0, ctx->netp);
		if (ret == -1) {
			fprintf(stderr, "Error, pcap_compile, %s\n", pcap_geterr(ctx->descr));
			exit(1);
		}

		ret = pcap_setfilter(ctx->descr, &fp);
		if (ret == -1) {
			fprintf(stderr, "Error, pcap_setfilter\n");
			exit(1);
		}

		pcap_setnonblock(ctx->descr, 1, ctx->errbuf);
	} else
	if (ctx->iftype == IF_TYPE_MPEGTS_FILE) {

		if (ltntstools_source_rcts_alloc(&sm, ctx, &sm_callbacks, ctx->ifname, ctx->fileLoops) < 0) {

		}
	} else
	if (ctx->iftype == IF_TYPE_MPEGTS_AVDEVICE) {
		buf = malloc(buflen);
		if (!buf) {
			ctx->pcap_threadRunning = 1;
			ctx->pcap_threadTerminated = 1;
			return NULL;
		}

		avformat_network_init();
	
		int ret = avio_open2(&puc, ctx->ifname, AVIO_FLAG_READ | AVIO_FLAG_NONBLOCK | AVIO_FLAG_DIRECT, NULL, NULL);
		if (ret < 0) {
			fprintf(stderr, "-i syntax error, invalid URL syntax, aborting.\n");
			exit(1);
		}
	}

	while (!ctx->pcap_threadTerminate) {

		if (ctx->iftype == IF_TYPE_PCAP) {
			processed = pcap_dispatch(ctx->descr, -1, pcap_callback, NULL);
			if (processed == 0) {
				ctx->pcap_dispatch_miss++;
				usleep(1 * 1000);
			}
		} else
		if (ctx->iftype == IF_TYPE_MPEGTS_FILE) {
			usleep(50 * 1000);
		} else
		if (ctx->iftype == IF_TYPE_MPEGTS_AVDEVICE) {
			/* TODO: Migrate this to use the source-avio.[ch] framework */

			/* Bulk reads of less than this (7 * 188 eg) cause the ffurl_read in libsrt
			 * to throw constant expcetions / warnings.
			 * Read larger buffer values to avoid the issue.
			 */
			int rlen = avio_read(puc, buf, buflen);
			if (rlen == -EAGAIN) {
				usleep(1 * 1000);
				continue;
			}
			if (rlen < 0) {
				// TODO: Do what if the URL breaks?
				break;
			}

			ltststools_reframer_write(ctx->reframer, buf, rlen);
		}

		time_t now;
		time(&now);

		/* Querying stats repeatidly is cpu expensive, we only need it 1sec intervals. */
		if (lastStatsCheck == 0) {
			if (ctx->iftype == IF_TYPE_PCAP) {
				/* Collect pcap packet loss stats */
				if (pcap_stats(ctx->descr, &ctx->pcap_stats_startup) != 0) {
					/* Error */
				}
			}
		}

		if (now != lastStatsCheck) {
			lastStatsCheck = now;

			if (ctx->iftype == IF_TYPE_PCAP) {
				/* Collect pcap packet loss stats */
				struct pcap_stat tmp;
				if (pcap_stats(ctx->descr, &tmp) != 0) {
					/* Error */
				}

				ctx->pcap_stats.ps_recv = tmp.ps_recv - ctx->pcap_stats_startup.ps_recv;
				ctx->pcap_stats.ps_drop = tmp.ps_drop - ctx->pcap_stats_startup.ps_drop;
				ctx->pcap_stats.ps_ifdrop = tmp.ps_ifdrop - ctx->pcap_stats_startup.ps_ifdrop;
			} else
			if (ctx->iftype == IF_TYPE_MPEGTS_FILE) {
				ctx->pcap_stats.ps_recv = 0;
				ctx->pcap_stats.ps_drop = 0;
				ctx->pcap_stats.ps_ifdrop = 0;
			} else
			if (ctx->iftype == IF_TYPE_MPEGTS_AVDEVICE) {
				/* TODO: Wire up the SRT loss stats these these? Show them in the UI? */
				ctx->pcap_stats.ps_recv = 0;
				ctx->pcap_stats.ps_drop = 0;
				ctx->pcap_stats.ps_ifdrop = 0;
			}

		}

		pcap_queue_rebalance(ctx);

		if (ctx->endTime) {
			if (now >= ctx->endTime) {
				//kill(getpid(), 0);
				gRunning = 0;
				break;
			}
		}
	}
	ctx->pcap_threadTerminated = 1;

	if (sm)
		ltntstools_source_rcts_free(sm);

	if (puc)
		avio_close(puc);

	if (buf) {
		free(buf);
		buf = NULL;
	}

	pthread_exit(NULL);
	return 0;
}

static void signal_handler(int signum)
{
	if (signum == SIGINT)
		printf("\nUser requested terminate.\n");

	gRunning = 0;
}

static void usage(const char *progname)
{
	printf("A tool to monitor PCAP multicast ISO13818 traffic.\n");
	printf("Usage:\n");
	printf("  -i <iface | filename.ts | filename.ts:loop>\n");
	printf("  -v Increase level of verbosity.\n");
	printf("  -h Display command line help.\n");
	printf("  -t <#seconds>. Stop after N seconds [def: 0 - unlimited]\n");
	printf("  -M Display an interactive console with stats.\n");
	printf("  -D <dir> Write any PCAP recordings in this target directory prefix. [def: %s else /tmp]\n", DEFAULT_STORAGE_LOCATION);
	printf("  -d <dir> Write summary stats per stream in this target directory prefix, every -n seconds.\n");
	printf("  -w <dir> Write detailed per pid stats per stream in this target directory prefix, every -n seconds.\n");
	printf("  -n <seconds> Interval to update -d file based stats [def: %d]\n", FILE_WRITE_INTERVAL);
	printf("  -F '<string>' Use a custom pcap filter. [def: '%s']\n", DEFAULT_PCAP_FILTER);
	printf("  -S <number> Packet buffer size [def: %d] (min: 2048)\n", g_snaplen_default);
	printf("  -B <number> Buffer size [def: %d]\n", g_buffer_size_default);
	printf("  -R Automatically record all discovered streams\n");
	printf("  -E Record in a single file, don't segment into 60sec files\n");
	printf("  -T Record int a TS format where possible [default is PCAP]\n");
	printf("  -I <#> (ms) max allowable IAT measured in ms [def: %d]\n", g_max_iat_ms);
	printf("\n");
	printf("  --udp-forwarder udp://a.b.c.d:port   Add up to %d url forwarders.\n", MAX_URL_FORWARDERS);
	printf("  --danger-skip-freespace-check        Skip the Disk Free space check, don't stop recording when disk has < 10pct free.\n");
	printf("  --measure-sei-latency-always         Look for the LTN SEI timing data, regardless of PMT version descriptoring.\n");
	printf("  --measure-scheduling-quanta          Test the scheduling quanta for 1000us sleep granularity.\n");
	printf("  --show-h264-metadata 0xnnnn          Analyze the given H264 PID (or detect it), show different codec stats (Experimental).\n");
	printf("  --report-rtp-headers                 For RTP UDP/TS streams, dump each RTP header to console.\n");
	printf("  --zmq-json-send tcp://url            Send 1sec json stats reports for all discovered streams [def: disabled] (Experimental).\n");
	printf("    Eg. tcp://127.0.0.1:1000\n");
	printf("  --report-memory-usage                Report memory usage and growth every 5 seconds.\n");
}

static int processArguments(struct tool_context_s *ctx, int argc, char *argv[])
{
	int forwarder_idx = 0;
	struct option long_options[] =
	{
		// 0 - 4
		{ "struct-sizes",				no_argument,		0, '@' },
		{ "pcap-buffer-size",			required_argument,	0, 'B' },
		{ "stats-summary-dir",			required_argument,	0, 'd' },
		{ "pcap-filter",				required_argument,	0, 'F' },
		{ "help",						required_argument,	0, 'h' },

		// 5 - 9
		{ "help",						required_argument,	0, '?' },
		{ "input",						required_argument,	0, 'i' },
		{ "iat-max",					required_argument,	0, 'I' },
		{ "stats-write-interval",		required_argument,	0, 'n' },
		{ "terminate-after",			required_argument,	0, 't' },

		// 10 - 14
		{ "verbose",					no_argument,		0, 'v' },
                { "ui",                                                 no_argument,            0, 'M' },
		{ "danger-skip-freespace-check", no_argument,		0, 0 },
		{ "pcap-record-dir",			required_argument,	0, 'D' },
		{ "record-single-file",			no_argument,		0, 'E' },

		// 15 - 19
		{ "pcap-packet-size",			required_argument,	0, 'S' },
		{ "stats-detailed-dir",			required_argument,	0, 'w' },
		{ "record-as-transport",		no_argument,		0, 'T' },
		{ "record-on-startup",			no_argument,		0, 'R' },
		{ "test-arg-19",				no_argument,		0, 0 },

		// 20 - 24
		{ "udp-forwarder",				required_argument,	0, 0 },
		{ "measure-scheduling-quanta",	no_argument,		0, 0 },
		{ "show-h264-metadata",			required_argument,	0, 0 },
		{ "zmq-json-send",		        required_argument,	0, 0 },
		{ "report-rtp-headers",			no_argument,		0, 0 },

		// 25 - 29
		{ "measure-sei-latency-always", no_argument,		0, 0 },
		{ "report-memory-usage", 		no_argument,		0, 0 },

		{ 0, 0, 0, 0 }
	};	

	int ch;
	while (1) {
		int option_index = 0;
		char *opts = "?hd:B:D:EF:i:I:t:vMn:w:RS:T@";
		ch = getopt_long(argc, argv, opts, long_options, &option_index);
		if (ch == -1)
			break;

//printf("ch = '%c', optidx %d\n", ch, option_index);

		switch (ch) {
		case '@':
			printf("\n");
			printf("sizeof(struct ltntstools_stream_statistics_s) = %lu\n", sizeof(struct ltntstools_stream_statistics_s));
			printf(" + 2x256KB for histograms per PCR pid\n");
			printf("sizeof(struct rtp_hdr_analyzer_s) = %lu\n", sizeof(struct rtp_hdr_analyzer_s));
			printf(" + 2x256KB for histograms\n");
			printf("\n");
			exit(1);
			break;
		case 'B':
			ctx->bufferSize = atoi(optarg);
			if (ctx->bufferSize < (2 * 1048576))
				ctx->bufferSize = 2 * 1048576;
			break;
		case 'd':
			free(ctx->file_prefix);
			ctx->file_prefix = strdup(optarg);
			break;
		case 'F':
			ctx->pcap_filter = strdup(optarg);
			break;
		case '?':
		case 'h':
			usage(argv[0]);
			exit(1);
			break;
		case 'i':
			ctx->ifname = optarg;

			// Eg. hls+http://sportsgrid-vizio.amagi.tv/playlist.m3u8
			
			ctx->fileLoops = 0;
			if (strstr(ctx->ifname, "srt://")) {
				ctx->iftype = IF_TYPE_MPEGTS_AVDEVICE;
			} else
			if (strstr(ctx->ifname, ":loop")) {
				ctx->fileLoops = 1;
				ctx->ifname[strlen (ctx->ifname) - 5] = 0;
			}
			if (ctx->iftype == IF_TYPE_MPEGTS_AVDEVICE) {

			} else
			if (isValidTransportFile(ctx->ifname)) {
				ctx->iftype = IF_TYPE_MPEGTS_FILE;
			} else {

				if (networkInterfaceExistsByName(ctx->ifname) == 0) {
					fprintf(stderr, "\nNo such network interface '%s', available interfaces:\n", ctx->ifname);
					networkInterfaceList();
					printf("\n");
					exit(1);
				}

			}
			break;
		case 'I':
			ctx->iatMax = atoi(optarg);
			break;
		case 'n':
			ctx->file_write_interval = atoi(optarg);
			if (ctx->file_write_interval < 1)
				ctx->file_write_interval = 1;
			break;
		case 't':
			time(&ctx->endTime);
			ctx->endTime += atoi(optarg);
			break;
		case 'v':
			ctx->verbose++;
			break;
                case 'M':
                        break;
		case 'D':
			free(ctx->recordingDir);
			ctx->recordingDir = strdup(optarg);
			break;
		case 'E':
			ctx->recordWithSegments = 0;
			break;
		case 'S':
			ctx->snaplen = atoi(optarg);
			if (ctx->snaplen < 2048)
				ctx->snaplen = 2048;
			break;
		case 'w':
			free(ctx->detailed_file_prefix);
			ctx->detailed_file_prefix = strdup(optarg);
			break;
		case 'T':
			ctx->recordAsTS = 1;
			break;
		case 'R':
			ctx->automaticallyRecordStreams = 1;
			break;
		default:
			switch (option_index) {
			case 12: /* danger-skip-freespace-check */
				ctx->skipFreeSpaceCheck = 1;
				break;
			case 19: /* test-arg-19 */
				printf("Checking test-arg-19, success!\n");
				exit(1);
				break;
			case 20: /* udp-forwarder-url */
				if (forwarder_idx == MAX_URL_FORWARDERS) {
					fprintf(stderr, "\nError, too many forwarders defined, max is %d\n", MAX_URL_FORWARDERS);
					exit(1);
				}
				if (sscanf(optarg, "udp://%99[^:]:%d",
					&ctx->url_forwards[forwarder_idx].addr[0],
					&ctx->url_forwards[forwarder_idx].port) != 2)
				{
					fprintf(stderr, "\nError parsing forwarding url, check syntax. Must be udp://a.b.c.d:port\n");
					exit(1);
				}
				sprintf(&ctx->url_forwards[forwarder_idx].uilabel[0], "%s:%d",
					ctx->url_forwards[forwarder_idx].addr,
					ctx->url_forwards[forwarder_idx].port);
				forwarder_idx++;
				break;
			case 21: /* measure-scheduling-quanta */
				{
					struct timeval a, b, r;
					gettimeofday(&a, NULL);
					usleep(1000);
					gettimeofday(&b, NULL);
					ltn_histogram_timeval_subtract(&r, &b, &a);
					uint32_t diffUs = ltn_histogram_timeval_to_us(&r);
					printf("\nSlept for 1000us, woke to find we'd spent %dus asleep.\n\n", diffUs);
					exit(1);
				}
				break;
			case 22: /* show-h264-metadata */
				ctx->gatherH264Metadata = 1;
				if ((sscanf(optarg, "0x%x", &ctx->gatherH264MetadataPID) != 1) || (ctx->gatherH264MetadataPID > 0x1fff)) {
					usage(argv[0]);
					exit(1);
				}
				break;
			case 23: /* zmq-json-send */
				ctx->automaticallyJSONProbeStreams = 1;
				strcpy(&ctx->json_http_url[0], optarg);
				break;
			case 24: /* report-rtp-headers */
				ctx->reportRTPHeaders = 1;
				break;
			case 25: /* measure-sei-latency-always */
				ctx->measureSEILatencyAlways = 1;
				break;
			case 26: /* report-memory-usage */
				ctx->reportProcessMemoryUsage = 1;
				break;
			default:
				usage(argv[0]);
				exit(1);
			}
		}
	} 

	if (ctx->ifname == NULL) {
		usage(argv[0]);
		fprintf(stderr, "\nError, -i is mandatory.\n\n");
		exit(1);
	}

	return 0;
}

int tsprobe(int argc, char *argv[])
{
	//int ch;

	pthread_mutex_init(&ctx->lock, NULL);
	xorg_list_init(&ctx->list);

	pthread_mutex_init(&ctx->lockpcap, NULL);
	xorg_list_init(&ctx->listpcapFree);
	xorg_list_init(&ctx->listpcapUsed);

#if MEDIA_MONITOR
	media_init();
#endif

	pthread_mutex_init(&ctx->lockJSONPost, NULL);
	xorg_list_init(&ctx->listJSONPost);
	ctx->jsonSocket = -1;

	ctx->reframer = ltntstools_reframer_alloc(ctx, 7 * 188, (ltntstools_reframer_callback)reframer_cb);

	pcap_queue_initialize(ctx);
	ctx->file_write_interval = FILE_WRITE_INTERVAL;
	ctx->json_write_interval = JSON_WRITE_INTERVAL;
	ctx->pcap_filter = DEFAULT_PCAP_FILTER;
	ctx->snaplen = g_snaplen_default;
	ctx->bufferSize = g_buffer_size_default;
	ctx->recordWithSegments = 1;
	ctx->skipFreeSpaceCheck = 0;
	ctx->iatMax = g_max_iat_ms;
	ctx->iftype = IF_TYPE_PCAP;
	ctx->startTime = time(NULL);
	strcpy(ctx->json_http_url, "tcp://127.0.0.1:1000");

	for (int i = 0; i < 3; i++) {
		sprintf(&ctx->url_forwards[i].addr[0], "227.1.240.%d", i + 7);
		ctx->url_forwards[i].port = 4001;
		sprintf(&ctx->url_forwards[i].uilabel[0], "%s:%d", ctx->url_forwards[i].addr, ctx->url_forwards[i].port);
	}

	if (processArguments(ctx, argc, argv) < 0) {
		usage(argv[0]);
		exit(1);
	}

	if (ctx->verbose) {
		printf("  iface: %s\n", ctx->ifname);
	}

	/* Configure automatic core-dumps */
	struct rlimit core_limit;
	core_limit.rlim_cur = RLIM_INFINITY;
	core_limit.rlim_max = RLIM_INFINITY;
	if (setrlimit(RLIMIT_CORE, &core_limit) < 0) {
		fprintf(stderr, "setrlimit: unable to enable automatic core dumps, ignoring.\n");
	} else {
		printf("automatic core dumps enabled.\n");
	}

	if (ctx->iftype == IF_TYPE_PCAP) {
		pcap_lookupnet(ctx->ifname, &ctx->netp, &ctx->maskp, ctx->errbuf);

		struct in_addr ip_net, ip_mask;
		ip_net.s_addr = ctx->netp;
		ip_mask.s_addr = ctx->maskp;
		if (ctx->verbose) {
			printf("network: %s\n", inet_ntoa(ip_net));
			printf("   mask: %s\n", inet_ntoa(ip_mask));
			printf(" filter: %s\n", ctx->pcap_filter);
			printf("snaplen: %d\n", ctx->snaplen);
			printf("buffSiz: %d\n", ctx->bufferSize);
		}
	} else
	if (ctx->iftype == IF_TYPE_MPEGTS_FILE) {
	} else
	if (ctx->iftype == IF_TYPE_MPEGTS_AVDEVICE) {
	}

	if (ctx->verbose) {
		printf("file write interval: %d\n", ctx->file_write_interval);
		printf("json write interval: %d\n", JSON_WRITE_INTERVAL);
	}

	gRunning = 1;
	pthread_create(&ctx->stats_threadId, 0, stats_thread_func, ctx);
	if (ctx->iftype == IF_TYPE_PCAP || ctx->iftype == IF_TYPE_MPEGTS_FILE || ctx->iftype == IF_TYPE_MPEGTS_AVDEVICE) {
		pthread_create(&ctx->pcap_threadId, 0, pcap_thread_func, ctx);
	}
	pthread_create(&ctx->json_threadId, 0, json_thread_func, ctx);

	/* Framework to track the /proc/net/udp socket buffers stats - primarily for loss */
	ltntstools_proc_net_udp_alloc(&ctx->procNetUDPContext);

	ctx->monitor = 1;
	discovered_items_select_all(ctx);
	discovered_items_unhide_all(ctx);

	/* Start any threads, main loop processes keybaord. */
	signal(SIGINT, signal_handler);
	timeout(300);

	/* Measure the memory used by this process */
	process_memory_init(&ctx->memUsage);

	time(&ctx->lastResetTime);
	while (gRunning) {

		process_memory_update(&ctx->memUsage, 5);

		if (ctx->startTime + 2 == time(NULL)) {
			time(&ctx->lastResetTime);
			discovered_items_stats_reset(ctx);
			ltntstools_proc_net_udp_items_reset_drops(ctx->procNetUDPContext);
			ctx->lastSocketReport = 0;
		}

		usleep(1000 * 1000);
	}

	discovered_items_abort(ctx);

	time_t periodEnds = time(NULL);

	/* Shutdown stats collection */
	ctx->pcap_threadTerminate = 1;
	ctx->stats_threadTerminate = 1;
	ctx->json_threadTerminate = 1;
	while (!ctx->pcap_threadTerminated)
		usleep(50 * 1000);
	while (!ctx->stats_threadTerminated)
		usleep(50 * 1000);
	while (!ctx->json_threadTerminated)
		usleep(50 * 1000);

	/* Prepare stats window messages for later print. */
	char ts_b[64];
	sprintf(&ts_b[0], "%s", ctime(&ctx->lastResetTime));
	ts_b[ strlen(ts_b) - 1] = 0;

	char ts_e[64];
	sprintf(&ts_e[0], "%s", ctime(&periodEnds));
	ts_e[ strlen(ts_e) - 1] = 0;

	time_t d = periodEnds - ctx->lastResetTime;
	struct tm diff = { 0 };
	gmtime_r(&d, &diff);

	discovered_items_console_summary(ctx);

	struct ltntstools_proc_net_udp_item_s *items;
	int itemCount;
	if (ltntstools_proc_net_udp_item_query(ctx->procNetUDPContext, &items, &itemCount) == 0) {
		printf("System wide UDP socket buffers\n");
		printf("-------------------------------------------------------------------------------------------->\n");
		ltntstools_proc_net_udp_item_dprintf(ctx->procNetUDPContext, 0, items, itemCount);
		printf("\n");

		ltntstools_proc_net_udp_item_free(ctx->procNetUDPContext, items);
	}

	ltntstools_proc_net_udp_free(ctx->procNetUDPContext);

	if (ctx->verbose) {
		printf("pcap_free_miss %" PRIi64 "\n", ctx->pcap_free_miss);
		printf("pcap_dispatch_miss %" PRIi64 "\n", ctx->pcap_dispatch_miss);
		printf("pcap_malloc_miss %" PRIi64 "\n", ctx->pcap_malloc_miss);
		printf("pcap_mangled_list_items %" PRIi64 "\n", ctx->pcap_mangled_list_items);
		printf("ctx->listpcapFreeDepth %d\n", ctx->listpcapFreeDepth);
		printf("ctx->listpcapUsedDepth %d\n", ctx->listpcapUsedDepth);
		printf("ctx->rebalance_last_buffers_used %d\n", ctx->rebalance_last_buffers_used);
		printf("ctx->cacheHitRatio %.02f%% (%" PRIu64 ", %" PRIu64 ")\n", ctx->cacheHitRatio, ctx->cacheHit, ctx->cacheMiss);
	}

	if (ctx->iftype == IF_TYPE_PCAP) {
		printf("pcap nic '%s' stats: dropped: %d/%d\n",
			ctx->ifname, ctx->pcap_stats.ps_drop, ctx->pcap_stats.ps_ifdrop);
	}

	printf("\nStats window:\n");
	printf("  from %s -> %s\n", ts_b, ts_e);
	printf("  duration %02d:%02d:%02d (HH:MM:SS)\n\n", diff.tm_hour, diff.tm_min, diff.tm_sec);

	printf("Flushing the streams and recorders...\n");
	discovered_items_free(ctx);

	free(ctx->file_prefix);
	free(ctx->detailed_file_prefix);

	ltntstools_reframer_free(ctx->reframer);

	/* free memory */
	pcap_queue_free(ctx);

	return 0;
}
