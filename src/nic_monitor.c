
#include <stdio.h>
#include <sys/resource.h>

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

#if defined(__linux__)
extern int pthread_setname_np(pthread_t thread, const char *name);
#endif

int ltnpthread_setname_np(pthread_t thread, const char *name)
{
#if defined(__linux__)
        return pthread_setname_np(thread, name);
#endif
#if defined(__APPLE__)
        /* We don't support thread naming on OSX, yet. */
        return 0;
#endif
}

/* Seeing some crashes inside getch, five leves deep related to dorefresh
 * in ncurses. Make sure we don't call getch without ensuring
 * the ui thread isn't refreshing the display.
 */
static char ui_syncronized_getch(struct tool_context_s *ctx)
{
	pthread_mutex_lock(&ctx->ui_threadLock);
	char c = getch();
	pthread_mutex_unlock(&ctx->ui_threadLock);

	return c;
}

static void *ui_thread_func(void *p)
{
	struct tool_context_s *ctx = p;
	ctx->ui_threadRunning = 1;
	ctx->ui_threadTerminate = 0;
	ctx->ui_threadTerminated = 0;
	ctx->trailerRow = DEFAULT_TRAILERROW;
	double totalMbps = 0;
	int totalStreams = 0;
	struct ltntstools_proc_net_udp_item_s *items = NULL;
	int itemCount = 0;

	ltnpthread_setname_np(ctx->ui_threadId, "tstools-ui");
	pthread_detach(pthread_self());
	setlocale(LC_NUMERIC, "");

	noecho();
	curs_set(0);
	start_color();
	init_pair(1, COLOR_WHITE, COLOR_BLUE);
	init_pair(2, COLOR_CYAN, COLOR_BLACK);
	init_pair(3, COLOR_RED, COLOR_BLACK);
	init_pair(4, COLOR_WHITE, COLOR_RED);
	init_pair(5, COLOR_WHITE, COLOR_GREEN);
	init_pair(7, COLOR_YELLOW, COLOR_BLACK);

	while (!ctx->ui_threadTerminate) {

		totalMbps = 0;
		totalStreams = 0;
		time_t now;
		time(&now);

		if (ctx->freezeDisplay & 1) {
			usleep(50 * 1000);
			continue;
		}

		pthread_mutex_lock(&ctx->ui_threadLock);

		clear();

		struct in_addr ip_net, ip_mask;
		ip_net.s_addr = ctx->netp;
		ip_mask.s_addr = ctx->maskp;
		//printf("network: %s\n", inet_ntoa(ip_net));
		//printf("   mask: %s\n", inet_ntoa(ip_mask));

		char title_a[160], title_b[160], title_c[160];
		sprintf(title_a, "%s", ctx->pcap_filter);
		char mask[64];
		sprintf(mask, "%s", inet_ntoa(ip_mask));
		sprintf(title_c, "NIC: %s (%s/%s) Dropped: %d/%d", ctx->ifname, inet_ntoa(ip_net), mask,
			ctx->pcap_stats.ps_drop,
			ctx->pcap_stats.ps_ifdrop);
		int blen = 111 - (strlen(title_a) + strlen(title_c));
		memset(title_b, 0x20, sizeof(title_b));
		title_b[blen] = 0;

		if (ctx->pcap_stats.ps_drop || ctx->pcap_stats.ps_ifdrop) {
			attron(COLOR_PAIR(4));
		} else {
			attron(COLOR_PAIR(1));
		}
		mvprintw( 0, 0, "%s%s%s", title_a, title_b, title_c);

		if (ctx->pcap_stats.ps_drop || ctx->pcap_stats.ps_ifdrop) {
			attroff(COLOR_PAIR(4));
		} else {
			attroff(COLOR_PAIR(1));
		}

		attron(COLOR_PAIR(1));
		mvprintw( 1, 0, "<--------------------------------------------------- M/BIT <---------PACKETS <------CCErr <-IAT(uS)------------");
		attroff(COLOR_PAIR(1));

		int streamCount = 1;
		struct discovered_item_s *di = NULL;
		pthread_mutex_lock(&ctx->lock);
		xorg_list_for_each_entry(di, &ctx->list, list) {

			if (discovered_item_state_get(di, DI_STATE_HIDDEN))
				continue;

			if (di->stats.ccErrors)
				discovered_item_state_set(di, DI_STATE_CC_ERROR);
			else
				discovered_item_state_clr(di, DI_STATE_CC_ERROR);

			if (discovered_item_state_get(di, DI_STATE_CC_ERROR))
				attron(COLOR_PAIR(3));

			if (discovered_item_state_get(di, DI_STATE_DST_DUPLICATE))
				attron(COLOR_PAIR(4));

			if (discovered_item_state_get(di, DI_STATE_SELECTED))
				attron(COLOR_PAIR(5));

			totalMbps += ltntstools_pid_stats_stream_get_mbps(&di->stats);
			totalStreams++;
			if ((di->payloadType == PAYLOAD_RTP_TS) || (di->payloadType == PAYLOAD_UDP_TS)) {
				mvprintw(streamCount + 2, 0, "%s %21s -> %21s %7.2f  %'16" PRIu64 " %12" PRIu64 "   %7d / %d / %d",
					payloadTypeDesc(di->payloadType),
					di->srcaddr,
					di->dstaddr,
					ltntstools_pid_stats_stream_get_mbps(&di->stats),
					di->stats.packetCount,
					di->stats.ccErrors,
					di->iat_cur_us, di->iat_lwm_us, di->iat_hwm_us);
			} else
			if (di->payloadType == PAYLOAD_A324_CTP) {
				mvprintw(streamCount + 2, 0, "%s %21s -> %21s %7.2f  %'16" PRIu64 " %12" PRIu64 "   %7d / %d / %d",
					payloadTypeDesc(di->payloadType),
					di->srcaddr,
					di->dstaddr,
					ltntstools_ctp_stats_stream_get_mbps(&di->stats),
					di->stats.packetCount,
					di->stats.ccErrors,
					di->iat_cur_us, di->iat_lwm_us, di->iat_hwm_us);
				totalMbps += ltntstools_ctp_stats_stream_get_mbps(&di->stats);
			} else
			if ((di->payloadType == PAYLOAD_SMPTE2110_20_VIDEO) ||
				(di->payloadType == PAYLOAD_SMPTE2110_30_AUDIO) ||
				(di->payloadType == PAYLOAD_SMPTE2110_40_ANC)) {
				mvprintw(streamCount + 2, 0, "%s %21s -> %21s %7.2f  %'16" PRIu64 " %12" PRIu64 "   %7d / %d / %d",
					payloadTypeDesc(di->payloadType),
					di->srcaddr,
					di->dstaddr,
					ltntstools_ctp_stats_stream_get_mbps(&di->stats),
					di->stats.packetCount,
					di->stats.ccErrors,
					di->iat_cur_us, di->iat_lwm_us, di->iat_hwm_us);
				totalMbps += ltntstools_ctp_stats_stream_get_mbps(&di->stats);
			} else
			if (di->payloadType == PAYLOAD_BYTE_STREAM) {
				mvprintw(streamCount + 2, 0, "%s %21s -> %21s %7.2f  %'16" PRIu64 " %12s   %7d / %d / %d",
					payloadTypeDesc(di->payloadType),
					di->srcaddr,
					di->dstaddr,
					ltntstools_bytestream_stats_stream_get_mbps(&di->stats),
					di->stats.packetCount,
					"-",
					di->iat_cur_us, di->iat_lwm_us, di->iat_hwm_us);
				totalMbps += ltntstools_bytestream_stats_stream_get_mbps(&di->stats);
			}

			if (discovered_item_state_get(di, DI_STATE_SELECTED))
				attroff(COLOR_PAIR(5));

			if (discovered_item_state_get(di, DI_STATE_DST_DUPLICATE))
				attroff(COLOR_PAIR(4));

			if (discovered_item_state_get(di, DI_STATE_CC_ERROR))
				attroff(COLOR_PAIR(3));

			if (discovered_item_state_get(di, DI_STATE_STREAM_FORWARDING)) {
				streamCount++;
				mvprintw(streamCount + 2, 0, " -> Forwarding stream to %s", di->forwardURL);
				streamCount++;
			}

			if (discovered_item_state_get(di, DI_STATE_PCAP_RECORDING)) {

				char fn[512] = { 0 };
				int ret = ltntstools_segmentwriter_get_current_filename(di->pcapRecorder, &fn[0], sizeof(fn));
				if (ret < 0)
					sprintf(fn, "pending open file");

				double fsusedpct = 100.0 - ltntstools_segmentwriter_get_freespace_pct(di->pcapRecorder);
				int segcount = ltntstools_segmentwriter_get_segment_count(di->pcapRecorder);
				double totalsize = ltntstools_segmentwriter_get_recording_size(di->pcapRecorder);
				totalsize /= 1048576; /* MB */
				int mb = 1;
				if (totalsize > 4000) {
					totalsize /= 1024; /* Convert to GB */
					mb = 0;
				}

				time_t startTime = ltntstools_segmentwriter_get_recording_start_time(di->pcapRecorder);
				char st[64];
				sprintf(st, "%s", ctime(&startTime));
				st[ strlen(st) - 1] = 0;

				streamCount++;
				mvprintw(streamCount + 2, 0, " -> %s to ... %s",
					ctx->recordWithSegments ? "Segmented recording" : "Recording",
					fn);

				double fs_full_warning_level = 80.0;
				if (fsusedpct > fs_full_warning_level)
					attron(COLOR_PAIR(3));

				streamCount++;
				if (ctx->recordWithSegments) {
					mvprintw(streamCount + 2, 0, "    %d segment%s @ %'.02f%s, %s fs %5.02f%% full, since %s",
						segcount,
						segcount == 1 ? "" : "(s)",
						totalsize,
						mb == 1 ? "MB" : "GB",
						dirname(&fn[0]),
						fsusedpct,
						st);
				} else {
					mvprintw(streamCount + 2, 0, "    One file @ %'.02f%s, %s fs %5.02f%% full, since %s",
						totalsize,
						mb == 1 ? "MB" : "GB",
						dirname(&fn[0]),
						fsusedpct,
						st);
				}

				if (fsusedpct > fs_full_warning_level)
					attroff(COLOR_PAIR(3));

				int qdepth = ltntstools_segmentwriter_get_queue_depth(di->pcapRecorder);
				if (qdepth > 300 * 1000) {
					attron(COLOR_PAIR(7));
					streamCount++;
					mvprintw(streamCount + 2, 0, "    Recorder I/O is falling behind realtime, %d items waiting", qdepth);
					attroff(COLOR_PAIR(7));
				}
			}
#if PROBE_REPORTER
			if (discovered_item_state_get(di, DI_STATE_JSON_PROBE_ACTIVE)) {
				streamCount++;
				mvprintw(streamCount + 2, 0, " -> JSON Probe Active");
			}
#endif

			if (discovered_item_state_get(di, DI_STATE_SHOW_PIDS)) {
				if (di->payloadType == PAYLOAD_SMPTE2110_20_VIDEO) {
					streamCount++;
					mvprintw(streamCount + 2, 0, " -> PID Report not available for SMPTE2110-20 Video streams");
				}
				if (di->payloadType == PAYLOAD_SMPTE2110_30_AUDIO) {
					streamCount++;
					mvprintw(streamCount + 2, 0, " -> PID Report not available for SMPTE2110-30 Audio streams");
				}
				if (di->payloadType == PAYLOAD_SMPTE2110_40_ANC) {
					streamCount++;
					mvprintw(streamCount + 2, 0, " -> PID Report not available for SMPTE2110-40 Ancillary Data streams");
				}
				if (di->payloadType == PAYLOAD_A324_CTP) {
					streamCount++;
					mvprintw(streamCount + 2, 0, " -> PID Report not available for A/324 Studio Transmitter Link CTP streams");
				}
				if (di->payloadType == PAYLOAD_BYTE_STREAM) {
					streamCount++;
					mvprintw(streamCount + 2, 0, " -> PID Report not available for unidentified byte streams");
				}
				for (int i = 0; i < MAX_PID; i++) {
					if (di->stats.pids[i].enabled) {
						streamCount++;
						if (i == 0) {
							mvprintw(streamCount + 2, 0, " -> PID Report");
						}

						mvprintw(streamCount + 2, 37, "0x%04x (%4d) %7.2f %'17" PRIu64 " %12" PRIu64 "\n",
							i,
							i,
							ltntstools_pid_stats_pid_get_mbps(&di->stats, i),
							di->stats.pids[i].packetCount,
							di->stats.pids[i].ccErrors);
					}
				}
				streamCount++;

				if (di->notMultipleOfSevenError && (di->payloadType != PAYLOAD_A324_CTP) &&
					(di->payloadType != PAYLOAD_SMPTE2110_20_VIDEO) &&
					(di->payloadType != PAYLOAD_SMPTE2110_30_AUDIO) &&
					(di->payloadType != PAYLOAD_SMPTE2110_40_ANC)) {
					attron(COLOR_PAIR(4));
					mvprintw(streamCount + 2, 37, "Warning: %" PRIi64 " UDP packets that are less then 1316 bytes long", di->notMultipleOfSevenError);
					attroff(COLOR_PAIR(4));
					streamCount++;
				}
			}

			if (discovered_item_state_get(di, DI_STATE_SHOW_TR101290)) {
#if 0
        /* Priority 1 */
        E101290_P1_1__TS_SYNC_LOSS,
        E101290_P1_2__SYNC_BYTE_ERROR,
        E101290_P1_3__PAT_ERROR,
        E101290_P1_3a__PAT_ERROR_2,
        E101290_P1_4__CONTINUITY_COUNTER_ERROR,
        E101290_P1_5__PMT_ERROR,
        E101290_P1_5a__PMT_ERROR_2,
        E101290_P1_6__PID_ERROR,

        /* Priority 2 */
        E101290_P2_1__TRANSPORT_ERROR,
        E101290_P2_2__CRC_ERROR,
        E101290_P2_3__PCR_ERROR,
        E101290_P2_3a__PCR_REPETITION_ERROR,
        E101290_P2_4__PCR_ACCURACY_ERROR,
        E101290_P2_5__PTS_ERROR,
        E101290_P2_6__CAT_ERROR,

#endif
				if (di->payloadType == PAYLOAD_SMPTE2110_20_VIDEO) {
					streamCount++;
					mvprintw(streamCount + 2, 0, " -> TR101290 Status not available for SMPTE2110-20 Video streams");
					streamCount++;
				} else
				if (di->payloadType == PAYLOAD_SMPTE2110_30_AUDIO) {
					streamCount++;
					mvprintw(streamCount + 2, 0, " -> TR101290 Status not available for SMPTE2110-30 Audio streams");
					streamCount++;
				} else
				if (di->payloadType == PAYLOAD_SMPTE2110_40_ANC) {
					streamCount++;
					mvprintw(streamCount + 2, 0, " -> TR101290 Status not available for SMPTE2110-40 Ancillary Data streams");
					streamCount++;
				} else
				if (di->payloadType == PAYLOAD_A324_CTP) {
					streamCount++;
					mvprintw(streamCount + 2, 0, " -> TR101290 Status not available for A/324 Studio Transmitter Link CTP streams");
					streamCount++;
				} else
				if (di->payloadType == PAYLOAD_BYTE_STREAM) {
					streamCount++;
					mvprintw(streamCount + 2, 0, " -> TR101290 Status not available for unidentified byte streams");
					streamCount++;
				} else {
					streamCount++;
					mvprintw(streamCount + 2, 0, " -> TR101290 Status (NOT YET SUPPORTED)");
					streamCount++;
					int p1col = 10;

					/* Everything RED until further notice */
					//attron(COLOR_PAIR(3));
					mvprintw(streamCount + 2, p1col, "P1.1  BAD [TS SYNC  ]");
					//attroff(COLOR_PAIR(3));

					//attron(COLOR_PAIR(6));
					mvprintw(streamCount + 3, p1col, "P1.2  OK  [SYNC BYTE]");
					mvprintw(streamCount + 4, p1col, "P1.3  OK  [PAT      ]");
					mvprintw(streamCount + 5, p1col, "P1.3a OK  [PAT 2    ]");
					mvprintw(streamCount + 6, p1col, "P1.4  OK  [CC       ]");
					mvprintw(streamCount + 7, p1col, "P1.5  OK  [PMT      ]");
					mvprintw(streamCount + 8, p1col, "P1.5a OK  [PMT 2    ]");
					mvprintw(streamCount + 9, p1col, "P1.6  OK  [PID      ]");

					int p2col = 45;
					mvprintw(streamCount + 2, p2col, "P2.1  OK  [TRANSPORT     ]");
					mvprintw(streamCount + 3, p2col, "P2.2  OK  [CRC           ]");
					mvprintw(streamCount + 4, p2col, "P2.3  OK  [PCR           ]");
					mvprintw(streamCount + 5, p2col, "P2.3a OK  [PCR REPETITION]");
					mvprintw(streamCount + 6, p2col, "P2.4  OK  [PCR ACCURACY  ]");
					mvprintw(streamCount + 7, p2col, "P2.5  OK  [PTS           ]");
					//attroff(COLOR_PAIR(6));

					attron(COLOR_PAIR(3));
					mvprintw(streamCount + 8, p2col, "P2.6  BAD [CAT           ]");
					attroff(COLOR_PAIR(3));

					streamCount += 8;
				}
			}

			if (discovered_item_state_get(di, DI_STATE_SHOW_IAT_HISTOGRAM)) {
				streamCount++;
				mvprintw(streamCount + 2, 0, " -> ");

				char *s;
				ltn_histogram_interval_print_buf(&s, di->packetIntervals, 0);
				if (s) {
					char *buf = s;

					char *p = strtok(buf, "\n");
					while (p) {
						mvprintw(streamCount + 2, 4, "%s", p);
						p = strtok(NULL, "\n");
						if (p) {
							streamCount++;
						}
					}
					free(s);
					streamCount++;
				}

			}
			if (discovered_item_state_get(di, DI_STATE_SHOW_PROCESSES)) {
				streamCount++;
				mvprintw(streamCount + 2, 0, " -> Socket / Process Report");

				static time_t lastReport;

				if (lastReport + 2 < now) {
					lastReport = now;

					if (items) {
						ltntstools_proc_net_udp_item_free(ctx->procNetUDPContext, items);
						items = NULL;
					}
					ltntstools_proc_net_udp_item_query(ctx->procNetUDPContext, &items, &itemCount);
				}

				if (itemCount) {
					mvprintw(streamCount + 2, 55, "PID           COMMAND        DROPS");
					streamCount++;
				} else {
					mvprintw(streamCount + 2, 55, "PID           COMMAND        DROPS   (discovery mode)");
					streamCount++;
				}

				if (items && itemCount) {
					for (int i = 0; i < itemCount; i++) {
						struct ltntstools_proc_net_udp_item_s *e = &items[i];

						// TODO: String compare is slow. Convert to uint32_t for a fast match.
						if (((e->local_addr.sin_addr.s_addr == INADDR_ANY) && (e->local_addr.sin_port == di->dstport)) ||
							(strcmp(e->locaddr, di->dstaddr) == 0))
						{
							if (e->drops)
								attron(COLOR_PAIR(4));

							mvprintw(streamCount + 2, 50, "%8" PRIu64 "  %16s    %9" PRIu64,
								e->pidList[0].pid,
								e->pidList[0].comm,
								e->drops);

							if (e->drops)
								attroff(COLOR_PAIR(4));
							streamCount++;
						}
					}
					
					//ltntstools_proc_net_udp_item_dprintf(ctx->procNetUDPContext, 0, items, itemCount);
				}
			}

			if (discovered_item_state_get(di, DI_STATE_SHOW_STREAMMODEL)) {
				streamCount++;
				if (di->payloadType == PAYLOAD_SMPTE2110_20_VIDEO) {
					mvprintw(streamCount + 2, 0, " -> Service Information Report not available for SMPTE2110-20 Video streams");
					streamCount++;
				} else
				if (di->payloadType == PAYLOAD_SMPTE2110_30_AUDIO) {
					mvprintw(streamCount + 2, 0, " -> Service Information Report not available for SMPTE2110-30 Audio streams");
					streamCount++;
				} else
				if (di->payloadType == PAYLOAD_SMPTE2110_40_ANC) {
					mvprintw(streamCount + 2, 0, " -> Service Information Report not available for SMPTE2110-40 Ancillary Data streams");
					streamCount++;
				} else
				if (di->payloadType == PAYLOAD_A324_CTP) {
					mvprintw(streamCount + 2, 0, " -> Service Information Report not available for A/324 Studio Transmitter Link CTP streams");
					streamCount++;
				} else
				if (di->payloadType == PAYLOAD_BYTE_STREAM) {
					mvprintw(streamCount + 2, 0, " -> Service Information Report not available for unidentified byte streams");
					streamCount++;
				} else {
					mvprintw(streamCount + 2, 0, " -> Service Information Report");
				}

				struct ltntstools_pat_s *m = NULL;
				if (ltntstools_streammodel_query_model(di->streamModel, &m) == 0) {

					int mpts = ltntstools_streammodel_is_model_mpts(di->streamModel, m);

					mvprintw(streamCount + 2, 31, "%s", mpts ? "MPTS" : "SPTS");

					streamCount++;
					mvprintw(streamCount + 2, 4, "programs: %d  pat-tsid: 0x%04x  version: %d  CNI: %d",
						m->program_count,
						m->transport_stream_id,
						m->version_number,
						m->current_next_indicator);

					streamCount++;
					mvprintw(streamCount + 2, 4, "prog#  PMT_PID  PCR_PID  Streams  ES_PID  TYPE  Description");

					for (int p = 0; p < m->program_count; p++) {

						int has_scte35 = ltntstools_descriptor_list_contains_scte35_cue_registration(&m->programs[p].pmt.descr_list);

						streamCount++;
						if (m->programs[p].program_number == 0) {
							mvprintw(streamCount + 2, 1, "   %5d        -        -        -       -     -  Network Information Table",
								m->programs[p].program_number);
						} else {
							mvprintw(streamCount + 2, 1, "   %5d   0x%04x   0x%04x      %3d",
								m->programs[p].program_number,
								m->programs[p].program_map_PID,
								m->programs[p].pmt.PCR_PID,
								m->programs[p].pmt.stream_count);
						}
						for (int s = 0; s < m->programs[p].pmt.stream_count; s++) {
							if (s > 0)
								streamCount++;
							const char *d = ltntstools_GetESPayloadTypeDescription(m->programs[p].pmt.streams[s].stream_type);
							mvprintw(streamCount + 2, 38, "0x%04x  0x%02x  %.*s%s",
								m->programs[p].pmt.streams[s].elementary_PID,
								m->programs[p].pmt.streams[s].stream_type,
								52,
								d,
								strlen(d) >= 52 ? "..." : "");
						}

						if (m->programs[p].pmt.stream_count > 0) {
							streamCount++;
							mvprintw(streamCount + 2, 52, "SCTE35 Registration: %s", has_scte35 ? "Yes" : "No");
						}

						unsigned int major, minor, patch;
						int ret = ltntstools_descriptor_list_contains_ltn_encoder_sw_version(&m->programs[p].pmt.descr_list,
							&major, &minor, &patch);
						if (ret == 1) {
							di->isLTNEncoder = 1;

							streamCount++;
							mvprintw(streamCount + 2, 52, "LTN Encoder S/W: %d.%d.%d / Latency: ",
								major, minor, patch);

							int64_t ms = ltntstools_probe_ltnencoder_get_total_latency(di->LTNLatencyProbe);
							if (ms >= 0) {
								mvprintw(streamCount + 2, 86, "%" PRIi64 "ms", ms);
							} else {
								mvprintw(streamCount + 2, 86, "n/a");
							}
						}
						

					}

					ltntstools_pat_free(m);
					streamCount++;
				}
			}

			streamCount++;
		}
		pthread_mutex_unlock(&ctx->lock);

		if (ctx->showUIOptions) {
			streamCount++;
			mvprintw(streamCount + 2, 0, "@) Record Mode: %s",
				ctx->recordWithSegments ? "Segments" : "Single File");

			streamCount++;
			mvprintw(streamCount + 2, 0, "$) Record Format: %s",
				ctx->recordAsTS ? "MPEG-TS" : "PCAP");

			streamCount++;
			mvprintw(streamCount + 2, 0, "f) Freeze UI display (analysis continues)");
			streamCount++;
			mvprintw(streamCount + 2, 0, "h) Toggle help menu");
			streamCount++;
			mvprintw(streamCount + 2, 0, "D) Deselect the current stream");
			streamCount++;
			mvprintw(streamCount + 2, 0, "F) Forward stream to a new multicast endpoint");
			streamCount++;
			mvprintw(streamCount + 2, 0, "S) Select all streams for a batch operation");
			streamCount++;
			mvprintw(streamCount + 2, 0, "H) Hide the selected stream (analysis continues)");
			mvprintw(streamCount + 2, 0, "U) Unhide all hidden streams");
			mvprintw(streamCount + 2 - 7, 53, "I) Toggle stream IAT histogram report");
			mvprintw(streamCount + 2 - 6, 53, "M) Toggle stream PSIP model report");
			mvprintw(streamCount + 2 - 5, 53, "P) Toggle stream PID traffic report");
			mvprintw(streamCount + 2 - 4, 53, "r) Reset stats counters and begin new measurement period");
			mvprintw(streamCount + 2 - 3, 53, "R) Start/Stop stream recording");
			mvprintw(streamCount + 2 - 2, 53, "s) Toggle process/socket report");
			mvprintw(streamCount + 2 - 1, 53, "T) Start/Stop TR101290 analysis (NOT YET SUPPORTED)");
			streamCount++;
			mvprintw(streamCount + 2, 0, "cursor keys) Select and navigate the cursor");

			streamCount++;
		}

		attron(COLOR_PAIR(2));
		ctx->trailerRow = streamCount + 3;
		if (ctx->showForwardOptions) {
			mvprintw(ctx->trailerRow, 12, "-- 7) 227.1.240.7:4001 8) 227.1.240.8:4001 9) 227.1.240.9:4001");
		}
		mvprintw(ctx->trailerRow, 0, "q)uit h)elp");
		attroff(COLOR_PAIR(2));


		char tail_a[160], tail_b[160], tail_c[160];
		attron(COLOR_PAIR(1));

		char s[64];
		sprintf(s, "%s", ctime(&now));
		s[ strlen(s) - 1 ] = 0;
		memset(tail_b, '-', sizeof(tail_b));
		if (totalStreams == 1) {
			sprintf(tail_a, "%s                           %7.02f / %d stream", s, totalMbps, totalStreams);
		} else {
			sprintf(tail_a, "%s                           %7.02f / %d streams", s, totalMbps, totalStreams);
		}
		sprintf(tail_c, "Since: %s", ctime(&ctx->lastResetTime));
		blen = 112 - (strlen(tail_a) + strlen(tail_c));
		memset(tail_b, 0x20, sizeof(tail_b));
		tail_b[blen] = 0;

		mvprintw(ctx->trailerRow + 1, 0, "%s%s%s", tail_a, tail_b, tail_c);

		attroff(COLOR_PAIR(1));

		/* -- */
		refresh();
		pthread_mutex_unlock(&ctx->ui_threadLock);

		usleep(200 * 1000);
	}

	if (items) {
		ltntstools_proc_net_udp_item_free(ctx->procNetUDPContext, items);
		items = NULL;
	}

	ctx->ui_threadTerminated = 1;

	pthread_exit(NULL);
	return 0;
}

#if PROBE_REPORTER
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

	int workdone = 0;
	while (!ctx->json_threadTerminate) {

		workdone = 0;

		time(&now);
		if (json_next_post_time <= now) {
			json_next_post_time = now + json_post_interval;

			/* Look at the queue, take everything off it, issue http post reqs. */
			int failed = 0;
			struct json_item_s *item = json_queue_peek(ctx);
			while (item) {
#if 1
				if (json_item_post_http(ctx, item) == 0) {
#else
				if (json_item_post_socket(ctx, item) == 0) {
#endif
					/* Success, remove the item from the list */
					item = json_queue_pop(ctx);
					json_item_free(ctx, item);
					item = NULL;

					failed = 0;
				} else {
					usleep(250 * 1000); /* Natural rate limit if the post fails */
					failed += 250;
				}
				workdone++;

				if (failed >= 2000) {
					/* Back off for 30 seconds before we try again. */
					json_next_post_time = now + 30;
					break;
				}

				/* Success, take this of the queue and destroy it */
				item = json_queue_peek(ctx);
			}
		}

		/* We don't want the thread thrashing when we have nothing to process. */
		if (!workdone)
			usleep(50 * 1000);
	}
	ctx->json_threadTerminated = 1;

	pthread_exit(NULL);
	return 0;
}
#endif

static void *stats_thread_func(void *p)
{
	struct tool_context_s *ctx = p;
	ctx->stats_threadRunning = 1;
	ctx->stats_threadTerminate = 0;
	ctx->stats_threadTerminated = 0;

	ltnpthread_setname_np(ctx->stats_threadId, "tstools-stats");
	pthread_detach(pthread_self());

	time_t now;
	time(&now);
	if (ctx->file_next_write_time == 0) {
		ctx->file_next_write_time = now + ctx->file_write_interval;
	}

	int workdone = 0;
	while (!ctx->stats_threadTerminate) {

		workdone = 0;
		int count = pcap_queue_service(ctx);
		if (count)
			workdone++;

		time(&now);
		if ((ctx->file_prefix || ctx->detailed_file_prefix) && ctx->file_next_write_time <= now) {
			ctx->file_next_write_time = now + ctx->file_write_interval;
			discovered_items_file_summary(ctx);
			workdone++;
		}

#if PROBE_REPORTER
		if (ctx->json_next_write_time <= now) {
			ctx->json_next_write_time = now + ctx->json_write_interval;
			discovered_items_json_summary(ctx);
			workdone++;
		}
#endif

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

static void *pcap_thread_func(void *p)
{
	struct tool_context_s *ctx = p;
	ctx->pcap_threadRunning = 1;
	ctx->pcap_threadTerminate = 0;
	ctx->pcap_threadTerminated = 0;

	int processed;

	ltnpthread_setname_np(ctx->pcap_threadId, "tstools-pcap");
	pthread_detach(pthread_self());

	time_t lastStatsCheck = 0;

	ctx->descr = pcap_create(ctx->ifname, ctx->errbuf);
	if (ctx->descr == NULL) {
		fprintf(stderr, "Error, %s\n", ctx->errbuf);
		exit(1);
	}

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

	while (!ctx->pcap_threadTerminate) {

		processed = pcap_dispatch(ctx->descr, -1, pcap_callback, NULL);
		if (processed == 0) {
			ctx->pcap_dispatch_miss++;
			usleep(1 * 1000);
		}

		time_t now;
		time(&now);

		/* Querying stats repeatidly is cpu expensive, we only need it 1sec intervals. */
		if (lastStatsCheck == 0) {
			/* Collect pcap packet loss stats */
			if (pcap_stats(ctx->descr, &ctx->pcap_stats_startup) != 0) {
				/* Error */
			}
		}

		if (now != lastStatsCheck) {
			lastStatsCheck = now;
			/* Collect pcap packet loss stats */
			struct pcap_stat tmp;
			if (pcap_stats(ctx->descr, &tmp) != 0) {
				/* Error */
			}

			ctx->pcap_stats.ps_recv = tmp.ps_recv - ctx->pcap_stats_startup.ps_recv;
			ctx->pcap_stats.ps_drop = tmp.ps_drop - ctx->pcap_stats_startup.ps_drop;
			ctx->pcap_stats.ps_ifdrop = tmp.ps_ifdrop - ctx->pcap_stats_startup.ps_ifdrop;
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

	pthread_exit(NULL);
	return 0;
}

static void signal_handler(int signum)
{
	if (!ctx->monitor && signum == SIGINT)
		printf("\nUser requested terminate.\n");

	gRunning = 0;
}

static void usage(const char *progname)
{
	printf("A tool to monitor PCAP multicast ISO13818 traffic.\n");
	printf("Usage:\n");
	printf("  -i <iface>\n");
	printf("  -v Increase level of verbosity.\n");
	printf("  -h Display command line help.\n");
	printf("  -t <#seconds>. Stop after N seconds [def: 0 - unlimited]\n");
	printf("  -M Display an interactive console with stats.\n");
	printf("  -D <dir> Write any PCAP recordings in this target directory prefix. [def: /tmp]\n");
	printf("  -d <dir> Write detailed pid stats per stream in this target directory prefix, every -n seconds.\n");
	printf("  -w <dir> Write summary stats per stream in this target directory prefix, every -n seconds.\n");
	printf("  -n <seconds> Interval to update -d file based stats [def: %d]\n", FILE_WRITE_INTERVAL);
	printf("  -F '<string>' Use a custom pcap filter. [def: '%s']\n", DEFAULT_PCAP_FILTER);
#if PROBE_REPORTER
	printf("  -J Automatically send JSON reports for all discovered streams [def: disabled]\n");
#endif
#if 0
	printf("  -o <output filename> (optional)\n");
#endif
	printf("  -S <number> Packet buffer size [def: %d] (min: 2048)\n", g_snaplen_default);
	printf("  -B <number> Buffer size [def: %d]\n", g_buffer_size_default);
	printf("  -R Automatically record all discovered streams\n");
	printf("  -E Record in a single file, don't segment into 60sec files\n");
	printf("  -T Record int a TS format where possible [default is PCAP]\n");
	printf("  -1 Test the scheduling quanta for 1ms sleeps\n");
}

int nic_monitor(int argc, char *argv[])
{
	int ch;

	pthread_mutex_init(&ctx->lock, NULL);
	xorg_list_init(&ctx->list);

	pthread_mutex_init(&ctx->ui_threadLock, NULL);
	pthread_mutex_init(&ctx->lockpcap, NULL);
	xorg_list_init(&ctx->listpcapFree);
	xorg_list_init(&ctx->listpcapUsed);

#if PROBE_REPORTER
	pthread_mutex_init(&ctx->lockJSONPost, NULL);
	xorg_list_init(&ctx->listJSONPost);
	ctx->jsonSocket = -1;
#endif

	pcap_queue_initialize(ctx);
#if PROBE_REPORTER
	ctx->file_write_interval = FILE_WRITE_INTERVAL;
	ctx->json_write_interval = JSON_WRITE_INTERVAL;
#endif
	ctx->pcap_filter = DEFAULT_PCAP_FILTER;
	ctx->snaplen = g_snaplen_default;
	ctx->bufferSize = g_buffer_size_default;
	ctx->recordWithSegments = 1;

#if PROBE_REPORTER
	while ((ch = getopt(argc, argv, "?hd:B:D:EF:i:Jt:vMn:w:RS:T")) != -1) {
#else
	while ((ch = getopt(argc, argv, "?hd:B:D:EF:i:t:vMn:w:RS:T")) != -1) {
#endif
		switch (ch) {
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
			if (networkInterfaceExists(ctx->ifname) == 0) {
				fprintf(stderr, "\nNo such network interface '%s', available interfaces:\n", ctx->ifname);
				networkInterfaceList();
				printf("\n");
				exit(1);
			}
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
			ctx->monitor = 1;
			break;
		case 'D':
			ctx->recordingDir = optarg;
			break;
		case 'E':
			ctx->recordWithSegments = 0;
			break;
#if PROBE_REPORTER
		case 'J':
			ctx->automaticallyJSONProbeStreams = 1;
			break;
#endif
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
			usage(argv[0]);
			exit(1);
		}
	}

	if (ctx->ifname == NULL) {
		usage(argv[0]);
		fprintf(stderr, "\nError, -i is mandatory.\n\n");
		exit(1);
	}

	printf("  iface: %s\n", ctx->ifname);

	/* Configure automatic core-dumps */
	struct rlimit core_limit;
	core_limit.rlim_cur = RLIM_INFINITY;
	core_limit.rlim_max = RLIM_INFINITY;
	if (setrlimit(RLIMIT_CORE, &core_limit) < 0) {
		fprintf(stderr, "setrlimit: unable to enable automatic core dumps, ignoring.\n");
	} else {
		printf("automatic core dumps enabled.\n");
	}

	pcap_lookupnet(ctx->ifname, &ctx->netp, &ctx->maskp, ctx->errbuf);

	struct in_addr ip_net, ip_mask;
	ip_net.s_addr = ctx->netp;
	ip_mask.s_addr = ctx->maskp;
	printf("network: %s\n", inet_ntoa(ip_net));
	printf("   mask: %s\n", inet_ntoa(ip_mask));
	printf(" filter: %s\n", ctx->pcap_filter);
	printf("snaplen: %d\n", ctx->snaplen);
	printf("buffSiz: %d\n", ctx->bufferSize);

	gRunning = 1;
	pthread_create(&ctx->stats_threadId, 0, stats_thread_func, ctx);
	pthread_create(&ctx->pcap_threadId, 0, pcap_thread_func, ctx);
#if PROBE_REPORTER
	pthread_create(&ctx->json_threadId, 0, json_thread_func, ctx);
#endif

	/* Framework to track the /proc/net/udp socket buffers stats - primarily for loss */
	ltntstools_proc_net_udp_alloc(&ctx->procNetUDPContext);

	if (ctx->monitor) {
		initscr();
		pthread_create(&ctx->ui_threadId, 0, ui_thread_func, ctx);
	}

	/* Start any threads, main loop processes keybaord. */
	signal(SIGINT, signal_handler);
	timeout(300);

	time(&ctx->lastResetTime);
	while (gRunning) {
		char c = ui_syncronized_getch(ctx);
		if (c == 'F') {
			ctx->showForwardOptions = 1;
			while (gRunning) {
				char c = ui_syncronized_getch(ctx);
				if (c == '7') {
					/* Forward to location slot 7 */
					discovered_items_select_forward_toggle(ctx, 7);
					break;
				} else
				if (c == '8') {
					discovered_items_select_forward_toggle(ctx, 8);
					break;
				} else
				if (c == '9') {
					discovered_items_select_forward_toggle(ctx, 9);
					break;
				} else
				if (c == 'q') {
					break;
				} else {
					usleep(50 * 1000);
					continue;
				}
			}
			ctx->showForwardOptions = 0;
		}

		if (c == 'q')
			break;
		if (c == 'f') {
			ctx->freezeDisplay++;
		}
		if (c == 'r') {
			time(&ctx->lastResetTime);
			discovered_items_stats_reset(ctx);
		}
		if (c == 'D') {
			discovered_items_select_none(ctx);
		}
		if (c == 'S') {
			discovered_items_select_all(ctx);
		}
		if (c == 'T') {
			discovered_items_select_show_tr101290_toggle(ctx);
		}
		if (c == 'R') {
			discovered_items_select_record_toggle(ctx);
		}
		if (c == 's') {
			discovered_items_select_show_processes_toggle(ctx);
		}
		if (c == 'P') {
			discovered_items_select_show_pids_toggle(ctx);
		}
		if (c == 'I') {
			discovered_items_select_show_iats_toggle(ctx);
		}
#if PROBE_REPORTER
		if (c == 'J') {
			discovered_items_select_json_probe_toggle(ctx);
		}
#endif
		if (c == 'H') {
			discovered_items_select_hide(ctx);
		}
		if (c == 'U') {
			discovered_items_unhide_all(ctx);
		}
		if (c == 'M') {
			discovered_items_select_show_streammodel_toggle(ctx);
		}
		if (c == '$') {
			ctx->recordAsTS = (ctx->recordAsTS + 1) & 0x1;
		}
		if (c == '@') {
			ctx->recordWithSegments = (ctx->recordWithSegments + 1) & 0x1;
		}
		if (c == 'h') {
			ctx->showUIOptions = ~ctx->showUIOptions;
		}

		/* Cursor key support */
		if (c == 0x1b) {
			c = ui_syncronized_getch(ctx);
			if (c == 0x5b) {
				c = ui_syncronized_getch(ctx);
				if (c == 0x41) { /* Up */
					discovered_items_select_prev(ctx);
				} else
				if (c == 0x42) { /* Down */
					discovered_items_select_next(ctx);
				} else
				if (c == 0x43) { /* Right */
					discovered_items_select_first(ctx);
				} else
				if (c == 0x44) { /* Left */
					discovered_items_select_none(ctx);
				}
			}
		}

		usleep(50 * 1000);
	}

	discovered_items_abort(ctx);

	/* Shutdown stats collection */
	ctx->ui_threadTerminate = 1;
	ctx->pcap_threadTerminate = 1;
	ctx->stats_threadTerminate = 1;
#if PROBE_REPORTER
	ctx->json_threadTerminate = 1;
#endif
	while (!ctx->pcap_threadTerminated)
		usleep(50 * 1000);
	while (!ctx->stats_threadTerminated)
		usleep(50 * 1000);
#if PROBE_REPORTER
	while (!ctx->json_threadTerminated)
		usleep(50 * 1000);
#endif

	/* Shutdown ui */
	if (ctx->monitor) {
		while (!ctx->ui_threadTerminated) {
			usleep(50 * 1000);
			printf("Blocked on ui\n");
		}
		endwin();
	}

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

printf("pcap_free_miss %" PRIi64 "\n", ctx->pcap_free_miss);
printf("pcap_dispatch_miss %" PRIi64 "\n", ctx->pcap_dispatch_miss);
printf("ctx->listpcapFreeDepth %d\n", ctx->listpcapFreeDepth);
printf("ctx->listpcapUsedDepth %d\n", ctx->listpcapUsedDepth);
printf("ctx->rebalance_last_buffers_used %d\n", ctx->rebalance_last_buffers_used);
printf("ctx->cacheHitRatio %.02f%% (%" PRIu64 ", %" PRIu64 ")\n", ctx->cacheHitRatio, ctx->cacheHit, ctx->cacheMiss);

	printf("pcap nic '%s' stats: dropped: %d/%d\n",
		ctx->ifname, ctx->pcap_stats.ps_drop, ctx->pcap_stats.ps_ifdrop);

	pcap_queue_free(ctx);

	printf("Flushing the streams and recorders...\n");
	discovered_items_free(ctx);

	free(ctx->file_prefix);
	free(ctx->detailed_file_prefix);
	return 0;
}
