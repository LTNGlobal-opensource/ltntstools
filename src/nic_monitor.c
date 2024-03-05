
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
static int g_max_iat_ms = 45;

#if defined(__linux__)
extern int pthread_setname_np(pthread_t thread, const char *name);
#endif

extern int ltnpthread_setname_np(pthread_t thread, const char *name);

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
	double totalMbps = 0, totalRxMbps = 0, totalTxMbps = 0;
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
		totalRxMbps = 0;
		totalTxMbps = 0;
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
		if (ctx->iftype == IF_TYPE_PCAP) {
			sprintf(title_c, "NIC: %s (%s/%s) Dropped: %d/%d", ctx->ifname, inet_ntoa(ip_net), mask,
				ctx->pcap_stats.ps_drop,
				ctx->pcap_stats.ps_ifdrop);
		} else
		if (ctx->iftype == IF_TYPE_MPEGTS_FILE) {
			if (ctx->fileLoops) {
				sprintf(title_c, "LOOP: %s @ %6.2f%%", ctx->ifname, ctx->fileLoopPct);
			} else {
				sprintf(title_c, "FILE: %s @ %6.2f%%", ctx->ifname, ctx->fileLoopPct);
			}
		} else
		if (ctx->iftype == IF_TYPE_MPEGTS_AVDEVICE) {
			sprintf(title_a, "NIC Monitor");
			sprintf(title_c, "URL: %s", ctx->ifname);
		}

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
		mvprintw( 1, 0, "<--------------------------------------------------- M/BIT <---------PACKETS <------CCErr <--IAT--Flags--------");
		attroff(COLOR_PAIR(1));

		int streamCount = 1;
		struct discovered_item_s *di = NULL;
		pthread_mutex_lock(&ctx->lock);
		xorg_list_for_each_entry(di, &ctx->list, list) {

			if (discovered_item_state_get(di, DI_STATE_HIDDEN))
				continue;

			time_t now;
			time(&now);

			/* Deal with cases were output bitrate on a udp stream is low low, that we're unable to
			 * detect its stream type.
			 */
			if (di->firstSeen + 2 <= now && di->payloadType == PAYLOAD_UNDEFINED) {
				di->payloadType = PAYLOAD_BYTE_STREAM;
			}

			if (di->stats->ccErrors)
				discovered_item_state_set(di, DI_STATE_CC_ERROR);
			else
				discovered_item_state_clr(di, DI_STATE_CC_ERROR);

			if (discovered_item_state_get(di, DI_STATE_CC_ERROR) || di->iat_hwm_us / 1000 > ctx->iatMax)			
				attron(COLOR_PAIR(3));

			if (discovered_item_state_get(di, DI_STATE_DST_DUPLICATE))
				attron(COLOR_PAIR(4));

			if (discovered_item_state_get(di, DI_STATE_SELECTED))
				attron(COLOR_PAIR(5));

			if (di->srcOriginRemoteHost) {
				totalRxMbps += ltntstools_pid_stats_stream_get_mbps(di->stats);
			} else {
				totalTxMbps += ltntstools_pid_stats_stream_get_mbps(di->stats);
			}
			totalMbps = totalRxMbps + totalTxMbps;

			totalStreams++;
			if ((di->payloadType == PAYLOAD_RTP_TS) || (di->payloadType == PAYLOAD_UDP_TS)) {
				mvprintw(streamCount + 2, 0, "%s %21s -> %21s %7.2f  %'16" PRIu64 " %12" PRIu64 "   %4d  %s",
					payloadTypeDesc(di->payloadType),
					di->srcaddr,
					di->dstaddr,
					ltntstools_pid_stats_stream_get_mbps(di->stats),
					di->stats->packetCount,
					di->stats->ccErrors,
					di->iat_hwm_us / 1000,
					di->warningIndicatorLabel);
			} else
			if (di->payloadType == PAYLOAD_A324_CTP) {
				mvprintw(streamCount + 2, 0, "%s %21s -> %21s %7.2f  %'16" PRIu64 " %12" PRIu64 "   %4d  %s",
					payloadTypeDesc(di->payloadType),
					di->srcaddr,
					di->dstaddr,
					ltntstools_ctp_stats_stream_get_mbps(di->stats),
					di->stats->packetCount,
					di->stats->ccErrors,
					di->iat_hwm_us / 1000,
					di->warningIndicatorLabel);
				totalMbps += ltntstools_ctp_stats_stream_get_mbps(di->stats);
			} else
			if ((di->payloadType == PAYLOAD_SMPTE2110_20_VIDEO) ||
				(di->payloadType == PAYLOAD_SMPTE2110_30_AUDIO) ||
				(di->payloadType == PAYLOAD_SMPTE2110_40_ANC)) {
				mvprintw(streamCount + 2, 0, "%s %21s -> %21s %7.2f  %'16" PRIu64 " %12" PRIu64 "   %4d  %s",
					payloadTypeDesc(di->payloadType),
					di->srcaddr,
					di->dstaddr,
					ltntstools_ctp_stats_stream_get_mbps(di->stats),
					di->stats->packetCount,
					di->stats->ccErrors,
					di->iat_hwm_us / 1000,
					di->warningIndicatorLabel);
				totalMbps += ltntstools_ctp_stats_stream_get_mbps(di->stats);
			} else
			if (di->payloadType == PAYLOAD_BYTE_STREAM) {
				mvprintw(streamCount + 2, 0, "%s %21s -> %21s %7.2f  %'16" PRIu64 " %12s   %4d  %s",
					payloadTypeDesc(di->payloadType),
					di->srcaddr,
					di->dstaddr,
					ltntstools_bytestream_stats_stream_get_mbps(di->stats),
					di->stats->packetCount,
					"-",
					di->iat_hwm_us / 1000,
					di->warningIndicatorLabel);
				totalMbps += ltntstools_bytestream_stats_stream_get_mbps(di->stats);
			}

			if (discovered_item_state_get(di, DI_STATE_SELECTED))
				attroff(COLOR_PAIR(5));

			if (discovered_item_state_get(di, DI_STATE_DST_DUPLICATE))
				attroff(COLOR_PAIR(4));

			if (discovered_item_state_get(di, DI_STATE_CC_ERROR) || di->iat_hwm_us / 1000 > ctx->iatMax)
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
			if (discovered_item_state_get(di, DI_STATE_JSON_PROBE_ACTIVE)) {
				streamCount++;
				mvprintw(streamCount + 2, 0, " -> JSON Probe Active");
			}

			if (discovered_item_state_get(di, DI_STATE_SHOW_CLOCKS)) {
				if (di->payloadType == PAYLOAD_SMPTE2110_20_VIDEO) {
					streamCount++;
					mvprintw(streamCount + 2, 0, " -> Clock Report not available for SMPTE2110-20 Video streams");
				}
				if (di->payloadType == PAYLOAD_SMPTE2110_30_AUDIO) {
					streamCount++;
					mvprintw(streamCount + 2, 0, " -> Clock Report not available for SMPTE2110-30 Audio streams");
				}
				if (di->payloadType == PAYLOAD_SMPTE2110_40_ANC) {
					streamCount++;
					mvprintw(streamCount + 2, 0, " -> Clock Report not available for SMPTE2110-40 Ancillary Data streams");
				}
				if (di->payloadType == PAYLOAD_A324_CTP) {
					streamCount++;
					mvprintw(streamCount + 2, 0, " -> Clock Report not available for A/324 Studio Transmitter Link CTP streams");
				}
				if (di->payloadType == PAYLOAD_BYTE_STREAM) {
					streamCount++;
					mvprintw(streamCount + 2, 0, " -> Clock Report not available for unidentified byte streams");
				}
				streamCount++;
				mvprintw(streamCount + 2, 0, " -> Clock Report (working)");
				int j = 0;
				for (int i = 0; i < MAX_PID; i++) {
					if (!di->stats->pids[i].enabled)
						continue;
					if (!di->stats->pids[i].hasPCR)
						continue;
					if (!di->stats->pids[i].pcrTickIntervals)
						continue;

					if (j++ == 0) {
						/* Replace the provisional '(working)' line above... */
						mvprintw(streamCount + 2, 0, " -> Clock Report for PID %04x", i);
						streamCount++;
					}
					

					/* The Model report starts the stream model analyzer, where the PCR pids are discovered.
					 * This only works if the stream model view is also enabled, else no PCR pids are found.
					 */

					char *s;
					ltn_histogram_interval_print_buf(&s, di->stats->pids[i].pcrTickIntervals, 0);
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
						s = NULL;
						streamCount++;
					}
					streamCount++;

					ltn_histogram_interval_print_buf(&s, di->stats->pids[i].pcrWallDrift, 0);
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
			} /* Show clocks */

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
					if (di->stats->pids[i].enabled) {
						streamCount++;
						if (i == 0) {
							mvprintw(streamCount + 2, 0, " -> PID Report");
						}

						mvprintw(streamCount + 2, 37, "0x%04x (%4d) %7.2f %'17" PRIu64 " %12" PRIu64 "\n",
							i,
							i,
							ltntstools_pid_stats_pid_get_mbps(di->stats, i),
							di->stats->pids[i].packetCount,
							di->stats->pids[i].ccErrors);
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
					mvprintw(streamCount + 2, 0, " -> TR101290 Status (Coming Soon.... Drum roll or sad trombone?)");
					streamCount++;
					int p1col = 10;
					int p2col = 45;
					//int p3col = 75;

					nic_monitor_tr101290_draw_ui(di, &streamCount, p1col, p2col);

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
					s = NULL;
					streamCount++;
				}
				double a = ((double)di->bitrate_hwm_us_10ms_last_nsecond * 100.0) / 1000000.0;
				double b = ((double)di->bitrate_hwm_us_100ms_last_nsecond * 10.0) / 1000000.0;
				mvprintw(streamCount + 2, 52, "%6.02f @ 10ms\n", a);
				streamCount++;
				mvprintw(streamCount + 2, 52, "%6.02f @ 100ms\n", b);
				streamCount++;

			}

			if (discovered_item_state_get(di, DI_STATE_SHOW_PROCESSES)) {
				streamCount++;
				mvprintw(streamCount + 2, 0, " -> Socket / Process Report");

				if (ctx->lastSocketReport + 2 < now) {
					ctx->lastSocketReport = now;

					if (items) {
						ltntstools_proc_net_udp_item_free(ctx->procNetUDPContext, items);
						items = NULL;
					}
					ltntstools_proc_net_udp_item_query(ctx->procNetUDPContext, &items, &itemCount);
				}

				if (itemCount) {
					mvprintw(streamCount + 2, 55, "PID           COMMAND        DROPS    TOTAL");
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
							if (e->drops_delta)
								attron(COLOR_PAIR(4));

							mvprintw(streamCount + 2, 50, "%8" PRIu64 "  %16s    %9" PRIu64 "%9" PRIu64,
								e->pidList[0].pid,
								e->pidList[0].comm,
								e->drops_delta,
								e->drops);

							if (e->drops_delta)
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

					/* Now that we have a working stream model, look PCR for each stream
					 * and establish a clock analyzer through the stats infrastructure.
					 * We'll do this during the program pid enumeration below.
					 */

					int mpts = ltntstools_streammodel_is_model_mpts(di->streamModel, m);

					mvprintw(streamCount + 2, 31, "%s", mpts ? "MPTS" : "SPTS");

					streamCount++;
					mvprintw(streamCount + 2, 4, "programs: %d  pat-tsid: 0x%04x  version: %d  CNI: %d",
						m->program_count,
						m->transport_stream_id,
						m->version_number,
						m->current_next_indicator);

					streamCount++;
					mvprintw(streamCount + 2, 4, "prog#  PMT_PID ----->  PCR_PID ----->  Streams  ES_PID ----->  TYPE  Description");

					for (int p = 0; p < m->program_count; p++) {

						int has_scte35 = ltntstools_descriptor_list_contains_scte35_cue_registration(&m->programs[p].pmt.descr_list);
						int has_smpte2038 = 0;

						streamCount++;
						if (m->programs[p].program_number == 0) {
							mvprintw(streamCount + 2, 1, "   %5d        -        -        -       -     -  Network Information Table",
								m->programs[p].program_number);
						} else {
							mvprintw(streamCount + 2, 1, "   %5d   0x%04x (%4d)   0x%04x (%4d)      %3d",
								m->programs[p].program_number,
								m->programs[p].program_map_PID,
								m->programs[p].program_map_PID,
								m->programs[p].pmt.PCR_PID,
								m->programs[p].pmt.PCR_PID,
								m->programs[p].pmt.stream_count);

							/* Poke the stats model and let it know we should be receiving PCRs on this pid. */
							ltntstools_pid_stats_pid_set_contains_pcr(di->stats, m->programs[p].pmt.PCR_PID);
						}
						for (int s = 0; s < m->programs[p].pmt.stream_count; s++) {
							if (s > 0)
								streamCount++;

							char iso639_lang[64] = { 0 };
							unsigned int audio_type = 0;
							unsigned char lbl[16] = { 0 };
							int x = ltntstools_descriptor_list_contains_iso639_audio_descriptor(&m->programs[p].pmt.streams[s].descr_list, &lbl[0], &audio_type);
							if (x) {
								sprintf(&iso639_lang[0], "'%s' Type: %s",
									lbl,
									audio_type == 0 ? "None" :
									audio_type == 1 ? "Clean effects" :
									audio_type == 2 ? "Hearing impaired" :
									audio_type == 3 ? "Visual impaired commentary" : "Reserved");
							}

							const char *d = ltntstools_GetESPayloadTypeDescription(m->programs[p].pmt.streams[s].stream_type);
							mvprintw(streamCount + 2, 52, "0x%04x (%4d)  0x%02x  %.*s%s",
								m->programs[p].pmt.streams[s].elementary_PID,
								m->programs[p].pmt.streams[s].elementary_PID,
								m->programs[p].pmt.streams[s].stream_type,
								52,
								d,
								strlen(d) >= 52 ? "..." : "");

							if (x) {
								streamCount++;
								mvprintw(streamCount + 2, 54, "lang: %s", iso639_lang);
							}

							if (m->programs[p].pmt.streams[s].stream_type  == 0x06 /* Private PES */) {
								has_smpte2038 = ltntstools_descriptor_list_contains_smpte2038_registration(&m->programs[p].pmt.streams[s].descr_list);
							}

							if (m->programs[p].pmt.streams[s].stream_type  == 0x1b /* H.264 */) {

								int slicesEnabled = 0;
								struct h264_slice_counter_results_s slices;

								pthread_mutex_lock(&di->h264_sliceLock);
								if (di->h264_slices) {
									if (h264_slice_counter_get_pid(di->h264_slices) == m->programs[p].pmt.streams[s].elementary_PID) {
										slicesEnabled = 1;
										h264_slice_counter_query(di->h264_slices, &slices);
									} else {
										/* Set the pid to match this stream and we'll catch the stats the next time around. */
										h264_slice_counter_reset_pid(di->h264_slices, m->programs[p].pmt.streams[s].elementary_PID);
									}
								}
								pthread_mutex_unlock(&di->h264_sliceLock);

								pthread_mutex_lock(&di->h264_metadataLock);
								if (di->h264_metadata_parser) {
									pthread_mutex_unlock(&di->h264_metadataLock);
									streamCount++;
									mvprintw(streamCount + 2, 54, "%s", di->h264_video_colorspace);
									streamCount++;
									mvprintw(streamCount + 2, 54, "%s", di->h264_video_format);
								} else {
									pthread_mutex_unlock(&di->h264_metadataLock);
								}

								if (slicesEnabled) {
									streamCount++;
									mvprintw(streamCount + 2, 54, "I: %'" PRIu64 " B: %'" PRIu64 " P: %'" PRIu64 " : %s...",
										slices.i, slices.b, slices.p,
										slices.sliceHistory);
								}

							} /* If H264 */

							if (m->programs[p].pmt.streams[s].stream_type  == 0x24 /* H.265 */) {

								pthread_mutex_lock(&di->h265_metadataLock);
								if (di->h265_metadata_parser) {
									pthread_mutex_unlock(&di->h265_metadataLock);
									streamCount++;
									mvprintw(streamCount + 2, 54, "%s", di->h265_video_colorspace);
									streamCount++;
									mvprintw(streamCount + 2, 54, "%s", di->h265_video_format);
								} else {
									pthread_mutex_unlock(&di->h265_metadataLock);
								}

							} /* If H.265 / HEVC */

						}

						if (m->programs[p].pmt.stream_count > 0) {
							streamCount++;
							mvprintw(streamCount + 2, 54, "SCTE35 Registration: %s", has_scte35 ? "Yes" : "No");
							streamCount++;
							mvprintw(streamCount + 2, 54, "SMPTE2038 Registration: %s", has_smpte2038 ? "Yes" : "No");
						}

						unsigned int major, minor, patch;
						int ret = ltntstools_descriptor_list_contains_ltn_encoder_sw_version(&m->programs[p].pmt.descr_list,
							&major, &minor, &patch);
						if (ret == 1) {
							di->isLTNEncoder = 1;

							streamCount++;
							mvprintw(streamCount + 2, 54, "LTN Encoder S/W: %d.%d.%d / Latency: ",
								major, minor, patch);

							int64_t ms = ltntstools_probe_ltnencoder_get_total_latency(di->LTNLatencyProbe);
							if (ms >= 0) {
								mvprintw(streamCount + 2, 89, "%" PRIi64 "ms", ms);
							} else {
								mvprintw(streamCount + 2, 89, "n/a");
							}
						} else {
							if (ctx->measureSEILatencyAlways) {
								/* Measure latency thorugh video transformers that strip the PMT ES encoder descriptor. */
								streamCount++;

								int64_t ms = ltntstools_probe_ltnencoder_get_total_latency(di->LTNLatencyProbe);
								if (ms >= 0) {
									mvprintw(streamCount + 2, 54, "Latency: %" PRIi64 "ms", ms);
								} else {
									mvprintw(streamCount + 2, 54, "Latency n/a");
								}
							}
						}

						if (m->programs[p].program_number > 0 && m->programs[p].pmt.PCR_PID) {
							int64_t pcr = ltntstools_pid_stats_pid_get_pcr(di->stats, m->programs[p].pmt.PCR_PID);
							char *ts = NULL;
							ltntstools_pcr_to_ascii(&ts, pcr);
							mvprintw(streamCount + 1, 82, "PCR: %s", ts);
							free(ts);
						}

						if (0) {
							streamCount++;
							mvprintw(streamCount + 2, 52, "PCR Drift (us): %7" PRIi64 ", %" PRIi64 " %" PRIi64 " %" PRIi64,
								di->stats->pids[m->programs[p].pmt.PCR_PID].clocks[ltntstools_CLOCK_PCR].drift_us,
								di->stats->pids[m->programs[p].pmt.PCR_PID].clocks[ltntstools_CLOCK_PCR].drift_us_lwm,
								di->stats->pids[m->programs[p].pmt.PCR_PID].clocks[ltntstools_CLOCK_PCR].drift_us_hwm,
								di->stats->pids[m->programs[p].pmt.PCR_PID].clocks[ltntstools_CLOCK_PCR].drift_us_max
								);
						}

						if (m->programs[p].service_name[0] && m->programs[p].service_provider[0]) {
							streamCount++;
							mvprintw(streamCount + 2, 52, "Service/Provider: '%s' / '%s'",
								m->programs[p].service_name,
								m->programs[p].service_provider);
						} else {
							if (m->programs[p].service_name[0]) {
								streamCount++;
								mvprintw(streamCount + 2, 52, "Service: '%s'",
									m->programs[p].service_name);
							}
							if (m->programs[p].service_name[0]) {
								streamCount++;
								mvprintw(streamCount + 2, 52, "Provider: '%s'",
									m->programs[p].service_provider);
							}
						}

					} /* For each program */

					ltntstools_pat_free(m);
					streamCount++;
				}
			}

			if (discovered_item_state_get(di, DI_STATE_SHOW_STREAM_LOG)) {
				streamCount++;
				mvprintw(streamCount + 2, 0, " -> Stream Log / Report");
				streamCount++;
				display_doc_render(&di->doc_stream_log, streamCount + 2, 8);
				streamCount += di->doc_stream_log.pageSize;
			}

			streamCount++;
		} /* For each DI */

		pthread_mutex_unlock(&ctx->lock);

		if (ctx->showUIOptions) {
			streamCount++;
			mvprintw(streamCount + 2, 0, "Stream Selection - Press right arrow key, then use up/down arrow to select individual stream");

			streamCount++;
			mvprintw(streamCount + 2, 0, "@) Record Mode: %s",
				ctx->recordWithSegments ? "Segments" : "Single File");

			streamCount++;
			mvprintw(streamCount + 2, 0, "$) Record Format: %s",
				ctx->recordAsTS ? "MPEG-TS" : "PCAP");

			streamCount++;
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
			mvprintw(streamCount + 2 - 8, 53, "I) Toggle stream IAT histogram report");
			mvprintw(streamCount + 2 - 7, 53, "L) Toggle stream log report");
			mvprintw(streamCount + 2 - 6, 53, "M) Toggle stream PSIP model report");
			mvprintw(streamCount + 2 - 5, 53, "P) Toggle stream PID traffic report");
			mvprintw(streamCount + 2 - 4, 53, "C) Toggle stream Clock report");
			mvprintw(streamCount + 2 - 3, 53, "r) Reset stats counters and begin new measurement period");
			mvprintw(streamCount + 2 - 2, 53, "R) Start/Stop stream recording");
			mvprintw(streamCount + 2 - 1, 53, "s) Toggle process/socket report");
			mvprintw(streamCount + 2 - 0, 53, "T) Start/Stop TR101290 analysis (NOT YET SUPPORTED)");
#if 0
			mvprintw(streamCount + 2 - 0, 53, "3) Toggle SCTE35 report");
#endif
			streamCount++;
		}


		if (ctx->reportProcessMemoryUsage) {
			if (process_memory_sprintf(&ctx->memUsageStatus[0], &ctx->memUsage, 5, FALSE) == 0) {
				streamCount++;
				mvprintw(streamCount + 2, 0, "Memory: %s", ctx->memUsageStatus);
				streamCount++;
			}
		}

		attron(COLOR_PAIR(2));
		ctx->trailerRow = streamCount + 3;
		if (ctx->showForwardOptions) {
			mvprintw(ctx->trailerRow, 12, "-- 7) %s 8) %s 9) %s",
				ctx->url_forwards[0].uilabel,
				ctx->url_forwards[1].uilabel,
				ctx->url_forwards[2].uilabel);
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
			sprintf(tail_a, "%s       T:%7.02f R:%7.02f %7.02f / %d stream", s, totalTxMbps, totalRxMbps, totalMbps, totalStreams);
		} else {
			sprintf(tail_a, "%s       T:%7.02f R:%7.02f %7.02f / %d streams", s, totalTxMbps, totalRxMbps, totalMbps, totalStreams);
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
			while (item && ctx->json_threadTerminate == 0) {
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
					json_next_post_time = now + 1;
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

#if KAFKA_REPORTER
static void *kafka_thread_func(void *p)
{
	struct tool_context_s *ctx = p;
	ctx->kafka_threadRunning = 1;
	ctx->kafka_threadTerminate = 0;
	ctx->kafka_threadTerminated = 0;

	ltnpthread_setname_np(ctx->kafka_threadId, "tstools-kafka");
	pthread_detach(pthread_self());

	while (!ctx->kafka_threadTerminate) {
		//discovered_items_kafka_summary(ctx);
		usleep(500 * 1000);
	}
	ctx->kafka_threadTerminated = 1;

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

static void reformat_to_pcap(struct tool_context_s *ctx, const uint8_t *pkts, int packetCount)
{
	/* Convert a series of packets into a PCAP like structure */
	if (packetCount != 7) {
		/* Should never happen.
		 * Of the two possible callers:
		 * RCTS reframes to guarantee to 7 packets.
		 * SRT AVcodec reframes to guarantee to 7 packets.
		 */
		printf("nic_monitor: file input, packetcount != 7, got %d, reframing not working.\n", packetCount);
	}

	gettimeofday(&file_pkthdr.ts, NULL);
	file_pkthdr.caplen = 42 + (packetCount * 188);
	file_pkthdr.len = file_pkthdr.caplen;

	memset(&file_pktdata[42], 0, 7 * 188);
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
}

static void * sm_cb_raw(void *userContext, const uint8_t *pkts, int packetCount)
{
	struct tool_context_s *ctx = userContext;

	/* push to reframer */
	ltststools_reframer_write(ctx->reframer, pkts, packetCount * 188);
	
	return NULL;
}

static void *reframer_cb(void *userContext, const uint8_t *buf, int lengthBytes)
{
	struct tool_context_s *ctx = userContext;
	reformat_to_pcap(ctx, buf, lengthBytes / 188);

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
	if (!ctx->monitor && signum == SIGINT)
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
	printf("  --http-json-reporting http://url     Send 1sec json stats reports for all discovered streams [def: disabled] (Experimental).\n");
	printf("    Eg. http://127.0.0.1:13400/whatever_resource_name_you_want\n");
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
		{ "ui",							no_argument,		0, 'M' },
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
		{ "http-json-reporting",		required_argument,	0, 0 },
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
#if 0
			if (strstr(ctx->ifname, "http://")) {
				ctx->iftype = IF_TYPE_MPEGTS_AVDEVICE;
				printf("We have an HTTP input!!!\n");
				We might need to pcr the pcr and rate limit it, for example for a HTTP faster than realtime source
			} else
#endif
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
			ctx->monitor = 1;
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
			case 23: /* http-json-reporting */
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

int nic_monitor(int argc, char *argv[])
{
	//int ch;

	pthread_mutex_init(&ctx->lock, NULL);
	xorg_list_init(&ctx->list);

	pthread_mutex_init(&ctx->ui_threadLock, NULL);
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
	strcpy(ctx->json_http_url, "http://127.0.0.1:13400/nicmonitor");

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
#if KAFKA_REPORTER
	pthread_create(&ctx->kafka_threadId, 0, kafka_thread_func, ctx);
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

	if (ctx->reportProcessMemoryUsage) {
		/* Measure the memory used by this process */
		process_memory_init(&ctx->memUsage);
	}

	time(&ctx->lastResetTime);
	while (gRunning) {

		if (ctx->reportProcessMemoryUsage) {
			process_memory_update(&ctx->memUsage, 5);

			if (ctx->monitor == 0) {
				/* Report status to console */
				process_memory_dprintf(STDOUT_FILENO, &ctx->memUsage, 5);
			}
		}

		char c = ui_syncronized_getch(ctx);

		if (ctx->startTime + 2 == time(NULL)) {
			c = 'r';
		}
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
			ltntstools_proc_net_udp_items_reset_drops(ctx->procNetUDPContext);
			ctx->lastSocketReport = 0;
		}
		if (c == 'C') {
			discovered_items_select_show_clocks_toggle(ctx);
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
		if (c == 'J') {
			discovered_items_select_json_probe_toggle(ctx);
		}
		if (c == 'L') {
			discovered_items_select_show_stream_log_toggle(ctx);
		}
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
#if 0
		if (c == '3') {
			discovered_items_select_scte35_toggle(ctx);
		}
#endif
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
				else
				if (c == 0x35) { /* Page Up */
					//printf("0x%02x up\n", c);
					discovered_items_select_show_stream_log_pageup(ctx);
				} else
				if (c == 0x36) { /* Page Down */
					//printf("0x%02x dn\n", c);
					discovered_items_select_show_stream_log_pagedown(ctx);
				}
			}
		}

		usleep(50 * 1000);
	}

	discovered_items_abort(ctx);

	time_t periodEnds = time(NULL);

	/* Shutdown stats collection */
	ctx->ui_threadTerminate = 1;
	ctx->pcap_threadTerminate = 1;
	ctx->stats_threadTerminate = 1;
	ctx->json_threadTerminate = 1;
	while (!ctx->pcap_threadTerminated)
		usleep(50 * 1000);
	while (!ctx->stats_threadTerminated)
		usleep(50 * 1000);
	while (!ctx->json_threadTerminated)
		usleep(50 * 1000);

	/* Shutdown ui */
	if (ctx->monitor) {
		while (!ctx->ui_threadTerminated) {
			usleep(50 * 1000);
			printf("Blocked on ui\n");
		}
		endwin();
	}

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

	printf("Flushing the streams and recorders...\n");
	discovered_items_free(ctx);

	pcap_queue_free(ctx);

	printf("\nStats window:\n");
	printf("  from %s -> %s\n", ts_b, ts_e);
	printf("  duration %02d:%02d:%02d (HH:MM:SS)\n\n", diff.tm_hour, diff.tm_min, diff.tm_sec);

	free(ctx->file_prefix);
	free(ctx->detailed_file_prefix);

	ltntstools_reframer_free(ctx->reframer);

	return 0;
}
