/* Copyright LiveTimeNet, Inc. 2025. All Rights Reserved. */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <math.h>
#include <inttypes.h>
#include <string.h>
#include <assert.h>
#include <signal.h>

#include <libltntstools/ltntstools.h>
#include <libklscte35/scte35.h>
#include "ffmpeg-includes.h"
#include "source-avio.h"

#include "libzvbi.h"
#include "langdict.h"

#define TELETEXT_DISPLAYSIZE 8192

char *strcasestr(const char *haystack, const char *needle);
extern int langdict_sort_dict(enum langdict_type_e langtype);

enum pid_type_e {
	PT_UNKNOWN = 0,
	PT_OP47,
	PT_VIDEO,
};

struct input_pid_s
{
	struct tool_ctx_s *ctx;

	int enabled;                   /* Pid active. Boolean */
	enum pid_type_e payloadType;   /* PT_OP47, PT_VIDEO etc */
	uint16_t pid;                  /* Max 0x1fff */
	uint16_t streamId;             /* Pes Extractor StreamID 0xC0, 0xE0 etc */
	uint16_t ttx_page;             /* Teletext subtitle page, typically 888 */
	uint16_t programNumber;        /* MPEGTS stream program number */

	void *pe;                      /* PesExtractor Context */

	vbi_decoder *decoder;          /* zvbi decoder */
	vbi_page page;                 /* zvbi decoder */
	char *display;                 /* Buffer to contact decoded caption/subtitle ASCII */

	void *langdict_ctx;            /* Dictionary context */

	uint64_t syntaxError;          /* Count of number of syntax errors we're detecting for this stream */
};

struct tool_ctx_s
{
	int verbose;

	void *src_pcap;            /* Source-pcap context */
	char *iname;
	char *pcap_filter;

	uint64_t callbackCounter;

	void *sm;                  /* StreamModel Context */
	int smcomplete;            /* Is the streamModel complete and ready for access? Bool. */
	int isMPTS;                /* Bool */

#define MODE_SOURCE_AVIO 0
#define MODE_SOURCE_PCAP 1
	int mode;                  /* AVIO or PCAP */
	int isRTP;                 /* Bool */

#define MAX_PIDS 0x2000
	struct input_pid_s pids[MAX_PIDS];

	int totalOrderedPids;     /* Number of active pids in the ordered list */
	struct input_pid_s *pidsOrdered[MAX_PIDS];
};

static void dumpPid(struct tool_ctx_s *ctx, struct input_pid_s *p)
{
	printf("DEBUG: pid[0x%04x].pid = 0x%04x, pt = %d, pe = %p\n",
		p->pid, p->pid, p->payloadType, p->pe);
}

static void dumpPids(struct tool_ctx_s *ctx)
{
	for (int i = 0; i < MAX_PIDS; i++) {
		if (ctx->pids[i].enabled) {
			dumpPid(ctx, &ctx->pids[i]);
		}
	}
}

/* TODO: Move this into the libltntstools once we're completely happy with it.
 * See ISO-14496-10:2004 section 7.3.1 NAL unit Syntax.
 */
static void ltn_nal_h264_strip_emulation_prevention(struct ltn_nal_headers_s *h)
{
	int dropped = 0;
	for (int i = 1; i < h->lengthBytes; i++) {
		if (i + 2 < h->lengthBytes &&
			h->ptr[i + 0] == 0x00 &&
			h->ptr[i + 1] == 0x00 &&
			h->ptr[i + 2] == 0x03)
		{
				/* Convert 00 00 03 to 00 00 */
				memcpy((unsigned char *)&h->ptr[i + 2], &h->ptr[i + 3], h->lengthBytes - i - 3);
				dropped++;
		}
	}
	h->lengthBytes -= dropped;
}

static int get_row_first(vbi_page *page)
{
    for (int i = 0; i < page->rows * page->columns; i++) {
        if (page->text[i].opacity != VBI_TRANSPARENT_SPACE) {
            return i / page->columns;
        }
    }
    return -1;
}

static int get_row_last(vbi_page *page)
{
    for (int i = page->rows * page->columns - 1; i >= 0; i--) {
        if (page->text[i].opacity != VBI_TRANSPARENT_SPACE) {
            return i / page->columns;
        }
    }
    return -1;
}

static void page_dump(vbi_page *pg, int start_row, int last_row)
{
	for (int row = start_row; row < last_row; ++row) {
		fprintf (stderr, "%2d: >", row);
		const vbi_char *cp = pg->text + row * pg->columns;
		for (int column = 0; column < pg->columns; ++column) {
			int c = cp[column].unicode;
			if (c < 0x20 || c > 0x7E) {
					c = '.';
			}
			fputc (c, stderr);
		}
		fputs ("<\n", stderr);
	}
}

/* Convert unicode vbi_page to a line of text */
static void page_export(vbi_page *pg, int start_row, int last_row, char *dst)
{
	int i = 0;
	for (int row = start_row; row < last_row; ++row) {
		const vbi_char *cp = pg->text + row * pg->columns;

		for (int column = 0; column < pg->columns; ++column) {
			int c = cp[column].unicode;
			if (c < 0x20 || c > 0x7E) {
					c = ' ';
			}

			*(dst + i++) = c;
		}
	}
	*(dst + i++) = 0;
}

/* Push a text string into the dictionaries for stats checks */
static void analyze_text(struct tool_ctx_s *ctx, struct input_pid_s *p, char *display)
{
	if (ctx->verbose) {
		printf("Analyze: '%s'\n", p->display);
	}

	/* Send it through the dictionaries for language detection */
	langdict_parse(p->langdict_ctx, display, strlen(display));

	/* Check the results, words found or missing per language */
	char *langname[] = { "eng", "spa", "ger", "ita", "fra", "?" };
	enum langdict_type_e langs[] = { LANG_ENGLISH, LANG_SPANISH, LANG_GERMAN, LANG_ITALIAN, LANG_FRENCH, LANG_UNDEFINED };

	/* TODO: Figure out what to do with these stats */
	/* TODO: Pull the stats from the dicts in a seperate thread and manage stats reporting properly. */
	/* TODO: Print the program and pid number */

	printf("# %s program %d pid 0x%04x (%d)\n",
		ctx->isMPTS ? "MPTS" : "SPTS",
		p->programNumber,
		p->pid, p->pid);
	printf("lang   found    missing  processed   accuracy   last processed            last word                 frame Err    idle secs\n");
	int i = 0;
	while (langs[i] != LANG_UNDEFINED) {
		struct langdict_stats_s s;
		if (langdict_get_stats(p->langdict_ctx, langs[i], &s) == 0) {

			char a[256];
			sprintf(a, "%s", ctime(&s.time_last_search));
			a[ strlen(a) - 1] = 0;

			char b[256];
			sprintf(b, "%s", ctime(&s.time_last_found));
			b[ strlen(b) - 1] = 0;

			int idlesecs = -1;
			char secs[16] = "-";
			if (s.time_last_search && s.time_last_found) {
				idlesecs = s.time_last_search - s.time_last_found;
				sprintf(secs, "%12d", idlesecs);
			}

			printf("%4s %7ld    %7ld    %7ld     %5.0f%%   %24s  %24s   %8" PRIu64 " %12s\n",
				langname[i], s.found, s.missing, s.processed, s.accuracypct,
				a, b, p->syntaxError,
				secs);
		}
		i++;
	}	
}

static void ttx_event_handler(vbi_event *ev, void *user_data)
{
	struct input_pid_s *p = (struct input_pid_s *)user_data;
	struct tool_ctx_s *ctx = p->ctx;
	memset(&p->page, 0, sizeof(p->page));

    if (ev->type == VBI_EVENT_CAPTION) {
		/* Attempt to process each CEA608 page 1..4 */
		for (int i = 0; i < 4; i++) {

			/* Fetch the page for subtitles / captions */
			vbi_bool success = vbi_fetch_cc_page(p->decoder, &p->page, i + 1, TRUE);
			if (success && p->page.dirty.y1 != -1) {

				int r_first = get_row_first(&p->page);
				int r_last = get_row_last(&p->page);

				if (ctx->verbose) {
					page_dump(&p->page, r_first, r_last + 1);
				}

				/* Convert the page into ASCII */
				page_export(&p->page, r_first, r_last + 1, p->display);

				analyze_text(ctx, p, p->display);
	
			}
		}
	} else
    if (ev->type == VBI_EVENT_TTX_PAGE) {
		if (ctx->verbose) {
			printf("Received Teletext page: pgno 0x%x subno 0x%x\n",
				ev->ev.ttx_page.pgno,
				ev->ev.ttx_page.subno);
		}

		/* Fetch the page for subtitles / captions */
		if (vbi_fetch_vt_page(p->decoder, &p->page, vbi_dec2bcd( p->ttx_page ), ev->ev.ttx_page.subno, VBI_WST_LEVEL_1, 25, 1) > 0) {

			/* Get the caption visible region */
			int r_first = get_row_first(&p->page);
			int r_last = get_row_last(&p->page);
			int rows_visible = r_last - r_first - 1;

			/* Convert the page to ASCII, for the lines containing visible content */
			vbi_print_page_region(&p->page, p->display, TELETEXT_DISPLAYSIZE, "UTF-8", 0, 0, 0,
				r_first, p->page.columns, rows_visible);

			analyze_text(ctx, p, p->display);
		}
    }
}

static void setPidType(struct tool_ctx_s *ctx, uint16_t pid, enum pid_type_e pt, uint16_t programNumber)
{
	struct input_pid_s *p = &ctx->pids[pid];

	p->enabled = 1;
	p->payloadType = pt;
	p->pid = pid;
	p->ctx = ctx;
	p->streamId = 0xc0;
	p->ttx_page = 888; /* TODO: hardcoded */
	p->programNumber = programNumber;

	if (pt == PT_VIDEO) {
		p->streamId = 0xe0;
	} else
	if (pt == PT_OP47) {
		p->streamId = 0xbd;
	}

	/* Allocate a dictionary, pick a default language, doesnt actually matter
	 * what language is chosen. All languages are processed.
	 */
	if (langdict_alloc(&p->langdict_ctx) < 0) {
		fprintf(stderr, "Unable to allocate language dictionaries, aborting.\n");
		exit(1);
	}

	p->display = calloc(1, TELETEXT_DISPLAYSIZE);
	if (!p->display) {
		fprintf(stderr, "Unable to allocate zvbi decoder, aborting.\n");
		exit(1);
	}

	p->decoder = vbi_decoder_new();
	if (!p->decoder) {
		fprintf(stderr, "Unable to allocate zvbi decoder, aborting.\n");
		exit(1);
	}

	if (!vbi_event_handler_add(p->decoder, VBI_EVENT_CAPTION | VBI_EVENT_TTX_PAGE, ttx_event_handler, p)) {
		fprintf(stderr, "Failed to add event handler, aborting.\n");
		exit(1);
	}

	/* TODO: tone down the log level bellow 0xffff */
	vbi_set_log_fn(0xffff, vbi_log_on_stderr, /* user_data */ NULL);

	/* Put pid into a contigious array for optimized enumeration */
	for (int i = 0; i < MAX_PIDS; i++) {
		if (ctx->pidsOrdered[i] == 0) {
			ctx->pidsOrdered[i] = &ctx->pids[pid];
			ctx->totalOrderedPids++;
			break;
		}
	}
}

static int countPidsByPayloadType(struct tool_ctx_s *ctx, enum pid_type_e pt)
{
	int cnt = 0;
	for (int i = 0; i < MAX_PIDS; i++) {
		struct input_pid_s *p = &ctx->pids[i];
		if (p->enabled == 0)
			continue;
		if (p->payloadType == pt)
			cnt++;
	}

	return cnt;
}

static int gRunning = 1;
static void signal_handler(int signum)
{
	gRunning = 0;
}

static void process_transport_buffer(struct tool_ctx_s *ctx, const unsigned char *buf, int byteCount);

#ifdef __APPLE__
#define iphdr ip
#endif

static void *source_pcap_raw_cb(void *userContext, const struct pcap_pkthdr *hdr, const u_char *pkt)
{
	struct tool_ctx_s *ctx = (struct tool_ctx_s *)userContext;

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
				src, dst, ntohs(udphdr->len), ptr[0], ptr[1], ptr[2], ptr[3]);
		}

		int lengthPayloadBytes = ntohs(udphdr->len) - sizeof(struct udphdr);
		
		if ((lengthPayloadBytes > 12) && ((lengthPayloadBytes - 12) % 188 == 0)) {
			/* It's RTP */
			ptr += 12;
			lengthPayloadBytes -= 12;
		}

		process_transport_buffer(ctx, ptr, lengthPayloadBytes);
	}

	return NULL;
}

static struct ltntstools_source_pcap_callbacks_s pcap_callbacks = 
{
    .raw = (ltntstools_source_pcap_raw_callback)source_pcap_raw_cb,
};

/* Process captions in H.264 specific PES frames */
static int pe_callback_video(struct tool_ctx_s *ctx, struct input_pid_s *ptr, struct ltn_pes_packet_s *pes)
{
	int arrayLength = 0;
	struct ltn_nal_headers_s *array = NULL;
	if (ltn_nal_h264_find_headers(pes->data, pes->dataLengthBytes, &array, &arrayLength) == 0) {

		for (int i = 0; i < arrayLength; i++) {
			struct ltn_nal_headers_s *e = array + i;

			if (e->nalType == 0x6 /* SEI */ &&
				e->ptr[4] == 0x04 /* SEI PAYLOAD_TYPE == USER_DATA_REGISTERED_ITU_T_T35 */ &&
				e->ptr[13] == 0x03 /* usercode: CEA-608 Captions */)
			{
				if (e->ptr[6] != 0xb5 /* United States */) {
					ptr->syntaxError++;
					fprintf(stderr, "CEA608 PES has incorrect country_code 0x%02x, expected 0x0b5, skipping\n",
						e->ptr[6]);
					continue;
				}

				if (e->ptr[7] != 0x00 || e->ptr[8] != 0x31 /* Provide_code - ATSC complicant */) {
					ptr->syntaxError++;
					fprintf(stderr, "CEA608 PES has incorrect provider_code 0x%02x 0x%02x, expected 0x00 0x31, skipping\n",
						e->ptr[7], e->ptr[8]);
					continue;
				}
				/* These should be captions, do more checks */
				if (e->ptr[9] != 'G' || e->ptr[10] != 'A' || e->ptr[11] != '9' || e->ptr[12] != '4') {
					ptr->syntaxError++;
					fprintf(stderr, "CEA608 PES has incorrect signature, extected GA94, found %02x %02x %02x %02x, skipping\n",
						e->ptr[9], e->ptr[10], e->ptr[11], e->ptr[12]);
					continue;
				}

				ltn_nal_h264_strip_emulation_prevention(e);

				//int process_cc_data_flag = (e->ptr[14] > 6) & 1;
				//int zerobit = (e->ptr[14] > 5) & 1;
				int cc_count = e->ptr[14] & 0x1f;
				switch (cc_count) {
				case 10:
				case 20:
				case 1:
				case 2:
					break;
				default:	
					ptr->syntaxError++;
					fprintf(stderr, "CEA608 PES cc_count invalid %d, wanted 1, 2, 10 or 20, skipping\n", cc_count);
					continue;
				}

				vbi_sliced sliced_frame[2];
		
				/* Tupples start at position 16.
				 * Genenerally speaking, you should have one fd tupple and one fc tupple per cc_count set.
				 * Certain equipment puts then anywayere in the set, not just in the first position, so look
				 * for them across the entire set. Importantly, the majority of the tupples will be throw away
				 * and up to 2 of them used for CC decoding.
				 */
				int sliced_count = 0;
				int s = 16;
				for (int i = 0; i < cc_count; i++) {
					if (e->ptr[s + 0] == 0xfc || e->ptr[s + 0] == 0xfd) {
						if (sliced_count >= 2) {
							ptr->syntaxError++;
							fprintf(stderr, "CEA608 PES contains more than 2 slices, skipping\n");
							break;
						}
						sliced_frame[sliced_count].id      = e->ptr[s + 0] == 0xfc ? VBI_SLICED_CAPTION_525_F1 : VBI_SLICED_CAPTION_525_F2;
						sliced_frame[sliced_count].line    = e->ptr[s + 0] == 0xfc ? 21 : 284;
						sliced_frame[sliced_count].data[0] = e->ptr[s + 1];
						sliced_frame[sliced_count].data[1] = e->ptr[s + 2];
						sliced_count++;
					}
					s += 3;
				}

				/* Feed the unit to the decoder */
				if (sliced_count <= 2) {
					vbi_decode(ptr->decoder, sliced_frame, sliced_count, 0);
				}
			} /* if SEI */
		} /* for all NALs */
	} /* find nal headers */

	free(array);

	return 0;
}

/* Process teletext specific PES frames */
static int pe_callback_teletext(struct tool_ctx_s *ctx, struct input_pid_s *ptr, struct ltn_pes_packet_s *pes)
{
	/* EN300472 v1.2.2 for field packing */
	if (pes->PES_header_data_length != 0x24) {
		ptr->syntaxError++;
		fprintf(stderr, "PES has incorrect PES_header_data_length size field, wanted %d got %d, skipping\n",
			0x24, pes->PES_header_data_length);
		return -EINVAL;
	}

	int i = 0x1f;
	unsigned char *p = &pes->data[i];
	unsigned char *e = &pes->data[pes->dataLengthBytes];
	if (*(p++) != 0x10) {
		ptr->syntaxError++;
		fprintf(stderr, "PES has incorrect data_identifier field, wanted 0x%x got 0x%x, skipping\n", 0x10, *p);
		return -EINVAL;
	}

	/* Extract each Teletext unit, pass each unit to a decoder for decoding */
	int c = 0;
	while (p < e) {
		unsigned char data_unit_id = *(p + 0);
		unsigned char data_unit_length = *(p + 1);
		if (data_unit_id == 0xff) {
			p += (data_unit_length + 2);
			c++;
			continue;
		}
		if (data_unit_id != 0x3) { /* EBU Teletext Subtitle Data */
			ptr->syntaxError++;
			fprintf(stderr, "%d: PES has incorrect data_unit_id field, wanted 0x%x got 0x%x, skipping\n",
				c, 3, data_unit_id);
			break;
		}
		if (data_unit_length != 0x2c) {
			ptr->syntaxError++;
			fprintf(stderr, "%d: PES has incorrect data_unit_length field, wanted 0x%x got 0x%x, skipping\n",
				c, 0x2c, data_unit_length);
			break;
		}

		if (ctx->verbose) {
			/* 'p' represents EN 300 472 v1.2.2 page 7, beginning "data unit id" */
			printf("0x%04x: %02x %02x : ", ptr->pid, *(p + 0), *(p + 1));
			for (int j = 0; j < data_unit_length; j++) {
				printf("%02x ", *(p + j + 2));
			}
			printf("\n");
		}

		/* Push data to the decoder */
		vbi_sliced sliced_frame[1];
    	sliced_frame[0].id = VBI_SLICED_TELETEXT_B;
    	sliced_frame[0].line = (*(p + 2) & 0x1f) + ((*(p + 2) & 0x20) ? 0 : 313);
		for (int i = 0; i < 42; i++) {
			sliced_frame[0].data[i] = vbi_rev8(p[4 + i]);
		}

		/* Feed the unit to the decoder */
		vbi_decode(ptr->decoder, sliced_frame, 1, 0);

		p += (data_unit_length + 2);
		c++;
	}

	return 0;
}

static void *pe_callback(void *userContext, struct ltn_pes_packet_s *pes)
{
	struct input_pid_s *ptr = (struct input_pid_s *)userContext;
	struct tool_ctx_s *ctx = ptr->ctx;

	ctx->callbackCounter++;

	if (ctx->verbose >= 2) {
		ltn_pes_packet_dump(pes, "");
	}

	if (ptr->payloadType == PT_OP47) {
		pe_callback_teletext(ctx, ptr, pes);
	} else
	if (ptr->payloadType == PT_VIDEO) {
		pe_callback_video(ctx, ptr, pes);
	}

	ltn_pes_packet_free(pes);

	return NULL;
}

static void usage(const char *progname)
{
	printf("A tool to parse CEA608/708 captions from SPTS/MPTS SEI nals, and extract OP47/WST/Subtitles from PES frames.\n");
	printf("Extract captions from both formats, run them through dictionaries and do language detection and word counts.\n");
	printf("Usage:\n");
	printf("  -i <url | nicname>   Eg: rtp|udp://227.1.20.45:4001?localaddr=192.168.20.45\n");
    printf("                           192.168.20.45 is the IP addr where we'll issue a IGMP join\n");
	printf("                       Eg: eno2    (Also see -F)\n");
	printf("  -v Increase level of verbosity.\n");
	printf("  -h Display command line help.\n");
	printf("  -P 0xnnnn PID containing the Teletext/OP47 messages (Optional)\n");
	printf("  -V 0xnnnn PID containing the video stream (Optional)\n");
	printf("  -F exact pcap filter. Eg 'host 227.1.20.80 && udp port 4001'\n");
	printf("\nExample:\n");
	printf("  sudo %s -i eno2 -F 'host 227.1.20.80 && udp port 4001'  -- auto-detect SCTE/video pids from nic\n", progname);
	printf("       %s -i recording.ts                                 -- auto-detect SCTE/video pids from file\n", progname);
	printf("       %s -i recording.ts -V 0x1e1 -P 0x67 -P 0x69        -- Disable auto-detect force decode of various pids\n", progname);
	printf("       %s -i udp://227.1.20.80:4001                       -- auto-detect SCTE/video pids from socket/stream\n", progname);
}

static void process_transport_buffer(struct tool_ctx_s *ctx, const unsigned char *buf, int byteCount)
{
	if (ctx->isRTP)
		buf += 12;

	if (ctx->verbose >= 2) {
		for (int j = 0; j < byteCount; j += 188) {
			uint16_t pidnr = ltntstools_pid(buf + j);
			if (ctx->pids[pidnr].payloadType != PT_UNKNOWN) {
				printf("PID %04x : ", pidnr);
				for (int i = 0; i < 188; i++)
					printf("%02x ", buf[j + i]);
				printf("\n");
			}
		}
	}

	/* Detect any Teletext pids if non were set */
	if (ctx->sm == NULL && ((countPidsByPayloadType(ctx, PT_OP47) == 0) || (countPidsByPayloadType(ctx, PT_VIDEO) == 0))) {
		if (ltntstools_streammodel_alloc(&ctx->sm, NULL) < 0) {
			fprintf(stderr, "\nUnable to allocate streammodel object.\n\n");
			exit(1);
		}
	}

	/* Write transport into the stream mode, until it's complete, then initialize pids and extractors */
	if (ctx->sm && ctx->smcomplete == 0 && ((countPidsByPayloadType(ctx, PT_OP47) == 0) || (countPidsByPayloadType(ctx, PT_VIDEO) == 0))) {

        struct timeval nowtv;
        gettimeofday(&nowtv, NULL);
		ltntstools_streammodel_write(ctx->sm, &buf[0], byteCount / 188, &ctx->smcomplete, &nowtv);

		/* With a complete PSIP streammodel, find any video or teletext pids,
		 * setup extractors and mechanisms to gain access to their payload.
		 */
		if (ctx->smcomplete) {
			struct ltntstools_pat_s *pat = NULL;
			if (ltntstools_streammodel_query_model(ctx->sm, &pat) == 0) {

				/* Walk all the services, find all video PMTs. */
				int e = 0;
				struct ltntstools_pmt_s *pmt;
				uint16_t videopid = 0;
				ctx->isMPTS = ltntstools_streammodel_is_model_mpts(ctx->sm, pat);

				while (ltntstools_pat_enum_services_video(pat, &e, &pmt) == 0) {

					uint8_t estype;
					ltntstools_pmt_query_video_pid(pmt, &videopid, &estype);

					setPidType(ctx, videopid, PT_VIDEO, pmt->program_number);

					printf("Found %s program %d video pid 0x%04x (%d)\n",
						ctx->isMPTS ? "MPTS" : "SPTS",
						pmt->program_number,
						videopid, videopid);

				}

				/* Walk all the services, process any OP47 / Teletext pids */
				e = 0;
				while (ltntstools_pat_enum_services_teletext(pat, &e, &pmt) == 0) {
					for (int i = 0; i < pmt->stream_count; i++) {
						struct ltntstools_pmt_entry_s *se = &pmt->streams[i];

						if (ltntstools_descriptor_list_contains_teletext(&se->descr_list)) {
							setPidType(ctx, se->elementary_PID, PT_OP47, pmt->program_number);

							printf("Found %s program %d teletext/op47/wst pid 0x%04x (%d)\n",
								ctx->isMPTS ? "MPTS" : "SPTS",
								pmt->program_number,
								se->elementary_PID, se->elementary_PID);
						}
					}
				}

				if (ctx->verbose > 1) {
					ltntstools_pat_dprintf(pat, STDOUT_FILENO);
				}

				ltntstools_pat_free(pat);
			}
		}
	}

	/* For each op47/video stream, allocate an extractor */
	for (int i = 0; i < ctx->totalOrderedPids; i++) {
		struct input_pid_s *p = ctx->pidsOrdered[i];

		if (p->payloadType == PT_OP47 || p->payloadType == PT_VIDEO) {
			if (p->pid && p->pe == NULL) {
				/* Setup a pes extractor for any found video or teletext pids, if not previously allocated, */
				if (ltntstools_pes_extractor_alloc(&p->pe, p->pid, p->streamId, (pes_extractor_callback)pe_callback,
					p, (1024 * 1024), (1024 * 1024)) < 0)
				{
					fprintf(stderr, "\nUnable to allocate pes_extractor object.\n\n");
					exit(1);
				}

				/* Ensure the PES extractor also gives us payload */
				/* We want the PES decoding in the correct temporal order */
				ltntstools_pes_extractor_set_skip_data(p->pe, 0);
				ltntstools_pes_extractor_set_ordered_output(p->pe, 1);
				
				if (ctx->verbose) {
					dumpPids(ctx);
				}
			}
		}

	}

	/* Feed any PES extractors */
	for (int i = 0; i < ctx->totalOrderedPids; i++) {
		struct input_pid_s *p = ctx->pidsOrdered[i];
		if (p->pe) {
			ltntstools_pes_extractor_write(p->pe, &buf[0], byteCount / 188);
		}
	}
}

static void process_pcap_input(struct tool_ctx_s *ctx)
{
	if (ltntstools_source_pcap_alloc(&ctx->src_pcap, ctx, &pcap_callbacks, ctx->iname, ctx->pcap_filter, (1024 * 1024 * 4)) < 0) {
		fprintf(stderr, "Failed to open source_pcap interface, check permissions (sudo) or syntax.\n");
		return;
	}

	while (gRunning) {
		usleep(50 * 1000);
	}

	ltntstools_source_pcap_free(ctx->src_pcap);
}

static void *_avio_raw_callback(void *userContext, const uint8_t *pkts, int packetCount)
{
	struct tool_ctx_s *ctx = (struct tool_ctx_s *)userContext;
	process_transport_buffer(ctx, pkts, packetCount * 188);

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
		signal_handler(0);
		break;
	default:
		fprintf(stderr, "unsupported avio state %d\n", status);
	}
	return NULL;
}

static void process_avio_input(struct tool_ctx_s *ctx)
{
	if (strcasestr(ctx->iname, "rtp://")) {
		ctx->isRTP = 1;
	}

	struct ltntstools_source_avio_callbacks_s cbs = { 0 };
	cbs.raw = (ltntstools_source_avio_raw_callback)_avio_raw_callback;
	cbs.status = (ltntstools_source_avio_raw_callback_status)_avio_raw_callback_status;

	void *srcctx = NULL;
	int ret = ltntstools_source_avio_alloc(&srcctx, ctx, &cbs, ctx->iname);
	if (ret < 0) {
		fprintf(stderr, "-i syntax error\n");
		return;
	}

	while (gRunning) {
		usleep(50 * 1000);
	}

	ltntstools_source_avio_free(srcctx);
}

int caption_analyzer(int argc, char *argv[])
{
	struct tool_ctx_s *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		fprintf(stderr, "Unable to allocate memory for application context, aborting.\n");
		return -1;
	}
	ctx->verbose = 0;
	ctx->mode = MODE_SOURCE_AVIO;

	int ch, pid;
	while ((ch = getopt(argc, argv, "@:?hvi:F:P:V:")) != -1) {
		switch (ch) {
		case '?':
		case 'h':
			usage(argv[0]);
			exit(1);
			break;
		case '@':
			langdict_sort_dict(atoi(optarg));
			exit(1);
		case 'i':
			ctx->iname = strdup(optarg);
			break;
		case 'F':
			ctx->pcap_filter = strdup(optarg);
			ctx->mode = MODE_SOURCE_PCAP;
			break;
		case 'P':
			if ((sscanf(optarg, "0x%x", &pid) != 1) || (pid > 0x1fff)) {
				usage(argv[0]);
				exit(1);
			}
			setPidType(ctx, pid, PT_OP47, 0);
			break;
		case 'v':
			ctx->verbose++;
			break;
		case 'V':
			if ((sscanf(optarg, "0x%x", &pid) != 1) || (pid > 0x1fff)) {
				usage(argv[0]);
				exit(1);
			}
			setPidType(ctx, pid, PT_VIDEO, 0);
			break;
		default:
			usage(argv[0]);
			exit(1);
		}
	}

	if (getuid() == 0 && getenv("SUDO_UID") && getenv("SUDO_GID") && ctx->mode != MODE_SOURCE_PCAP) {
		usage(argv[0]);
		fprintf(stderr, "\n**** Don't use SUDO against file or udp socket sources, ONLY nic/pcap sources ****.\n\n");
		exit(1);
	}

	if (ctx->iname == NULL) {
		usage(argv[0]);
		fprintf(stderr, "\n-i is mandatory.\n\n");
		exit(1);
	}

	signal(SIGINT, signal_handler);

	/* Main processing loop */
	if (ctx->mode == MODE_SOURCE_AVIO) {
		printf("Mode: AVIO\n");
		process_avio_input(ctx);
	} else
	if (ctx->mode == MODE_SOURCE_PCAP) {
		printf("Mode: PCAP\n");
		process_pcap_input(ctx);
	}

	/* Tear down the application */
	for (int i = 0; i < MAX_PIDS; i++) {
		struct input_pid_s *p = &ctx->pids[i];
		if (p->enabled == 0)
			continue;
		if (p->pe)
			ltntstools_pes_extractor_free(p->pe);
		if (p->display)
			free(p->display);
		if (p->langdict_ctx)
			langdict_free(p->langdict_ctx);
	}

	if (ctx->sm)
		ltntstools_streammodel_free(ctx->sm);
	if (ctx->iname)
		free(ctx->iname);
	free(ctx);

	return 0;
}


