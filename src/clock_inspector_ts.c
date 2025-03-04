#include "clock_inspector_public.h"

void processPacketStats(struct tool_context_s *ctx, uint8_t *pkt, uint64_t filepos, struct timeval ts)
{
	uint16_t pid = ltntstools_pid(pkt);
	ctx->pids[pid].pkt_count++;

	uint32_t cc = ltntstools_continuity_counter(pkt);

	if (ctx->dumpHex) {
		if (ctx->ts_linenr++ == 0) {
			printf("+TS Packet         filepos ------------>\n");
			printf("+TS Packet             Hex           Dec   PID  Packet --------------------------------------------------------------------------------------->\n");
		}
		if (ctx->ts_linenr > 24)
			ctx->ts_linenr = 0;

		printf("TS  #%09" PRIu64 " -- %08" PRIx64 " %13" PRIu64 "  %04x  ",
			ctx->ts_total_packets,
			filepos,
			filepos,
			pid);
	}

	if (ctx->dumpHex == 1) {
		ltntstools_hexdump(pkt, 32, 32 + 1); /* +1 avoid additional trailing CR */
	} else
	if (ctx->dumpHex == 2) {
		ltntstools_hexdump(pkt, 188, 32);
	}

	uint32_t afc = ltntstools_adaption_field_control(pkt);
	if ((afc == 1) || (afc == 3)) {
		/* Every pid will be in error the first occurece. Check on second and subsequent pids. */
		if (ctx->pids[pid].pkt_count > 1) {
			if (((ctx->pids[pid].cc + 1) & 0x0f) != cc) {
				/* Don't CC check null pid. */
				if (pid != 0x1fff) {
					char str[64];
					sprintf(str, "%s", ctime(&ctx->current_stream_time));
					str[ strlen(str) - 1] = 0;
					printf("!CC Error. PID %04x expected %02x got %02x @ %s\n",
						pid, (ctx->pids[pid].cc + 1) & 0x0f, cc, str);
					ctx->pids[pid].cc_errors++;
				}
			}
		}
	}
	ctx->pids[pid].cc = cc;
}

