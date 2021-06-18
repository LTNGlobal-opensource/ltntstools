
#include "nic_monitor.h"

#define QUEUE_MIN (8 * 1024)

/* Initialize the queue to N items */
int pcap_queue_initialize(struct tool_context_s *ctx)
{
	pthread_mutex_lock(&ctx->lockpcap);

	for (int i = 0; i < QUEUE_MIN; i++) {
		struct pcap_item_s *item = malloc(sizeof(*item));
		if (item) {
			item->h = malloc(sizeof(struct pcap_pkthdr));
			item->pkt = malloc(1700);
			memset(item->pkt, 0xcd, 1700);
			xorg_list_append(&item->list, &ctx->listpcapFree);
			ctx->listpcapFreeDepth++;
		}
	}

	pthread_mutex_unlock(&ctx->lockpcap);
	return 0;
}

void pcap_queue_free(struct tool_context_s *ctx)
{
	/* walk all queues and free and allocations */
	pthread_mutex_lock(&ctx->lockpcap);
	while (!xorg_list_is_empty(&ctx->listpcapFree)) {
		struct pcap_item_s *item = xorg_list_first_entry(&ctx->listpcapFree, struct pcap_item_s, list);
		xorg_list_del(&item->list);
		ctx->listpcapFreeDepth--;
		free(item->h);
		free(item->pkt);
		free(item);
	}
	while (!xorg_list_is_empty(&ctx->listpcapUsed)) {
		struct pcap_item_s *item = xorg_list_first_entry(&ctx->listpcapUsed, struct pcap_item_s, list);
		xorg_list_del(&item->list);
		ctx->listpcapUsedDepth--;
		free(item->h);
		free(item->pkt);
		free(item);
	}
	pthread_mutex_unlock(&ctx->lockpcap);
}

int pcap_queue_push(struct tool_context_s *ctx, const struct pcap_pkthdr *h, const u_char *pkt)
{
	struct pcap_item_s *item = NULL;

	/* Either take a free item off the list or alloc a new item. */
	/* We're 100% free to hold the lockpcap mutex for as long as we want
	 * we're running on the most important thread in the design,
	 * any other thread who wants access to the listpcap* lists via
	 * this lock, will hold the lock for the purposes of moving
	 * list items into a temporary list.
	 */
	int ret = -1;

	pthread_mutex_lock(&ctx->lockpcap);

	do {
		if (xorg_list_is_empty(&ctx->listpcapFree)) {
			ctx->pcap_free_miss++;
			item = malloc(sizeof(*item));
			if (!item) {
				break;
			}

			item->h = malloc(sizeof(*h));
			item->pkt = malloc(h->len);
		} else {
			item = xorg_list_first_entry(&ctx->listpcapFree, struct pcap_item_s, list);
			xorg_list_del(&item->list);
			ctx->listpcapFreeDepth--;

			if (item->h->len < h->len)
				item->pkt = realloc(item->pkt, h->len);
		}

		memcpy(item->h, h, sizeof(*h));
		memcpy(item->pkt, pkt, h->len);
		xorg_list_append(&item->list, &ctx->listpcapUsed);
		ctx->listpcapUsedDepth++;

		/* Receiving thread isn't sitting on a semaphore, no point
		 * bradcasting a signal.
		 */

		ret = 0;

	} while (0);

	pthread_mutex_unlock(&ctx->lockpcap);

	return ret;
}

/* Called on the pcap thread, avoid all blocking. */
static void _processPackets_Stats(struct tool_context_s *ctx,
	struct ether_header *ethhdr, struct iphdr *iphdr, struct udphdr *udphdr,
	const uint8_t *pkts, uint32_t pktCount, int isRTP,
	const struct pcap_pkthdr *cb_h, const u_char *cb_pkt)
{
	struct discovered_item_s *di = discovered_item_findcreate(ctx, ethhdr, iphdr, udphdr);

	di->isRTP = isRTP;

	struct timeval diff;
	if (di->iat_last_frame.tv_sec) {
		ltn_histogram_timeval_subtract(&diff, (struct timeval *)&cb_h->ts, &di->iat_last_frame);
		di->iat_cur_us = ltn_histogram_timeval_to_us(&diff);
		if (di->iat_cur_us <= di->iat_lwm_us)
			di->iat_lwm_us = di->iat_cur_us;
		if (di->iat_cur_us >= di->iat_hwm_us)
			di->iat_hwm_us = di->iat_cur_us;

		ltn_histogram_interval_update(di->packetIntervals);
		//ltn_histogram_interval_print(STDOUT_FILENO, di->packetIntervals, 5);

		if (di->streamModel) {
			int complete;
			ltntstools_streammodel_write(di->streamModel, pkts, pktCount, &complete);
		}
	}
	di->iat_last_frame = cb_h->ts;

	ltntstools_pid_stats_update(&di->stats, pkts, pktCount);
}

/* Called on the stats thread */
static void _processPackets_IO(struct tool_context_s *ctx,
	struct ether_header *ethhdr, struct iphdr *iphdr, struct udphdr *udphdr,
	const uint8_t *pkts, uint32_t pktCount, int isRTP,
	const struct pcap_pkthdr *cb_h, const u_char *cb_pkt)
{
	struct discovered_item_s *di = discovered_item_findcreate(ctx, ethhdr, iphdr, udphdr);
	if (!di)
		return;

	time_t now;
	time(&now);

	di->isRTP = isRTP;

	if (isRTP) {
		if (ntohs(udphdr->uh_ulen) - 8 + 12 != (7 * 188)) {
        		di->notMultipleOfSevenError++;
        		time(&di->notMultipleOfSevenErrorLastEvent);
		}
	} else {
		if (ntohs(udphdr->uh_ulen) - 8 != (7 * 188)) {
        		di->notMultipleOfSevenError++;
        		time(&di->notMultipleOfSevenErrorLastEvent);
		}
	}

	if (discovered_item_state_get(di, DI_STATE_PCAP_RECORD_STOP)) {
		discovered_item_state_clr(di, DI_STATE_PCAP_RECORD_START);
		discovered_item_state_clr(di, DI_STATE_PCAP_RECORD_STOP);
		discovered_item_state_clr(di, DI_STATE_PCAP_RECORDING);

		ltntstools_segmentwriter_free(di->pcapRecorder);
		di->pcapRecorder = NULL;
	}
	if (discovered_item_state_get(di, DI_STATE_PCAP_RECORD_START)) {
		discovered_item_state_clr(di, DI_STATE_PCAP_RECORD_START);
		discovered_item_state_set(di, DI_STATE_PCAP_RECORDING);

		char prefix[512];
		char dirprefix[256] = "/tmp";
		if (ctx->recordingDir) {
			strcpy(dirprefix, ctx->recordingDir);
		}	
		sprintf(prefix, "%s/nic_monitor-%s-%s", dirprefix, ctx->ifname, di->dstaddr);

		/* Cleanup the filename so we don't have :, they mess up handing recordings via scp. */
		/* Substitute : for . */
		character_replace(prefix, ':', '.');

		int ret = ltntstools_segmentwriter_alloc(&di->pcapRecorder, prefix, ".pcap", ctx->recordWithSegments);
		if (ret < 0) {
			fprintf(stderr, "%s() unable to allocate a segment writer\n", __func__);
			exit(1);
		}

		struct pcap_file_header hdr;
		hdr.magic = 0xa1b2c3d4;
		hdr.version_major = PCAP_VERSION_MAJOR;
		hdr.version_minor = PCAP_VERSION_MINOR;
		hdr.thiszone = 0;
		hdr.sigfigs = 0;
		hdr.snaplen = 0x400000;
		hdr.linktype = DLT_EN10MB;

		ltntstools_segmentwriter_set_header(di->pcapRecorder, (const uint8_t *)&hdr, sizeof(hdr));
	}
	if (discovered_item_state_get(di, DI_STATE_PCAP_RECORDING)) {
		/* Dump the cb_h and cb_pkt payload to disk, via a thread. */
		/* Make sure the timestamps are 4 bytes long, not the native struct size
		 * for the running platform.
		 */

		void *obj = NULL;
		uint8_t *ptr = NULL;
		int ret = ltntstools_segmentwriter_object_alloc(di->pcapRecorder, 16 + cb_h->len, &obj, &ptr);
		if (ret < 0 || !ptr || !obj) {
			return;
		}

		uint8_t *dst = ptr;
		uint8_t *src = (uint8_t *)cb_h;

		memcpy(dst +  0, src +  0, 4);
		memcpy(dst +  4, src +  8, 4);
		memcpy(dst +  8, src + 16, 8);
		memcpy(dst + 16, cb_pkt, cb_h->len);

		ssize_t len = ltntstools_segmentwriter_object_write(di->pcapRecorder, obj);
		if (len < 0) {
			/* Now what? */
			/* Nothing */
		}

		/* Every 5 seconds */
		if (di->lastTimeFSFreeSpaceCheck + 5 <= now) {
			di->lastTimeFSFreeSpaceCheck = now;

			/* Deal with the case where the filesystem is above 90% and we want the recording
			 * to silently terminate. Abort recording if filesystem has 10% freespace or less.
			 */
			double fsfreepct = ltntstools_segmentwriter_get_freespace_pct(di->pcapRecorder);
			if (fsfreepct >= 0.0) {
				if (fsfreepct <= 10.0) {
					discovered_item_state_set(di, DI_STATE_PCAP_RECORD_STOP);
				}
			}
		}
	}
}

/* Called on the UI stream, and writes files to disk, handles recordings etc */
static void pcap_io_process(struct tool_context_s *ctx, const struct pcap_pkthdr *h, const u_char *pkt) 
{ 
	int isRTP = 0;

	if (h->len < sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr))
		return;

	struct ether_header *eth = (struct ether_header *)pkt;
	if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
		struct iphdr *ip = (struct iphdr *)((u_char *)eth + sizeof(struct ether_header));

#ifdef __APPLE__
		if (ip->ip_p != IPPROTO_UDP)
			return;
#endif
#ifdef __linux__
		if (ip->protocol != IPPROTO_UDP)
			return;
#endif

		struct udphdr *udp = (struct udphdr *)((u_char *)ip + sizeof(struct iphdr));
		uint8_t *ptr = (uint8_t *)((uint8_t *)udp + sizeof(struct udphdr));

		if (ctx->verbose) {
			struct in_addr dstaddr, srcaddr;
#ifdef __APPLE__
			srcaddr.s_addr = ip->ip_src.s_addr;
			dstaddr.s_addr = ip->ip_dst.s_addr;
#endif
#ifdef __linux__
			srcaddr.s_addr = ip->saddr;
			dstaddr.s_addr = ip->daddr;
#endif

			char src[24], dst[24];
			sprintf(src, "%s:%d", inet_ntoa(srcaddr), ntohs(udp->uh_sport));
			sprintf(dst, "%s:%d", inet_ntoa(dstaddr), ntohs(udp->uh_dport));

			printf("%s -> %s : %4d : %02x %02x %02x %02x\n",
				
				src, dst,
				ntohs(udp->uh_ulen),
				ptr[0], ptr[1], ptr[2], ptr[3]);
		}

		/* TODO: Handle RTP with FEC correctly. */

		if (ptr[0] != 0x47) {
			/* Make a rash assumption that's it's RTP where possible. */
			if (ptr[12] == 0x47) {
				ptr += 12;
				isRTP = 1;
			}
		}

		/* TS Packet, almost certainly */
		/* We can safely assume there are len / 188 packets. */
		int pktCount = ntohs(udp->uh_ulen) / 188;
		_processPackets_IO(ctx, eth, ip, udp, ptr, pktCount, isRTP, h, pkt);
	}
}

/* Called on the pcap thread */
void pcap_update_statistics(struct tool_context_s *ctx, const struct pcap_pkthdr *h, const u_char *pkt) 
{ 
	int isRTP = 0;

	if (h->len < sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr))
		return;

	struct ether_header *eth = (struct ether_header *)pkt;
	if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
		struct iphdr *ip = (struct iphdr *)((u_char *)eth + sizeof(struct ether_header));

#ifdef __APPLE__
		if (ip->ip_p != IPPROTO_UDP)
			return;
#endif
#ifdef __linux__
		if (ip->protocol != IPPROTO_UDP)
			return;
#endif

		struct udphdr *udp = (struct udphdr *)((u_char *)ip + sizeof(struct iphdr));
		uint8_t *ptr = (uint8_t *)((uint8_t *)udp + sizeof(struct udphdr));

		if (ctx->verbose) {
			struct in_addr dstaddr, srcaddr;
#ifdef __APPLE__
			srcaddr.s_addr = ip->ip_src.s_addr;
			dstaddr.s_addr = ip->ip_dst.s_addr;
#endif
#ifdef __linux__
			srcaddr.s_addr = ip->saddr;
			dstaddr.s_addr = ip->daddr;
#endif

			char src[24], dst[24];
			sprintf(src, "%s:%d", inet_ntoa(srcaddr), ntohs(udp->uh_sport));
			sprintf(dst, "%s:%d", inet_ntoa(dstaddr), ntohs(udp->uh_dport));

			printf("%s -> %s : %4d : %02x %02x %02x %02x\n",
				
				src, dst,
				ntohs(udp->uh_ulen),
				ptr[0], ptr[1], ptr[2], ptr[3]);
		}

		/* TODO: Handle RTP with FEC correctly. */

		if (ptr[0] != 0x47) {
			/* Make a rash assumption that's it's RTP where possible. */
			if (ptr[12] == 0x47) {
				ptr += 12;
				isRTP = 1;
			}
		}

		/* TS Packet, almost certainly */
		/* We can safely assume there are len / 188 packets. */
		int pktCount = ntohs(udp->uh_ulen) / 188;
		_processPackets_Stats(ctx, eth, ip, udp, ptr, pktCount, isRTP, h, pkt);
	}
}

/* Return the number of list items processed.
 * We're being called on the stats thread, so while we're
 * expected to take the listpcap lock, we do so for the shortest
 * amount of time possible, then do all of the expensive
 * analysis and filewriting tasks WHILE NOT holding the mutex.
 */
int pcap_queue_service(struct tool_context_s *ctx)
{
	int count = 0;

	pthread_mutex_lock(&ctx->lockpcap);
	if (xorg_list_is_empty(&ctx->listpcapUsed)) {
		pthread_mutex_unlock(&ctx->lockpcap);
		return count;
	}

	/* Move all of the Used buffers into a temporary list, its quick. */
	struct xorg_list items;
	xorg_list_init(&items);

	struct pcap_item_s *item = NULL;
	while (!xorg_list_is_empty(&ctx->listpcapUsed)) {
		item = xorg_list_first_entry(&ctx->listpcapUsed, struct pcap_item_s, list);
		xorg_list_del(&item->list);
		ctx->listpcapUsedDepth--;
		xorg_list_append(&item->list, &items);
		count++;
	}
	pthread_mutex_unlock(&ctx->lockpcap);

	/* Now, relatively, we can take as long as we like to process 'items'. */
	while (!xorg_list_is_empty(&items)) {
		item = xorg_list_first_entry(&items, struct pcap_item_s, list);
		xorg_list_del(&item->list);

		if (item->h && item->pkt) /* safety */
			pcap_io_process(ctx, item->h, item->pkt); 

		/* back on the free list */
		pthread_mutex_lock(&ctx->lockpcap);
		xorg_list_append(&item->list, &ctx->listpcapFree);
		ctx->listpcapFreeDepth++;
		pthread_mutex_unlock(&ctx->lockpcap);
	}

	time_t now;
	time(&now);

	if (ctx->rebalance_last_buffer_time != now) {
		ctx->rebalance_last_buffer_time = now;
		ctx->rebalance_last_buffers_used = ctx->rebalance_buffers_used;
		ctx->rebalance_buffers_used = 0;
	}
        ctx->rebalance_buffers_used += count;

	return count;
}

static void pcap_queue_free_reduce(struct tool_context_s *ctx, int bufferCount)
{
	pthread_mutex_lock(&ctx->lockpcap);
	while (bufferCount-- > 0 && ctx->listpcapFreeDepth > QUEUE_MIN) {
		if (xorg_list_is_empty(&ctx->listpcapFree))
			break;
		struct pcap_item_s *item = xorg_list_first_entry(&ctx->listpcapFree, struct pcap_item_s, list);
		xorg_list_del(&item->list);
		ctx->listpcapFreeDepth--;

		free(item->h);
		free(item->pkt);
		free(item);
	}
	pthread_mutex_unlock(&ctx->lockpcap);
}

/* Goal: To prevent the amount of free pcap buffers from remaining excessively
 * high after a significant I/O stall has caused additional free
 * buffers to be created, and they're now largely idle and consuming
 * ram. Remove them.
 */
int pcap_queue_rebalance(struct tool_context_s *ctx)
{
	time_t now;
	time(&now);

	if (ctx->rebalance_queue_time_last + 5 < now) {
		ctx->rebalance_queue_time_last = now;

		/* Try to keep 50% free buffers for platform stall/spikes. */
		double demand = (double)ctx->rebalance_last_buffers_used * 0.15;
		double avail = (double)ctx->listpcapFreeDepth;
		if (avail > demand) {
			double balance = avail - demand;
			if (balance > 100000) {
				pcap_queue_free_reduce(ctx, 100000);
			} else
			if (balance > 50000) {
				pcap_queue_free_reduce(ctx, 50000);
			} else
			if (balance > 20000) {
				pcap_queue_free_reduce(ctx, 20000);
			} else
			if (balance > 10000) {
				pcap_queue_free_reduce(ctx, 10000);
			}
		}
	}

	return 0;
}

