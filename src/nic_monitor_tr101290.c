
#include "nic_monitor.h"

static void *tr101290_cb(void *userContext, struct ltntstools_tr101290_alarm_s *array, int count)
{
	struct discovered_item_s *di = (struct discovered_item_s *)userContext;

	//printf("%s(%p, %d) XXXXXXXXX\n", __func__, array, count);

	pthread_mutex_lock(&di->trLock);
	if (di->trArray) {
		free(di->trArray);
		di->trArray = NULL;
		di->trCount = 0;
	}

	di->trArray = array;
	di->trCount = count;
	pthread_mutex_unlock(&di->trLock);

	for (int i = 0; i < count; i++) {
		//struct ltntstools_tr101290_alarm_s *ae = &array[i];
		//ltntstools_tr101290_event_dprintf(0, ae);
	}

	return NULL;
}

void nic_monitor_tr101290_free(struct discovered_item_s *di)
{
	if (di->trArray) {
		free(di->trArray);
		di->trArray = NULL;
	}
	if (di->trHandle) {
		ltntstools_tr101290_free(di->trHandle);
		di->trHandle = NULL;
	}
}

int nic_monitor_tr101290_alloc(struct discovered_item_s *di)
{
	int ret;

	if (ltntstools_tr101290_alloc(&di->trHandle, (ltntstools_tr101290_notification)tr101290_cb, di) < 0) {
		fprintf(stderr, "\nUnable to allocate tr101290 analyzer, it's safe to continue.\n\n");
		ret = -1;
	} else {
		ret = 0; /* Success */
	}

	pthread_mutex_init(&di->trLock, NULL);

	if (ret == 0) {
		char fname[512];
		char dirprefix[256] = "/tmp";
		if (di->ctx->recordingDir) {
			strcpy(dirprefix, di->ctx->recordingDir);
		}
		sprintf(fname, "%s/tr101290-%s-%s.log", dirprefix, di->ctx->ifname, di->dstaddr);

		/* Cleanup the filename so we don't have :, they mess up handing recordings via scp. */
		/* Substitute : for . */
		character_replace(fname, ':', '.');

		if (ltntstools_tr101290_log_enable(di->trHandle, fname) < 0) {
			fprintf(stderr, "\nUnable to create tr101290 analyzer log, will continue without logging.\n\n");
		}
	}

	return ret;
}

void nic_monitor_tr101290_reset(struct discovered_item_s *di)
{
	if (!di->trHandle)
		return;

	ltntstools_tr101290_reset_alarms(di->trHandle);
}

ssize_t nic_monitor_tr101290_write(struct discovered_item_s *di, const uint8_t *pkts, size_t packetCount)
{
	if (!di->trHandle)
		return -1;
		
	return ltntstools_tr101290_write(di->trHandle, pkts, packetCount);
}

void nic_monitor_tr101290_draw_ui(struct discovered_item_s *di, int *sc, int p1col, int p2col)
{
	/* Prevent our 101290 callback avoe from touching this while we're rendering results. */
	pthread_mutex_lock(&di->trLock);

	struct ltntstools_tr101290_summary_item_s *items;
	int itemCount;
	if (ltntstools_tr101290_summary_get(di->trHandle, &items, &itemCount) < 0) {
		pthread_mutex_unlock(&di->trLock);
		return;
	}

	int streamCount = *sc;

	/* Everything RED until further notice */

	char *stateDesc[] = { "OK ", "BAD" };

	for (int i = 0; i < itemCount; i++) {
		struct ltntstools_tr101290_summary_item_s *item = &items[i];
		if (item->enabled == 0)
			continue;

		char *sl = stateDesc[0];

		if (item->raised) {
			sl = stateDesc[1];
			attron(COLOR_PAIR(3));
		}

		int cols[] = { 0, p1col, p2col, p2col };
		int col = cols[ item->priorityNr ];

		switch (item->id) {
		case E101290_P1_1__TS_SYNC_LOSS:
			mvprintw(streamCount + 2, col, "P1.1  %s [SYNC LOSS]", sl);
			break;
		case E101290_P1_2__SYNC_BYTE_ERROR:
			mvprintw(streamCount + 3, col, "P1.2  %s [SYNC BYTE]", sl);
			break;
		case E101290_P1_3__PAT_ERROR:
			mvprintw(streamCount + 4, col, "P1.3  %s [PAT      ]", sl);
			break;
		case E101290_P1_3a__PAT_ERROR_2:
			mvprintw(streamCount + 5, col, "P1.3a %s [PAT 2    ]", sl);
			break;
		case E101290_P1_4__CONTINUITY_COUNTER_ERROR:
			mvprintw(streamCount + 6, col, "P1.4  %s [CC       ]", sl);
			break;
		case E101290_P1_5__PMT_ERROR:
			mvprintw(streamCount + 7, col, "P1.5  %s [PMT      ]", sl);
			break;
		case E101290_P1_5a__PMT_ERROR_2:
			mvprintw(streamCount + 8, col, "P1.5a %s [PMT 2    ]", sl);
			break;
		case E101290_P1_6__PID_ERROR:
			mvprintw(streamCount + 9, col, "P1.6  %s [PID      ] %s", sl, item->arg);
			break;
		case E101290_P2_1__TRANSPORT_ERROR:
			mvprintw(streamCount + 2, col, "P2.1  %s [TRANSPORT TEI ]", sl);
			break;
		case E101290_P2_2__CRC_ERROR:
			mvprintw(streamCount + 3, col, "P2.2  %s [CRC           ] %s", sl, item->arg);
			break;
		case E101290_P2_3__PCR_ERROR:
			mvprintw(streamCount + 4, col, "P2.3  %s [PCR           ] %s", sl, item->arg);
			break;
		case E101290_P2_3a__PCR_REPETITION_ERROR:
			mvprintw(streamCount + 5, col, "P2.3a %s [PCR REPETITION] %s", sl, item->arg);
			break;
		case E101290_P2_4__PCR_ACCURACY_ERROR:
			mvprintw(streamCount + 6, col, "P2.4  %s [PCR ACCURACY  ]", sl);
			break;
		case E101290_P2_5__PTS_ERROR:
			mvprintw(streamCount + 7, col, "P2.5  %s [PTS           ]", sl);
			break;
		case E101290_P2_6__CAT_ERROR:
			mvprintw(streamCount + 8, col, "P2.6  %s [CAT           ]", sl);
			break;
		default:
			//mvprintw(streamCount + 2, col, "%s %s", ltntstools_tr101290_event_name_ascii(ae->id), ae->description);
			break;
		}

		if (item->raised) {
			attroff(COLOR_PAIR(3));
		}
	}
	if (items) {
		free(items);
	}

	(*sc) += 8;
	
	pthread_mutex_unlock(&di->trLock);
}