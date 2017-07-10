/* Copyright LiveTimeNet, Inc. 2017. All Rights Reserved. */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>
#include <dvbpsi/dvbpsi.h>
#include <dvbpsi/psi.h>
#include <dvbpsi/pat.h>

static int gDumpAll = 0;
static int gPATCount = 0;
static int gVerbose = 0;

static int ReadPacket(int fd, uint8_t *dst)
{
	int i = 187;
	int rc = 1;

	dst[0] = 0;

 	while((dst[0] != 0x47) && (rc > 0)) {
		rc = read(fd, dst, 1);
 	}

	while((i != 0) && (rc > 0)) {
		rc = read(fd, dst + 188 - i, i);
		if (rc >= 0)
			i -= rc;
	}

	return (i == 0) ? true : false;
}

static void DumpPAT(void* p_zero, dvbpsi_pat_t* p_pat)
{
	dvbpsi_pat_program_t* p_program = p_pat->p_first_program;
	printf("transport_stream_id = 0x%04x\n", p_pat->i_ts_id);
	printf("version_number      = %d\n", p_pat->i_version);
	printf("current_next        = %d\n", p_pat->b_current_next);

	int i = 0;
	while(p_program) {
		printf("  [%02d] program_number = %d, pid = 0x%04x (%d)\n",
			i, p_program->i_number, p_program->i_pid, p_program->i_pid);

		p_program = p_program->p_next;
	}
	dvbpsi_pat_delete(p_pat);
	gPATCount++;
}

static void message(dvbpsi_t *handle, const dvbpsi_msg_level_t level, const char* msg)
{
	switch(level) {
        case DVBPSI_MSG_ERROR: fprintf(stderr, "Error: "); break;
        case DVBPSI_MSG_WARN:  fprintf(stderr, "Warning: "); break;
        case DVBPSI_MSG_DEBUG: fprintf(stderr, "Debug: "); break;
        default: /* do nothing */
            return;
	}
	fprintf(stderr, "%s\n", msg);
}

static void usage(const char *progname)
{
	printf("A tool to display one or more PAT structures from a ISO13818 transport stream.\n");
	printf("Usage:\n");
	printf("  -i <inputfile.ts>\n");
	printf("  -v Increase level of verbosity.\n");
	printf("  -h Display command line help.\n");
}

int pat_inspector(int argc, char *argv[])
{
	int ch;
	int i_fd;
	uint8_t data[188];
	dvbpsi_t *p_dvbpsi;
	bool b_ok;
	char *iname = NULL;

	while ((ch = getopt(argc, argv, "a?hvi:")) != -1) {
		switch (ch) {
		case 'a':
			gDumpAll = 1;
			break;
		case '?':
		case 'h':
			usage(argv[0]);
			exit(1);
			break;
		case 'i':
			iname = optarg;
			break;
		case 'v':
			gVerbose = 1;
			break;
		default:
			usage(argv[0]);
			exit(1);
		}
	}

	if (iname == NULL) {
		fprintf(stderr, "-i is mandatory.\n");
		exit(1);
	}

	i_fd = open(iname, 0);
	if (i_fd < 0)
		return 1;

	if (gVerbose)
		p_dvbpsi = dvbpsi_new(&message, DVBPSI_MSG_DEBUG);
	else
		p_dvbpsi = dvbpsi_new(&message, DVBPSI_MSG_NONE);
	if (p_dvbpsi == NULL)
		goto out;

	if (!dvbpsi_pat_attach(p_dvbpsi, DumpPAT, NULL))
		goto out;

	b_ok = ReadPacket(i_fd, data);

	while(b_ok)
	{
		uint16_t i_pid = ((uint16_t)(data[1] & 0x1f) << 8) + data[2];
		if(i_pid == 0x0)
			dvbpsi_packet_push(p_dvbpsi, data);
		b_ok = ReadPacket(i_fd, data);

		if (gPATCount && !gDumpAll)
			break;
	}

out:
	if (p_dvbpsi) {
		dvbpsi_pat_detach(p_dvbpsi);
		dvbpsi_delete(p_dvbpsi);
	}
	close(i_fd);

	return 0;
}
