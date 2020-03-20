/* Copyright LiveTimeNet, Inc. 2017. All Rights Reserved. */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <math.h>
#include <inttypes.h>

#include <libltntstools/ltntstools.h>
#include "dump.h"

static int gDumpAll = 0;
static int gPMTCount = 0;
static int gVerbose = 0;

static uint16_t i_program_number, i_pmt_pid;

static void DumpPMT(void *p_zero, dvbpsi_pmt_t *p_pmt)
{
  tstools_DumpPMT(p_zero, p_pmt, gVerbose > 0, i_pmt_pid);
  dvbpsi_pmt_delete(p_pmt);
  gPMTCount++;
}

/*****************************************************************************
 * main
 *****************************************************************************/
int pmt_inspector(int i_argc, char* pa_argv[])
{
  int i_fd;
  uint8_t data[188];
  dvbpsi_t *p_dvbpsi;
  bool b_ok;

  if (i_argc != 4)
    return 1;

  i_fd = open(pa_argv[1], 0);
  if (i_fd < 0)
      return 1;

  i_program_number = atoi(pa_argv[2]);
  i_pmt_pid = atoi(pa_argv[3]);

  p_dvbpsi = dvbpsi_new(&tstools_message, DVBPSI_MSG_NONE);
  if (p_dvbpsi == NULL)
        goto out;

  if (!dvbpsi_pmt_attach(p_dvbpsi, i_program_number, DumpPMT, NULL))
      goto out;

  b_ok = tstools_ReadPacket(i_fd, data);

  while(b_ok)
  {
    uint16_t i_pid = ((uint16_t)(data[1] & 0x1f) << 8) + data[2];
    if(i_pid == i_pmt_pid)
      dvbpsi_packet_push(p_dvbpsi, data);
    b_ok = tstools_ReadPacket(i_fd, data);

		if (gPMTCount && !gDumpAll)
			break;
  }

out:
  if (p_dvbpsi)
  {
    dvbpsi_pmt_detach(p_dvbpsi);
    dvbpsi_delete(p_dvbpsi);
  }
  close(i_fd);

  return 0;
}

