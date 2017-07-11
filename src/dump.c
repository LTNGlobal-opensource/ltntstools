/* Copyright LiveTimeNet, Inc. 2017. All Rights Reserved. */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>
#include <math.h>

#include "dump.h"


#define VIDEO_STREAM_DR		0xF2
#define CA_DR			0x09
#define SYSTEM_CLOCK_DR		0x0B
#define MAX_BITRATE_DR		0x0E
#define STREAM_IDENTIFIER_DR	0x52
#define SUBTITLING_DR		0x59

char *tstools_GetTypeName(uint8_t type)
{
  switch (type)
    {
    case 0x00: return "Reserved";
    case 0x01: return "ISO/IEC 11172 Video";
    case 0x02: return "ISO/IEC 13818-2 Video";
    case 0x03: return "ISO/IEC 11172 Audio";
    case 0x04: return "ISO/IEC 13818-3 Audio";
    case 0x05: return "ISO/IEC 13818-1 Private Section";
    case 0x06: return "ISO/IEC 13818-1 Private PES data packets";
    case 0x07: return "ISO/IEC 13522 MHEG";
    case 0x08: return "ISO/IEC 13818-1 Annex A DSM CC";
    case 0x09: return "H222.1";
    case 0x0A: return "ISO/IEC 13818-6 type A";
    case 0x0B: return "ISO/IEC 13818-6 type B";
    case 0x0C: return "ISO/IEC 13818-6 type C";
    case 0x0D: return "ISO/IEC 13818-6 type D";
    case 0x0E: return "ISO/IEC 13818-1 auxillary";
    case 0x0F: return "ISO/IEC 13818-7 Audio with ADTS transport syntax - usually AAC";
    case 0x1B: return "H.264 Video";
    case 0x81: return "ATSC AC-3 Audio";
    default:
      if (type < 0x80)
        return "ISO/IEC 13818-1 reserved";
      else
        return "User Private";
    }
}

static void DumpCADescriptor(dvbpsi_mpeg_ca_dr_t *p_ca_descriptor)
{
	printf("CA: System %04x PID %04x\n",
		p_ca_descriptor->i_ca_system_id,
		p_ca_descriptor->i_ca_pid);
}

static void DumpMaxBitrateDescriptor(dvbpsi_mpeg_max_bitrate_dr_t* bitrate_descriptor)
{
  printf("Bitrate: %d\n", bitrate_descriptor->i_max_bitrate);
}

static void DumpSystemClockDescriptor(dvbpsi_mpeg_system_clock_dr_t* p_clock_descriptor)
{
  printf("External clock: %s, Accuracy: %E\n",
     p_clock_descriptor->b_external_clock_ref ? "Yes" : "No",
     p_clock_descriptor->i_clock_accuracy_integer *
     pow(10.0, -(double)p_clock_descriptor->i_clock_accuracy_exponent));
}

static void DumpStreamIdentifierDescriptor(dvbpsi_dvb_stream_identifier_dr_t* p_si_descriptor)
{
  printf("Component tag: %d\n",
     p_si_descriptor->i_component_tag);
}

static void DumpSubtitleDescriptor(dvbpsi_dvb_subtitling_dr_t* p_subtitle_descriptor)
{
  int a;

  printf("%d subtitles,\n", p_subtitle_descriptor->i_subtitles_number);
  for (a = 0; a < p_subtitle_descriptor->i_subtitles_number; ++a)
    {
      printf("       | %d - lang: %c%c%c, type: %d, cpid: %d, apid: %d\n", a,
         p_subtitle_descriptor->p_subtitle[a].i_iso6392_language_code[0],
         p_subtitle_descriptor->p_subtitle[a].i_iso6392_language_code[1],
         p_subtitle_descriptor->p_subtitle[a].i_iso6392_language_code[2],
         p_subtitle_descriptor->p_subtitle[a].i_subtitling_type,
         p_subtitle_descriptor->p_subtitle[a].i_composition_page_id,
         p_subtitle_descriptor->p_subtitle[a].i_ancillary_page_id);
    }
}

static void DumpVideoStreamDescriptor(dvbpsi_mpeg_vstream_dr_t *d)
{
	printf("Video Stream: frame_rate_code 0x%02x\n",
		d->i_frame_rate_code);
}

void tstools_DumpDescriptors(const char* str, dvbpsi_descriptor_t* p_descriptor)
{
  int i;

  while(p_descriptor)
  {
    printf("%s%02x %02x : ", str, p_descriptor->i_tag, p_descriptor->i_length);
    for (int x = 0; x < p_descriptor->i_length; x++)
        printf("%02x ", p_descriptor->p_data[x]);
    printf("- ");

    switch (p_descriptor->i_tag)
      {
      case SYSTEM_CLOCK_DR:
    DumpSystemClockDescriptor(dvbpsi_decode_mpeg_system_clock_dr(p_descriptor));
    break;
      case MAX_BITRATE_DR:
    DumpMaxBitrateDescriptor(dvbpsi_decode_mpeg_max_bitrate_dr(p_descriptor));
    break;
      case STREAM_IDENTIFIER_DR:
    DumpStreamIdentifierDescriptor(dvbpsi_decode_dvb_stream_identifier_dr(p_descriptor));
    break;
      case SUBTITLING_DR:
	    DumpSubtitleDescriptor(dvbpsi_decode_dvb_subtitling_dr(p_descriptor));
	    break;
	case CA_DR:
		DumpCADescriptor((dvbpsi_mpeg_ca_dr_t *)p_descriptor);
		break;
		case VIDEO_STREAM_DR:
			DumpVideoStreamDescriptor((dvbpsi_mpeg_vstream_dr_t *)p_descriptor);
			break;
      default:
    printf("\"");
    for(i = 0; i < p_descriptor->i_length; i++)
      printf("%c", p_descriptor->p_data[i]);
    printf("\"\n");
      }
    p_descriptor = p_descriptor->p_next;
  }
};

void tstools_DumpPAT(void* p_zero, dvbpsi_pat_t* p_pat)
{
	dvbpsi_pat_program_t* p_program = p_pat->p_first_program;
	printf("PAT -- transport_stream_id = 0x%04x  ", p_pat->i_ts_id);
	printf("version_number = %d  ", p_pat->i_version);
	printf("current_next = %d\n", p_pat->b_current_next);

	int i = 0;
	while(p_program) {
		printf("  [%02d] program_number = %d, pid = 0x%04x (%d)\n",
			i, p_program->i_number, p_program->i_pid, p_program->i_pid);

		p_program = p_program->p_next;
	}
}

void tstools_DumpPMT(void *p_zero, dvbpsi_pmt_t *p_pmt)
{
  dvbpsi_pmt_es_t *p_es = p_pmt->p_first_es;
  printf("PMT -- program_number = %d  ", p_pmt->i_program_number);
  printf("version_number = %d  ", p_pmt->i_version);
  printf("PCR_PID = 0x%x (%d)\n", p_pmt->i_pcr_pid, p_pmt->i_pcr_pid);
  tstools_DumpDescriptors("       -> descr ", p_pmt->p_first_descriptor);
  while(p_es)
  {
    printf("       stream_type = 0x%02x pid 0x%x (%d) [%s]\n",
           p_es->i_type,
       p_es->i_pid, p_es->i_pid,
       tstools_GetTypeName(p_es->i_type));
    tstools_DumpDescriptors("         -> descr ", p_es->p_first_descriptor);
    p_es = p_es->p_next;
  }
}

void tstools_message(dvbpsi_t *handle, const dvbpsi_msg_level_t level, const char* msg)
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
