/* Copyright LiveTimeNet, Inc. 2017. All Rights Reserved. */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>
#include <math.h>
#include <ctype.h>

#include "dump.h"

#define DATA_STREAM_ALIGNMENT_DR		    0x06
#define VIDEO_STREAM_DR		    0xF2
#define CA_DR			            0x09
#define SMOOTHING_DR	            0x10
#define ISO639_LANGUAGE_DR	    0x0A
#define SYSTEM_CLOCK_DR		    0x0B
#define MAX_BITRATE_DR		    0x0E
#define STREAM_IDENTIFIER_DR	0x52
#define TELETEXT_DR		    0x56
#define SUBTITLING_DR		      0x59
#define CUE_IDENTIFICATION_DR 0x8a
#define REGISTRATION_DR       0x05

int tstools_ReadPacket(int fd, uint8_t *dst)
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
    case 0x32: return "JPEG-XS Video";
    case 0x81: return "ATSC AC-3 Audio";
    default:
      if (type < 0x80)
        return "ISO/IEC 13818-1 reserved";
      else
        return "User Private";
    }
}

static void DumpSmoothingDescriptor(dvbpsi_smoothing_buffer_dr_t *d)
{
	printf("Smoothing: leak rate %d, size %d\n",
		d->i_sb_leak_rate,
		d->i_sb_size);
}

static void DumpCADescriptor(dvbpsi_ca_dr_t *p_ca_descriptor)
{
	printf("CA: System %04x PID %04x\n",
		p_ca_descriptor->i_ca_system_id,
		p_ca_descriptor->i_ca_pid);
}

static void DumpMaxBitrateDescriptor(dvbpsi_max_bitrate_dr_t* bitrate_descriptor)
{
  printf("Bitrate: %d\n", bitrate_descriptor->i_max_bitrate);
}

static void DumpSystemClockDescriptor(dvbpsi_system_clock_dr_t* p_clock_descriptor)
{
  printf("External clock: %s, Accuracy: %E\n",
     p_clock_descriptor->b_external_clock_ref ? "Yes" : "No",
     p_clock_descriptor->i_clock_accuracy_integer *
     pow(10.0, -(double)p_clock_descriptor->i_clock_accuracy_exponent));
}

static void DumpISO639LanguageDescriptor(dvbpsi_iso639_dr_t* p_lang_descriptor)
{
  for (int i = 0; i < p_lang_descriptor->i_code_count; i++) {
    printf("iso639 '%c%c%c' type: %s\n",
      p_lang_descriptor->code[i].iso_639_code[0],
      p_lang_descriptor->code[i].iso_639_code[1],
      p_lang_descriptor->code[i].iso_639_code[2],
      p_lang_descriptor->code[i].i_audio_type == 0 ? "Undefined" :
      p_lang_descriptor->code[i].i_audio_type == 1 ? "Clean effects" :
      p_lang_descriptor->code[i].i_audio_type == 2 ? "Hearing impaired" :
      p_lang_descriptor->code[i].i_audio_type == 3 ? "Visual impaired commentary" : "Reserved");
  }
}

static void DumpStreamIdentifierDescriptor(dvbpsi_stream_identifier_dr_t* p_si_descriptor)
{
  printf("Component tag: %d\n",
     p_si_descriptor->i_component_tag);
}

static char *teletextTypeASCII(int nr)
{
  switch(nr) {
    case 1: return "initial";
    case 2: return "subtitle";
    case 3: return "additional info";
    case 4: return "programme schedule";
    case 5: return "subtitle hearing imparied";
    default: return "reserved";
  }
}

static void DumpTeletextDescriptor(dvbpsi_teletext_dr_t* p_ttx_descriptor)
{
  for (int i = 0; i < p_ttx_descriptor->i_pages_number; i++) {
    int pagenr = p_ttx_descriptor->p_pages[i].i_teletext_page_number;
    if (p_ttx_descriptor->p_pages[i].i_teletext_magazine_number == 0) {
        pagenr |= 0x800;
    } else {
        pagenr |= (p_ttx_descriptor->p_pages[i].i_teletext_magazine_number << 8);
    }
    printf("Teletext: lang %c%c%c, magazine %d, page 0x%x [%3x], type 0x%x [ %s ]\n",
        p_ttx_descriptor->p_pages[i].i_iso6392_language_code[0],
        p_ttx_descriptor->p_pages[i].i_iso6392_language_code[1],
        p_ttx_descriptor->p_pages[i].i_iso6392_language_code[2],
        p_ttx_descriptor->p_pages[i].i_teletext_magazine_number,
        p_ttx_descriptor->p_pages[i].i_teletext_page_number,
        pagenr,
        p_ttx_descriptor->p_pages[i].i_teletext_type,
        teletextTypeASCII(p_ttx_descriptor->p_pages[i].i_teletext_type));
  }
}

static void DumpSubtitleDescriptor(dvbpsi_subtitling_dr_t* p_subtitle_descriptor)
{
  int a;

  printf("%d subtitles:\n", p_subtitle_descriptor->i_subtitles_number);
  for (a = 0; a < p_subtitle_descriptor->i_subtitles_number; ++a)
    {
      printf("            [%d] - lang: %c%c%c, type: %d, cpid: %d, apid: %d\n", a,
         p_subtitle_descriptor->p_subtitle[a].i_iso6392_language_code[0],
         p_subtitle_descriptor->p_subtitle[a].i_iso6392_language_code[1],
         p_subtitle_descriptor->p_subtitle[a].i_iso6392_language_code[2],
         p_subtitle_descriptor->p_subtitle[a].i_subtitling_type,
         p_subtitle_descriptor->p_subtitle[a].i_composition_page_id,
         p_subtitle_descriptor->p_subtitle[a].i_ancillary_page_id);
    }
}

static void DumpVideoStreamDescriptor(dvbpsi_vstream_dr_t *d)
{
	printf("Video Stream: frame_rate_code 0x%02x\n",
		d->i_frame_rate_code);
}

static const char *cue_stream_type_descriptions[] = 
{
  "splice_insert, splice_null, splice_schedule",
  "All Commands",
  "Segmentation",
  "Tiered Splicing",
  "Tiered Segmentation",
  "Reserved",
  "User Defined"
};

static void DumpCueIdentificationDescriptor(dvbpsi_cuei_dr_t *p_descriptor)
{
  if (p_descriptor == NULL) {
    printf("Cue Identification -- Bug in libdvbpsi, avoiding segfault\n");
  } else {
    const char *desc = cue_stream_type_descriptions[5];
    if (p_descriptor->i_cue_stream_type <= 4)
      desc = cue_stream_type_descriptions[p_descriptor->i_cue_stream_type];
    else
    if (p_descriptor->i_cue_stream_type >= 0x80)
      desc = cue_stream_type_descriptions[6];

  	printf("Cue Identification: 0x%02x [%s]\n", p_descriptor->i_cue_stream_type, desc);
  }
}

static void DumpDataStreamAlignmentDescriptor(dvbpsi_ds_alignment_dr_t *p_descriptor)
{
	printf("Data Stream Alignment: 0x%02x\n", p_descriptor->i_alignment_type);
}

static void DumpRegistrationDescriptor(dvbpsi_registration_dr_t *p_descriptor)
{
  char b[5] = {
    p_descriptor->i_format_identifier >> 24,
    p_descriptor->i_format_identifier >> 16,
    p_descriptor->i_format_identifier >> 8,
    p_descriptor->i_format_identifier,
    0
  };

  for (int i = 0; i < 4; i++) {
    if (!isprint(b[i]))
      b[i] = '.';
  }
	printf("Registration: 0x%x [%s]\n", p_descriptor->i_format_identifier, b);
}

static void DumpAVCVideoDescriptor(const char* str, dvbpsi_descriptor_t* p_descriptor)
{
  uint8_t profile_idc = p_descriptor->p_data[0];

  uint8_t constraint_set_flag[6];      
  constraint_set_flag[0] = (p_descriptor->p_data[1] >> 7) & 1;
  constraint_set_flag[1] = (p_descriptor->p_data[1] >> 6) & 1;
  constraint_set_flag[2] = (p_descriptor->p_data[1] >> 5) & 1;
  constraint_set_flag[3] = (p_descriptor->p_data[1] >> 4) & 1;
  constraint_set_flag[4] = (p_descriptor->p_data[1] >> 3) & 1;
  constraint_set_flag[5] = (p_descriptor->p_data[1] >> 2) & 1;

  uint8_t AVC_compatible_flags = p_descriptor->p_data[1] & 0x03;

  uint8_t level_idc = p_descriptor->p_data[2];
  uint8_t AVC_still_present = (p_descriptor->p_data[3] >> 7) & 1;
  uint8_t AVC_24_hour_picture_flag = (p_descriptor->p_data[3] >> 6) & 1;
  uint8_t Frame_Packing_SEI_not_present_flag = (p_descriptor->p_data[3] >> 5) & 1;

  /* This is a little loosy goosy, should be a common func and doesn't take into consideration the constraint sets */
  printf("AVC_Video_descriptor: profile_idc = %s? [0x%02x], level_idc = %3.1f\n",
    profile_idc == 66 ? "Baseline" :
    profile_idc == 77 ? "Main" :
    profile_idc == 44 ? "High" :
    profile_idc == 88 ? "Main" :
    profile_idc == 100 ? "High" :
    profile_idc == 110 ? "High" :
    profile_idc == 122 ? "High" :
    profile_idc == 224 ? "High" : "Unknown",
    profile_idc,
    ((double)level_idc) / 10.0);
  printf("%50s constraint_set0..5_flags = %d %d %d %d %d %d",
    "",
    constraint_set_flag[0],
    constraint_set_flag[1],
    constraint_set_flag[2],
    constraint_set_flag[3],
    constraint_set_flag[4],
    constraint_set_flag[5]
    );
  printf(", AVC_compatible_flags = 0x%02x\n", AVC_compatible_flags);
  printf("%50s AVC_still_present = %d", "", AVC_still_present);
  printf(", AVC_24_hour_picture_flag = %d", AVC_24_hour_picture_flag);
  printf(", Frame_Packing_SEI_not_present_flag = %d\n", Frame_Packing_SEI_not_present_flag);

}

void tstools_DumpDescriptors(const char* str, dvbpsi_descriptor_t* p_descriptor)
{
  while(p_descriptor) {
    printf("%s%02x %02x : ", str, p_descriptor->i_tag, p_descriptor->i_length);
    for (int x = 0; x < p_descriptor->i_length; x++)
      printf("%02x ", p_descriptor->p_data[x]);
    printf("- ");

    switch (p_descriptor->i_tag) {
    case ISO639_LANGUAGE_DR:
      DumpISO639LanguageDescriptor(dvbpsi_DecodeISO639Dr(p_descriptor));
      break;
    case SYSTEM_CLOCK_DR:
      DumpSystemClockDescriptor(dvbpsi_DecodeSystemClockDr(p_descriptor));
      break;
    case MAX_BITRATE_DR:
      DumpMaxBitrateDescriptor(dvbpsi_DecodeMaxBitrateDr(p_descriptor));
      break;
    case STREAM_IDENTIFIER_DR:
      DumpStreamIdentifierDescriptor(dvbpsi_DecodeStreamIdentifierDr(p_descriptor));
      break;
    case TELETEXT_DR:
      DumpTeletextDescriptor(dvbpsi_DecodeTeletextDr(p_descriptor));
      break;
    case SUBTITLING_DR:
      DumpSubtitleDescriptor(dvbpsi_DecodeSubtitlingDr(p_descriptor));
      break;
    case CA_DR:
      DumpCADescriptor(dvbpsi_DecodeCADr(p_descriptor));
      break;
    case SMOOTHING_DR:
      DumpSmoothingDescriptor(dvbpsi_DecodeSmoothingBufferDr(p_descriptor));
      break;
    case VIDEO_STREAM_DR:
      DumpVideoStreamDescriptor(dvbpsi_DecodeVStreamDr(p_descriptor));
      break;
    case CUE_IDENTIFICATION_DR:
      DumpCueIdentificationDescriptor(dvbpsi_DecodeCUEIDr(p_descriptor));
      break;
    case DATA_STREAM_ALIGNMENT_DR:
      DumpDataStreamAlignmentDescriptor(dvbpsi_DecodeDSAlignmentDr(p_descriptor));
      break;
    case REGISTRATION_DR:
      DumpRegistrationDescriptor(dvbpsi_DecodeRegistrationDr(p_descriptor));
      break;
    case 0x28: /* AVC_VIDEO_DESCRIPTOR */
      DumpAVCVideoDescriptor(str, p_descriptor);
      break;
    default:
      printf("\"");
      for(int i = 0; i < p_descriptor->i_length; i++)
        printf("%c", isprint(p_descriptor->p_data[i]) ? p_descriptor->p_data[i] : '.');
      printf("\"\n");
    }
    p_descriptor = p_descriptor->p_next;
  }
};

void tstools_DumpPAT(void* p_zero, dvbpsi_pat_t* p_pat)
{
	dvbpsi_pat_program_t* p_program = p_pat->p_first_program;
	printf("PAT -- transport_stream_id = 0x%04x (%d)  ", p_pat->i_ts_id, p_pat->i_ts_id);
	printf("version_number = %d  ", p_pat->i_version);
	printf("current_next = %d\n", p_pat->b_current_next);

	int i = 0;
	while(p_program) {
		printf("  [%02d] program_number = %d, pid = 0x%04x (%d)\n",
			i, p_program->i_number, p_program->i_pid, p_program->i_pid);

		p_program = p_program->p_next;
	}
}

void tstools_DumpPMT(void *p_zero, dvbpsi_pmt_t *p_pmt, int dumpDescriptors, uint16_t pid)
{
  dvbpsi_pmt_es_t *p_es = p_pmt->p_first_es;
  printf("PMT -- program_number = %d  pid = 0x%04x  ",
    p_pmt->i_program_number,
    pid);

  printf("version_number = %d  ", p_pmt->i_version);
  printf("PCR_PID = 0x%04x (%d)\n", p_pmt->i_pcr_pid, p_pmt->i_pcr_pid);
  if (dumpDescriptors)
    tstools_DumpDescriptors("       -> program descriptors ", p_pmt->p_first_descriptor);

  int es_position = 0;
  while(p_es)
  {
    printf("       [%02d] stream_type = 0x%02x, pid = 0x%04x (%d) [%s]\n",
      es_position++,
      p_es->i_type,
      p_es->i_pid, p_es->i_pid,
      tstools_GetTypeName(p_es->i_type));
    if (dumpDescriptors)
      tstools_DumpDescriptors("         -> es descriptors ", p_es->p_first_descriptor);
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
