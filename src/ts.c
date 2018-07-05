#include "ts.h"
#include <inttypes.h>

/* Convert a pcr base + extension field back into a 27MHz System Clock reference value.
 * Ptr points to a 6 byte raw data, which we'll parse.
 * The Adaption spec calls for the PCR to have the following format:
 * program_clock_reference_base       33bits
 * reserved                            6bits
 * program_clock_reference_extension   9bits
 */
uint64_t kl_iso13818_pcrToScr(unsigned char *ptr, int len)
{
        uint64_t pcr_base;
        pcr_base  = (((uint64_t)*(ptr + 0)) << 25);
        pcr_base |= (((uint64_t)*(ptr + 1)) << 17);
        pcr_base |= (((uint64_t)*(ptr + 2)) <<  9);
        pcr_base |= (((uint64_t)*(ptr + 3)) <<  1);
        pcr_base |= (((uint64_t)*(ptr + 4)) >>  7);
        pcr_base &= 0x1ffffffffLL;

        uint64_t pcr_ext;
        pcr_ext  = ((uint64_t)*(ptr + 4)) << 8;
        pcr_ext |= ((uint64_t)*(ptr + 5));
        pcr_ext &= 0x1ff;

        return (pcr_base * 300) + pcr_ext;
}

int ltn_iso13818_scr(uint8_t *pkt, uint64_t *scr)
{
	if (ltn_iso13818_sync_present(pkt) == 0)
		return -1;

	if (ltn_iso13818_adaption_field_control(pkt) < 2)
		return -1;

	uint8_t adaption_field_length = *(pkt + 4);
	if (adaption_field_length == 0)
		return -1;

	/* Extract the PCR -- See ISO13818 Table 2.7 */

	/* Ensure PCR_flag is set. */
	if ((*(pkt + 5) & 0x10) == 0)
		return -1;

	uint64_t v = kl_iso13818_pcrToScr(pkt + 6, 6);
	*scr = v;

	return 0;
}

int ltn_iso13818_contains_pes_header(uint8_t *pkt, int len)
{
	const char pattern[] = { 0x00, 0x00, 0x01 };
	for (int i = 0; i < len - 4; i++) {
		if (memcmp(pkt + i, pattern, sizeof(pattern)) == 0)
			return i;
	}

	return -1;
}

