#ifndef OBE_TIMECODE_H
#define OBE_TIMECODE_H

/* 
 * Helper functions to hand various timecodes used across the s/w stack.
 * obe internals timecode primarily.
 *
 * Implement a small state machine that tarcks timecodes and
 * determines timejumps, discontinuities.
 */

#include <stdio.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/time.h>

struct timecode_s
{
	int hours, minutes, seconds, frame;
	int corrected_frame;
};

/* Don't touch these fields directly.
 * only use accessors, or add new fcuntions if neederd.
 */
struct timecode_context_s
{
	int discontinuity;
	int dup_time;
	uint32_t intendedFPS;
	struct timecode_s curr;
	struct timecode_s prev;
	struct timeval lastDiscontinuity;
};

void obe_timecode_clear(struct timecode_context_s *ctx, uint32_t intendedFPS);
void obe_timecode_reset(struct timecode_context_s *ctx);
void obe_timecode_update(struct timecode_context_s *ctx, unsigned int hrs, unsigned int mins, unsigned int secs, unsigned int frame);
int  obe_timecode_get_discontinuity(struct timecode_context_s *ctx);
int  obe_timecode_get_corrected_frame(struct timecode_context_s *ctx);

#endif /* OBE_TIMECODE_H */
