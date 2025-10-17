#include "timecode.h"

#include <stdlib.h>
#include <string.h>

#define LOCAL_DEBUG 0
#define MESSAGE_PREFIX "PIC TIMING: "

int g_timecode_trigger_discontinuity = 0;

/* Secondary verification */
unsigned int timecode_timeToSequenceMax(int framerate)
{
    unsigned int seq = (24 * 60 * 60) - 1;
    seq *= framerate;
    seq += (framerate - 1);

    return seq;
}

/* Convert h:m:s.frame into a single sequence continiously incrementing by 1 */
unsigned int timecode_timeToSequence(int h, int m, int s, int framerate, int frame)
{
    unsigned int seq = s + (m * 60) + (h * 3600);
    seq *= framerate;
    seq += frame;

    return seq;
}

/* Convert a single number sequence code into h:m:s.frame */
void timecode_SequenceToTime(int *h, int *m, int *s, int framerate, int *frame, unsigned int seq)
{
    unsigned int n = seq;

    *frame = n % framerate;
    n /= framerate;

    *s = n % 60;
    n /= 60;

    *m = n % 60;
    n /= 60;

    *h = n % 24;
    n /= 24;
}
/* End: Secondary verification */

void obe_timecode_reset(struct timecode_context_s *ctx)
{
    ctx->curr.corrected_frame = -1;
    ctx->updateCount = 0;
}

void obe_timecode_clear(struct timecode_context_s *ctx, uint32_t intendedFPS)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->intendedFPS = intendedFPS;
    ctx->seqNrMax = timecode_timeToSequenceMax(ctx->intendedFPS);
    obe_timecode_reset(ctx);
}

static void obe_timecode_raise_discontinuity(struct timecode_context_s *ctx)
{
    ctx->discontinuity = 1;
    gettimeofday(&ctx->lastDiscontinuity, NULL);
    
    time_t now = time(0);
    printf(MESSAGE_PREFIX "timecode discontinuity detected @ %s", ctime(&now));
    printf(MESSAGE_PREFIX "timecode prev %02d:%02d:%02d.%03d (seq %08x) curr %02d:%02d:%02d.%03d (seq %08x)\n",
        ctx->prev.hours, ctx->prev.minutes, ctx->prev.seconds, ctx->prev.frame, ctx->prev.seqNr,
        ctx->curr.hours, ctx->curr.minutes, ctx->curr.seconds, ctx->curr.frame, ctx->curr.seqNr);

}

static void obe_timecode_clear_discontinuity(struct timecode_context_s *ctx)
{
    ctx->discontinuity = 0;
}

void obe_timecode_update(struct timecode_context_s *ctx, unsigned int hrs, unsigned int mins, unsigned int secs, unsigned int frame)
{
    ctx->updateCount++;

    int discontinuity = 1; /* assume there is a time discontinuity */
    int secondaryDiscontinuity = 1; /* assume there is a time discontinuity */

    memcpy(&ctx->prev, &ctx->curr, sizeof(ctx->curr));
    ctx->curr.hours = hrs;
    ctx->curr.minutes = mins;
    ctx->curr.seconds = secs;
    ctx->curr.frame = frame;
    ctx->curr.seqNr = timecode_timeToSequence(hrs, mins, secs, ctx->intendedFPS, frame);

    /* Once we have atleast two codes, start doing a sequence+1 comparison */
    if (ctx->updateCount >= 2) {
        if (ctx->prev.seqNr == ctx->seqNrMax && ctx->curr.seqNr == 0) {
            /* All good*/
            secondaryDiscontinuity = 0;
        } else if (ctx->prev.seqNr + 1 == ctx->curr.seqNr) {
            /* All good*/
            secondaryDiscontinuity = 0;
        } else {
            /* Problem */
        }
    }

    /* Deal with the lack of marker bits on some upstream timecode equipment.
     * Look for a duplicate timecode and correct the actual output frmae number.
     */
    if (ctx->intendedFPS <= 30) {
        ctx->curr.corrected_frame = ctx->curr.frame;
    } else {
        if (ctx->curr.frame == 0 && ctx->prev.frame != 0) {
            /* We've just wrapped */
            ctx->curr.corrected_frame = ctx->curr.frame;
        } else
        if (ctx->curr.corrected_frame >= 0) {
            ctx->curr.corrected_frame++;
        } else {
            /* correct_frame is -1, and will remain -1 until
             * the incoming timecode has fully wrapped to input frame 0.
             */
        }
    }

    /* We'll flag a discontinuity with a major time distortion */
    int32_t t2 = (ctx->curr.hours * 3600) + (ctx->curr.minutes * 60) + ctx->curr.seconds;
    int32_t t1 = (ctx->prev.hours * 3600) + (ctx->prev.minutes * 60) + ctx->prev.seconds;

    int time_ok = 0; /* assume time is bad */

    if (t2 - t1 == 0) {
        /* Time hasn't moved */
        if (ctx->dup_time++ < 80) {
            /* No change in time is OK, but put a safety to catch stuck timecodes */
            time_ok++;
        } else {
            /* Time hasn't moved for many many frames.
             * We haven't marked the time as ok, we'll catch the issue.
             */
        }
    } else
    if (t2 - t1 == 1) {
        /* Time has moved forward, good */
        time_ok++;
        ctx->dup_time = 0;
    } if ((t2 - (t1 + 1) % 86400) == 0) {
        /* Clock wrapped 23:59:59 to 00:00:00 */
        time_ok++;
    } else {
        /* Time has exceeded some reasonable change.
         * We haven't marked the time as ok, we'll catch the issue.
         */
        ctx->dup_time = 0;
    }

#if LOCAL_DEBUG
    printf(MESSAGE_PREFIX "prior %d, calc %d, curr %d\n",
        ctx->prev.frame, ((ctx->prev.frame + 1) % 30), ctx->curr.frame);
#endif

    if (time_ok) {
        if (ctx->prev.frame == ctx->curr.frame) {
            /* dup frame we allow */
        } else
        if (((ctx->prev.corrected_frame + 1) % ctx->intendedFPS) == ctx->curr.corrected_frame) {
            /* next frame in sequence we allow */
        } else
        if (ctx->curr.corrected_frame == -1) {
            /* Waiting for syncronization during startup */
        }
        else {
            /* Not the same, not +1, not starting up, it must be an error. */
            time_ok = 0;
        }
    }

    if (time_ok) {
        discontinuity = 0; /* time is ok */
    }

    if (g_timecode_trigger_discontinuity) {
        g_timecode_trigger_discontinuity = 0;
        discontinuity = 1;
        ctx->curr.seconds = 61;
    }

    if (ctx->updateCount == 1) {
        /* Avoid conditions where the first timecode
         * given is a natural discontinuity
         */
        return; /* Success */
    }

    /* Trigger a discontinuity if either the primary or secondary
     * checks fire. While this might create false positives,
     * I'm totally OK with that given the bug I'm trying to catch
     * in some other system I'm currently monitoring.
     */
    if (discontinuity || secondaryDiscontinuity) {
        obe_timecode_raise_discontinuity(ctx);
    } else {
        obe_timecode_clear_discontinuity(ctx);
    }
}

int obe_timecode_get_discontinuity(struct timecode_context_s *ctx)
{
    return ctx->discontinuity;
}

int obe_timecode_get_corrected_frame(struct timecode_context_s *ctx)
{
    return ctx->curr.corrected_frame;
}
