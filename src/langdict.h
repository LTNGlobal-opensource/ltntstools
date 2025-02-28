/* Copyright LiveTimeNet, Inc. 2025. All Rights Reserved. */

/* A mechanism to parse strings, lokup words in various language dictionaries
 * and maintain counts and times for words found vs missed.
 */

#ifndef LANGDICT_H
#define LANGDICT_H

#include <stdio.h>
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

enum langdict_type_e {
    LANG_UNDEFINED = 0,
    LANG_ENGLISH,
    LANG_SPANISH,
    LANG_GERMAN,
    LANG_ITALIAN,
    LANG_FRENCH,
};

struct langdict_stats_s {
    enum langdict_type_e lang;

    uint64_t found;            /* number of words found in dictionary */
    uint64_t missing;          /* number of words missing from dictionary */
    uint64_t processed;        /* total number of words extracted from input */
    time_t   time_last_found;  /* Walltime last successful dictionary occured */
    time_t   time_last_search; /* Walltime last lookup in the doctionary occured */

    float    accuracypct;      /* (found / processed) * 100 */
};

int langdict_alloc(void **handle, enum langdict_type_e langtype);
void langdict_free(void *handle);

int langdict_parse(void *handle, char *display, int lengthBytes);

void langdict_stats_reset(void *handle);

int langdict_get_stats(void *handle, enum langdict_type_e langtype, struct langdict_stats_s *stats);

#ifdef __cplusplus
};
#endif

#endif /* LANGDICT_H */
