/**
 * @file        langdict.h
 * @author      Steven Toth <steven.toth@ltnglobal.com>
 * @copyright   Copyright (c) 2025 LTN Global,Inc. All Rights Reserved.
 * @brief       A framework to parse strings and compare contents across many languages.
 *              Word counts and stats are gather and exposed to the caller.
 */

#ifndef LANGDICT_H
#define LANGDICT_H

#include <stdio.h>
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief  A list of supported languages
 */
enum langdict_type_e {
    LANG_UNDEFINED = 0,
    LANG_ENGLISH,
    LANG_SPANISH,
    LANG_GERMAN,
    LANG_ITALIAN,
    LANG_FRENCH,
};

/**
 * @brief  Framework statistics the user can query
 */
struct langdict_stats_s {
    enum langdict_type_e lang;

    uint64_t found;            /** number of words found in dictionary */
    uint64_t missing;          /** number of words missing from dictionary */
    uint64_t processed;        /** total number of words extracted from input */
    time_t   time_last_found;  /** Walltime last successful dictionary occured */
    time_t   time_last_search; /** Walltime last lookup in the doctionary occured */

    float    accuracypct;      /** (found / processed) * 100 */
};

/**
 * @brief       Allocate a new context, it's threadsafe.
 * @param[out]  void **handle - Newly created context.
 * @return      0 - Success, else < 0 on error.
 */
int langdict_alloc(void **handle);

/**
 * @brief      Free a previously allocated context
 * @param[in]  void *handle - A previously allocated context.
 */
void langdict_free(void *handle);

/**
 * @brief       Run the input string through all the dictionaries and updates the statistics.
 * @param[in]   void *handle - A previously allocated context.
 * @param[in]   const char *display - input string
 * @param[in]   int lengthBytes - length of string buffer
 * @return      0 - Success, else < 0 on error.
 */
int langdict_parse(void *handle, const char *display, int lengthBytes);

/**
 * @brief      Reset any internal statistical counters
 * @param[in]  void *handle - A previously allocated context.
 */
void langdict_stats_reset(void *handle);

/**
 * @brief       Gather language parsing statistics for a specific langauge
 * @param[in]   void *handle - A previously allocated context.
 * @param[in]   enum langdict_type_e langtype - language Eg. LANG_SPANISH
 * @param[in]   struct langdict_stats_s *stats - user allocated stats struct to be updated
 * @return      0 - Success, else < 0 on error.
 */
int langdict_get_stats(void *handle, enum langdict_type_e langtype, struct langdict_stats_s *stats);

#ifdef __cplusplus
};
#endif

#endif /* LANGDICT_H */
