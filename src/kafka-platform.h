#ifndef KAFKA_PLATFORM_H
#define KAFKA_PLATFORM_H
#if 0

/**
 * @file        pes.h
 * @author      Steven Toth <steven.toth@ltnglobal.com>
 * @copyright   Copyright (c) 2020-2022 LTN Global,Inc. All Rights Reserved.
 * @brief       A framework to handle and manipulate ISO13818-1 PES headers
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief       Allocate a kafka platform producer. Multiple statistics will be pushed
 *              to kafka on a 15 to 30 second basis.
 * @return      0 on success, else < 0 on error.
 */
int ltntstools_kplatform_alloc(void **hdl);

/**
 * @brief       Free a previously allocated handle, and any attached payload
 * @param[in]   void *hdl - object
 */
void ltntstools_kplatform_free(void *hdl);

struct kafka_item_s *ltntstools_kplatform_item_alloc(void *ctx, int lengthBytesMax);
void ltntstools_kplatform_item_free(void *ctx, struct kafka_item_s *item);

#ifdef __cplusplus
};
#endif
#endif
#endif /* KAFKA_PLATFORM_H */
