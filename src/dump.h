/* Copyright LiveTimeNet, Inc. 2017. All Rights Reserved. */

#ifndef _DUMP_H
#define _DUMP_H

#include <dvbpsi/dvbpsi.h>
#include <dvbpsi/descriptor.h>
#include <dvbpsi/psi.h>
#include <dvbpsi/pat.h>
#include <dvbpsi/pmt.h>
#include <dvbpsi/dr.h>

#ifdef __cplusplus
extern "C" {
#endif

void tstools_DumpPAT(void* p_zero, dvbpsi_pat_t* p_pat);
void tstools_DumpPMT(void* p_zero, dvbpsi_pmt_t* p_pmt, int dumpDescriptors, uint16_t pid);
void tstools_message(dvbpsi_t *handle, const dvbpsi_msg_level_t level, const char* msg);
char *tstools_GetTypeName(uint8_t type);
void tstools_DumpDescriptors(const char* str, dvbpsi_descriptor_t* p_descriptor);
int tstools_ReadPacket(int fd, uint8_t *dst);

#ifdef __cplusplus
};
#endif

#endif /* _DUMP_H */
