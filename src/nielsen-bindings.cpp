

/* Copyright (c) 2020 LTN Global Inc. All Rights Reserved. */

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <assert.h>
#include <libgen.h>
#include <signal.h>
#include <limits.h>

#if HAVE_IMONITORSDKPROCESSOR_H

#include "nielsen-bindings.h"

/* Nielsen SDK for audio monitoring */
#include <IMonitorSdkCallback.h>
#include <IMonitorSdkProcessor.h>
#include <MonitorSdkParameters.h>
#include <MonitorSdkSharedDefines.h>
#include <MonitorApi.h>

class CMonitorSdkCallback : public IMonitorSdkCallback
{
public:
	CMonitorSdkCallback(int pid, int channelNr);
	virtual ~CMonitorSdkCallback();

	virtual void ResultCallback(uint32_t elapsed_time, std::string result) override;
	virtual void LogCallback(int code, const char* pMessage) override;
	virtual void AlarmCallback(uint32_t elapsed_time, std::string warning_list) override;

private:
	int pairNumber;
public:
    int silentMode;
    int pid;
    int channelNr;
};

CMonitorSdkCallback::CMonitorSdkCallback(int pid, int channelNr)
{
	this->pairNumber = pairNumber;
    silentMode = 1; /* By default, silence all message outputs */
    this->pid = pid;
    this->channelNr = channelNr;
}

CMonitorSdkCallback::~CMonitorSdkCallback()
{
}

void CMonitorSdkCallback::ResultCallback(uint32_t elapsed_time, std::string result)
{
    if (!silentMode) {
	    printf("\nNielsen pid 0x%04x/ch#%d: @ %d - %s\n", pid, channelNr, elapsed_time, result.c_str());
    }
};

void CMonitorSdkCallback::LogCallback(int code, const char* pMessage)
{
    if (!silentMode) {
    	printf("\nNielsen pid 0x%04x/ch#%d - %d %s\n", pid, channelNr, code, pMessage);
    }
};

void CMonitorSdkCallback::AlarmCallback(uint32_t elapsed_time, std::string warning_list)
{
    if (!silentMode) {
	    printf("\nNielsen pid 0x%04x/ch#%d: @ %d - %s\n", pid, channelNr, elapsed_time, warning_list.c_str());
    }
};

void nielsen_bindings_write_silent(struct nielsen_bindings_decoder_s *ctx, int tf)
{
    for (int i = 0; i < ctx->channelCount; i++) {
        CMonitorSdkCallback *p = (CMonitorSdkCallback *)ctx->channels[i].callback;
        p->silentMode = tf;
    }    
}

void nielsen_bindings_free(struct nielsen_bindings_decoder_s *ctx)
{
    for (int i = 0; i < ctx->channelCount; i++) {
        delete (CMonitorApi *)ctx->channels[i].api;
        delete (CMonitorSdkParameters *)ctx->channels[i].params;
        delete (CMonitorSdkCallback *)ctx->channels[i].callback;
    }    
}

struct nielsen_bindings_decoder_s *nielsen_bindings_alloc(int pid, int channelCount)
{
    if ((channelCount <= 0) || (channelCount > 16))
        return NULL;

    struct nielsen_bindings_decoder_s *ctx = (struct nielsen_bindings_decoder_s *)calloc(1, sizeof(*ctx));
    ctx->pid = pid;
    ctx->channelCount = channelCount;

    for (int i = 0; i < ctx->channelCount; i++) {

        CMonitorSdkParameters *pNielsenParams = new CMonitorSdkParameters();
        pNielsenParams->SetSampleSize(16);
        pNielsenParams->SetPackingMode(TwoBytesNoPadding);
        pNielsenParams->SetSampleRate(48000);
        if (pNielsenParams->ValidateAllSettings() != 1) {
                fprintf(stderr, "Error validating nielsen parameters for pair %d, aborting.\n", i);
                exit(0);
        }

        CMonitorSdkCallback *pNielsenCallback = new CMonitorSdkCallback(pid, i);

        CMonitorApi *pNielsenAPI = new CMonitorApi(pNielsenParams, pNielsenCallback);
        pNielsenAPI->SetIncludeDetailedReport(1);
        pNielsenAPI->Initialize();
        if (pNielsenAPI->IsProcessorInitialized() != 1) {
                fprintf(stderr, "Error initializing nielsen decoder for pair %d, aborting.\n", i);
                exit(0);
        }

        ctx->channels[i].params    = (void *)pNielsenParams;
        ctx->channels[i].api       = (void *)pNielsenAPI;
        ctx->channels[i].callback  = (void *)pNielsenCallback;

    }
    return ctx;
}

int nielsen_bindings_write_plane(struct nielsen_bindings_decoder_s *ctx, int channelNr, uint8_t *sample, int lengthBytes)
{
    CMonitorApi *api = (CMonitorApi *)ctx->channels[channelNr].api;

    //printf("\tch%d %02x %02x\n", channelNr, *(sample + 0), *(sample + 1));
    api->InputAudioData(sample, lengthBytes);

    return 0;
}

#endif

