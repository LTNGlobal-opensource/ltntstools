
#ifdef __linux__

#define _UNICODE

#include <stdio.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <locale>

#include "media.h"

#include <MediaInfo/MediaInfo.h>

using namespace MediaInfoLib;

// https://fossies.org/linux/MediaInfo_CLI/MediaInfoLib/Source/Example/HowToUse_Dll.cpp

MediaInfo *MI;

int media_init()
{
    MI = new MediaInfo();

    const String y = L"File_IsSeekable";
    const String z = L"0";

    MI->Option(L"File_IsSeekable", L"0");
    MI->Option(L"Info_Parameters");
    MI->Option(L"Info_Codecs");
    MI->Open_Buffer_Init(8192 * 7 * 188);

    return 0;
}

int media_write(const unsigned char *buf, int packetCount)
{
    //printf("%p %d\n", buf, packetCount * 188);
    size_t Status = MI->Open_Buffer_Continue(buf, packetCount * 188);
#if 0
    if (Status != 0)
        printf("Status 0x%08x\n", Status);
#endif
    if (Status & 0x08) {
        // Finished
        printf("Media has finished detection\n");
        MI->Open_Buffer_Finalize();

        String widthCC = MI->Get(Stream_General, 0, L"Format");

        String To_Display = MI->Inform();
        MI->Close();

        std::wcout << To_Display;
        std::wcout << widthCC;

    }

    return 0;
}
#endif /* __linux__ */
