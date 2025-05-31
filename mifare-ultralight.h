#ifndef MIFARE_ULTRALIGHT_H
#define MIFARE_ULTRALIGHT_H

#ifndef MAIN_H
#include "main.h"
#endif

#ifndef COMMON_H
#include "common.h"
#endif

#ifndef LOGGING_C
#include "logging.c"
#endif

extern const BYTE ULTRALIGHT_1x_USER_MEMORY[12];
extern const BYTE ULTRALIGHT_1x_EXISTING_PAGES[20];

BOOL ultralight_read_page(BYTE page, SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize);
BOOL ultralight_fast_read(SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize);
BOOL ultralight_write_page(BYTE* data, BYTE page, SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize);
BOOL ultralight_reset_user_data(SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize);
BOOL ultralight_read_counter(BYTE counter, SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize);
BOOL ultralight_increment_counter(BYTE counter, SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize);

#endif
