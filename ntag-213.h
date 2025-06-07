#ifndef NTAG_213_H
#define NTAG_213_H

#ifndef MAIN_H
#include "main.h"
#endif

#ifndef COMMON_H
#include "common.h"
#endif

#ifndef LOGGING_C
#include "logging.c"
#endif

typedef struct NTAG_213_Pages {
    BYTE Pages[45][4]; // 45 pages (0x00 - 0x2C) with 4 bytes per page
} NTAG_213_Pages;

extern const BYTE NTAG_213_USER_MEMORY_PAGES[36];
extern const BYTE NTAG_213_EXISTING_PAGES[45];

void ntag_213_pages_object_print_all(BYTE from_page, BYTE to_page, NTAG_213_Pages *tag_content);

// functions
BOOL ntag_213_write_page(BYTE* data, BYTE page, SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize);
BOOL ntag_213_reset_user_data(SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize);
BOOL ntag_213_fast_read(BYTE from_page, BYTE to_page, SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize);


#endif
