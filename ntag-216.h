#ifndef NTAG_216_H
#define NTAG_216_H

#ifndef MAIN_H
#include "main.h"
#endif

#ifndef COMMON_H
#include "common.h"
#endif

#ifndef LOGGING_C
#include "logging.c"
#endif

typedef struct NTAG_216_Pages {
    BYTE Pages[231][4]; // 231 pages (0x00 - 0xE6) with 4 bytes per page
} NTAG_216_Pages;

extern const BYTE NTAG_216_USER_MEMORY_PAGES[222];
extern const BYTE NTAG_216_EXISTING_PAGES[231];

void ntag_216_pages_object_print_all(BYTE from_page, BYTE to_page, NTAG_216_Pages *tag_content);

// functions
BOOL ntag_216_write_page(BYTE* data, BYTE page, SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize);
BOOL ntag_216_reset_user_data(SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize);
BOOL ntag_216_fast_read(BYTE from_page, BYTE to_page, SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize);


#endif
