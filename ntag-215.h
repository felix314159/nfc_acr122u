#ifndef NTAG_215_H
#define NTAG_215_H

#ifndef MAIN_H
#include "main.h"
#endif

#ifndef COMMON_H
#include "common.h"
#endif

#ifndef LOGGING_C
#include "logging.c"
#endif

typedef struct NTAG_215_Pages {
    BYTE Pages[135][4]; // 135 pages (0x00 - 0x86) with 4 bytes per page
} NTAG_215_Pages;

extern const BYTE NTAG_215_USER_MEMORY_PAGES[126];
extern const BYTE NTAG_215_EXISTING_PAGES[135];

void ntag_215_pages_object_print_all(BYTE from_page, BYTE to_page, NTAG_215_Pages *tag_content);

// functions
BOOL ntag_215_write_page(BYTE* data, BYTE page, SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize);
BOOL ntag_215_reset_user_data(SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize);
BOOL ntag_215_fast_read(BYTE from_page, BYTE to_page, SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize);


#endif
