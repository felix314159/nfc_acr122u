#ifndef MIFARE_CLASSIC_H
#define MIFARE_CLASSIC_H

#ifndef MAIN_H
#include "main.h"
#endif

#ifndef COMMON_H
#include "common.h"
#endif

#ifndef LOGGING_C
#include "logging.c"
#endif

// SectorContent is a struct that holds the sectorID (0x00, 0x01, etc.), the content of each of the three blocks in the sector, and a status bool (success /failure) 
typedef struct {
    BYTE sectorID;
    BYTE Block_0[16];
    BYTE Block_1[16];
    BYTE Block_2[16];
    LONG status;
} SectorContent;

SectorContent mifare_classic_read_sector(BYTE sector, const BYTE *keyA, SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize);
BOOL mifare_classic_ndef_to_uninitialized(SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize);
BOOL mifare_classic_uninitialized_to_ndef(SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize);
BOOL mifare_classic_reset_card(const BYTE *keyA, SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize);
BOOL mifare_classic_write_block(const BYTE *BlockData, BYTE block, const BYTE *keyA, SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize);
BOOL is_byte_in_array(BYTE value, const BYTE *array, size_t size);

extern const BYTE NDEF_SECTOR_TRAILER_0[16];
extern const BYTE NDEF_SECTOR_TRAILER_115[16];

extern const BYTE UNINITIALIZED_SECTOR_TRAILER[16];

extern const BYTE SECTOR_BLOCKS[16];
extern const BYTE SECTOR_IDS[16];

extern const BYTE KEY_A_DEFAULT[6];
extern const BYTE KEY_B_DEFAULT[6];

extern const BYTE KEY_A_NDEF_SECTOR0[6];
extern const BYTE KEY_B_NDEF_SECTOR0[6];
extern const BYTE KEY_A_NDEF_SECTOR115[6];
extern const BYTE KEY_B_NDEF_SECTOR115[6];

extern const BYTE ACCESS_BITS_UNINITALIZED[4];
extern const BYTE ACCESS_BITS_NDEF_SECTOR0[4];
extern const BYTE ACCESS_BITS_NDEF_SECTOR115[4];

extern const BYTE NDEF_Block1[16];
extern const BYTE NDEF_Block2[16];
extern const BYTE NDEF_Block4[16];

#endif
