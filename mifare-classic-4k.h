#ifndef MIFARE_CLASSIC_4K_H
#define MIFARE_CLASSIC_4K_H

#ifndef MAIN_H
#include "main.h"
#endif

#ifndef COMMON_H
#include "common.h"
#endif

#ifndef LOGGING_C
#include "logging.c"
#endif

// SectorContent_3_Blocks is a struct that holds the sectorID (0x00, 0x01, etc.), the content of each of the three data blocks in the sector, and a status bool (success /failure) 
typedef struct SectorContent_3_Blocks {
    BYTE sectorID;
    BYTE blocks[3][16];  // 3 blocks, each of which holds 16 bytes
    LONG status;
} SectorContent_3_Blocks;

typedef struct SectorContent_15_Blocks {
    BYTE sectorID;
    BYTE blocks[15][16];  // 15 blocks, each of which holds 16 bytes
    LONG status;
} SectorContent_15_Blocks;

SectorContent_15_Blocks mifare_classic_4k_read_sector(BYTE sector, const BYTE *keyA, SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize);
BOOL mifare_classic_4k_ndef_to_uninitialized(SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize);
BOOL mifare_classic_4k_uninitialized_to_ndef(SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize);
BOOL mifare_classic_4k_reset_card(const BYTE *keyA, SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize);
BOOL mifare_classic_4k_write_block(const BYTE *BlockData, BYTE block, const BYTE *keyA, SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize);

extern const BYTE NDEF_SECTOR_TRAILER_0_AND_10_4K[16];
extern const BYTE NDEF_SECTOR_TRAILER_1_TO_0F_AND_11_TO_27_4K[16];

extern const BYTE UNINITIALIZED_SECTOR_TRAILER_4K[16];

extern const BYTE SECTOR_TRAILER_BLOCKS_4K[40];
extern const BYTE SECTOR_IDS_4K[40];

extern const BYTE KEY_A_DEFAULT_4K[6];
extern const BYTE KEY_B_DEFAULT_4K[6];

extern const BYTE KEY_A_NDEF_SECTOR_0_AND_10_4K[6]; //k
extern const BYTE KEY_B_NDEF_SECTOR_0_AND_10_4K[6]; //k
extern const BYTE KEY_A_NDEF_SECTOR_1_TO_0F_AND_11_TO_27_4K[6];
extern const BYTE KEY_B_NDEF_SECTOR_1_TO_0F_AND_11_TO_27_4K[6];

extern const BYTE NDEF_Block1_4K[16];
extern const BYTE NDEF_Block2_4K[16];
extern const BYTE NDEF_Block4_4K[16];
extern const BYTE NDEF_Block_40_4K[16];
extern const BYTE NDEF_Block_41_42_4K[16];

#endif
