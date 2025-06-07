#include "mifare-classic-4k.h"
#include "logging.c"
#include "main.h"

// KEYS
//		UNINITIALIZED KEYS
const BYTE KEY_A_DEFAULT_4K[6] = 							{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
const BYTE KEY_B_DEFAULT_4K[6] = 							{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
//		NDEF KEYS
const BYTE KEY_A_NDEF_SECTOR_0_AND_10_4K[6] = 				{ 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5 };
const BYTE KEY_A_NDEF_SECTOR_1_TO_0F_AND_11_TO_27_4K[6] = 	{ 0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7 };

const BYTE KEY_B_NDEF_SECTOR_0_AND_10_4K[6] = 				{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
const BYTE KEY_B_NDEF_SECTOR_1_TO_0F_AND_11_TO_27_4K[6] = 	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };


// SECTOR IDs
const BYTE SECTOR_IDS_4K[40] 				= { // sectors that contain 4 blocks
												0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, // 1k tag would end here
												0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 
												// sectors that contain 16 blocks
												0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27 };

// SECTOR TRAILER INDICES (potentially dangerous to write to these)
const BYTE SECTOR_TRAILER_BLOCKS_4K[40] 	= { // trailer blocks of sectors that contain 4 blocks
												0x03, 0x07, 0x0B, 0x0F, 
												0x13, 0x17, 0x1B, 0x1F, 
												0x23, 0x27, 0x2B, 0x2F, 
												0x33, 0x37, 0x3B, 0x3F,			
												0x43, 0x47, 0x4B, 0x4F,
												0x53, 0x57, 0x5B, 0x5F,
												0x63, 0x67, 0x6B, 0x6F,
												0x73, 0x77, 0x7B, 0x7F,
												// trailer blocks of sectors that contain 16 blocks
												0x8F, 0x9F, 0xAF, 0xBF, 
												0xCF, 0xDF, 0xEF, 0xFF };

// SECTOR TRAILER CONTENT
//		UNINITIALIZED
const BYTE UNINITIALIZED_SECTOR_TRAILER_4K[16] = { 	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  	// key A
													0xFF, 0x07, 0x80, 0x69, 				// access bits
													0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };	// key B
//		NDEF
const BYTE NDEF_SECTOR_TRAILER_0_AND_10_4K[16] =  { 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 	// key A  
													0x78, 0x77, 0x88, 0xC1,    				// access bits
													0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };	// key B

const BYTE NDEF_SECTOR_TRAILER_1_TO_0F_AND_11_TO_27_4K[16] =   { 	0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7, 	// key A
																	0x7F, 0x07, 0x88, 0x40,     			// access bits
																	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };	// key B

// A few more NDEF blocks 

// 		NDEF Block 0x01
const BYTE NDEF_Block1_4K[16] = { 0x14, 0x01, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1 };

// 		NDEF Block 0x02
const BYTE NDEF_Block2_4K[16] = { 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1 };

// 		NDEF Block 0x04
const BYTE NDEF_Block4_4K[16] = { 0x03, 0x00, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

//		NDEF Block 0x40
const BYTE NDEF_Block_40_4K[16] = { 0xE8, 0x01, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1 };

// 		NDEF Blocks 0x41 - 0x42 (MAD2 structure, you say that the next 24 sectors contain NDEF data, 8x'03 E1'x3 )
const BYTE NDEF_Block_41_42_4K[16] = { 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1 };


// mifare_classic_4k_read_sector reads all data blocks in a sector (does not read sector trailer) and prints it
SectorContent_15_Blocks mifare_classic_4k_read_sector(BYTE sectorId, const BYTE *keyA, SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize) {
	// prepare data type that holds the data that will be returned on success
    SectorContent_15_Blocks sector_content = {0}; // initialize all fields to 0, when you return early due to error just set false as .status, when a sector that only holds 4 blocks is read no problem, just ignore the rest (which will be all zeroes)
    sector_content.sectorID = sectorId;

	// check whether passed sector is valid for mifare 4k
	if (!is_byte_in_array(sectorId, SECTOR_IDS_4K, 40)) {
		LOG_WARN("0x%02x is not a valid sector! You can only read sectors [0x00, 0x27].", sectorId);
		sector_content.status = FALSE;
		return sector_content;
	}

	// load provided key
	LOG_INFO("Loading key..");
	BYTE APDU_LoadDefaultKey[11] = { 0xff, 0x82, 0x00, 0x00, 0x06, keyA[0], keyA[1], keyA[2], keyA[3], keyA[4], keyA[5] };
	ApduResponse response = executeApdu(hCard, APDU_LoadDefaultKey, sizeof(APDU_LoadDefaultKey), pbRecvBuffer, pbRecvBufferSize);
	//		ensure key loaded successfully
	if (response.status != 0) {
		LOG_ERROR("Failed to load provided key. Aborting..");
		sector_content.status = FALSE;
		return sector_content;
	}

	if (!( (pbRecvBuffer[0] == 0x90) && (pbRecvBuffer[1] == 0x00) )) {
		LOG_ERROR("Failed to load provided key. Aborting..");
		sector_content.status = FALSE;
		return sector_content;
	}
	printf("Key A has been loaded successfully\n\n");


	// authenticate blocks in sector
	LOG_INFO("Authenticating and reading blocks in sector %d..", sectorId);

	// chosen sector contains either 4 blocks or 16 blocks
	BOOL is4BlockSector = sectorId < 0x20;
	//		base is helper to keep track of current block id (by calculating the starting block id [you keep counting even when new sector would begin])
	BYTE base = is4BlockSector ? sectorId * 4 : (32*4 + (sectorId - 0x20) * 16);
	//		loopLimit keeps track of block index within sector
	BYTE loopLimit = is4BlockSector ? 3 : 15;
	for (BYTE i = 0; i < loopLimit; i++) {
		BYTE block = base + i;

		BYTE APDU_Authenticate_Block[10] = { 0xff, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, block, 0x60, 0x00 };
		response = executeApdu(hCard, APDU_Authenticate_Block, sizeof(APDU_Authenticate_Block), pbRecvBuffer, pbRecvBufferSize);
		if (response.status != 0 || !(pbRecvBuffer[0] == 0x90 && pbRecvBuffer[1] == 0x00)) {
			LOG_ERROR("Failed to authenticate block 0x%02x. Aborting..", block);
			sector_content.status = FALSE;
			return sector_content;
		}

		LOG_INFO("Authenticated block 0x%02x successfully", block);
		
		// this delay is recommended in the acr122u ACR122U_APIDriverManual.pdf (page 16)
		//SLEEP_CUSTOM(2000);
		// however i never had issues without it, so why bother

		// read data from block that you are now allowed to access
		BYTE APDU_Read[5] = { 0xff, 0xb0, 0x00, block, 0x10 }; // page 16 of ACR122U_APIDriverManual.pdf (reads 16 bytes, and the page number is a coincidence)
		LOG_INFO("Reading block 0x%02x..", block);


		response = executeApdu(hCard, APDU_Read, sizeof(APDU_Read), pbRecvBuffer, pbRecvBufferSize);
		if (response.status != 0 || !( (pbRecvBuffer[16] == 0x90) && pbRecvBuffer[17] == 0x00))   {
			LOG_ERROR("Failed to read data from block 0x%02x. Aborting..", block);
			sector_content.status = FALSE;
			return sector_content;
		}

		printf("Block 0x%02x:", block);
		for (int j = 0; j < 16; j++) {
		    printf(" %02x", pbRecvBuffer[j]);
		}
		printf("\n");

		// store data read from this block
		memcpy(sector_content.blocks[i], pbRecvBuffer, 16);
    
	}
	
	return sector_content;
}

// currently only supports authentication via keyA
BOOL mifare_classic_4k_write_block(const BYTE *BlockData, BYTE block, const BYTE *keyA, SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize) {
	// sanity checks
	if (block == 0x00) {
		LOG_WARN("You can't write to block 0, try a different block.");
		return FALSE;
	}
	if (block > 0xFF) { // mifare classic 4k
		LOG_WARN("You can't write to block 0x%02x, the last block of a Mifare Classic 4k is block 0xFF.", block);
		return FALSE;
	}

	// warn user if he is writing to sector trailer (allowed but has consequences)
	if (is_byte_in_array(block, SECTOR_TRAILER_BLOCKS_4K, 40)) {
		LOG_WARN("You have chosen block 0x%02x, this is allowed but keep in mind that this is a sector trailer block.", block);
	}

	// load provided key
	LOG_INFO("Loading key..");
	BYTE APDU_LoadDefaultKey[11] = { 0xff, 0x82, 0x00, 0x00, 0x06, keyA[0], keyA[1], keyA[2], keyA[3], keyA[4], keyA[5] }; // page 12, stores key at location 0
	ApduResponse response = executeApdu(hCard, APDU_LoadDefaultKey, sizeof(APDU_LoadDefaultKey), pbRecvBuffer, pbRecvBufferSize);
	if (response.status != 0) {
		LOG_ERROR("Failed to load provided key. Aborting..");
		return FALSE;
	}
	if (!( (pbRecvBuffer[0] == 0x90) && (pbRecvBuffer[1] == 0x00) )) {
		LOG_ERROR("Failed to load provided key. Aborting..");
		return FALSE;
	}
	printf("Key A has been loaded successfully\n\n");

	// authenticate block
	LOG_INFO("Authenticating block 0x%02x..", block);
	BYTE APDU_Authenticate_Block[10] = { 0xff, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, block, 0x60, 0x00 };
	response = executeApdu(hCard, APDU_Authenticate_Block, sizeof(APDU_Authenticate_Block), pbRecvBuffer, pbRecvBufferSize);
	if (response.status != 0 || !(pbRecvBuffer[0] == 0x90 && pbRecvBuffer[1] == 0x00)) {
		LOG_ERROR("Failed to authenticate block 0x%02x. Aborting..", block);
		return FALSE;
	}
	LOG_INFO("Authenticated block 0x%02x successfully", block);

	// write data to block
	BYTE APDU_Write[5 + 16] = { 0xff, 0xd6, 0x00, block, 0x10 };	// base command 5 bytes + 16 byte to write to block
	memcpy(APDU_Write + 5, BlockData, 16);
	response = executeApdu(hCard, APDU_Write, sizeof(APDU_Write), pbRecvBuffer, pbRecvBufferSize);
	if (response.status != 0 || !(pbRecvBuffer[0] == 0x90 && pbRecvBuffer[1] == 0x00)) {
		LOG_ERROR("Failed to write to block 0x%02x. Aborting..", block);
		return FALSE;
	}
	LOG_INFO("Wrote data to block 0x%02x with success.", block);


	return TRUE;
}

// this function resets all writable data blocks (so it skips sector trailers) to all zeroes
// assumes card is using same key A for every block (e.g. would be true for uninitialized card), or is fully NDEF formatted (pass key for sectors 1-15)
BOOL mifare_classic_4k_reset_card(const BYTE *keyA, SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize) {
	// detect whether passed key is for NDEF (sectors 1-15). its an edge case cuz then sector 0 has different key
	BOOL is_NDEF_key = FALSE;
	if ( keyA[0] == 0xD3 && keyA[1] == 0xF7 && keyA[2] == 0xD3 && keyA[3] == 0xF7 && keyA[4] == 0xD3 && keyA[5] == 0xF7 ) {
		is_NDEF_key = TRUE;
	}

	// load provided key
	LOG_INFO("Loading key..");
	BYTE APDU_LoadDefaultKey[11] = { 0xff, 0x82, 0x00, 0x00, 0x06, keyA[0], keyA[1], keyA[2], keyA[3], keyA[4], keyA[5] }; // page 12, stores key at location 0
	ApduResponse response = executeApdu(hCard, APDU_LoadDefaultKey, sizeof(APDU_LoadDefaultKey), pbRecvBuffer, pbRecvBufferSize);
	if (response.status != 0) {
		LOG_ERROR("Failed to load provided key. Aborting..");
		return FALSE;
	}
	if (!( (pbRecvBuffer[0] == 0x90) && (pbRecvBuffer[1] == 0x00) )) {
		LOG_ERROR("Failed to load provided key. Aborting..");
		return FALSE;
	}
	printf("Key A has been loaded successfully\n\n");

	// reset blocks
	//		iterate over all sectors
	BYTE lastSectorWith4Blocks = 0x1F;
	for (BYTE s = 0x00; s <= 0x27; s++) {
		// from sector ID we can tell how many blocks it cntains
		BYTE amountOfBlocksInSector = (s <= lastSectorWith4Blocks) ? 4 : 16;

		for (BYTE b = 0; b < amountOfBlocksInSector; b++) {
			// calculate absolute block ID (when you don't reset to 0 with each new sector and just keep counting)
			BYTE block = (s <= lastSectorWith4Blocks) ? (s*4 + b) : (32*4 + (s - 0x20)*16 + b);

			// handle special cases (block 0 and sector trailers are skipped)
			if (block == 0x00) continue; // block 0 is not writable
			if (is_byte_in_array(block, SECTOR_TRAILER_BLOCKS_4K, 40)) continue; // not really needed as we use < not <=

			// 		edge case: if card is ndef formatted, then sectors 0 and 0x10 have a different key
			if (((s == 0x00) || (s == 0x10)) && is_NDEF_key) {
				LOG_INFO("NDEF Key A detected. Will skip sectors 0 and 0x10 for now and reset them at the end");
				continue;
			}

			// authenticate block
			LOG_INFO("Authenticating block 0x%02x..", block);
			BYTE APDU_Authenticate_Block[10] = { 0xff, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, block, 0x60, 0x00 };
			response = executeApdu(hCard, APDU_Authenticate_Block, sizeof(APDU_Authenticate_Block), pbRecvBuffer, pbRecvBufferSize);
			if (response.status != 0 || !(pbRecvBuffer[0] == 0x90 && pbRecvBuffer[1] == 0x00)) {
				LOG_ERROR("Failed to authenticate block 0x%02x. Aborting..", block);
				return FALSE;
			}
			LOG_INFO("Authenticated block 0x%02x successfully", block);

			// write data to block
			BYTE APDU_Write[5 + 16] = { 0xff, 0xd6, 0x00, block, 0x10 };	// base command 5 bytes + 16 byte to write to block
			memset(APDU_Write + 5, 0x00, 16); // write 16 zero bytes
			response = executeApdu(hCard, APDU_Write, sizeof(APDU_Write), pbRecvBuffer, pbRecvBufferSize);
			if (response.status != 0 || !(pbRecvBuffer[0] == 0x90 && pbRecvBuffer[1] == 0x00)) {
				LOG_ERROR("Failed to write to block 0x%02x. Aborting..", block);
				return FALSE;
			}
			LOG_INFO("Reset block 0x%02x to all zeroes", block);

		}
		
	}

	// if ndef:
	//	- reset sector 0: 		blocks 1 and 2
	//	- reset setcor 0x10: 	blocks 0x40, 0x41 and 0x42
	if (is_NDEF_key) {
		// load key for NDEF sector 0 (you HAVE to authenticate with key B it seems)
		LOG_INFO("Loading NDEF key B for sector 0..");
		BYTE APDU_LoadDefaultKey[11] = { 0xff, 0x82, 0x00, 0x00, 0x06, KEY_B_NDEF_SECTOR_0_AND_10_4K[0], KEY_B_NDEF_SECTOR_0_AND_10_4K[1], KEY_B_NDEF_SECTOR_0_AND_10_4K[2], KEY_B_NDEF_SECTOR_0_AND_10_4K[3], KEY_B_NDEF_SECTOR_0_AND_10_4K[4], KEY_B_NDEF_SECTOR_0_AND_10_4K[5] };
		ApduResponse response = executeApdu(hCard, APDU_LoadDefaultKey, sizeof(APDU_LoadDefaultKey), pbRecvBuffer, pbRecvBufferSize);
		if (response.status != 0) {
			LOG_ERROR("Failed to load provided key. Aborting..");
			return FALSE;
		}
		if (!( (pbRecvBuffer[0] == 0x90) && (pbRecvBuffer[1] == 0x00) )) {
			LOG_ERROR("Failed to load provided key. Aborting..");
			return FALSE;
		}
		printf("NDEF key B for sector 0 has been loaded successfully\n\n");
		
		// reset sector 0: 		blocks 1 and 2
		for (BYTE block = 0x01; block < 0x03; block++) {
			// authenticate block
			LOG_INFO("Authenticating block 0x%02x..", block);
			BYTE APDU_Authenticate_Block[10] = { 0xff, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, block, 0x61, 0x00 }; // 0x61 - key B, 0x60 - key A
			response = executeApdu(hCard, APDU_Authenticate_Block, sizeof(APDU_Authenticate_Block), pbRecvBuffer, pbRecvBufferSize);
			if (response.status != 0 || !(pbRecvBuffer[0] == 0x90 && pbRecvBuffer[1] == 0x00)) {
				LOG_ERROR("Failed to authenticate block 0x%02x. Aborting..", block);
				return FALSE;
			}
			LOG_INFO("Authenticated block 0x%02x successfully", block);

			// write data to block
			BYTE APDU_Write[5 + 16] = { 0xff, 0xd6, 0x00, block, 0x10 };	// base command 5 bytes + 16 byte to write to block
			memset(APDU_Write + 5, 0x00, 16); // write 16 zero bytes
			response = executeApdu(hCard, APDU_Write, sizeof(APDU_Write), pbRecvBuffer, pbRecvBufferSize);
			if (response.status != 0 || !(pbRecvBuffer[0] == 0x90 && pbRecvBuffer[1] == 0x00)) {
				LOG_ERROR("Failed to write to block 0x%02x. Aborting..", block);
				return FALSE;
			}
			LOG_INFO("Reset block 0x%02x to all zeroes", block);
		}

		// reset sector 0x10: 	blocks 0x40, 0x41 and 0x42
		for (BYTE block = 0x40; block < 0x43; block++) {
			// authenticate block
			LOG_INFO("Authenticating block 0x%02x..", block);
			BYTE APDU_Authenticate_Block[10] = { 0xff, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, block, 0x61, 0x00 };
			response = executeApdu(hCard, APDU_Authenticate_Block, sizeof(APDU_Authenticate_Block), pbRecvBuffer, pbRecvBufferSize);
			if (response.status != 0 || !(pbRecvBuffer[0] == 0x90 && pbRecvBuffer[1] == 0x00)) {
				LOG_ERROR("Failed to authenticate block 0x%02x. Aborting..", block);
				return FALSE;
			}
			LOG_INFO("Authenticated block 0x%02x successfully", block);

			// write data to block
			BYTE APDU_Write[5 + 16] = { 0xff, 0xd6, 0x00, block, 0x10 };	// base command 5 bytes + 16 byte to write to block
			memset(APDU_Write + 5, 0x00, 16); // write 16 zero bytes
			response = executeApdu(hCard, APDU_Write, sizeof(APDU_Write), pbRecvBuffer, pbRecvBufferSize);
			if (response.status != 0 || !(pbRecvBuffer[0] == 0x90 && pbRecvBuffer[1] == 0x00)) {
				LOG_ERROR("Failed to write to block 0x%02x. Aborting..", block);
				return FALSE;
			}
			LOG_INFO("Reset block 0x%02x to all zeroes", block);
		}
	}

	LOG_INFO("Successfully reset entire tag.");

	return TRUE;
}

BOOL mifare_classic_4k_uninitialized_to_ndef(SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize) {
	// first wipe all non-sectortrailer blocks to all zeroes
	BOOL success = mifare_classic_4k_reset_card(KEY_A_DEFAULT_4K, hCard, pbRecvBuffer, pbRecvBufferSize);
	if (!success) {
		LOG_ERROR("Failed to wipe uninitialized tag..");
		return FALSE;
	}

	// load provided key A
	LOG_INFO("Loading key A..");
	BYTE APDU_LoadDefaultKey[11] = { 0xff, 0x82, 0x00, 0x00, 0x06, KEY_A_DEFAULT_4K[0], KEY_A_DEFAULT_4K[1], KEY_A_DEFAULT_4K[2], KEY_A_DEFAULT_4K[3], KEY_A_DEFAULT_4K[4], KEY_A_DEFAULT_4K[5] }; // page 12 of acr122u api docs, stores key at location 0
	ApduResponse response = executeApdu(hCard, APDU_LoadDefaultKey, sizeof(APDU_LoadDefaultKey), pbRecvBuffer, pbRecvBufferSize);
	if (response.status != 0) {
		LOG_ERROR("Failed to load provided key. Aborting..");
		return FALSE;
	}
	if (!( (pbRecvBuffer[0] == 0x90) && (pbRecvBuffer[1] == 0x00) )) {
		LOG_ERROR("Failed to load provided key. Aborting..");
		return FALSE;
	}
	printf("Key A has been loaded successfully\n\n");

	// write NDEF message into blocks 0x01, 0x02, 0x04, 0x40, 0x41 and 0x42
	//		0x01
	success = mifare_classic_4k_write_block(NDEF_Block1_4K, 0x01, KEY_A_DEFAULT_4K, hCard, pbRecvBuffer, pbRecvBufferSize);
	if (!success) {
		LOG_ERROR("Failed to write NDEF message to block 0x01. Aborting..");
		return FALSE;
	}
	//		0x02
	success = mifare_classic_4k_write_block(NDEF_Block2_4K, 0x02, KEY_A_DEFAULT_4K, hCard, pbRecvBuffer, pbRecvBufferSize);
	if (!success) {
		LOG_ERROR("Failed to write NDEF message to block 0x02. Aborting..");
		return FALSE;
	}
	//		0x04
	success = mifare_classic_4k_write_block(NDEF_Block4_4K, 0x04, KEY_A_DEFAULT_4K, hCard, pbRecvBuffer, pbRecvBufferSize);
	if (!success) {
		LOG_ERROR("Failed to write NDEF message to block 0x04. Aborting..");
		return FALSE;
	}
	//		0x40
	success = mifare_classic_4k_write_block(NDEF_Block_40_4K, 0x40, KEY_A_DEFAULT_4K, hCard, pbRecvBuffer, pbRecvBufferSize);
	if (!success) {
		LOG_ERROR("Failed to write NDEF message to block 0x40. Aborting..");
		return FALSE;
	}
	// 0x41, 0x42
	for (BYTE fooBlock = 0x41; fooBlock < 0x43; fooBlock++) {
		success = mifare_classic_4k_write_block(NDEF_Block_41_42_4K, fooBlock, KEY_A_DEFAULT_4K, hCard, pbRecvBuffer, pbRecvBufferSize);
		if (!success) {
			LOG_ERROR("Failed to write NDEF message to block 0x%02X. Aborting..", fooBlock);
			return FALSE;
		}
	}

	// rewrite sector trailers (except the trailers of sectors 0 and 0x10)
	for (BYTE b = 0; b < 40; b++) {
		BYTE block = SECTOR_TRAILER_BLOCKS_4K[b];

		if (block == 0x03 || block == 0x43) continue; // handle sectors 0 and 0x10 later

		// authenticate block
		LOG_INFO("Authenticating block 0x%02x..", block);
		BYTE APDU_Authenticate_Block[10] = { 0xff, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, block, 0x60, 0x00 };
		response = executeApdu(hCard, APDU_Authenticate_Block, sizeof(APDU_Authenticate_Block), pbRecvBuffer, pbRecvBufferSize);
		if (response.status != 0 || !(pbRecvBuffer[0] == 0x90 && pbRecvBuffer[1] == 0x00)) {
			LOG_ERROR("Failed to authenticate block 0x%02x. Aborting..", block);
			return FALSE;
		}
		LOG_INFO("Authenticated block 0x%02x successfully", block);

		// write data to block
		BYTE APDU_Write[5 + 16] = { 0xff, 0xd6, 0x00, block, 0x10 };	// base command 5 bytes + 16 byte to write to block
		memcpy(&APDU_Write[5], NDEF_SECTOR_TRAILER_1_TO_0F_AND_11_TO_27_4K, 16);

		response = executeApdu(hCard, APDU_Write, sizeof(APDU_Write), pbRecvBuffer, pbRecvBufferSize);
		if (response.status != 0 || !(pbRecvBuffer[0] == 0x90 && pbRecvBuffer[1] == 0x00)) {
			LOG_ERROR("Failed to write to block 0x%02x. Aborting..", block);
			return FALSE;
		}
		LOG_INFO("Wrote new sector trailer 0x%02x", block);
		
	}

	// now write the trailer blocks 0x03 and 0x43 that we skipped earlier
	static const BYTE trailerBlocksLeft[] = { 0x03, 0x43 };
	for (BYTE idx = 0; idx < 2; idx++) {
    	BYTE block = trailerBlocksLeft[idx];
	
		BYTE APDU_Authenticate_Block[10] = { 0xff, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, block, 0x60, 0x00 };
		response = executeApdu(hCard, APDU_Authenticate_Block, sizeof(APDU_Authenticate_Block), pbRecvBuffer, pbRecvBufferSize);
		if (response.status != 0 || !(pbRecvBuffer[0] == 0x90 && pbRecvBuffer[1] == 0x00)) {
			LOG_ERROR("Failed to authenticate block 0x%02x. Aborting..", block);
			return FALSE;
		}
		LOG_INFO("Authenticated block 0x%02x successfully", block);

		// write data to block
		BYTE APDU_Write[5 + 16] = { 0xff, 0xd6, 0x00, block, 0x10 };
		memcpy(&APDU_Write[5], NDEF_SECTOR_TRAILER_0_AND_10_4K, 16);

		response = executeApdu(hCard, APDU_Write, sizeof(APDU_Write), pbRecvBuffer, pbRecvBufferSize);
		if (response.status != 0 || !(pbRecvBuffer[0] == 0x90 && pbRecvBuffer[1] == 0x00)) {
			LOG_ERROR("Failed to write to block 0x%02x. Aborting..", block);
			return FALSE;
		}
		LOG_INFO("Wrote new sector trailer 0x%02x", block);
	}


	LOG_INFO("Successfully NDEF-formatted the tag");
	return TRUE;
}

BOOL mifare_classic_4k_ndef_to_uninitialized(SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize) {
	// first wipe all non-sectortrailer blocks to all zeroes
	BOOL success = mifare_classic_4k_reset_card(KEY_A_NDEF_SECTOR_1_TO_0F_AND_11_TO_27_4K, hCard, pbRecvBuffer, pbRecvBufferSize);
	if (!success) {
		LOG_ERROR("Failed to wipe NDEF-formatted tag..");
		return FALSE;
	}

	// load provided key B
	LOG_INFO("Loading key B..");
	BYTE APDU_LoadDefaultKey[11] = { 0xff, 0x82, 0x00, 0x00, 0x06, 	KEY_B_NDEF_SECTOR_1_TO_0F_AND_11_TO_27_4K[0], // page 12, stores key at location 0
																	KEY_B_NDEF_SECTOR_1_TO_0F_AND_11_TO_27_4K[1], 
																	KEY_B_NDEF_SECTOR_1_TO_0F_AND_11_TO_27_4K[2], 
																	KEY_B_NDEF_SECTOR_1_TO_0F_AND_11_TO_27_4K[3], 
																	KEY_B_NDEF_SECTOR_1_TO_0F_AND_11_TO_27_4K[4], 
																	KEY_B_NDEF_SECTOR_1_TO_0F_AND_11_TO_27_4K[5] };

	ApduResponse response = executeApdu(hCard, APDU_LoadDefaultKey, sizeof(APDU_LoadDefaultKey), pbRecvBuffer, pbRecvBufferSize);
	if (response.status != 0) {
		LOG_ERROR("Failed to load provided key. Aborting..");
		return FALSE;
	}
	if (!( (pbRecvBuffer[0] == 0x90) && (pbRecvBuffer[1] == 0x00) )) {
		LOG_ERROR("Failed to load provided key. Aborting..");
		return FALSE;
	}
	printf("Key B has been loaded successfully\n\n");

	// rewrite sector trailers (except block 0x03 (sector 0) and block 0x43 (sector 0x10))
	for (BYTE b = 0; b < 40; b++) {
		BYTE block = SECTOR_TRAILER_BLOCKS_4K[b];

		if (block == 0x03 || block == 0x43) continue; // we will handle these later
	
		// authenticate block (we use key B so its 0x61 instead of 0x60)
		LOG_INFO("Authenticating block 0x%02x..", block);
		BYTE APDU_Authenticate_Block[10] = { 0xff, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, block, 0x61, 0x00 };
		response = executeApdu(hCard, APDU_Authenticate_Block, sizeof(APDU_Authenticate_Block), pbRecvBuffer, pbRecvBufferSize);
		if (response.status != 0 || !(pbRecvBuffer[0] == 0x90 && pbRecvBuffer[1] == 0x00)) {
			LOG_ERROR("Failed to authenticate block 0x%02x. Aborting..", block);
			return FALSE;
		}
		LOG_INFO("Authenticated block 0x%02x successfully", block);

		// write data to block
		BYTE APDU_Write[5 + 16] = { 0xff, 0xd6, 0x00, block, 0x10 };	// base command 5 bytes + 16 byte to write to block
		memcpy(&APDU_Write[5], UNINITIALIZED_SECTOR_TRAILER_4K, 16);

		response = executeApdu(hCard, APDU_Write, sizeof(APDU_Write), pbRecvBuffer, pbRecvBufferSize);
		if (response.status != 0 || !(pbRecvBuffer[0] == 0x90 && pbRecvBuffer[1] == 0x00)) {
			LOG_ERROR("Failed to write to block 0x%02x. Aborting..", block);
			return FALSE;
		}
		LOG_INFO("Wrote new sector trailer 0x%02x", block);

	}

	// finally, rewrite sector trailers of block 0x03 and block 0x43

	// load key for NDEF sector 0 (you HAVE to authenticate with key B it seems)
	LOG_INFO("Loading NDEF key B for sector 0..");
	// 		replace key A that was previously used with key B
	APDU_LoadDefaultKey[5] = KEY_B_NDEF_SECTOR_0_AND_10_4K[0];
	APDU_LoadDefaultKey[6] = KEY_B_NDEF_SECTOR_0_AND_10_4K[1];
	APDU_LoadDefaultKey[7] = KEY_B_NDEF_SECTOR_0_AND_10_4K[2];
	APDU_LoadDefaultKey[8] = KEY_B_NDEF_SECTOR_0_AND_10_4K[3];
	APDU_LoadDefaultKey[9] = KEY_B_NDEF_SECTOR_0_AND_10_4K[4];
	APDU_LoadDefaultKey[10] = KEY_B_NDEF_SECTOR_0_AND_10_4K[5];

	response = executeApdu(hCard, APDU_LoadDefaultKey, sizeof(APDU_LoadDefaultKey), pbRecvBuffer, pbRecvBufferSize);
	if (response.status != 0) {
		LOG_ERROR("Failed to load provided key. Aborting..");
		return FALSE;
	}
	if (!( (pbRecvBuffer[0] == 0x90) && (pbRecvBuffer[1] == 0x00) )) {
		LOG_ERROR("Failed to load provided key. Aborting..");
		return FALSE;
	}
	printf("NDEF key B for sector 0 has been loaded successfully\n\n");
	

	// now write the trailer blocks 0x03 and 0x43 that we skipped earlier
	static const BYTE trailerBlocksLeft[] = { 0x03, 0x43 };
	for (BYTE idx = 0; idx < 2; idx++) {
    	BYTE block = trailerBlocksLeft[idx];

    	// authenticate block
		BYTE APDU_Authenticate_Block[10] = { 0xff, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, block, 0x61, 0x00 }; // 0x61 - key B, 0x60 - key A
		response = executeApdu(hCard, APDU_Authenticate_Block, sizeof(APDU_Authenticate_Block), pbRecvBuffer, pbRecvBufferSize);
		if (response.status != 0 || !(pbRecvBuffer[0] == 0x90 && pbRecvBuffer[1] == 0x00)) {
			LOG_ERROR("Failed to authenticate block 0x%02x. Aborting..", block);
			return FALSE;
		}
		LOG_INFO("Authenticated block 0x%02x successfully", block);

		// write data to block
		BYTE APDU_Write[5 + 16] = { 0xff, 0xd6, 0x00, block, 0x10 };	// base command 5 bytes + 16 byte to write to block
		memcpy(&APDU_Write[5], UNINITIALIZED_SECTOR_TRAILER_4K, 16);

		response = executeApdu(hCard, APDU_Write, sizeof(APDU_Write), pbRecvBuffer, pbRecvBufferSize);
		if (response.status != 0 || !(pbRecvBuffer[0] == 0x90 && pbRecvBuffer[1] == 0x00)) {
			LOG_ERROR("Failed to write to block 0x%02x. Aborting..", block);
			return FALSE;
		}
		LOG_INFO("Wrote new sector trailer 0x%02x", block);

    }

	LOG_INFO("Successfully reset the tag back to uninitialized");
	return TRUE;
}
