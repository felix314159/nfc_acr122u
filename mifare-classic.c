#include "mifare-classic.h"
#include "logging.c"
#include "main.h"

// SECTOR TRAILERS
//		NDEF FORMATTED
const BYTE NDEF_SECTOR_TRAILER_0[16] = 		  { 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,   	// key A  
												0x78, 0x77, 0x88, 0xC1,    				// access bits
												0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };	// key B

const BYTE NDEF_SECTOR_TRAILER_115[16] = 	  { 0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7,     // key A
												0x7F, 0x07, 0x88, 0x40,     			// access bits
												0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };	// key B

//		UNINITIALIZED
const BYTE UNINITIALIZED_SECTOR_TRAILER[16] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  	// key A
												0xFF, 0x07, 0x80, 0x69, 				// access bits
												0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };	// key B

// SECTOR TRAILER INDICES (blocks 0,1,2 in each sector contain data, block 3 holds key config. exception: in sector 0 block 0 is not usable)
const BYTE SECTOR_BLOCKS[16] 			= { 0x03, 0x07, 0x0B, 0x0F, 0x13, 0x17, 0x1B, 0x1F,
											0x23, 0x27, 0x2B, 0x2F, 0x33, 0x37, 0x3B, 0x3F };
// SECTOR IDs (e.g. sector 0 holds blocks 0,1,2,3 and sector 5 holds blocks 0x17-3, 0x17-2,0x17-1 and 0x17)
const BYTE SECTOR_IDS[16] 				= { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
											0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

// KEYS
//		uninitialized default keys
const BYTE KEY_A_DEFAULT[6] 			= { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
const BYTE KEY_B_DEFAULT[6] 			= { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

//		ndef-formatted default keys
const BYTE KEY_A_NDEF_SECTOR0[6] 		= { 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5 };
const BYTE KEY_B_NDEF_SECTOR0[6] 		= { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

const BYTE KEY_A_NDEF_SECTOR115[6] 		= { 0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7 };	// 64 33 66 37 64 33 66 37 64 33 66 37
const BYTE KEY_B_NDEF_SECTOR115[6] 		= { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

// ACCESS BITS
//		uninitialized access bits
const BYTE ACCESS_BITS_UNINITALIZED[4] 	=  { 0xFF, 0x07, 0x80, 0x69 };
const BYTE ACCESS_BITS_NDEF_SECTOR0[4] 	=  { 0x78, 0x77, 0x88, 0xC1 };
const BYTE ACCESS_BITS_NDEF_SECTOR115[4] = { 0x7F, 0x07, 0x88, 0x40 };

// NDEF Block 0x01
const BYTE NDEF_Block1[16] = { 0x14, 0x01, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1 };

// NDEF Block 0x02
const BYTE NDEF_Block2[16] = { 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1 };

// NDEF Block 0x04
const BYTE NDEF_Block4[16] = { 0x03, 0x00, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };


// is_byte_in_array is a helper function to check whether passed byte value is an element in the array 'array' of size 'size'
// C feels really old here, not being able to get size of array that has static size because it decays to a pointer in this function is kinda cringe no cap
BOOL is_byte_in_array(BYTE value, const BYTE *array, size_t size) {
    for (size_t i = 0; i < size; i++) {
        if (array[i] == value) {
            return TRUE;
        }
    }
    return FALSE;
}


// mifare_classic_read_sector reads an entire sector and prints it
// currently only supports mifare classic 1k
SectorContent mifare_classic_read_sector(BYTE sectorId, const BYTE *keyA, SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize) {
	// prepare data type that holds the data that will be returned on success
    SectorContent sector_content = {0}; // initialize all fields to 0, when you return early due to error just set false as .status
    sector_content.sectorID = sectorId;

	// check whether passed sector is valid for mifare 4k
	if (!is_byte_in_array(sectorId, SECTOR_IDS, 16)) {
		LOG_WARN("0x%02x is not a valid sector! You are only allowed to read sectors 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E and 0x0F.", sectorId);
		sector_content.status = FALSE;
		return sector_content;
	}

	// load provided key
	LOG_INFO("Loading key..");
	BYTE APDU_LoadDefaultKey[11] = { 0xff, 0x82, 0x00, 0x00, 0x06, keyA[0], keyA[1], keyA[2], keyA[3], keyA[4], keyA[5] }; // page 12, stores key at location 0
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

	for (BYTE i = 0; i < 3; i++) {
		BYTE block = sectorId * 4 + i;

		BYTE APDU_Authenticate_Block[10] = { 0xff, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, block, 0x60, 0x00 };

	    // page 13 (0x60 is Key A, 0x61 is key B)
		//BYTE APDU_Authenticate_Block[6] = { 0xff, 0x88, 0x00, block_s_minus_3, 0x60, 0x00 };
		// Note: If the APDU[10] does not work it is because your PCSC library is using an old version (<2.07), in such cases the correct command is: APDU[10] as seen on page 15. On linux see your version using: pcscd --version

		response = executeApdu(hCard, APDU_Authenticate_Block, sizeof(APDU_Authenticate_Block), pbRecvBuffer, pbRecvBufferSize);
		if (response.status != 0 || !(pbRecvBuffer[0] == 0x90 && pbRecvBuffer[1] == 0x00)) {
			LOG_ERROR("Failed to authenticate block 0x%02x. Aborting..", block);
			sector_content.status = FALSE;
			return sector_content;
		}

		LOG_INFO("Authenticated block 0x%02x successfully", block);
		
		//SLEEP_CUSTOM(2000); // page 16 notes to wait 2 sec on mifare classic 2k

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
		if (i == 0) {
			memcpy(sector_content.Block_0, pbRecvBuffer, 16);
		}
	    else if (i == 1) {
	    	memcpy(sector_content.Block_1, pbRecvBuffer, 16);
	    } 
	    else if (i == 2) {
	    	memcpy(sector_content.Block_2, pbRecvBuffer, 16);
	    } 
    
	}
	
	return sector_content;
}

// currently only supports authentication via keyA
BOOL mifare_classic_write_block(const BYTE *BlockData, BYTE block, const BYTE *keyA, SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize) {
	// sanity checks
	if (block == 0x00) {
		LOG_WARN("You can't write to block 0, try a different block.");
		return FALSE;
	}
	if (block > 0x3F) { // mifare classic 1k
		LOG_WARN("You can't write to block 0x%02x, the last block of a Mifare Classic 1k is block 0x3F.", block);
		return FALSE;
	}

	// warn user if he is writing to sector trailer (allowed but has consequences)
	if (is_byte_in_array(block, SECTOR_BLOCKS, 16)) {
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

// this function resets all writable blocks (except sector trailers) to all zeroes
// assumes card is using same key A for every block (e.g. would be true for uninitialized card), or is fully NDEF formatted (pass key for sectors 1-15)
BOOL mifare_classic_reset_card(const BYTE *keyA, SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize) {
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
	for (BYTE s = 0x00; s < 0x0F+1; s++) {
		for (BYTE b = 0; b < 3; b++) {
			BYTE block = s * 4 + b;
			if (block == 0x00) continue; // block 0 is not writable
			if (is_byte_in_array(block, SECTOR_BLOCKS, 16)) continue; // not necessary tbh

			
			// only edge case: if card is ndef formatted, then sector 0 has a different key
			if ((s == 0x00) && is_NDEF_key) {
				//LOG_INFO("NDEF Key A detected. Will skip sector 0 for now and reset it at the end");
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


	// if ndef, reset sector 0 blocks 1 and 2
	if (is_NDEF_key) {
		// load key for NDEF sector 0 (you HAVE to authenticate with key B it seems)
		LOG_INFO("Loading NDEF key B for sector 0..");
		BYTE APDU_LoadDefaultKey[11] = { 0xff, 0x82, 0x00, 0x00, 0x06, KEY_B_NDEF_SECTOR0[0], KEY_B_NDEF_SECTOR0[1], KEY_B_NDEF_SECTOR0[2], KEY_B_NDEF_SECTOR0[3], KEY_B_NDEF_SECTOR0[4], KEY_B_NDEF_SECTOR0[5] };
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
		
		// reset blocks 1 and 2
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
	}

	return TRUE;
}

BOOL mifare_classic_ndef_to_uninitialized(SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize) {
	// first wipe all non-sectortrailer blocks to all zeroes
	BOOL success = mifare_classic_reset_card(KEY_A_NDEF_SECTOR115, hCard, pbRecvBuffer, pbRecvBufferSize);
	if (!success) {
		LOG_ERROR("Failed to wipe NDEF-formatted tag..");
		return FALSE;
	}

	// load provided key B
	LOG_INFO("Loading key B..");
	BYTE APDU_LoadDefaultKey[11] = { 0xff, 0x82, 0x00, 0x00, 0x06, KEY_B_NDEF_SECTOR115[0], KEY_B_NDEF_SECTOR115[1], KEY_B_NDEF_SECTOR115[2], KEY_B_NDEF_SECTOR115[3], KEY_B_NDEF_SECTOR115[4], KEY_B_NDEF_SECTOR115[5] }; // page 12, stores key at location 0
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

	// rewrite sector trailers (except sector 0)
	for (BYTE b = 0; b < 16; b++) {
		BYTE block = SECTOR_BLOCKS[b];

		if (block == 0x03) continue; // we will handle sector trailer 0 later
	
		//printf("block 0x%02x\n", block);

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
		memcpy(&APDU_Write[5], UNINITIALIZED_SECTOR_TRAILER, 16);

		response = executeApdu(hCard, APDU_Write, sizeof(APDU_Write), pbRecvBuffer, pbRecvBufferSize);
		if (response.status != 0 || !(pbRecvBuffer[0] == 0x90 && pbRecvBuffer[1] == 0x00)) {
			LOG_ERROR("Failed to write to block 0x%02x. Aborting..", block);
			return FALSE;
		}
		LOG_INFO("Wrote new sector trailer 0x%02x", block);

	
		
	}

	// finally, rewrite sector trailer of sector 0

	// load key for NDEF sector 0 (you HAVE to authenticate with key B it seems)
	LOG_INFO("Loading NDEF key B for sector 0..");
	// replace key A that was previously used with key B
	APDU_LoadDefaultKey[5] = KEY_B_NDEF_SECTOR0[0];
	APDU_LoadDefaultKey[6] = KEY_B_NDEF_SECTOR0[1];
	APDU_LoadDefaultKey[7] = KEY_B_NDEF_SECTOR0[2];
	APDU_LoadDefaultKey[8] = KEY_B_NDEF_SECTOR0[3];
	APDU_LoadDefaultKey[9] = KEY_B_NDEF_SECTOR0[4];
	APDU_LoadDefaultKey[10] = KEY_B_NDEF_SECTOR0[5];

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
	

	// authenticate block 3 (sector trailer of sector 0)
	BYTE block = SECTOR_BLOCKS[0];
	BYTE APDU_Authenticate_Block[10] = { 0xff, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, block, 0x61, 0x00 }; // 0x61 - key B, 0x60 - key A
	response = executeApdu(hCard, APDU_Authenticate_Block, sizeof(APDU_Authenticate_Block), pbRecvBuffer, pbRecvBufferSize);
	if (response.status != 0 || !(pbRecvBuffer[0] == 0x90 && pbRecvBuffer[1] == 0x00)) {
		LOG_ERROR("Failed to authenticate block 0x%02x. Aborting..", block);
		return FALSE;
	}
	LOG_INFO("Authenticated block 0x%02x successfully", block);

	// write data to block
	BYTE APDU_Write[5 + 16] = { 0xff, 0xd6, 0x00, block, 0x10 };	// base command 5 bytes + 16 byte to write to block
	memcpy(&APDU_Write[5], UNINITIALIZED_SECTOR_TRAILER, 16);

	response = executeApdu(hCard, APDU_Write, sizeof(APDU_Write), pbRecvBuffer, pbRecvBufferSize);
	if (response.status != 0 || !(pbRecvBuffer[0] == 0x90 && pbRecvBuffer[1] == 0x00)) {
		LOG_ERROR("Failed to write to block 0x%02x. Aborting..", block);
		return FALSE;
	}
	LOG_INFO("Wrote new sector trailer 0x%02x", block);

	return TRUE;
}

BOOL mifare_classic_uninitialized_to_ndef(SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize) {
	// first wipe all non-sectortrailer blocks to all zeroes
	BOOL success = mifare_classic_reset_card(KEY_A_DEFAULT, hCard, pbRecvBuffer, pbRecvBufferSize);
	if (!success) {
		LOG_ERROR("Failed to wipe uninitialized tag..");
		return FALSE;
	}

	// load provided key A
	LOG_INFO("Loading key A..");
	BYTE APDU_LoadDefaultKey[11] = { 0xff, 0x82, 0x00, 0x00, 0x06, KEY_A_DEFAULT[0], KEY_A_DEFAULT[1], KEY_A_DEFAULT[2], KEY_A_DEFAULT[3], KEY_A_DEFAULT[4], KEY_A_DEFAULT[5] }; // page 12, stores key at location 0
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

	// write NDEF message into blocks 0x01, 0x02 and 0x04
	//		0x01
	success = mifare_classic_write_block(NDEF_Block1, 0x01, KEY_A_DEFAULT, hCard, pbRecvBuffer, pbRecvBufferSize);
	if (!success) {
		LOG_ERROR("Failed to write NDEF message to block 0x01. Aborting..");
		return FALSE;
	}
	//		0x02
	success = mifare_classic_write_block(NDEF_Block2, 0x02, KEY_A_DEFAULT, hCard, pbRecvBuffer, pbRecvBufferSize);
	if (!success) {
		LOG_ERROR("Failed to write NDEF message to block 0x02. Aborting..");
		return FALSE;
	}
	//		0x04
	success = mifare_classic_write_block(NDEF_Block4, 0x04, KEY_A_DEFAULT, hCard, pbRecvBuffer, pbRecvBufferSize);
	if (!success) {
		LOG_ERROR("Failed to write NDEF message to block 0x04. Aborting..");
		return FALSE;
	}


	// rewrite sector trailers (except sector 0)
	for (BYTE b = 0; b < 16; b++) {
		BYTE block = SECTOR_BLOCKS[b];

		if (block == 0x03) continue; // handle sector 0 later

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
		memcpy(&APDU_Write[5], NDEF_SECTOR_TRAILER_115, 16);

		response = executeApdu(hCard, APDU_Write, sizeof(APDU_Write), pbRecvBuffer, pbRecvBufferSize);
		if (response.status != 0 || !(pbRecvBuffer[0] == 0x90 && pbRecvBuffer[1] == 0x00)) {
			LOG_ERROR("Failed to write to block 0x%02x. Aborting..", block);
			return FALSE;
		}
		LOG_INFO("Wrote new sector trailer 0x%02x", block);
		
	}

	// authenticate block 3 (sector trailer of sector 0)
	BYTE block = SECTOR_BLOCKS[0];
	BYTE APDU_Authenticate_Block[10] = { 0xff, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, block, 0x60, 0x00 };
	response = executeApdu(hCard, APDU_Authenticate_Block, sizeof(APDU_Authenticate_Block), pbRecvBuffer, pbRecvBufferSize);
	if (response.status != 0 || !(pbRecvBuffer[0] == 0x90 && pbRecvBuffer[1] == 0x00)) {
		LOG_ERROR("Failed to authenticate block 0x%02x. Aborting..", block);
		return FALSE;
	}
	LOG_INFO("Authenticated block 0x%02x successfully", block);

	// write data to block
	BYTE APDU_Write[5 + 16] = { 0xff, 0xd6, 0x00, block, 0x10 };	// base command 5 bytes + 16 byte to write to block
	memcpy(&APDU_Write[5], NDEF_SECTOR_TRAILER_0, 16);

	response = executeApdu(hCard, APDU_Write, sizeof(APDU_Write), pbRecvBuffer, pbRecvBufferSize);
	if (response.status != 0 || !(pbRecvBuffer[0] == 0x90 && pbRecvBuffer[1] == 0x00)) {
		LOG_ERROR("Failed to write to block 0x%02x. Aborting..", block);
		return FALSE;
	}
	LOG_INFO("Wrote new sector trailer 0x%02x", block);

	return TRUE;
}
