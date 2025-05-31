#include "mifare-ultralight.h"
#include "logging.c"
#include "main.h"

// Note: Code was tested with MF0UL1x (Ultralight EV1, also called MF0UL11) (has 20 pages), but there also is MF0UL2x (also called MF0UL21) with 41 pages

// each page holds 4 bytes (48 bytes total user memory)
const BYTE ULTRALIGHT_1x_USER_MEMORY[12] =         {                          0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

const BYTE ULTRALIGHT_1x_EXISTING_PAGES[20] =      {  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                                                      0x10, 0x11, 0x12, 0x13, 
                                                    };


// -------------------------------- write / read tag ---------------------------------

// ultralight_read_page reads the provided page (actually also reads the next 3 pages)
BOOL ultralight_read_page(BYTE page, SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize) {
    LOG_DEBUG("Trying to read page 0x%02x.", page);
    // sanity check that page is in valid range
    if (!is_byte_in_array(page, ULTRALIGHT_1x_EXISTING_PAGES, 20)) {
        LOG_WARN("page 0x%02x you provided is not valid! Must be in [0x00, 0x13]", page);
        return FALSE;
    }

    // ff 00 00 00 04 (communicate with pn532 and 04 byte command will follow)
    //      d4 (data exchange command)
    //      42 (InCommunicateThru)
    //      30 (Read) [page 18 of MF0ULX1 document]
    //      read this page
    // Response:
    //      d5 43 00 
    //      all bytes read (it will actually read 4 pages [page, page+1, page+2, page+3]. when reaching the end of the card it will continue reading the start (e.g. 0x12, 0x13, 0x00, 0x01))
    //      90 00
    BYTE APDU_Read[9] = { 0xff, 0x00, 0x00, 0x00, 0x04, 0xd4, 0x42, 0x30, page };
    ApduResponse response = executeApdu(hCard, APDU_Read, sizeof(APDU_Read), pbRecvBuffer, pbRecvBufferSize);
    if (response.status != 0 || !(pbRecvBuffer[19] == 0x90 && pbRecvBuffer[20] == 0x00)) {
        LOG_ERROR("Reading page 0x%02x failed.", page);
        return FALSE;
    }

    //dump_response_buffer(pbRecvBuffer);

    return TRUE;
}

// ultralight_fast_read reads the entire tag at once (possible even with pn532 buffer limitation)
BOOL ultralight_fast_read(SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize) {
    LOG_DEBUG("Fast reading entire Ultralight tag..");
 
    // ff 00 00 00 05 (communicate with pn532 and 05 byte command will follow)
    //      d4 (data exchange command)
    //      42 (InCommunicateThru)
    //      3a (FastRead) [page 18 of MF0ULX1 document]
    //      read from page
    //      read to page
    // Response:
    //      d5 43 00 
    //      all bytes read
    //      90 00
    BYTE APDU_Read[10] = { 0xff, 0x00, 0x00, 0x00, 0x05, 0xd4, 0x42, 0x3a, ULTRALIGHT_1x_EXISTING_PAGES[0], ULTRALIGHT_1x_EXISTING_PAGES[19] };
    ApduResponse response = executeApdu(hCard, APDU_Read, sizeof(APDU_Read), pbRecvBuffer, pbRecvBufferSize);
    if (response.status != 0 || !(pbRecvBuffer[83] == 0x90 && pbRecvBuffer[84] == 0x00)) {
        LOG_ERROR("Fast reading the tag failed.");
        return FALSE;
    }

    dump_response_buffer_256(pbRecvBuffer);

    return TRUE;
}

// ultralight_write_page writes 4 bytes to the target page, but only if that page is user-memory (safe)
BOOL ultralight_write_page(BYTE* data, BYTE page, SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize) {
    LOG_DEBUG("Trying to write to page 0x%02x.", page);
    // sanity check
    if (!is_byte_in_array(page, ULTRALIGHT_1x_USER_MEMORY, 12)) {
        LOG_WARN("Page 0x%02x is not a user memory page. Refusing to write there.", page);
        return FALSE;
    }

    // ff 00 00 00 08 (communicate with pn532 and 8 byte command (4 byte command + 4 bytes data) will follow)
    //      d4 (data exchange command)
    //      42 (InCommunicateThru)
    //      a2 (Write) [page 18 of MF0ULX1 document]
    //      page (which page you target)
    //      4 bytes you want to write
    BYTE APDU_Write[9 + 4] = { 0xff, 0x00, 0x00, 0x00, 0x08, 0xd4, 0x42, 0xa2, page };
    memcpy(APDU_Write + 9, data, 4);

    // write to page
    ApduResponse response = executeApdu(hCard, APDU_Write, sizeof(APDU_Write), pbRecvBuffer, pbRecvBufferSize);
    if (response.status != 0 || !(pbRecvBuffer[3] == 0x90 && pbRecvBuffer[4] == 0x00)) {
        LOG_ERROR("Failed to write to page 0x%02x. Aborting..", page);
        return FALSE;
    }
    LOG_INFO("Wrote data to page 0x%02x with success.", page);

    return TRUE;
}

// ultralight_reset_user_data writes zeroes to pages 0x04 - 0x0F
BOOL ultralight_reset_user_data(SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize) {
    LOG_DEBUG("Trying to reset all user data pages to zeroes.");
    BYTE Zeroes[4] = {0};
    for (int i=0; i <12; ++i) {
        BOOL success = ultralight_write_page(Zeroes, ULTRALIGHT_1x_USER_MEMORY[i], hCard, pbRecvBuffer, pbRecvBufferSize);
        if (!success) {
            LOG_ERROR("An error occurred, aborting..");
            return FALSE;
        }
    }

    return TRUE;
}

// -------------------------------- counter read / write -------------------------------------

// ultralight_read_counter reads the current value of the counter (READ_CNT exists only in EV1, not in old ultralight)
// the tag has 3 different counters, all of which can only be incremented but not decremented. you must specify which counter you want to read (0x00, 0x01 or 0x02)
// a counter itself is 3 byte large, all three counters are stored 'after' page 0x13 (they are not accessible except for when you use READ_CNT or INCR_CNT)
BOOL ultralight_read_counter(BYTE counter, SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize) {
    LOG_DEBUG("Trying to read the counter of your Ultralight EV1.");
  
    // sanity check
    if (counter != 0x00 && counter != 0x01 && counter != 0x02) {
        LOG_WARN("Your tag has three counters (0x00, 0x01 and 0x02). You tried to read counter 0x%02x but this counter does not exist.", counter);
        return FALSE;
    }

    // ff 00 00 00 04 (communicate with pn532 and 4 byte command will follow)
    //      d4      (data exchange command)
    //      42      (InCommunicateThru)
    //      39      (READ_CNT) [page 18 of MF0ULX1 document]
    //      counter (0x00, 0x01 or 0x02)
    // Response:
    //      d5 43 00
    //      COUNTER (3 bytes, LSB)
    //      90 00
    BYTE APDU_Read[9] = { 0xff, 0x00, 0x00, 0x00, 0x04, 0xd4, 0x42, 0x39, counter};
    ApduResponse response = executeApdu(hCard, APDU_Read, sizeof(APDU_Read), pbRecvBuffer, pbRecvBufferSize);
    if (response.status != 0 || !(pbRecvBuffer[6] == 0x90 && pbRecvBuffer[7] == 0x00)) {
        LOG_ERROR("Failed to read the counter 0x%02x. Aborting..", counter);
        return FALSE;
    }
    LOG_INFO("Read counter 0x%02x successfully.", counter);

    // calculate MSB decimal result
    uint32_t counter_dez = pbRecvBuffer[5]*((16^4)-1) + pbRecvBuffer[4]*((16^2)-1) + pbRecvBuffer[3];
    LOG_INFO("Current counter value: %u (0x%06X)", counter_dez, counter_dez);

    return TRUE;
}

// ultralight_increment_counter increments the value of the targeted counter by 1 (INCR_CNT exists only in EV1, not in old ultralight)
// the highest possible counter value is (16^(3*2))-1 = 16_777_215 
BOOL ultralight_increment_counter(BYTE counter, SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize) {
    LOG_DEBUG("Trying to increment counter 0x%02x.", counter);
  
    // sanity check
    if (counter != 0x00 && counter != 0x01 && counter != 0x02) {
        LOG_WARN("Your tag has three counters (0x00, 0x01 and 0x02). You tried to increment counter 0x%02x but this counter does not exist.", counter);
        return FALSE;
    }

    // ff 00 00 00 08 (communicate with pn532 and 8 byte command will follow)
    //      d4 (data exchange command)
    //      42 (InCommunicateThru)
    //      a5 (INCR_CNT) [page 18 of MF0ULX1 document]
    // Response:
    //      d5 43
    //      02 (what does this mean?)
    //      90 00
    BYTE APDU_Inc[13] = { 0xff, 0x00, 0x00, 0x00, 0x08, 0xd4, 0x42, 0xa5, counter, 0x01, 0x00, 0x00, 0x00}; // 0x01 0x00 0x00 0x00 [LSB] means we increment the counter by just 1, in fact the last byte (here: 0x00) is completely ignored (so u can only increment by 0xFF FF FF at a time (+16_777_215) which makes sense cuz that is the max possible value, so u can only do this increment if the counter was 0)
    ApduResponse response = executeApdu(hCard, APDU_Inc, sizeof(APDU_Inc), pbRecvBuffer, pbRecvBufferSize);
    if (response.status != 0 || !(pbRecvBuffer[3] == 0x90 && pbRecvBuffer[4] == 0x00)) {
        LOG_ERROR("Failed to increment counter 0x%02x. Aborting..", counter);
        // Note: if the increment would make the result of the counter larger than 16_777_215 then it does not increment the counter at all! but from the response there seems to be no way whether the counter increment was successful or not. i could first read counter, then inc counter, then read counter again and compare to detetct such an event but i personally have no need for this feature rn
        return FALSE;
    }
    LOG_INFO("Incremented counter 0x%02x by 1.", counter);

    return TRUE;
}
