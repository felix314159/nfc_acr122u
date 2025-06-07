#include "ntag-213.h"
#include "logging.c"
#include "main.h"

// each page holds 4 bytes
const BYTE NTAG_213_USER_MEMORY_PAGES[36] = {                          0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                                               0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
                                               0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27 };

const BYTE NTAG_213_EXISTING_PAGES[45] =    {  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                                               0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
                                               0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C };

// ---------------- write / read tag --------------------------------------------------

// ntag_213_write_page writes 4 bytes to a page
BOOL ntag_213_write_page(BYTE* data, BYTE page, SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize) {
    LOG_DEBUG("Trying to write to page 0x%02x.", page);
    // sanity check
    if (!is_byte_in_array(page, NTAG_213_USER_MEMORY_PAGES, 36)) {
        LOG_WARN("Page 0x%02x is not a user memory page. Refusing to write there.", page);
        return FALSE;
    }

    // ff 00 00 00 08 (communicate with pn532 and 8 byte (4 byte command and 4 byte data) command will follow)
    //      d4 (data exchange command)
    //      42 (InCommunicateThru)
    //      a2 (Write) [page 41 of ntag21x document]
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

// ntag_213_reset_user_data writes zeroes to pages 0x04 - 0x27
BOOL ntag_213_reset_user_data(SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize) {
    LOG_DEBUG("Trying to reset all user data pages to zeroes.");
    BYTE Zeroes[4] = {0};
    for (int i=0; i<36; ++i) {
        BOOL success = ntag_213_write_page(Zeroes, NTAG_213_USER_MEMORY_PAGES[i], hCard, pbRecvBuffer, pbRecvBufferSize);
        if (!success) {
            LOG_ERROR("An error occurred, aborting..");
            return FALSE;
        }
    }

    return TRUE;
}

// ntag_213_fast_read reads all data between 'from_page' and 'to_page'
BOOL ntag_213_fast_read(BYTE from_page, BYTE to_page, SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize) {
    LOG_DEBUG("Trying to fast read from page 0x%02x to page 0x%02x.", from_page, to_page);
    // sanity checks
    //      both pages are in valid range
    if (!is_byte_in_array(from_page, NTAG_213_EXISTING_PAGES, 45)) {
        LOG_WARN("from_page 0x%02x you provided is not valid! Must be in [0x00, 0x2C]", from_page);
        return FALSE;
    }
    if (!is_byte_in_array(to_page, NTAG_213_EXISTING_PAGES, 45)) {
        LOG_WARN("to_page 0x%02x you provided is not valid! Must be in [0x00, 0x2C]", to_page);
        return FALSE;
    }
    //      swap the two pages if necessary
    if (from_page > to_page) {
        BYTE tmp = to_page;
        to_page = from_page;
        from_page = tmp;
        LOG_DEBUG("Swapped from_page and to_page");
    }

    BYTE amount_read_pages = to_page - from_page + 1;

    // store page data
    NTAG_213_Pages tag_content = {0};

    // ff 00 00 00 05 (communicate with pn532 and 05 byte command will follow)
    //      d4 (data exchange command)
    //      42 (InCommunicateThru)
    //      3a (FastRead) [page 39 of ntag21x document]
    //      read from page
    //      read to page
    // Response:
    //      d5 43 00 
    //      all bytes read
    //      90 00

    // reading all it once it safe with ntag213 cuz 45*4 + 3 + 2 = 185 < 256
    BYTE APDU_Read[10] = { 0xff, 0x00, 0x00, 0x00, 0x05, 0xd4, 0x42, 0x3a, from_page, to_page };
    ApduResponse response = executeApdu(hCard, APDU_Read, sizeof(APDU_Read), pbRecvBuffer, pbRecvBufferSize);
    if (response.status != 0 || !(pbRecvBuffer[3 + amount_read_pages * 4] == 0x90 && pbRecvBuffer[3 + amount_read_pages * 4 + 1] == 0x00)) {
        LOG_ERROR("Fast read from page 0x%02x to 0x%02x failed.", from_page, to_page);
        return FALSE;
    }

    // copy response bytes into object tag_content
    BYTE* pages_data_start = pbRecvBuffer + 3;
    for (int i = 0; i < amount_read_pages; ++i) {
        memcpy(tag_content.Pages[from_page + i], pages_data_start + i * 4, 4);
    }

    // print only the read pages in human-readable form (as in nicely formatted hex)
    ntag_213_pages_object_print_all(from_page, to_page, &tag_content);

    return TRUE;
}

void ntag_213_pages_object_print_all(BYTE from_page, BYTE to_page, NTAG_213_Pages *tag_content) {
    for (BYTE i = from_page; i <= to_page; ++i) {
        printf("[Page 0x%02X]\t0x%02X  0x%02X  0x%02X  0x%02X\n",
           i,
           tag_content->Pages[i][0],
           tag_content->Pages[i][1],
           tag_content->Pages[i][2],
           tag_content->Pages[i][3]);
    }
}
