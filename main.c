// Tested on macOS Sequoia, windows 10, windows 11

// windows instructions:
    // 0. install the windows sdk (e.g. via visual studio or via download)
    // 1. install latest llvm to get clang (https://github.com/llvm/llvm-project/releases/latest)
    // 2. Compile with (you might need to replace paths): clang.exe *.c -I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um" -I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared" -L"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um\x64" -lwinscard -o main.exe
    // 3. Run with: main
// macOS instructions:
    // 0. There is no need to install the official drivers for 122U (neither for windows nor for macOS)
    // 1. On older macOS versions ensure pcscd is running: sudo launchctl enable system/com.apple.pcscd , then reboot
    // 2. On newer macOS versions ctkpcscd is used (sandboxed XPC service), so you should be fine by default
    // 3. Compile with: make clean && make
    // 4. Run with: ./main
// linux instructions:
    // 0. sudo apt install libpcsclite-dev pcscd pcsc-tools opensc build-essential libccid libnfc-dev libnfc-bin libusb-1.0-0
    // 1. sudo updatedb (without this linux might not be able to find pcslite.h)
    // 2. Bug fix for acr122u (https://ludovicrousseau.blogspot.com/2013/11/linux-nfc-driver-conflicts-with-ccid.html):
    //      sudo rm -r /lib/modules/*/kernel/drivers/nfc/pn533
    // 3. sudo systemctl enable pcscd pcscd.service pcscd.socket
    // 4. sudo systemctl start pcscd pcscd.service pcscd.socket
    // 5. Unplug your acr122u and download and install these drivers: https://www.acs.com.hk/download-driver-unified/14214/acsccid-linux-bin-1.1.11-20240328.zip
    //      I use linux mint so I went 'cd ./acsccid_linux_bin-1.1.11/ubuntu/jammy && sudo dpkg -i libacsccid1_1.1.11-1~bpo22.04.1_amd64.deb'
    // 6. sudo reboot
    // 7. Connect reader again ;)
    // 8. pcsc_scan (should now be able to connect to reader and show info of any connected nfc tags)
    // 9. Note: Please run 'pkg-config --modversion libpcsclite' and ensure your pcsc version is v2.07 or newer, otherwise authenticating mifare classic block won't work with the apdu command used by default
    //      Linux Mint 22.1 only ships old versions of pcsc, here is how to build newer version from source:
    //          Note: Info taken from https://pcsclite.apdu.fr/ , the code is here: https://salsa.debian.org/rousseau/PCSC  and here: https://github.com/LudovicRousseau/PCSC
    //              sudo apt remove libpcsclite1   (remove old pcsc versions u might have, might remove software u have that relies on it!)
    //              git clone https://salsa.debian.org/rousseau/PCSC.git
    //              sudo apt install git build-essential flex libtool autoconf libsystemd-dev libudev-dev libusb-1.0-0-dev meson ninja-build pkg-config libpolkit-gobject-1-dev 
    //              cd PCSC && git checkout 2.3.3
    //              meson setup builddir
    //              cd builddir
    //              meson compile
    //              sudo ninja install && sudo ldconfig
    //              pkg-config --modversion libpcsclite  (should now show version 2.3.3)
    //              pcscd --version (should also show 2.3.3)
    //              sudo mkdir -p /run/pcscd
    //              sudo chown root:root /run/pcscd
    //              sudo chmod 755 /run/pcscd
    //              sudo /usr/local/sbin/pcscd --foreground   (keep this running and try to run this program is a different bash tab)
    //         We need to have the command above run as service at startup:
    //              sudo nano /etc/systemd/system/pcscd.service
    //                          [Unit]
    //                          Description=Custom PC/SC Smart Card Daemon (from source)
    //                          After=network.target

    //                          [Service]
    //                          Type=simple
    //                          ExecStart=/usr/local/sbin/pcscd --foreground
    //                          Restart=on-failure
    //                          RuntimeDirectory=pcscd

    //                          [Install]
    //                          WantedBy=multi-user.target

    //              sudo systemctl daemon-reload
    //              sudo systemctl enable pcscd
    //              sudo systemctl start pcscd
    // Note: If you have conflicting versions run:  ldconfig -p | grep libpcsclite , it might show old apt versions at /lib/x86_64-linux-gnu

// Other notes:
    // the compile_flags.txt is only needed for LSP-clangd 
    // You can verify that it works via 'sudo apt install clangd' followed by 'clangd --check=main.c'

#include "main.h"
#include "mifare-classic.h"
#include "ndef.h"
#include "ntag-215.h"

#include "logging.c"


// -------------------- Functions that interact with reader -------------------------------

LONG getAvailableReaders(SCARDCONTEXT hContext, char *mszReaders, DWORD *dwReaders) {
    LONG lRet = SCardListReaders(hContext, NULL, mszReaders, dwReaders);
    if (lRet != SCARD_S_SUCCESS) {
        if (lRet == 0x8010002E) {
            LOG_CRITICAL("Failed to list readers: Are you sure your smart card reader is connected and turned on?\n");
        } else {
            LOG_CRITICAL("Failed to list readers: 0x%lX\n", lRet);
        }
    }

    return lRet;
}

LONG connectToReader(SCARDCONTEXT hContext, const char *reader, SCARDHANDLE *hCard, DWORD *dwActiveProtocol, BOOL directConnect) {
    LONG lRet;

    if (directConnect) {
        // direct communication with reader (no present tag required)
        lRet = SCardConnect(hContext, reader, SCARD_SHARE_DIRECT, SCARD_PROTOCOL_T1, hCard, dwActiveProtocol);
    } else {
        // T1 = block transmission (works), T0 = character transmission (did not work when testing), Tx = T0 | T1 (works)
        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpesc/41673567-2710-4e86-be87-7b6f46fe10af
        lRet = SCardConnect(hContext, reader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1, hCard, dwActiveProtocol);
    }

    return lRet;
}

// executes command and returns the amount of bytes that the response contains
ApduResponse executeApdu(SCARDHANDLE hCard, BYTE *pbSendBuffer, DWORD dwSendLength, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize) {
    // first reset first 256 bytes of response buffer to all zeroes (to avoid that 90 00 from some previous command is later read and confused)
    resetBuffer256(pbRecvBuffer);

    // this took me long to figure out (part 1): i want to always remember the size of the array that holds the response. but SCardTransmit modifies the value of pbRecvBufferSize to the amount of bytes of the response. thats why we can lose the information how big our buffer is. this can lead to nasty bugs (e.g. you just once forget to update pbRecvBufferSize to the amount of bytes of the expected response and then u get UB due to buffer overflow. so safer is to just always reset to actual buffer size)
    DWORD pbRecvBufferSizeBackup = *pbRecvBufferSize;

    LONG lRet = SCardTransmit(hCard, SCARD_PCI_T1, pbSendBuffer, dwSendLength, NULL, pbRecvBuffer, pbRecvBufferSize);
    // also print reply
    if (lRet == SCARD_S_SUCCESS) {
        // print which command you sent
        printf("> ");
        printHex(pbSendBuffer, dwSendLength);

        // print what you received
        printf("< ");
        printHex(pbRecvBuffer, *pbRecvBufferSize);

    } else {
        //printf("%08x\n", lRet);
        printf("%08lx\n", lRet);
    }

    LOG_DEBUG("Response status: %lu (0 means success)\n", lRet);
    LOG_DEBUG("Response size: %lu bytes\n", *pbRecvBufferSize); // linux wants %lu, macos wants %u. just use either and ignore warning lul
    
    // return both status and length of response
    // ApduResponse response;
    // response.status = lRet;
    // response.amount_response_bytes = *pbRecvBufferSize;
    ApduResponse response = {
        .status = lRet,
        .amount_response_bytes = *pbRecvBufferSize
    };

    // this took me long to figure out (part 2): i want to always retain the constant buffer size in this variable
    *pbRecvBufferSize = pbRecvBufferSizeBackup;

    return response;
}

LONG disableBuzzer(SCARDCONTEXT hContext, const char *reader, SCARDHANDLE *hCard, DWORD *dwActiveProtocol, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize) {
    LONG lRet = connectToReader(hContext, reader, hCard, dwActiveProtocol, TRUE);
    if (lRet != SCARD_S_SUCCESS) {
        LOG_ERROR("Failed to connect: 0x%x\n", (unsigned int)lRet);
        return 1;
    }


    // Define ACR122U command to disable the buzzer sound (really annoying sound) [section: 'Set buzzer output during card detection']
    BYTE pbSendBuffer[] = { 0xFF, 0x00, 0x52, 0x00, 0x00 };
    DWORD cbRecvLength = 16;

    LONG result = SCardControl(*hCard, SCARD_CTL_CODE(3500), pbSendBuffer, sizeof(pbSendBuffer), pbRecvBuffer, *pbRecvBufferSize, &cbRecvLength); //  3500 escape code defined by microsoft, 2079 escape code defined by ACS, i tried both and only 3500 works on every OS

    return result;
}

void disconnectReader(SCARDHANDLE hCard, SCARDCONTEXT hContext) {
    SCardDisconnect(hCard, SCARD_LEAVE_CARD);
    SCardReleaseContext(hContext);
}

// -------------------- General Functions that interact with various tags -------------------------------

LONG getUID(SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize, BOOL printResult) {
    LOG_INFO("Will now try to determine UID");
    // Define the GET UID APDU command (PC/SC standard for many cards)
    BYTE pbSendBuffer[] = { 0xFF, 0xCA, 0x00, 0x00, 0x00 }; // if u change last byte to e.g. 0x04 then u only get first 4 bytes of UID
    ApduResponse response = executeApdu(hCard, pbSendBuffer, sizeof(pbSendBuffer), pbRecvBuffer, pbRecvBufferSize);

    // ensure 90 00 success is returned by acr122u ()
    if ((!((pbRecvBuffer[4] == 0x90 && pbRecvBuffer[5] == 0x00) ||   // UID of length 4: single UID
         (pbRecvBuffer[7] == 0x90 && pbRecvBuffer[8] == 0x00)  ||   // UID of length 7: double UID
         (pbRecvBuffer[10] == 0x90 && pbRecvBuffer[11] == 0x00)     // UID of length 10: oh baby a triple oh yeah UID
         )) || (response.status != SCARD_S_SUCCESS)) {      
        return ACR_90_00_FAILURE;
    }

    if (printResult) {
        // success: now print UID
        printf("Detected UID: ");
        for (DWORD i = 0; i < *pbRecvBufferSize - 2; i++) { // -2 because no need to print success code 90 00
            // avoid printing entire buffer of zeroes, but check for 90 00 only if i+1 is in bounds
            if ((i + 1 < *pbRecvBufferSize) &&
                (pbRecvBuffer[i] == 0x90) &&
                (pbRecvBuffer[i + 1] == 0x00)) {
                printf("\n");
                return response.status;
            }

            printf("%02X ", pbRecvBuffer[i]);
        }
        printf("\n");
    }
    printf("\n");

    return response.status;
}

// getATS_14443A sends a RATS (Request for Answer To Select) to the tag (afaik only stuff like desfire, smartMX and some java cards even support this)
ApduResponse getATS_14443A(SCARDHANDLE hCard, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize) {
    LOG_INFO("Will now try to determine ATS");
    BYTE pbSendBuffer[] = { 0xFF, 0xCA, 0x01, 0x00, 0x00 };
    ApduResponse response = executeApdu(hCard, pbSendBuffer, sizeof(pbSendBuffer), pbRecvBuffer, pbRecvBufferSize);

    if ((pbRecvBuffer[0] == 0x6A) && (pbRecvBuffer[1] == 0x81)) {
        LOG_WARN("Accessing ATS of this tag type is currently not supported by this program\n");
    }

    // KNOWN RESPONSES:
    //      06 75 77 81 02 80: Mifare desfire 8k
    //      06 77 77 71 02 80: Ntag 424 dna tt

    printf("\n");
    return response;
}

LONG getStatus(SCARDHANDLE *hCard, char *mszReaders, DWORD dwState, DWORD dwReaders, DWORD *dwActiveProtocol, BYTE *pbRecvBuffer, DWORD *pbRecvBufferSize, BOOL printResult, char *tagName) {
    LOG_INFO("Will now try to determine which model your tag is");
    LONG lRet = SCardStatus(*hCard, mszReaders, &dwReaders, &dwState, dwActiveProtocol, pbRecvBuffer, pbRecvBufferSize);
    if ((lRet == SCARD_S_SUCCESS) && printResult) {
        // success: now print status
        printf("Detected tag type: ");
        for (DWORD i = 0; i < *pbRecvBufferSize - 2; i++) { // -2 because no need to print success code 90 00
            printf("%02X ", pbRecvBuffer[i]);
        }
        printf("\n");

        if (*pbRecvBuffer < 8) {
            LOG_ERROR("Failed to identify the tag (reply too short)\n");
            strncpy(tagName, "UNIDENTIFIED TAG", 99);
            return 1;
        }

        // determine which kind of tag this is
        BYTE tagIdentifyingByte1 = pbRecvBuffer[13];
        BYTE tagIdentifyingByte2 = pbRecvBuffer[14];
        if ((tagIdentifyingByte1 == 0x00) &&  (tagIdentifyingByte2 == 0x01)) {
            printf("Identified tag as: Mifare Classic 1k\n");
            strncpy(tagName, "Mifare Classic 1k", 99); // copy less than 100 chars cuz that's how long the name buffer is
        } else if ((pbRecvBuffer[13] == 0x00) && (pbRecvBuffer[14] == 0x02)) {
            printf("Identified tag as: Mifare Classic 4k\n");
            strncpy(tagName, "Mifare Classic 4k", 99);
        } else if ((pbRecvBuffer[13] == 0x00) && (pbRecvBuffer[14] == 0x03)) {
            printf("Identified tag as: Mifare Ultralight or NTAG2xx\n");
            strncpy(tagName, "Mifare Ultralight or NTAG2xx", 99);
        } else if ((pbRecvBuffer[13] == 0x00) && (pbRecvBuffer[14] == 0x26)) {
            printf("Identified tag as: Mifare Mini\n");
            strncpy(tagName, "Mifare Mini", 99);
        } else if ((pbRecvBuffer[13] == 0xF0) && (pbRecvBuffer[14] == 0x04)) {
            printf("Identified tag as: Topaz/Jewel\n");
            strncpy(tagName, "Topaz/Jewel", 99);
        } else if ((pbRecvBuffer[13] == 0xF0) && (pbRecvBuffer[14] == 0x11)) {
            printf("Identified tag as: FeliCa 212K\n");
            strncpy(tagName, "FeliCa 212K", 99);
        } else if ((pbRecvBuffer[13] == 0xF0) && (pbRecvBuffer[14] == 0x12)) {
            printf("Identified tag as: FeliCa 424K\n");
            strncpy(tagName, "FeliCa 424K", 99);
        } else if ((pbRecvBuffer[0] == 0x3B) && (pbRecvBuffer[1] == 0x81) && (pbRecvBuffer[2] == 0x80) && (pbRecvBuffer[3] == 0x01) ) {
            printf("Identified tag as: Mifare Desfire 8k\n");
            strncpy(tagName, "Mifare Desfire 8k", 99); // page 10 of API-ACR122U-2.04
        } else if (pbRecvBuffer[13] == 0xFF) {
            LOG_WARN("Identified tag as: UNKNOWN TAG\n");
            strncpy(tagName, "UNKNOWN TAG", 99);
        } 

        else {
            LOG_ERROR("Failed to identify the tag\n");
            strncpy(tagName, "UNIDENTIFIED TAG", 99);
        }
    }

    printf("\n");
    return lRet;
}

// -------------------- Helper functions -------------------------------------------------------

BOOL containsSubstring(const char *string, const char *substring) {
    // Edge case: if substring is empty, it's always considered a match
    if (*substring == '\0') {
        return TRUE;
    }

    // Iterate through the string
    for (const char *s = string; *s != '\0'; ++s) {
        // Check if the current character matches the first character of substring
        if (*s == *substring) {
            const char *str_ptr = s;
            const char *sub_ptr = substring;

            // Compare the substring starting from here
            while (*sub_ptr != '\0' && *str_ptr == *sub_ptr) {
                str_ptr++;
                sub_ptr++;
            }

            // If the entire substring matches, return 1 (true)
            if (*sub_ptr == '\0') {
                return TRUE;
            }
        }
    }

    // Return 0 (false) if the substring was not found
    return FALSE;
}

// printHex prints bytes as hex
void printHex(LPCBYTE pbData, DWORD cbData) {
    for (DWORD i = 0; i < cbData; i++) {
        printf("%02x ", pbData[i]);
    }
    printf("\n");
}

// dump_response_buffer prints the first 16 values contained in the array (but there is more in the array, so maybe write a full dump function if necessary)
void dump_response_buffer(BYTE *pbRecvBuffer) {
    printf("\nDumping first 16 values in response buffer:\n");
    for (int i = 0; i < 16; i++) {
        printf("0x%02x", pbRecvBuffer[i]);
        if (i != 15) {
            printf("  ");
        }
    }
    printf("\n\n");
}

// resetBuffer256 is used to reset the reply buffer to all zeroes, e.g. resetBuffer(pbRecvBuffer);
void resetBuffer256(BYTE *buffer) {
    memset(buffer, 0, 256);
    LOG_DEBUG("Response buffer has been reset to all zeroes");
}

// resetBuffer2048 is used to reset the reply buffer to all zeroes, e.g. resetBuffer(pbRecvBufferLarge);
void resetBuffer2048(BYTE *buffer) {
    memset(buffer, 0, 2048);
    LOG_DEBUG("Response buffer has been reset to all zeroes");
}

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


// -------------------------------------------------------

int main(void) {
    SCARDCONTEXT hContext;
    SCARDHANDLE hCard = 0;
    DWORD dwActiveProtocol;
    char mszReaders[1024];
    DWORD dwReaders = sizeof(mszReaders);

    BYTE pbRecvBuffer[256] = {0}; // PN532 can only transfer 256 bytes at once (page 29 of PN532 application note)
    DWORD pbRecvBufferSize = sizeof(pbRecvBuffer);

    BYTE pbRecvBufferLarge[2048] = {0};
    DWORD pbRecvBufferSizeLarge = sizeof(pbRecvBufferLarge);
    
    DWORD dwState = SCARD_POWERED; // TODO: can u dynamically request the actual state somehow?

    char connectedTag[100]; // will later hold e.g. "Mifare Classic 4k", just pre-alloc 100 bytes for the name (and 100% reason to remember the name)

    // Establish context
    LONG lRet = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
    if (lRet != SCARD_S_SUCCESS) {
        if (lRet == 0x8010001E) {
            LOG_CRITICAL("Error: 'SCARD_E_SERVICE_STOPPED: The Smart card resource manager has shut down.' Could be related to incompatible PCSCLite version. Are there error-hinting logs when you run: 'sudo systemctl status pcscd' ?");
        } else {
            LOG_CRITICAL("Failed to establish context: 0x%X\n", (unsigned int)lRet);
        }
        
        return 1;
    }

    // Get available readers (you might have multiple smart card readers connected)
    lRet = getAvailableReaders(hContext, mszReaders, &dwReaders);
    if (lRet != SCARD_S_SUCCESS) {
        SCardReleaseContext(hContext);
        return 1;
    }

    // Print connected readers and select the first one
    LOG_INFO("Available Smart Card Readers:");
    char *reader = mszReaders;
    if (*reader == '\0') {
        LOG_CRITICAL("No readers found.\n");
        SCardReleaseContext(hContext);
        return 1;
    }
    printf("\t- %s\n", reader);
    // ensure you connected to ACR122U, this code is only tested with that reader
    const char *substring = "ACR122";
    BOOL isCorrectReader = containsSubstring(reader, substring);
    if (!isCorrectReader) {
        LOG_CRITICAL("Your reader does not seem to be an ACR122U, cancelling program execution!");
        disconnectReader(hCard, hContext);
        return 1;
    }
    printf("\n");

    // Turn off buzzer of ACR122U
    lRet = disableBuzzer(hContext, reader, &hCard, &dwActiveProtocol, pbRecvBuffer, &pbRecvBufferSize);
    if (lRet == 0) {
        LOG_INFO("Disabled buzzer of reader\n");
        SCardDisconnect(hCard, SCARD_LEAVE_CARD);
    } else {
        if (lRet == (int32_t)0x80100016) { // https://pcsclite.apdu.fr/api/group__ErrorCodes.html
            LOG_ERROR("Failed to disable buzzer of ACR122U: SCARD_E_NOT_TRANSACTED - An attempt was made to end a nonexistent transaction.\n");
        } else {
            LOG_ERROR("Failed to disable buzzer of ACR122U: 0x%x\n", (unsigned int)lRet);
        }
        
    }

    // Connect to the first reader
    lRet = connectToReader(hContext, reader, &hCard, &dwActiveProtocol, FALSE);
    BOOL didPrintWarningAlready = FALSE;
    while (lRet != SCARD_S_SUCCESS) {
        if ((lRet == SCARD_E_NO_SMARTCARD) || (lRet == SCARD_W_REMOVED_CARD) || (lRet == SCARD_E_TIMEOUT) || (lRet == SCARD_E_NO_SMARTCARD)) {
            if (!didPrintWarningAlready) {
                LOG_WARN("Did not detect a connected tag / NFC chip, please hold one near the reader\n");
                didPrintWarningAlready = TRUE;
            }
        }
        else {
            if (!didPrintWarningAlready) {
                LOG_ERROR("Google this pcsc-lite error code: 0x%x\n", (unsigned int)lRet);
                didPrintWarningAlready = TRUE;
            }
        }
        
        // wait a bit and retry (maybe user is not holding a tag near the reader yet)
        SLEEP_CUSTOM(50); // milliseconds (don't put this value too low, it never worked for me with 1 ms)
        lRet = connectToReader(hContext, reader, &hCard, &dwActiveProtocol, FALSE);
    }
    LOG_INFO("Connected to reader %s and detected an NFC tag\n", reader);

    // -------------- Interact with tag ---------------------------

    // Get UID of detected tag
    lRet = getUID(hCard, pbRecvBuffer, &pbRecvBufferSize, TRUE);
    if (lRet != SCARD_S_SUCCESS) {
        if (!(lRet == ACR_90_00_FAILURE)) {
            LOG_WARN("Failed to get UID of tag: 0x%x\n", (unsigned int)lRet);
        } else {
            LOG_WARN("Failed to get UID of tag: ACR122U did not return the expected 90 00 return code!\n");
        }
        
        disconnectReader(hCard, hContext);
        return 1;
    }

    lRet = getStatus(&hCard, mszReaders, dwState, dwReaders, &dwActiveProtocol, pbRecvBufferLarge, &pbRecvBufferSizeLarge, TRUE, connectedTag);
    if (lRet != SCARD_S_SUCCESS) {
        LOG_WARN("Failed to get status of tag: 0x%x\n", (unsigned int)lRet);
        disconnectReader(hCard, hContext);
        return 1;
    }
    // printf("%s", connectedTag);

    // only try to get RATS if currently connected tag is DESFIRE 8k (only desfire i have)
    if (strcmp(connectedTag, "Mifare Desfire 8k") == 0) {
        ApduResponse response = getATS_14443A(hCard, pbRecvBuffer, &pbRecvBufferSize);
        if (response.status != SCARD_S_SUCCESS) {
            LOG_WARN("Failed to get ATS of tag: 0x%x\n", (unsigned int)lRet);
            disconnectReader(hCard, hContext);
            return 1;
        }
    }
    
    // ----------- Mifare Classic 1k Examples ------------------------

    // READING EXAMPLES
        // example 1:   mifare_classic_read_sector(0x02, KEY_A_DEFAULT, hCard, pbRecvBuffer, &pbRecvBufferSize);
        //              -> read all blocks in sector 2, use KEY_A_DEFAULT (FF FF FF FF FF FF)
        // example 2:   mifare_classic_read_sector(0x03, KEY_A_NDEF_SECTOR115, hCard, pbRecvBuffer, &pbRecvBufferSize);
        //              -> read all blocks in sector 3, use KEY_A_NDEF_SECTOR115
        // example 3:   mifare_classic_read_sector(0x00, KEY_A_NDEF_SECTOR0, hCard, pbRecvBuffer, &pbRecvBufferSize);
        //              -> read all blocks in sector 0, use KEY_A_NDEF_SECTOR0
    //SectorContent sector_content = mifare_classic_read_sector(0x00, KEY_A_NDEF_SECTOR0, hCard, pbRecvBuffer, &pbRecvBufferSize);
    
    // WRITING EXAMPLE
        // example 1:   write the array below to block 0x04
            // const BYTE BlockData[16] = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };
            // BOOL success = mifare_classic_write_block(BlockData, 0x04, KEY_A_NDEF_SECTOR115, hCard, pbRecvBuffer, &pbRecvBufferSize);
   
        // example 2:   spam write data on your uninitialized mifare classik 1k
            // for (BYTE i = 0x01; i < 0x3F + 1; i++) {
            //     if(is_byte_in_array(i, SECTOR_BLOCKS, 16)) continue;

            //     BYTE BlockData[16];
            //     memset(BlockData, i, sizeof(BlockData)); // array is full of i (in block x write value x 16 times)

            //     BOOL success = mifare_classic_write_block(BlockData, i, KEY_A_DEFAULT, hCard, pbRecvBuffer, &pbRecvBufferSize);
            //     if (!success) return 1;
            // }

    // CARD RESET EXAMPLE
    //  // example 1: tag is NDEF formatted:
    //      mifare_classic_reset_card(KEY_A_NDEF_SECTOR115, hCard, pbRecvBuffer, &pbRecvBufferSize);
    
    //  // example 2: tag is NDEF uninitialized but u want to reset all blocks to zero:
    //      mifare_classic_reset_card(KEY_A_DEFAULT, hCard, pbRecvBuffer, &pbRecvBufferSize);

    // NDEF TO UNINTITIALIZED EXAMPLE
    //mifare_classic_ndef_to_uninitialized(hCard, pbRecvBuffer, &pbRecvBufferSize);

    // UNINTITIALIZED TO NDEF EXAMPLE
    //      mifare_classic_uninitialized_to_ndef(hCard, pbRecvBuffer, &pbRecvBufferSize);

    // TODO: why can't getStatus() distinguish between Ultralight and NTAG?

    // ------------------------- NTAG-215 EXAMPLES ------------------------
    //  WRITE TO PAGE:
    //      BYTE Msg[4] = { 0x05, 0x04, 0x03, 0x04 };
    //      BOOL success = ntag_215_write_page(Msg, 0x29, hCard, pbRecvBuffer, &pbRecvBufferSize);
    //  RESET USER MEMORY TO ZEROES:
    //      BOOL success = ntag_215_reset_user_data(hCard, pbRecvBuffer, &pbRecvBufferSize);

    //  READ FROM PAGE start TO PAGE end (here: read entire tag at once)
    //BOOL success = ntag_215_fast_read(0x00, 0x86, hCard, pbRecvBuffer, &pbRecvBufferSize);

    // -------------------- NDEF SR Text creation EXAMPLE ----------------
    // const char* my_text = "hello world!";
    // BYTE text_len = (BYTE)strlen(my_text);
    // size_t total_size;

    // BYTE* encoded = NewNDEF_SR_Text((const BYTE*)my_text, text_len, &total_size);
    // if (encoded == NULL) {
    //     return 1;
    // }

    // // create a multidimensional array with 4-byte rows
    // size_t num_blocks = total_size / 4;
    // BYTE output[num_blocks][4];
    // memcpy(output, encoded, total_size);
    // free(encoded);

    // // print result
    // printf("Encoded NDEF message (%zu bytes, %zu blocks of 4 bytes):\n", total_size, num_blocks);
    // for (size_t i = 0; i < num_blocks; i++) {
    //     printf("Block %2zu: %02X %02X %02X %02X\n", i, output[i][0], output[i][1], output[i][2], output[i][3]);
    // }

    // -------------------- Mifare Ultralight EXAMPLE ----------------
    // TODO
    // ---------------------------------------------------------------

    // Clean up
    disconnectReader(hCard, hContext);
    return 0;
}
