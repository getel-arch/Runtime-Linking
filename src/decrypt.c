#include <windows.h>

// Function to obfuscate data using character shifting
void shiftData(char *data, int shift) {
    size_t dataLength = strlen(data);

    for (size_t i = 0; i < dataLength; i++) {
        data[i] = data[i] - shift; // Shift character
    }
}

// Function to convert hex character to its decimal value
int hexCharToDec(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

// Function to convert hex string to ASCII
void hexToAscii(const char *hexStr, char *asciiStr) {
    size_t len = strlen(hexStr);
    if (len % 2 != 0) return;

    for (size_t i = 0; i < len; i += 2) {
        int highNibble = hexCharToDec(hexStr[i]);
        int lowNibble = hexCharToDec(hexStr[i + 1]);
        if (highNibble == -1 || lowNibble == -1) return;

        asciiStr[i / 2] = (highNibble << 4) | lowNibble;
    }
    asciiStr[len / 2] = '\0';
}

// Orchestrates Decryption
void decryptData(const char *encryptedData, char *decryptedData) {
    hexToAscii(encryptedData, decryptedData);
    shiftData(decryptedData, 3);
}