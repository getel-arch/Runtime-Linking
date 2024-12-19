#include <stdio.h>
#include <string.h>
#include <windows.h>

// Function to obfuscate data using character shifting
void shiftData(char *data, int shift) {
    size_t dataLength = strlen(data);

    for (size_t i = 0; i < dataLength; i++) {
        data[i] = data[i] + shift; // Shift character
    }
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <data> <shift>\n", argv[0]);
        return 1;
    }

    char *data = argv[1];       // Data to obfuscate
    DWORD shift = atoi(argv[2]);  // Shift value

    printf("Original Data: %s\n", data);

    // Obfuscate data
    shiftData(data, shift);
    printf("Obfuscated Data: %s\n", data);

    return 0;
}
