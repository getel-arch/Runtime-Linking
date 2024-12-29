#include <stdio.h>
#include <windows.h>
#include <string.h>

// Local Imports
#include "decrypt.c"
#include "loader.c"
#include "utils.c"
#include "spoof_ppid.c"

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("Usage: %s <parent_pid> <executable_path> <args>\n", argv[0]);
        return FALSE;
    }

    DWORD parentPid = atoi(argv[1]);
    char *executablePath = argv[2];
    char *arguments = argv[3];

    return SpoofPPID(parentPid, executablePath, arguments);
}
