#include <windows.h>

// Function to enable a privilege
BOOL EnablePrivilege(LPCTSTR privilege) {

    BOOL (WINAPI *pLookupPrivilegeValueA)(
        LPCSTR lpSystemName,
        LPCSTR lpName,
        PLUID lpLuid
        );
    BOOL (WINAPI *pOpenProcessToken)(
        HANDLE ProcessHandle,
        DWORD DesiredAccess,
        PHANDLE TokenHandle
        );
    BOOL (WINAPI *pAdjustTokenPrivileges)(
        HANDLE TokenHandle,
        BOOL DisableAllPrivileges,
        PTOKEN_PRIVILEGES NewState,
        DWORD BufferLength,
        PTOKEN_PRIVILEGES PreviousState,
        PDWORD ReturnLength
        );
    BOOL (WINAPI *pCloseHandle)(
        HANDLE hObject
        );
    HANDLE (WINAPI *pGetCurrentProcess)(
        void
        );
    
    // Decode and decrypt dll names
    char advapi32[50];
    decryptData("64677964736c363531676f6f", advapi32);

    char kernel32[100];
    decryptData("6e687571686f363531676f6f", kernel32);
    
    // Decode and decrypt function names
    char lookupPrivilegeValueA[50];
    decryptData("4f72726e787353756c796c6f686a6859646f786844", lookupPrivilegeValueA);

    char openProcessToken[50];
    decryptData("527368715375726668767657726e6871", openProcessToken);

    char adjustTokenPrivileges[50];
    decryptData("44676d78767757726e687153756c796c6f686a6876", adjustTokenPrivileges);

    char closeHandle[100];
    decryptData("466f7276684b6471676f68", closeHandle);

    char getCurrentProcess[100];
    decryptData("4a68774678757568717753757266687676", getCurrentProcess);

    // Load functions
    pLookupPrivilegeValueA = LoadLibraryAndFunction(advapi32, lookupPrivilegeValueA);
    pOpenProcessToken = LoadLibraryAndFunction(advapi32, openProcessToken);
    pAdjustTokenPrivileges = LoadLibraryAndFunction(advapi32, adjustTokenPrivileges);
    pCloseHandle = LoadLibraryAndFunction(kernel32, closeHandle);
    pGetCurrentProcess = LoadLibraryAndFunction(kernel32, getCurrentProcess);

    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!pLookupPrivilegeValueA(
            NULL,       // lpSystemName
            privilege,  // lpName
            &luid       // lpLuid
            )) {
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    HANDLE hToken;
    if (!pOpenProcessToken(
            pGetCurrentProcess(),        // ProcessHandle
            TOKEN_ADJUST_PRIVILEGES,    // DesiredAccess
            &hToken                     // TokenHandle
            )) {
        return FALSE;
    }

    if (!pAdjustTokenPrivileges(
            hToken,                     // TokenHandle
            FALSE,                      // DisableAllPrivileges
            &tp,                        // NewState
            sizeof(TOKEN_PRIVILEGES),   // BufferLength
            NULL,                       // PreviousState
            NULL                        // ReturnLength
            )) {
        pCloseHandle(hToken);
        return FALSE;
    }

    pCloseHandle(hToken);
    return TRUE;
}