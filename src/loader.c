#include <windows.h>

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
void* LoadLibraryAndFunction(const char* lpLibFileName, const char* lpProcName) {
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