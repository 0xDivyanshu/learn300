// dll_used_by_process.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include<windows.h>
#include<Psapi.h>

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

void Error_Out() {
    printf("[-] Run the code with admin rights!");
}

int main(int argc,char* argv[])
{
    if (argc != 2) {
        printf("[!] Enter process id as argument to inspect.\nEg: dllenum.exe 3200\n");
        return 0;
    }
    char *pid = argv[1];
    printf("Printing DLL used by process ID: %s \n",pid);

    if (!EnableWindowsPrivilege(SE_DEBUG_NAME)) {
        Error_Out();
        return -1;
    }
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, atoi(pid));
    if (hProcess == NULL) {
        printf("[-] Error opening the process. Check PID or run with admin rights");
        return -1;
    }

    // Arguments to EnumProcessModules are handle to process,array that has list of module handles,size of the back array,and no of bytes needed to store all module handles
    HMODULE modules[1024];
    DWORD total_bytes;
    if (EnumProcessModules(hProcess, modules, sizeof modules, &total_bytes)) {
        for (int i = 1; i < (int)total_bytes / sizeof(HMODULE); i++) {
            wchar_t name[1024];
            DWORD output = GetModuleBaseName(hProcess, modules[i], name, sizeof(name)/sizeof(TCHAR));
            if (output == 0) {
                printf("[!] Error printing the DLL name");
            }
            else {
                for (int j = 0; j < (int)output; j++)
                    std::cout << (char)name[j];
                std::cout << "\n";
            }
        }
    }
    printf("[+]Done!\n");
    CloseHandle(hProcess);
    return 0;
}
