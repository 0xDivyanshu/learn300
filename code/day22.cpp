// syscalls.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include<Windows.h>
#include "winternl.h"

#pragma comment(lib, "ntdll")

EXTERN_C NTSTATUS SysNtReadFile(
	HANDLE       hFile,
	LPVOID       lpBuffer,
	DWORD        nNumberOfBytesToRead,
	LPDWORD      lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped
);

int main() {
	FARPROC addr = GetProcAddress(LoadLibraryA("ntdll"), "NtReadFile");
	SysNtReadFile(NULL, NULL, 0, NULL, NULL);
	return 0;
}
