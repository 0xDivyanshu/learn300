# Algorthims - Compression

- APLIB
- LZMA
- LZW
- ZLIB

To identify Compression using API lookout for 
```c++
NT_RTL_COMPRESS_API NTSTATUS RtlDecompressBuffer(
	USHORT CompressionFormat,
	PUCHAR UncompressedBuffer,
	ULONG UncompressedBufferSize,
	PUCHAR CompressedBuffer,
	ULONG CompressedBufferSize,
	PULONG FinalUncompressedSize
);
```
CompressionFormat can reveal the type of compression used.

Tools like signsrch can automate finding compression algo. You can also look into headers of compressed bytes to identify compression technique. For instance zlib sticks header of `x78x9c` and start of compresse bytes can tell you if zlib was used.

# DLL Injection

Executes the below code by using DLL injection technique. We get address to the function LoadLibraryW in kernel32.dll . We then copy the dll path string to memory allocated by VirtualAllocEx inside the target process and then point CreateRemoteThread to the address of the LoadLibraryW along with passing address of dll path in target process which gets executed.

Code
```c++
#include <iostream>
#include<Windows.h>

int main(int argc,char *argv[])
{
    PTHREAD_START_ROUTINE method_addr = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");

    int pid = atoi(argv[1]);
    char dll[] = "C:\\Users\\root\\Downloads\\tmp.dll";
    
    HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
    LPVOID address = VirtualAllocEx(phandle, NULL, sizeof dll, MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(phandle, address, dll, sizeof dll, NULL);

    //We are using DLL path to execute dll injection so we need pointer to function LoadLibraryA and pass the address of the dll path
    CreateRemoteThread(phandle, NULL, 0, method_addr, address, NULL,0);
    CloseHandle(phandle);
}
```
## Does it work?
No, above code doesnt seem to work so I need to debug it! So its for next time
