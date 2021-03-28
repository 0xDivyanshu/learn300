# Process Hollowing - Part 1

- All svchost.exe process run by defaul as SYSTEM meaning we can't inject into them using a low integrity access level. And even if we were to luanch `svchosts.exe` and try injecting, the process will terminate.
- Hence we gotta use process hollowing i.e launch svchost.exe process and modify it before it actually starts. This can let us execute our payload without terminating `svchost.exe`.

## Theory
- Use `CREATE_SUSPENDED` while creating process.
- We will use CreateProcess API for starting svchosts.exe
- Once Process is created we supply `CREATE_SUSPEND` so that the thread is halted. We now can find the entrypoint of the process and replace the memory with our shellcode.

## How do we find the entrypoint of process?

Locating entrypoint is a difficult thing due to presence of ASLR but once the process is created we can use `ZwQueryInformationProcess` to query the information about the process.From PEB we can get the base address of the process which can be used to parse pe header and locate the EntryPoint.
