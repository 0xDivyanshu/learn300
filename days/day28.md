# Reflective DLL Injection - Part 1

Allows to inject DLL into process from memory rather than disk. DLL injection is best explained by orginal author [here](https://github.com/stephenfewer/ReflectiveDLLInjection)

Lets first create a simple DLL that would pop a message box.

So I decided to get a meterpreter shell and then try injecting my hand made DLL and see if it works properly to understand how msf DLL Injection works.

My DLL Code:
```c++
// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH: {
        MessageBoxA(NULL, "test", "tmp", MB_OK);
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

But this DLL when injected is giving out error

```text
[*] Running module against <REDACTED>
[!] Output unavailable
[*] Opening handle to process 4456...
[+] Handle opened
[-] Post failed: NoMethodError undefined method `entries' for nil:NilClass
[-] Call stack:
[-]   /opt/metasploit-framework/embedded/framework/lib/msf/core/reflective_dll_loader.rb:62:in `parse_pe'
[-]   /opt/metasploit-framework/embedded/framework/lib/msf/core/reflective_dll_loader.rb:30:in `load_rdi_dll'
[-]   /opt/metasploit-framework/embedded/framework/lib/msf/core/post/windows/reflective_dll_injection.rb:49:in `inject_dll_into_process'
[-]   /opt/metasploit-framework/embedded/framework/modules/post/windows/manage/reflective_dll_inject.rb:98:in `inject_dll'
[-]   /opt/metasploit-framework/embedded/framework/modules/post/windows/manage/reflective_dll_inject.rb:133:in `run_dll'
[-]   /opt/metasploit-framework/embedded/framework/modules/post/windows/manage/reflective_dll_inject.rb:52:in `run'
[*] Post module execution completed
```

So gonna debug it next try.
