# Windows API hashing - Part 3.3

Finally got the code working. The error was that I was not doing the pointer artihmatic correctly. The `HMODULE` is a void * type and then adding it to e_lfanew was the mistake. I should have type casted the base address to get the pointer to first memory and then performed the memory operations. 

For instance is `handle` is of `HMODULE` type and then doing handle+1 would have actually done handle+4 on 32 bit since the size of handle is 4 byte. So to literally add the pointers we need to convert it to byte.

 
```c++
#include <iostream>
#include<Windows.h>

int main()
{
    HMODULE base_addr =  GetModuleHandleA((LPCSTR)"C:\\Windows\\System32\\kernel32.dll");
    if (base_addr == NULL) {
        return -1;
    }
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)base_addr;
    PIMAGE_NT_HEADERS pe_header = (PIMAGE_NT_HEADERS)((LPBYTE)base_addr + dos_header->e_lfanew);
    IMAGE_OPTIONAL_HEADER imgage_headers_kernel = (IMAGE_OPTIONAL_HEADER)(pe_header->OptionalHeader);
    IMAGE_DATA_DIRECTORY export_table = imgage_headers_kernel.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)base_addr+export_table.VirtualAddress);        //export_table.VirtualAddress is a RVA so add base_addr to get Virtual Address

    PDWORD functions = (PDWORD)((LPBYTE)base_addr+export_dir->AddressOfFunctions);
    PDWORD name = (PDWORD)((LPBYTE)base_addr + export_dir->AddressOfNames);

    for (int i = 0; i < export_dir->NumberOfNames; i++) {

        std::cout<<(LPBYTE)base_addr+name[i]<<"\n";
    }
    return 0;
}
```

This would print all the methods that are exported by kernel32.dll . This just solved a major problem. We now have the memory address for the function and can easily bypass IAT listing for target function.
