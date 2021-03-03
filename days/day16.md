# Windows API - Hashing 

This day was mostly about implementing stuff practically
```c++
#include <iostream>
#include<Windows.h>

int main()
{
    HMODULE base_addr =  GetModuleHandle((LPCTSTR)"kernel32.dll");
    if (base_addr == NULL) {
        return -1;
    }
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)base_addr;
    PIMAGE_NT_HEADERS pe_header = (PIMAGE_NT_HEADERS)(base_addr + dos_header->e_lfanew);
    IMAGE_OPTIONAL_HEADER imgage_headers_kernel = (IMAGE_OPTIONAL_HEADER)(pe_header->OptionalHeader);
    IMAGE_DATA_DIRECTORY export_table = imgage_headers_kernel.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)(base_addr+export_table.VirtualAddress);        //export_table.VirtualAddress is a RVA so add base_addr to get Virtual Address
    DWORD names = export_dir->AddressOfNames;
    std::cout << export_dir->AddressOfFunctions<<"\n";
    return 0;
}
```
The above code still doesnt work and even after deugging for 2-3 hours I cant figure out. So its for next time
