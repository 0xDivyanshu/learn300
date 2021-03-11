# Reading .rdata section

So we will try to get the address for .rdata section. Below function will return back the .rdata section address.

For reference PE header is the one containing address for all the section. So we need to iterate through PE headers and find the one matching with `.rdata` . So we simply extract pe_headers and then iterate over the number of sections and increment the section each time till the name matches with .rdata


Code:
```c++
PIMAGE_SECTION_HEADER GetSection(LPCSTR DllName,LPCSTR SectionName) {
    HANDLE base_addr = GetModuleHandleA(DllName);
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)base_addr;
    PIMAGE_NT_HEADERS pe_header = (PIMAGE_NT_HEADERS)((LPBYTE)base_addr + dos_header->e_lfanew);

    PIMAGE_SECTION_HEADER section  = IMAGE_FIRST_SECTION(pe_header);
    PIMAGE_SECTION_HEADER rdata = section;
    PIMAGE_SECTION_HEADER rsection = section;

    for (int i = 0; i < pe_header->FileHeader.NumberOfSections; i++) {
//        byte *tmp = section->Name;
        if (!strcmp((char*)section->Name, (char*)SectionName)) {
            rsection = section;
            return section;
        }
        section++;
    }
    return (PIMAGE_SECTION_HEADER)NULL;
}
```
