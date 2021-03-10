# Reading NTDLL for Native API functions

We will be trying to read syscall stubs from NTDLL.dll

In the reference article here he use .rdata section so its time to understand all the sections i guess


Executable Code Section : .text
Data Section : .rdata,.data and .bss
Resource Section : .rsrc
Export Data Section : .edata
Import Data Section : .idata
Debug Information Section : .debug


- .text section : Contains compiled binary code i.e raw code/asm code for the executable. Think of them containing actuall function code
- .rdata section : Contains all read only data. 
- .data section : Represents unitialized data since its sometimes waste of memory as some variables might not have values untill program is executed.
- .rsrc section : Resource information for module (Useless for us)
- .edata section : Contains all information about exported method including rva and ordinal for those
- .idata section : Contains all information about imported methods including rva for those.


