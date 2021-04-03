# Process Hollowing

Code [here](../code/day42.cs)

Notes:
- Use `CREATE_SUSPEND` flag during process creation to stall execution of the newly created process.
- Once it hits the process creating point, we will overwrite Entrypoint of svchosts.exe content with our shellcode and let it continue to execute.
- Once the process is created we can use `ZwQueryInformationProcess` API to retrieve certain information about target process including PEB which contains base address to process which can then be used to parse PE headers and get the entrypoint.
- Base address of PE is at offset of 0x10 bytes from base address of PEB.
- Now to read next 0x10 byte from base address of PEB we need to use `ReadProcessMemory` since we need to read into remote process.
- Use `CreateProcess` API since other API wont let you create process in suspended state.



