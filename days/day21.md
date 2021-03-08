# Calling syscalls in Windows

### What is syscalls?

Basically when user land process want to increase its privilege and and talk with kernel, it calls out a middleman called syscalls which sends userland request to kernel. Hence user land process cant directly access kernel memory.


As shown [here](https://www.ired.team/offensive-security/defense-evasion/using-syscalls-directly-from-visual-studio-to-bypass-avs-edrs) I decided to replicate the logic and prepare a exploit code :wink:


So we are gonna create a asm file with the procedure for the methods and call it via the main c++ file. We had already tried the dynamic address resolution to avoid calling the win API by directly reading .edata section from DLL and then type casting the address to strucutre of the method, but this is a step ahead since we will be complelty removing the user land code and directly use the syscalls aka kernel land calling convention.


Few weird facts about Windows
- Consider method called OpenProcess which is exposed by Win API.Now the symbol/export table of DLL contains OpenProcess as method name but listing PDB of kernel32.dll, it will be shown by adding `Stub` suffix i.e it becomes OpenProcessStub. Both are same and stab suffix was used after code was migrated from kernel32.dll into kernelbase.dll on windows7.
- PDB is basically Program Database file which contains all the information about program i.e list of all symbols in a module along with their address.


### How does the user to kernel interaction work in windows?

If a user calls function such as CreateFile, then it has to be converted into kernel mode.After receiving ring 0 kernel mode privileges, it translates to NtCreateFile (APIs in the Native API always start out with one or two prefixes: either Nt or Zw). In their user-mode implementation in NTDLL.dll, the two groups of APIs are identical and point to the same code. In kernel mode, they differ: the Nt preffix is the actual implementation of the APIs, while the Zw preffix is the stubs that go through the system-call mechanism. 
In Windows OS, every system call made in user-mode must go through the gate of the kernel to reach kernel where it would be dispatched and executed. This gate is called interrupt `INT 2Eh`. Similary one can also use `SYSENTER` instruction to to switch to kernel mode.

So basically ntdll handles the system call from user land process and sends it to gateway. After passing via gateway it is then handled by **NTSOKRNL.exe** which invokes `KiSystemService()`. This method looks over the look up table in kernel called SST(System Service Table) and then calls the specific kernel function.

Example:
```asm
mov eax,0x1
lea edx,[esp+4]
int 2e
ret 0x24
```
The EAX register is loaded with the service number, and the EDX register points to the first parameter that the kernel mode function receives. When the int 2e instruction is invoked, the processor uses the Interrupt Descriptor Table (IDT) in order to determine which handler to call. The IDT (also called Interrupt Vector Table) is a processor-owned table that tells the processor which routine to invoke whenever an interrupt or exception takes place. The IDT entry for interrupt 2e points to an internal NTOSKRNL function called KiSystemService, which is the kernel-service dispatcher. KiSystemService verifies that the service number and the stack pointer are valid, and calls into the specific kernel function requested. 

## Reference
- List of full windows 64 bit syscall table is [here](https://j00ru.vexillium.org/syscalls/nt/64/)
- A very good article [here](https://www.codeproject.com/Articles/33870/A-Primer-of-the-Windows-Architecture)
