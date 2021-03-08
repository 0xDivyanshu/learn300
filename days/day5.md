# IPC via Memory Mapping and pipes

## What are pipes?

So there are 2 process with which you want to communicate with. For instance where you just want to send some stuff to another process pipes would be helpful. There are 2 kind of pipes. First one being anonymous pipes which can perform IPC on local machine and second one being named pipes for performing IPC over network. But since I was not able to find a way to execute stuff which making it visible to another process, I decided to look for something else!

## Shared Memory

Windows offer another way for IPC called shared memory files which seems a perfect choice for my problem statement. I can just create a shared memory region, pass my shellcode over that region and then use the elevated process to execute the shellcode.This seems easy, but after trying for 2-3 hrs I am not able to make the elevated process have access to shared memory region. So I am currently looking into access rights of shared memeory and maybe modifying those will let elevated process access it?


In case you are curious here is the code I am currently dealing with

- The below code is the main code which would do stuff and open port 8080 and once you send shellcode over 8080, it would create shared memory and write the shellcode on that.
Code can be found [here](../code/day5_1.cs)
- Below is code for the Execute.exe which would take the mapped memeory and execute stuff from that. Sadly, somehow it is not able to access the mapped memory.
Code:

Full code can be found [here](../code/day5_2.cs)
