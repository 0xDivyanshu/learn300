# DLL - Injection Part 2

So I have been reading about DLL Injection and till now here's what I actually understood
- We first allocate a Heap and copy the DLL content into Heap.
- We then use that heap to get the structure of the DLL since the structure will be same but the DLL itself wont work if we just use heap because we need to change IAT table and other dynamic stuff during runtime which will link back to kernel32.dll
- So we need to allocate another memory using `VirtualAlloc` and then copy from DLL section by section and each time making sure that we also change the runtime values like changing IAT table or resolving functions used in DLL.

The incomplete code can be found [here](../code/day29.cpp)

My Questions!

- Why are we only copying from Optional header! Why not copy the DOS and PE File headers also?
=> The DOS header and PE File header deal with the loading of PE i.e it tells the entry point of DLL and etc. So since we are already loading the DLL using `VirtualAlloc` there is no need to import the DOS and PE File headers. Just start from Optinal Headers.

- Why are we using both Heap and VirtualAlloc to allocate memory 2 times?
=> According to me we are using HEAP to save the DLL so that we can access the structure of DLL to write IAT table and other import things. For instance if DLL uses `CreateThread` then we need to resolve the address from kernel32.dll dynamically and build up a IAT table. So to access sections and all other stuff we use Heap but to actually build the DLL content into memory we are using `VirtualAlloc`.
