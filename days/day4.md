# Dumping lsass.exe memory - Part 2

This is again a **failed** post, but I came accross new stuff to research on. So apparently I found a way to form UAC bypass but inorder to test my theory, I need to run the memory dump function in context of elevated process.

## What now?

- I need to use some sort of IPC to communicate accross medium integrity and high integrity process. 
- IPC exsists in multiple way in windows, i.e you can use shared pipes which medium inegrity process writes to pipe which is read by high integrity process and executes it.
- You can also use shared memory region, RPC or COM for the need but these are bit complicated to code for.

Code :
Full code can be found [here](../code/day4.cs)

As of now the code wont work since there is no dumping run in context on elevated process. But the same snippet can be used to perform UAC bypass in c#.

So considering todays progress I would find ways to run `WriteMem` in context of elvated process.
