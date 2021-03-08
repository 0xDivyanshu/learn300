## Dumping lsass.exe memory - Part 1 

This is going to be **failed** story where I thought that it is very simple to dump lsass.exe memory. Upon trying to run the code it kept on showing `Access Denied` which meant that even though I am Administrator I can't still access SYSTEM level process. This means that I need to look for ways to elevate myself from Administrator to SYSTEM to try dumping it again. But again this is just seems to be a resonable explaination for the error.

Code:
Full code can be found [here](../code/day3.cs)
## Result?
- This showed `Access Denied` ruining my short win xD.
- Time to look into more detailed approach by evelation privs which should be for next part
