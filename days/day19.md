# Windows API hashing 

- Finally got the full exploit code working. 
- The below code will bypass latest defender and uses process injection into explorer.exe and uses dynamic address resolution for methods in kernel32.dll to bypass IAT.

Code can be found [here](../code/win-api_hash.cpp)

Took me literally 3 hours to spot a mistake. Apparantly the final address of a method is:
	Final address = base_addr of DLL + function_address[ordinal_address[i]], where i is the counter with name[i] equal to method we wanna get address of!

