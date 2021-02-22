# Process Injection/Migration

We need this to make sure our payload persists even after the application is closed. This helps avoid creating new process which might be caught by blue-team and sometimes can help bypass AV also. 

So some potential candidates are 
- Explorer.exe which host's user desktop exprience
- Any hidden spawn process
- svchost.exe responsible for network communication
