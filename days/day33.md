# Learning Frida for windows DLL monitoring

- Frida can be used to inject our own javascript into apps of windows,Linux,Android
- Debug live process
- Lets you execute your own script into  process.

Install using `pip install frida-tools`

A case study

- Prepare a short c++ code which will just display a number.
```c++
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

void f(int n){
        printf("Number called: %d\n",n);
}

int main(){

        int n=1;
        printf("Address of function f() is: %p\n",f);
        while(true){
                f(n);
                n=n+1;
                sleep(1);
        }
}
```
- Now keep on running the code on one side of terminal and on other side create a frida agent code
```js
'use strict';

Interceptor.attach(ptr('0x55c159f18145'),{
        onEnter: function(args){
                console.log("f() called with n= "+args[0].toInt32());
        }
});
```
- Now just load the frida and you can easily monitor real time process.
```text
frida <process_name> -l agent.js
```
- It is also possible to infact change the live process. For instance this agent will simply add 1000 to output values and change the live process output.
```js
'use strict';

Interceptor.attach(ptr('0x55c159f18145'),{
        onEnter: function(args){
                console.log("f() called with n= "+args[0].toInt32());
                args[0]=args[0].add(1000);
        }
});
```

This seems a very powerfull tool to debug live process and can be used in game hacking.

# Reference
- This [video](https://www.youtube.com/watch?v=QC2jQI7GLus)
