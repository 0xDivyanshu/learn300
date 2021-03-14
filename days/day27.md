# DLL Injection

Code can be found [here](../code/day27.cpp)

Mistake done was that I was using `LoadLibraryW` which accepts `wchar_t*` but I was giving it `char*`. Hence just changed LoadLibraryW to LoadLibraryA
