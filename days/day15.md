# Windows API - hashing Part 3.1

Today was mostly reading about docs for various c++ functions that I can use to get the PE structure for DLL.

1. `LoadLibraryA`
```c++
HMODULE LoadLibraryA(
  LPCSTR lpLibFileName
);
```
Just need to pass the filename and it will return handle to the DLL which maybe used to read the structure.

2. `ImageNTHeader`
```c++
PIMAGE_NT_HEADERS IMAGEAPI ImageNtHeader(
  PVOID Base
);
```
This will return pointer to `IMAGE_NT_HEADERS` which is the easiest way according to me to read the structure and find the export table of DLL but I couldn't get it working in visual studio since it gave errors saying `external _image_ntheaders not recognised`.

3. `ReadFile`
```c++
BOOL ReadFile(
  HANDLE       hFile,
  LPVOID       lpBuffer,
  DWORD        nNumberOfBytesToRead,
  LPDWORD      lpNumberOfBytesRead,
  LPOVERLAPPED lpOverlapped
);
```
This can again also be used to read DLL but I dont want to use it since the lpBuffer is the memory used to read the file. Its like either you read the full DLL into memory or just ready maybe first 10000 bytes into memory. I just want to read the headers and there is no need to save stuff to memory so this seems to be memory expensive solution so not that much in favor of this.


I am mostly trying to make `ImageNtHeader` work out and if not then maybe go ahead with LoadLibraryA and perform some memory conversions to read into strcuture.
