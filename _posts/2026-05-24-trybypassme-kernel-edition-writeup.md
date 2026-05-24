---
title: "TryBypassMe Kernel Edition (TBMKEv1)"
tags: CTF
series: Crackmes
description: A write-up for TryBypassMe (TBMKEv1), an advanced crackme featuring a ring 0 kernel driver, encrypted watchdog, anti-analysis, and memory integrity defenses.
---

## TryBypassMe

[TryBypassMe](https://crackmes.one/crackme/69db34d6b38f9259eec7eb32) (TBMKEv1) - Advanced Crackme Game

### Description and Goal:
Welcome to TryBypassMe! This is a custom-built, educational top-down shooter designed specifically to test your reverse engineering skills.

Your goal is to successfully reverse engineer the protections and create a working bypass/trainer (e.g., infinite health, infinite ammo, or score manipulation) without triggering the game-over kill switch or crashing the application. Because of the heavy integrity checks, simple memory patching or basic injections will not work. A valid writeup must detail exactly how you neutered the tamper guards, bypassed the kernel/watchdog communications, and successfully cheated.

## Features and Protections to Defeat:

Ring 0 Kernel Driver (TBMKD.sys): Implements VAD scanning, handle stripping, remote thread blocking, and driver self-integrity checks.

Encrypted Watchdog: User-mode watchdog process communicating via named pipes with strict HMAC validation and sequence numbering.

Anti-Analysis: Aggressive debugger checks (PEB, HW Breakpoints, NtQueryInformationProcess), blacklisted process/window scanning, and TLS callback monitoring.

Memory Defenses: .text section CRC hashing, IAT integrity checks, encrypted variables (shadow copies + canaries), and 24+ active tamper guards monitoring thread liveness and execution flow.

![Game screenshot](/assets/img/tbmke-game-screenshot.png)

The challenge consists of three files of interest. The game components with built in anti-cheat: `TBM.exe`, a kernel driver `TBMKD.sys` and a Watchdog binary `WatchdogMain.exe`.

# TBM.exe Analysis 
IDA identifies the `WinMain` function, the first function called is then `sub_140024DD0`

## Memory Integrity Check

### CRC32 Hashing The .text Section

![CRC32 hashing the .text section](/assets/img/tbmke-crc32-text-section.png)

This first function gets a handle to the current executing module and checks that it's a portable executable:

```C
ModuleHandleA = GetModuleHandleA(nullptr);    // Base address of current executable
Result = IMAGE_DOS_SIGNATURE;                 // 0x4d5a
if ( *(_WORD *)ModuleHandleA == IMAGE_DOS_SIGNATURE )// Check we're an executable
```

It then identifies the IMAGE_SECTION_HEADER, and looks for the .text section:

```c
e_lfanew = (char *)ModuleHandleA + *((int *)ModuleHandleA + 0xF);// int = 4, 0xF x 4 = 0x3C = Offset to PE Header (e_lfanew)
 v2 = 0;
 counter = 0;
 number_of_sections = *((_WORD *)e_lfanew + 3);
 section_headers = &e_lfanew[*((unsigned __int16 *)e_lfanew + 10) + 24];// Some pointer arithmetic to land at IMAGE_SECTION_HEADER
 if ( number_of_sections )
 {                                           // Looks for .text section
   while ( *(_DWORD *)section_headers != 'xet.' || section_headers[4] != 't' )
   {
     ++counter;
     section_headers += 40;
     if ( counter >= number_of_sections )
       return;
```

The function then calculates the CRC32 hash of the .text section and writes the result to a global variable:

```c
if ( *((_DWORD *)section_headers + 2) )
{
  do
  {
    v10 = (unsigned __int8)v9[v3++];
    v11 = ((((v7 ^ v10) >> 1) ^ -(((unsigned __int8)v7 ^ (unsigned __int8)v10) & 1) & 0xEDB88320) >> 1)// 0xEDB88320 = CRC32 hash
        ^ -(((unsigned __int8)((v7 ^ v10) >> 1) ^ -(((unsigned __int8)v7 ^ (unsigned __int8)v10) & 1) & 0x20) & 1)
        & 0xEDB88320;
    v12 = (((v11 >> 1) ^ -(v11 & 1) & 0xEDB88320) >> 1)
        ^ -(((unsigned __int8)(v11 >> 1) ^ -(v11 & 1) & 0x20) & 1)
        & 0xEDB88320;
    v13 = (((v12 >> 1) ^ -(v12 & 1) & 0xEDB88320) >> 1)
        ^ -(((unsigned __int8)(v12 >> 1) ^ -(v12 & 1) & 0x20) & 1)
        & 0xEDB88320;
    v14 = v13;
    Result = (unsigned __int64)(v13 >> 1);
    v7 = (((unsigned int)Result ^ -(v14 & 1) & 0xEDB88320) >> 1)
       ^ -(((unsigned __int8)Result ^ -(v14 & 1) & 0x20) & 1)
       & 0xEDB88320;
  }
  while ( v3 < v8 );
}
text_crc32_hash = ~v7;                    // Calculates CRC32 hash of .text section
```

This function does not perform any checks itself, but is used to calculate the hash and store the value. We can check cross references to `text_crc32_hash` to see where this gets used.

![Cross references to text_crc32_hash](/assets/img/tbmke-xrefs-text-crc32.png)

### Encrypting And Storing The Hash

We are presented with the following code:

```c
text_hash = text_crc32_hash;                // Local variable = Global variable
if ( !text_crc32_hash )                     // If no hash value
  text_hash = AC::Other_CRC32_text_hash();  // Calculate a new one
if ( text_hash_xor_1 )
{
  text_hash_xor_2 = ::text_hash_xor_2;
  if ( ::text_hash_xor_2 )
  {
    text_hash_xor_3 = ::text_hash_xor_3;
    if ( ::text_hash_xor_3 )
    {
      if ( ::encoding_key )// derived from PID ^ TickCount, meaning this key is different each run
      {
        encoding_key_1 = *::encoding_key;
        *text_hash_xor_1 = *::encoding_key ^ (text_hash >> 22) ^ 0x13375EED;// Store first XOR'd result
        *text_hash_xor_2 = (3 * encoding_key_1) ^ (text_hash >> 11) & 0x7FF ^ 0xFEEDF00D;// Store second XOR'd result
        *text_hash_xor_3 = text_hash & 0x7FF ^ (7 * encoding_key_1) ^ 0xC001C0DE;// Store third XOR'd result
      }
    }
  }
```

The anti-cheat stores 3 values calculated from XOR operations against the CRC32 hash of the .text section.

Looking at cross references to these globals, we see them being used in three functions. One of which is at `sub_140037490` and acts as a one shot check pretty early on in `WinMain`. The other is performed in `sub_140042E50` as part of a thread and is run in an infinite loop. This thread function also performs additional checks which we haven't looked at yet. The third is `sub_14004C260`, which is our current function. It's huge and performs a lot of initialisation. 

### Saving .text Section Bytes

Within `sub_14004C260`, a copy of the .text bytes are stored in a global variable:

```c
v152 = v146 + *(v150 + 12);
v153 = *(v150 + 8);
text_section_size = v153;                   // VirtualSize of .text
live_text_section = v152;                   // module_base + VirtualAddress
v154 = GetProcessHeap();
copy_text_section = HeapAlloc(v154, 0, v153);
::copy_text_section = copy_text_section;
if ( copy_text_section )
  memcpy(copy_text_section, live_text_section, text_section_size);
```

### Performing The Integrity Check

The memory integrity logic in `sub_140042E50` and `sub_140037490` is nearly identical. It essentially checks the hash that was calculated early on in execution vs a newly calculated hash.


```c
new_text_hash = AC::Other_CRC32_text_hash();
```

```c
previous_text_hash = ((*text_hash_xor_3 ^ (7 * v4)) ^ 0xDE) & 0x7FF | (((*text_hash_xor_1 ^ *v2) << 22) ^ 0xBB7FFFFF) & 0xFFC00000 | ((6144 * v4) ^ ((*text_hash_xor_2 ^ 0xD) << 11)) & 0x3FF800;
```

```c
if ( new_text_hash != previous_text_hash )
{
  v69 = v1;
  if ( copy_text_section )
  {
    sub_140024A50(&byte_140070B0D, 1);
    if ( VirtualProtect(live_text_section, text_section_size, 0x40u, flOldProtect) )
    {
      memcpy(live_text_section, copy_text_section, text_section_size);
      VirtualProtect(live_text_section, text_section_size, flOldProtect[0], flOldProtect);
    }
```

A new hash is calculated from the live .text section. It is compared against the previously stored result, and if they do not match, the section is patched with the previous .text section's bytes.

The anti-cheat then creates a thread, the function of which spawns a message box:

```c
  strcpy(Caption, "Anti-Cheat");
  MessageBoxA(nullptr, lpThreadParameter, Caption, 0x41010u);
  free(lpThreadParameter);
  return 0;
```

The process is then terminated.

```c
CurrentProcess = GetCurrentProcess();
TerminateProcess(CurrentProcess, 1u);
```

## String Encryption

Back to the `WinMain` function we're presented with string encryption.

![String encryption](/assets/img/tbmke-string-encryption.png)


The string encryption works by XORing the first byte with the hex value `0x30` (Or ASCII 0), and increasing by 1 for each byte (second byte XOR'd with 0x31, then 0x32, etc).

```c
  qmemcpy(Source, "dCKqMEWDKt_;", 12);
  counter = 0;
  if ( dword_140070010 < 2 )
  {
    ciphertext = Source;
    do
    {
      ++ciphertext;
      v25 = 56 * (counter / 56u);
      i = counter++;
      *(ciphertext - 1) ^= i - v25 + 0x30;
    }
    while ( counter < 12 );
```

The ASCII representation if 0x30 - 0x42 is '0123456789:;', as such, we can use the following [Binary Refinery](https://github.com/binref/refinery) pipeline to decrypt this string:

```
emit 'dCKqMEWDKt_;' | xor '0123456789:;'
TryBypassMe
```

A better alternative is to use the `alu` module and custom expression:

```
emit <ciphertext> | alu "B ^ ((K % 56) + 52)"
```

## Admin Check

The anti-cheat the proceeds to check if it's running in an elevated state:

![Admin check](/assets/img/tbmke-admin-check.png)

If it is not, it simply prompts the user to either re-open as admin, or exit.

![Admin prompt](/assets/img/tbmke-admin-prompt.png)

The program can then re-open as administrator, or simply terminate:

```c
GetModuleFileNameA(nullptr, Filename, 0x104u);
strcpy(IsMember, "runas");
ShellExecuteA(nullptr, IsMember, Filename, nullptr, nullptr, 1);
AC::teardown();
```

The function I named `AC::teardown` function closes connection to the driver and stops and deletes the service `TBMKEv1`. This function is called numerous times throughout the binary on every exit path.

If the process is running in an elevated state, we head into a function I named`AntiCheat_init`. We partly analysed this function earlier when we followed through with our memory integrity analysis.

## File Integrity Check
The first function called in `AntiCheat_init` is `sub_14002C1D0`. This function was relatively easy to recognise as it's similar to the previous memory integrity check we analysed in that it reutns a CRC32 hash. In this case, it's returning a hash of the current running executable (`TBM.exe`).

```c
  memset(Filename, 0, 260u);
  GetModuleFileNameA(nullptr, Filename, 0x104u);// Returns file name of current executed process
  FileA = CreateFileA(Filename, 0x80000000, 1u, nullptr, 3u, 0x80u, nullptr);// Gets handle to itself
  v1 = FileA;
  if ( FileA == -1LL )
    return 0;
  NumberOfBytesRead = 0;
  CRC32_hash = -1;
  if ( ReadFile(FileA, Buffer, 0x1000u, &NumberOfBytesRead, nullptr) )// Reads itself
  {
    do
    {
      if ( !NumberOfBytesRead )
        break;
      v4 = Buffer;
      v5 = NumberOfBytesRead;
      do
      {                                         // Calculates CRC32 hash of itself
        v6 = *v4++;
        v7 = ((((CRC32_hash ^ v6) >> 1) ^ -((CRC32_hash ^ v6) & 1) & 0xEDB88320) >> 1)// 0xEDB88320 = CRC32
           ^ -((((CRC32_hash ^ v6) >> 1) ^ -((CRC32_hash ^ v6) & 1) & 0x20) & 1)
           & 0xEDB88320;
        v8 = (((v7 >> 1) ^ -(v7 & 1) & 0xEDB88320) >> 1) ^ -(((v7 >> 1) ^ -(v7 & 1) & 0x20) & 1) & 0xEDB88320;
        v9 = (((v8 >> 1) ^ -(v8 & 1) & 0xEDB88320) >> 1) ^ -(((v8 >> 1) ^ -(v8 & 1) & 0x20) & 1) & 0xEDB88320;
        CRC32_hash = (((v9 >> 1) ^ -(v9 & 1) & 0xEDB88320) >> 1) ^ -(((v9 >> 1) ^ -(v9 & 1) & 0x20) & 1) & 0xEDB88320;
        --v5;
      }
      while ( v5 );
    }
    while ( ReadFile(v1, Buffer, 0x1000u, &NumberOfBytesRead, nullptr) );
  }
  CloseHandle(v1);
  return ~CRC32_hash;                           // Return calculated CRC32 hash
}
```

This hash is XOR'd twice and stored in two global variables:

```c
  TBM_CRC32_hash = AC::Calc_TBM_exe_CRC32();
  if ( qword_140070AB0 && XORed_TBM_CRC32_hash_0 && XORed_TBM_CRC32_hash_1 )
  {
    key = *qword_140070AB0 ^ dword_140070C50;
    *XORed_TBM_CRC32_hash_0 = key ^ TBM_CRC32_hash;
    *XORed_TBM_CRC32_hash_1 = TBM_CRC32_hash ^ ~key;// Inverted
```

Looking at cross references, these values are used again in `sub_140037B70` and `sub_14003E790`:

![Cross references to file CRC hashes](/assets/img/tbmke-xrefs-file-crc32.png)

In `sub_140037B70`, the anti-cheat first decrypts the values back to the hash and verifies they match:

```c
if ( qword_140070AB0 && XORed_TBM_CRC32_hash_0 && XORed_TBM_CRC32_hash_1 )
{
  XOR_key = *qword_140070AB0 ^ dword_140070C50;
  inverted_XOR_key = ~XOR_key;
  TBM_CRC32_hash_0 = *XORed_TBM_CRC32_hash_0 ^ XOR_key;
  TBM_CRC32_hash_1 = *XORed_TBM_CRC32_hash_1 ^ inverted_XOR_key;
  verify_hash_match = TBM_CRC32_hash_0 == TBM_CRC32_hash_1;
```

Next comes the logic if the newly calculated hash does not match the hash previously calculated:

```c
if ( TBM_CRC32_hash_0 && AC::Calc_TBM_exe_CRC32() != TBM_CRC32_hash_0 )
```

In this case, the following prompt is shown:

```
[!] CHEAT DETECTED

Reason: Disk CRC storage tampered (key mismatch)

Game will terminate.
```

and the process terminates:

```c
CreateThread(nullptr, 0, AntiCheat_msg, v84, 0, nullptr);
Sleep(0x1388u);
AC::teardown();
Proc = GetCurrentProcess();
TerminateProcess(Proc, 1u);
v88 = AC::calls_NtTerminateProcess(v86, v117);
```

`sub_14003E790` follows very similar logic, and will terminate and show the following message:

```
 [!] CHEAT DETECTED
 
 Reason: Disk CRC tampered (failed rekey)
 
 Game will terminate.
```

## Anti-Debugging

The first check is a simple call to the Windows API `IsDebuggerPresent`.

```
if ( IsDebuggerPresent() )
```

The other checks involve:

ProcessDebugPort:
```c
HMODULE ntdll = GetModuleHandleA("ntdll.dll");
auto NtQIP = GetProcAddress(ntdll, "NtQueryInformationProcess")
DWORD debug_port = 0;
NTSTATUS s2 = NtQIP(GetCurrentProcess(), 7 &debug_port, 4, NULL);
if (NT_SUCCESS(s2) && debug_port != 0) {
trigger("[!] CHEAT DETECTED\n\nReason: Debugger(DebugPort)\n\nGame will terminate.");
}
```

ProcessDebugFlags:
```c
DWORD debug_flags = 1;
NTSTATUS s3 = NtQIP(GetCurrentProcess(), 0x1F, &debug_flags, 4, NULL);
if (NT_SUCCESS(s3) && debug_flags == 0) {
trigger("[!] CHEAT DETECTED\n\nReason: Debugger (DebugFlags)\n\nGame will terminate.")
}
```

PEB.NtGlobalFlag:
```c
PEB* peb = (PEB*)__readgsqword(0x60);
if (peb->NtGlobalFlag & 0x70) {
    trigger("[!] CHEAT DETECTED\n\nReason: Debugger (NtGlobalFlag)\n\nGame will terminate.");
}
```

Hardware breakpoints:
```c
CONTEXT ctx = {};
ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
GetThreadContext(GetCurrentThread(), &ctx)
if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
    trigger("[!] CHEAT DETECTED\n\nReason: Hardware breakpoints (DR0-DR3)\n\nGame will terminate.");
}
```

## Process Enumeration

Three functions exist to detect running process that might be used to debug / cheat. These are at `0x14002CD10`, `0x14002EDE0` and `0x1400389A0`.

`0x14002CD10` uses the Windows API `CreateToolhelp32Snapshot` to scan all running processes and compare them against a list.

`0x14002EDE0` does a similar thing, but uses `EnumWindows` to scan process window titles.

`0x1400389A0` also uses `CreateToolhelp32Snapshot`, but it scans for loaded modules rather than processes.

The following error is displayed if a blocklisted process is found, followed by the process being terminated:

![Blocklisted process detection](/assets/img/tbmke-blocklist-detection.png)

## Looped Thread Function

As mentioned earlier there is further functionality includded in the `sub_140042E50` function, which I'll take quick look at now.

### Function Hooking Detection

Within the thread `sub_140042E50`, a call is made to `sub_140025530`. This function is responsible for checking the integrity of the init function we called `AntiCheat_init` for any hooking / tampering. There's quite a lot going on so I don't want to spend too much time looking at each function.

The function checks the first bytes of the function for common inline hooks:

```c
if ( *AC::AntiCheat_init == 0xE9 )
{
  v3 = *(AC::AntiCheat_init + 1);
  v4 = &loc_14004C263 + 2;
}
else
{
  if ( *AC::AntiCheat_init != 0xEB )
    goto LABEL_11;
```

### IAT Hook Detection

Firslty, DLLs are resolved. The Import Directory is then walked and validated for matching DLL names. 

```c
offsets = (*(*handle_to_self + 0x3CLL) + *handle_to_self + 0x90LL);
```

The DLLS checked are:
* `win32u.dll`
* `kernel32.dll`
* `ntdll.dll`
* `kernelbase.dll`
* `msvcrt.dll`

### Check .text Section Characteristics

The next check looks for its own .text section and whether it has been made writable.

Find .text section:
```c
qmemcpy(&v72, ".texL9", 6);
if ( v8 == v72.m128i_i32[0] && *(v7 + 4) == 't' )
```

Query the section:
```c
memset(&Buffer, 0, sizeof(Buffer));
if ( !VirtualQuery(v10, &Buffer, 0x30u) )
```

Check the characteristics:
```c
v12 = Buffer.Protect & 0xFFFFFCFF;
LOBYTE(v11) = (Buffer.Protect & 0xFFFFFCFF) == PAGE_EXECUTE_READWRITE
           || v12 == PAGE_EXECUTE_WRITECOPY
           || v12 == PAGE_READWRITE
           || v12 == PAGE_WRITECOPY;
```

### Further Integrity Checks

Many of the other functions called involve hashing a specific component, and later checking it and validating the result of a newly genereated hash, ensuring no tampering has taken place.
