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

# TBM.exe Analysis - Game And Userland Anti-Cheat
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

The ASCII representation of 0x30 + 12 is '0123456789:;', as such, we can use the following [Binary Refinery](https://github.com/binref/refinery) pipeline to decrypt this string:

```
emit 'dCKqMEWDKt_;' | xor '0123456789:;'
TryBypassMe
```

A better alternative is to use the `alu` module and custom expression:

```
emit <ciphertext> | alu "B ^ ((K % 56) + 52)"
```

## Admin Check

The anti-cheat then proceeds to check if it's running in an elevated state:

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

The function I named `AC::teardown` closes the connection to the driver and stops and deletes the service `TBMKEv1`. This function is called numerous times throughout the binary on every exit path.

If the process is running in an elevated state, we head into a function I named `AntiCheat_init`. We partly analysed this function earlier when we followed through with our memory integrity analysis.

## File Integrity Check
The first function called in `AntiCheat_init` is `sub_14002C1D0`. This function was relatively easy to recognise as it's similar to the previous memory integrity check we analysed in that it returns a CRC32 hash. In this case, it's returning a hash of the current running executable (`TBM.exe`).

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
NTSTATUS s2 = NtQIP(GetCurrentProcess(), 7, &debug_port, 4, NULL);
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

Three functions exist to detect running processes that might be used to debug / cheat. These are at `0x14002CD10`, `0x14002EDE0` and `0x1400389A0`.

`0x14002CD10` uses the Windows API `CreateToolhelp32Snapshot` to scan all running processes and compare them against a list.

`0x14002EDE0` does a similar thing, but uses `EnumWindows` to scan process window titles.

`0x1400389A0` also uses `CreateToolhelp32Snapshot`, but it scans for loaded modules rather than processes.

The following error is displayed if a blocklisted process is found, followed by the process being terminated:

![Blocklisted process detection](/assets/img/tbmke-blocklist-detection.png)

## Looped Thread Function

As mentioned earlier there is further functionality included in the `sub_140042E50` function, which I'll take quick look at now.

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

Firstly, DLLs are resolved. The Import Directory is then walked and validated for matching DLL names. 

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

Many of the other functions called involve hashing a specific component, and later checking it and validating the result of a newly generated hash, ensuring no tampering has taken place.

## TBM.exe Summary So Far

We've covered the main self-protection mechanisms in TBM.exe that run in looped threads and will terminate the process if triggered. There is a lot more that wasn't looked at in depth, but the important thing is that all of these usermode checks only protect against internal tampering. They can't stop an external process from reading or writing game memory. This is where the kernel driver comes in play.

Realistically I didn't need to reverse engineer all of the anti-cheat components to this level, but I enjoyed doing so. When we've worked out how to bypass the anti-cheat I'll revisit `TBM.exe` to identify prime candidates of game code for the cheat.

## Kernel Driver Communication

`TBM.exe` creates a service named `TBMKEv1`, which is used to communicate with the kernel driver. It opens `\\\\.\\TBMKEv1` via `CreateFileW` and stores the handle in a global.

There are then numerous functions and monitoring threads that register, authenticate and monitor the driver. `TBM.exe` proves that it is alive, is validated and validates target process status.

# TBMKD.sys Analysis - Kernel Driver

## Memory Scanning

The kernel driver attaches to the register process via `PsLookupProcessByProcessId` and `KeStackAttachProcess`. It then finds and validates the main module and scans memory regions - using `ZwQueryVirtualMemory` looking for pages matching `MEM_COMMIT` (0x1000), `MEM_PRIVATE` (0x20000) and Executable/writable protection (`PAGE_EXECUTE_READWRITE`, `PAGE_EXECUTE_WRITECOPY`, etc).

```c
if ( *(_WORD *)main_module == 0x5A4D ) // MZ header check
{
  offset_to_lfanew = *(int *)(main_module + 0x3C); // Offset to lfanew
  if ( *(_DWORD *)(offset_to_lfanew + main_module) == 0x4550 ) // PE header check
```

```c
if ( (_DWORD)v16 == 4096         // State == MEM_COMMIT
  && DWORD2(v16) == 0x20000      // Type == MEM_PRIVATE
  && v7 )                        // Protection is executable
```

This function is checking for any suspicious memory pages within the game's process, as that could indicate some kind of code has been injected.

## File Integrity Checks

The kernel driver also implements integrity checks by CRC32 hashing the file on disk and compares it to a hardcoded value - `0x688FFE38`

```c
tbm_hash = CRC32_hash(v2);
```

```c
if ( tbm_hash != hardcoded_hash )
```

```c
Watchdog_filepath = (struct _UNICODE_STRING *)build_file_path(v2, L"WatchdogMain.exe");
```

```c
watchdog_hash = CRC32_hash(Watchdog_filepath);
```

```c
if ( watchdog_hash == hardcoded_watchdog_hash )
```

## Handle Access Stripping (ObRegisterCallbacks)

The driver uses `ObRegisterCallbacks` to strip handle access rights from any external process that tries to open a handle to `TBM.exe`:

```c
{
    ULONG target_pid = PsGetProcessId(*(PEPROCESS*)(OperationInfo + 8));
    ULONG caller_pid = PsGetCurrentProcessId();

    if (ProcessId != 0)
    {
        if (target_pid == ProcessId && caller_pid != ProcessId)
        {
            ULONG *access = *(ULONG**)(OperationInfo + 0x20);
            ULONG original = *access;

            if (original & 0x87A)
            {
                *access = original & 0xFFFFF785;
                log("stripped handle rights from PID %d", caller_pid);
            }
        }
    }
    return OB_PREOP_SUCCESS;
}
```

The mask `0x87A` strips the following rights - `PROCESS_CREATE_THREAD`, `PROCESS_VM_OPERATION`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_DUP_HANDLE` and `PROCESS_SUSPEND_RESUME`. Making it difficult for any external process to read / write memory.

## Driver Self-Integrity Check

There's also a system thread running a monitoring loop every ~5 seconds, calling a self-integrity check:

```c
{
    __int64 last_integrity = SharedUserData->InterruptTime;

    while (1)
    {
        LARGE_INTEGER timeout = {.QuadPart = -10000000}; 
        if (!KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, &timeout))
            break;

        __int64 now = SharedUserData->InterruptTime;

        if (now - last_integrity >= 50000000) 
        {
            self_integrity_check();
            last_integrity = now;
        }
        
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}
```

Looking at `self_integrity_check`:

```c
char self_integrity_check()
{
    // byte-for-byte comparison of .text section against saved copy
    if (P && Source1 && Length)
    {
        if (RtlCompareMemory(Source1, P, Length) != Length)
        {
            set_violation_flags(32, 6);
            return 0;
        }

        // FNV-1 hash of the saved copy
        unsigned int fnv = 0x811C9DC5;
        for (SIZE_T i = 0; i < Length; i++)
            fnv = 0x01000193 * (fnv ^ Source1[i]);

        if (fnv != expected_fnv_hash)
        {
            set_violation_flags(32, 6);
            return 0;
        }
    }
    return 1;
}
```

Violation flags are set and reported back to `TBM.exe`, which terminates the game.

# Bypass - Driver Patching

Three patches to `TBMKD.sys` are needed.

## Disable Client CRC32 Validation

When `TBM.exe` registers with the driver, the driver CRC32 hashes `TBM.exe` and compares it against the hardcoded value `0x688FFE38`. The check is skipped if the stored hash is zero, so that's our solution. The hash sits at file offset `0x6C04` (`38 FE 8F 68`). We'll overwrite this with `00 00 00 00`. The watchdog hash nearby gets the same treatment.

## Disable Driver Self-Integrity Check

At file offset `0x26BC` the `self_integrity_check` prologue `48 89 5C 24 08 48` becomes `B8 01 00 00 00 C3` (`mov eax, 1 ; ret`), so it just returns.

## Disable Handle Access Stripping

The callback's first branch checks whether the game PID is set - if it's zero, nothing gets stripped. We'll just flip that conditional jump `jz` into an unconditional jump `jmp` so it always skips. At file offset `0x24BC`, `0F 84 BA 00 00 00` (`jz loc_14000317C`) becomes `E9 BB 00 00 00 90` (`jmp loc_14000317C; nop`). 

## Patcher Script

```python
import shutil

patches = [
    (0x24BC, "e9bb00000090"),
    (0x26BC, "b801000000c3"),
    (0x6C04, "00000000"),
]

shutil.copy2("TBMKD.sys", "TBMKD_patched.sys")
buf = bytearray(open("TBMKD_patched.sys", "rb").read())

for off, new in patches:
    new = bytes.fromhex(new)
    buf[off:off + len(new)] = new

open("TBMKD_patched.sys", "wb").write(buf)
```

With the patch in place, we revisit `TBM.exe`

# TBM.exe Again

## Identifying Game Code And Guards

We're going to try and create a cheat that gives us unlimited health and unlimited ammo. The first step in doing that is to identify where those values are within the game. I'm going to do this statically with IDA.

I was able to identify what were very likely game values within the `AntiCheat_init` function based on the decimal values corresponding to the games default health and ammo values.

```c
hash_fnv1a(&dword_140070990, 100); // Health = 100
hash_fnv1a(&dword_140070910, 30); // Ammo = 30
hash_fnv1a(&dword_140070800, 0);
hash_fnv1a(&dword_140070A10, 0);
hash_fnv1a(&dword_140070890, 1);
```

`hash_fnv1a` turns values into a 0x78 byte block.
Two keys are pulled and used from globals that are initialised during runtime:

```c
key_1 = ::key_1;
key_2 = ::key_2;
*a1 = *::key_1 ^ a2;
a1[26] = *key_2 ^ a2;
v5 = a1 + 1;
a1[8] = -559038242;
a1[14] = -1318387531;
v6 = 7;
v7 = *key_1 ^ *key_2 ^ a2;
.....
```

Both keys are derived at startup and are PID/tick-based, making them unique per run.

A monitoring thread, `sub_140043730`, shuffles and runs a set of guard functions:

```c
case 1: sub_1400336D0();   // health guard
case 2: sub_140033CD0();   // ammo guard
case 5: AC::anti_debugging();
```

The anti-cheat also keeps a shadow / backup copy of these values, and constantly checks the health and ammo against them.

Each one is stored as `value XOR a key`, which decodes to how much the value has changed (0 means unchanged).

To overcome this, write the key itself into the shadow, then `key XOR key = 0`, meaning unchanged, and the guard stays happy.

## Avoiding The Handle Scan

The anti-cheat also scans for any process that's currently holding a handle to `TBM.exe`. It queries `SystemHandleInformation` and walks every handle in the system:

```c
v44 = dwProcessId;
v111 = dwProcessId;
v45 = lpMem;
v46 = 0;
if ( *lpMem )
{
  while ( 1 )
  {
    v47 = v45[6 * v46 + 2];
    v48 = &v45[6 * v46];
    if ( v47 != CurrentProcessId && v47 != v44 && (v47 & 0xFFFFFFFB) != 0 && (v48[6] & 0x30) != 0 )
      break;
LABEL_34:
    if ( ++v46 >= *v45 )
      return 0;
  }
```

The scan only catches handles that are open at the moment it runs. So instead of having a handle open for the whole session, we'll open one, do a single read or write, and close it.

Putting all of this together, here's the trainer:

```python
import ctypes
import ctypes.wintypes as wt
import struct
import sys
import time

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.GetTickCount64.restype = ctypes.c_uint64

PROCESS_VM_READ           = 0x0010
PROCESS_VM_WRITE          = 0x0020
PROCESS_VM_OPERATION      = 0x0008
PROCESS_QUERY_INFORMATION = 0x0400
ACCESS = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION
TH32CS_SNAPPROCESS = 0x2
TH32CS_SNAPMODULE  = 0x8


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize",              wt.DWORD),
        ("cntUsage",            wt.DWORD),
        ("th32ProcessID",       wt.DWORD),
        ("th32DefaultHeapID",   ctypes.c_size_t),
        ("th32ModuleID",        wt.DWORD),
        ("cntThreads",          wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase",      ctypes.c_long),
        ("dwFlags",             wt.DWORD),
        ("szExeFile",           ctypes.c_char * 260),
    ]


class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize",        wt.DWORD),
        ("th32ModuleID",  wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("GlblcntUsage",  wt.DWORD),
        ("ProccntUsage",  wt.DWORD),
        ("modBaseAddr",   ctypes.POINTER(wt.BYTE)),
        ("modBaseSize",   wt.DWORD),
        ("hModule",       wt.HMODULE),
        ("szModule",      ctypes.c_char * 256),
        ("szExePath",     ctypes.c_char * 260),
    ]


def find_pid(name):
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    pe = PROCESSENTRY32()
    pe.dwSize = ctypes.sizeof(PROCESSENTRY32)
    pid = None
    if k32.Process32First(snap, ctypes.byref(pe)):
        while True:
            if pe.szExeFile.lower() == name.lower():
                pid = pe.th32ProcessID
                break
            if not k32.Process32Next(snap, ctypes.byref(pe)):
                break
    k32.CloseHandle(snap)
    return pid


def get_base(pid, name):
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)
    me = MODULEENTRY32()
    me.dwSize = ctypes.sizeof(MODULEENTRY32)
    base = None
    if k32.Module32First(snap, ctypes.byref(me)):
        while True:
            if me.szModule.lower() == name.lower():
                base = ctypes.cast(me.modBaseAddr, ctypes.c_void_p).value
                break
            if not k32.Module32Next(snap, ctypes.byref(me)):
                break
    k32.CloseHandle(snap)
    return base


# open/use/close every time so we never hold a handle the driver can scan for
def rpm(pid, addr, fmt):
    h = k32.OpenProcess(ACCESS, False, pid)
    buf = ctypes.create_string_buffer(struct.calcsize(fmt))
    k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, len(buf), None)
    k32.CloseHandle(h)
    return struct.unpack(fmt, buf.raw)[0]


def wpm(pid, addr, data):
    h = k32.OpenProcess(ACCESS, False, pid)
    k32.WriteProcessMemory(h, ctypes.c_void_p(addr), data, len(data), None)
    k32.CloseHandle(h)

# rebuild the 0x78 protected-value block the game expects (hash_fnv1a
def encode_var(key1, key2, value):
    out = [0] * 30
    v = value & 0xFFFFFFFF
    out[0]  = (key1 ^ v) & 0xFFFFFFFF
    out[8]  = 0xDEADC0DE
    out[14] = 0xB16B00B5
    out[26] = (key2 ^ v) & 0xFFFFFFFF
    h = (key1 ^ key2 ^ v) & 0xFFFFFFFF
    def step():
        nonlocal h
        h = ((16777619 * h) ^ 0x811C9DC5) & 0xFFFFFFFF
        return h
    for i in [*range(1, 8), *range(9, 14), *range(15, 26), *range(27, 30)]:
        out[i] = step()
    return struct.pack('<30I', *out)


KEY1   = 0x70888
KEY2   = 0x707C0
KEY_C8 = 0x707C8
KEY_D8 = 0x707D8
HEALTH = 0x70990
AMMO   = 0x70910
HP_SHADOWS   = (0x707F0, 0x70878)
AMMO_SHADOWS = (0x70AC0, 0x70880, 0x70988)
FIRE   = 0x70B74
RELOAD = 0x70FA4
RELOAD2= 0x70FA0
SCAN_TS = 0x70FE0


def main():
    pid = find_pid(b"TBM.exe")
    if not pid:
        sys.exit("TBM.exe not running")
    base = get_base(pid, b"TBM.exe")
    print(f"pid={pid} base={hex(base)}")

    while True:
        key1   = rpm(pid, rpm(pid, base + KEY1, '<Q'), '<I')
        key2   = rpm(pid, rpm(pid, base + KEY2, '<Q'), '<I')
        key_c8 = rpm(pid, rpm(pid, base + KEY_C8, '<Q'), '<I')
        key_d8 = rpm(pid, rpm(pid, base + KEY_D8, '<Q'), '<I')
        kc8 = struct.pack('<I', key_c8)
        kd8 = struct.pack('<I', key_d8)

        wpm(pid, base + HEALTH, encode_var(key1, key2, 100))
        for shd in HP_SHADOWS:
            p = rpm(pid, base + shd, '<Q')
            wpm(pid, p, kc8)
            wpm(pid, p + 4, kd8)

        wpm(pid, base + AMMO, encode_var(key1, key2, 30))
        for shd in AMMO_SHADOWS:
            p = rpm(pid, base + shd, '<Q')
            wpm(pid, p, kc8)
            wpm(pid, p + 4, kd8)

        wpm(pid, base + FIRE, b'\x00')
        wpm(pid, base + RELOAD, struct.pack('<I', 0))
        wpm(pid, base + RELOAD2, struct.pack('<I', 0))
        wpm(pid, base + SCAN_TS, struct.pack('<Q', k32.GetTickCount64()))

        time.sleep(0.1)


main()
```

# Bypass - Kernel Driver

Maybe a more "proper" way to solve this challenge is to develop and run a custom kernel driver and get that to do all of the memory patching.
Despite this game launching with a kernel driver, it does not enumerate kernel drivers on the system, therefore, we can use it and bypass all of the user-land checks.

```c
#include <ntddk.h>

#define DEVICE_NAME     L"\\Device\\CheatDrv"
#define SYMLINK_NAME    L"\\DosDevices\\CheatDrv"
#define POOL_TAG        'tChD'

#define IOCTL_READ_MEMORY  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_BASE     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _MEMORY_REQUEST {
    ULONG  ProcessId;
    ULONG  _pad;
    UINT64 Address;
    ULONG  Size;
    ULONG  _pad2;
    UCHAR  Buffer[4096];
} MEMORY_REQUEST, *PMEMORY_REQUEST;

NTKERNELAPI NTSTATUS MmCopyVirtualMemory(
    PEPROCESS SourceProcess,
    PVOID     SourceAddress,
    PEPROCESS TargetProcess,
    PVOID     TargetAddress,
    SIZE_T    BufferSize,
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T   ReturnSize
);

NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(PEPROCESS Process);

typedef struct _BASE_REQUEST {
    ULONG  ProcessId;
    ULONG  _pad;
    UINT64 BaseAddress;
} BASE_REQUEST, *PBASE_REQUEST;

static PDEVICE_OBJECT g_DeviceObject = NULL;

static NTSTATUS DispatchCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS DispatchClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS DispatchIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioctl = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG inLen = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR info = 0;
    PEPROCESS process = NULL;
    SIZE_T bytes = 0;

    if (ioctl == IOCTL_GET_BASE) {
        PBASE_REQUEST breq;
        PVOID base;
        if (inLen < sizeof(BASE_REQUEST) || outLen < sizeof(BASE_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
            goto done;
        }
        breq = (PBASE_REQUEST)Irp->AssociatedIrp.SystemBuffer;
        status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)breq->ProcessId, &process);
        if (!NT_SUCCESS(status))
            goto done;
        base = PsGetProcessSectionBaseAddress(process);
        ObDereferenceObject(process);
        breq->BaseAddress = (UINT64)base;
        info = sizeof(BASE_REQUEST);
        status = STATUS_SUCCESS;
        goto done;
    }

    {
        PMEMORY_REQUEST req = (PMEMORY_REQUEST)Irp->AssociatedIrp.SystemBuffer;

        if (inLen < sizeof(MEMORY_REQUEST) || outLen < sizeof(MEMORY_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
            goto done;
        }

        if (req->Size == 0 || req->Size > sizeof(req->Buffer)) {
            status = STATUS_INVALID_PARAMETER;
            goto done;
        }

        status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req->ProcessId, &process);
        if (!NT_SUCCESS(status))
            goto done;

        switch (ioctl) {
        case IOCTL_READ_MEMORY:
            status = MmCopyVirtualMemory(
                process, (PVOID)req->Address,
                PsGetCurrentProcess(), req->Buffer,
                req->Size, KernelMode, &bytes);
            if (NT_SUCCESS(status))
                info = sizeof(MEMORY_REQUEST);
            break;

        case IOCTL_WRITE_MEMORY:
            status = MmCopyVirtualMemory(
                PsGetCurrentProcess(), req->Buffer,
                process, (PVOID)req->Address,
                req->Size, KernelMode, &bytes);
            if (NT_SUCCESS(status))
                info = sizeof(MEMORY_REQUEST);
            break;

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
        }

        ObDereferenceObject(process);
    }

done:
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

static VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    UNICODE_STRING symlink;
    RtlInitUnicodeString(&symlink, SYMLINK_NAME);
    IoDeleteSymbolicLink(&symlink);

    if (g_DeviceObject)
        IoDeleteDevice(g_DeviceObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    UNICODE_STRING devName, symName;
    RtlInitUnicodeString(&devName, DEVICE_NAME);
    RtlInitUnicodeString(&symName, SYMLINK_NAME);

    NTSTATUS status = IoCreateDevice(
        DriverObject, 0, &devName,
        FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE,
        &g_DeviceObject);

    if (!NT_SUCCESS(status))
        return status;

    status = IoCreateSymbolicLink(&symName, &devName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    DriverObject->DriverUnload = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]  = DispatchClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;

    g_DeviceObject->Flags |= DO_BUFFERED_IO;
    g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    return STATUS_SUCCESS;
}
```

Modified trainer.py to communicate with our driver:
```python
import ctypes
import ctypes.wintypes as wt
import struct
import sys
import time

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.GetTickCount64.restype = ctypes.c_uint64

TH32CS_SNAPPROCESS = 0x2

IOCTL_READ  = 0x222000  # CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_WRITE = 0x222004  # CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_BASE  = 0x222008  # CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize",              wt.DWORD),
        ("cntUsage",            wt.DWORD),
        ("th32ProcessID",       wt.DWORD),
        ("th32DefaultHeapID",   ctypes.c_size_t),
        ("th32ModuleID",        wt.DWORD),
        ("cntThreads",          wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase",      ctypes.c_long),
        ("dwFlags",             wt.DWORD),
        ("szExeFile",           ctypes.c_char * 260),
    ]


class MEMORY_REQUEST(ctypes.Structure):
    _fields_ = [
        ("ProcessId", wt.DWORD),
        ("_pad",      wt.DWORD),
        ("Address",   ctypes.c_uint64),
        ("Size",      wt.DWORD),
        ("_pad2",     wt.DWORD),
        ("Buffer",    ctypes.c_ubyte * 4096),
    ]


class BASE_REQUEST(ctypes.Structure):
    _fields_ = [
        ("ProcessId",   wt.DWORD),
        ("_pad",        wt.DWORD),
        ("BaseAddress", ctypes.c_uint64),
    ]


def find_pid(name):
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    pe = PROCESSENTRY32()
    pe.dwSize = ctypes.sizeof(PROCESSENTRY32)
    pid = None
    if k32.Process32First(snap, ctypes.byref(pe)):
        while True:
            if pe.szExeFile.lower() == name.lower():
                pid = pe.th32ProcessID
                break
            if not k32.Process32Next(snap, ctypes.byref(pe)):
                break
    k32.CloseHandle(snap)
    return pid


def get_base_via_driver(hDrv, pid):
    """Get process base address via kernel driver (bypasses handle stripping)."""
    req = BASE_REQUEST()
    req.ProcessId = pid
    bytesReturned = wt.DWORD()
    ok = k32.DeviceIoControl(
        hDrv, IOCTL_BASE,
        ctypes.byref(req), ctypes.sizeof(req),
        ctypes.byref(req), ctypes.sizeof(req),
        ctypes.byref(bytesReturned), None
    )
    if ok and req.BaseAddress:
        return req.BaseAddress
    return None


def open_driver():
    h = k32.CreateFileW(
        "\\\\.\\CheatDrv",
        0xC0000000,  # GENERIC_READ | GENERIC_WRITE
        0, None, 3,  # OPEN_EXISTING
        0, None
    )
    if h == -1 or h == 0xFFFFFFFF:
        sys.exit("[!] Failed to open CheatDrv. Is the driver loaded?")
    return h


def rpm(hDrv, pid, addr, fmt):
    req = MEMORY_REQUEST()
    req.ProcessId = pid
    req.Address = addr
    req.Size = struct.calcsize(fmt)
    bytesReturned = wt.DWORD()
    ok = k32.DeviceIoControl(
        hDrv, IOCTL_READ,
        ctypes.byref(req), ctypes.sizeof(req),
        ctypes.byref(req), ctypes.sizeof(req),
        ctypes.byref(bytesReturned), None
    )
    if not ok:
        return None
    return struct.unpack_from(fmt, bytes(req.Buffer)[:req.Size])[0]


def wpm(hDrv, pid, addr, data):
    req = MEMORY_REQUEST()
    req.ProcessId = pid
    req.Address = addr
    req.Size = len(data)
    ctypes.memmove(req.Buffer, data, len(data))
    bytesReturned = wt.DWORD()
    k32.DeviceIoControl(
        hDrv, IOCTL_WRITE,
        ctypes.byref(req), ctypes.sizeof(req),
        ctypes.byref(req), ctypes.sizeof(req),
        ctypes.byref(bytesReturned), None
    )


def encode_var(key1, key2, value):
    """
    Rebuild the 0x78-byte (30 DWORDs) protected-value block that hash_fnv1a creates.
    The game stores values as: slot[0] = key1 ^ val, slot[26] = key2 ^ val,
    with canaries at [8]=0xDEADC0DE, [14]=0xB16B00B5, and FNV-1 chain filling the rest.
    """
    out = [0] * 30
    v = value & 0xFFFFFFFF
    out[0]  = (key1 ^ v) & 0xFFFFFFFF
    out[8]  = 0xDEADC0DE
    out[14] = 0xB16B00B5
    out[26] = (key2 ^ v) & 0xFFFFFFFF

    h = (key1 ^ key2 ^ v) & 0xFFFFFFFF

    def step():
        nonlocal h
        h = ((16777619 * h) ^ 0x811C9DC5) & 0xFFFFFFFF
        return h

    for i in [*range(1, 8), *range(9, 14), *range(15, 26), *range(27, 30)]:
        out[i] = step()

    return struct.pack('<30I', *out)


# Offsets into TBM.exe .data section (RVA from module base)
KEY1         = 0x70888
KEY2         = 0x707C0
KEY_C8       = 0x707C8
KEY_D8       = 0x707D8
HEALTH       = 0x70990
AMMO         = 0x70910
HP_SHADOWS   = (0x707F0, 0x70878)
AMMO_SHADOWS = (0x70AC0, 0x70880, 0x70988)
FIRE         = 0x70B74
RELOAD       = 0x70FA4
RELOAD2      = 0x70FA0
SCAN_TS      = 0x70FE0


def main():
    pid = find_pid(b"TBM.exe")
    if not pid:
        sys.exit("[!] TBM.exe not running")

    hDrv = open_driver()

    base = get_base_via_driver(hDrv, pid)
    if not base:
        sys.exit("[!] Could not get TBM.exe base address")

    print(f"[+] Attached: pid={pid}, base=0x{base:X}")
    print("[+] Trainer active - infinite health & ammo")

    while True:
        try:
            key1   = rpm(hDrv, pid, rpm(hDrv, pid, base + KEY1, '<Q'), '<I')
            key2   = rpm(hDrv, pid, rpm(hDrv, pid, base + KEY2, '<Q'), '<I')
            key_c8 = rpm(hDrv, pid, rpm(hDrv, pid, base + KEY_C8, '<Q'), '<I')
            key_d8 = rpm(hDrv, pid, rpm(hDrv, pid, base + KEY_D8, '<Q'), '<I')

            if key1 is None or key2 is None:
                time.sleep(0.5)
                continue

            kc8 = struct.pack('<I', key_c8)
            kd8 = struct.pack('<I', key_d8)

            # Health = 100
            wpm(hDrv, pid, base + HEALTH, encode_var(key1, key2, 100))
            for shd in HP_SHADOWS:
                p = rpm(hDrv, pid, base + shd, '<Q')
                if p:
                    wpm(hDrv, pid, p, kc8)
                    wpm(hDrv, pid, p + 4, kd8)

            # Ammo = 30
            wpm(hDrv, pid, base + AMMO, encode_var(key1, key2, 30))
            for shd in AMMO_SHADOWS:
                p = rpm(hDrv, pid, base + shd, '<Q')
                if p:
                    wpm(hDrv, pid, p, kc8)
                    wpm(hDrv, pid, p + 4, kd8)

            # Clear fire/reload state
            wpm(hDrv, pid, base + FIRE, b'\x00')
            wpm(hDrv, pid, base + RELOAD, struct.pack('<I', 0))
            wpm(hDrv, pid, base + RELOAD2, struct.pack('<I', 0))

            # Spoof the handle-scan timestamp so anti-cheat thinks it just ran
            wpm(hDrv, pid, base + SCAN_TS, struct.pack('<Q', k32.GetTickCount64()))

        except Exception as e:
            print(f"[!] Error: {e}")

        time.sleep(0.1)


if __name__ == "__main__":
    main()
```

new-2
```
#include <ntifs.h>
#include <ntimage.h>
#include "../shared/IOCTL.h"

extern "C" POBJECT_TYPE* IoDriverObjectType;

extern "C" NTKERNELAPI NTSTATUS NTAPI ObReferenceObjectByName(
    PUNICODE_STRING ObjectName,
    ULONG           Attributes,
    PACCESS_STATE   AccessState,
    ACCESS_MASK     DesiredAccess,
    POBJECT_TYPE    ObjectType,
    KPROCESSOR_MODE AccessMode,
    PVOID           ParseContext,
    PVOID*          Object
);

extern "C" NTKERNELAPI PVOID NTAPI PsGetProcessPeb(PEPROCESS Process);
extern "C" NTKERNELAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(PVOID Base);

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

/*
 * DETECTION SURFACE (GH: bypass_kernel.md, own_kernel_driver.md, be_bypass.md;
 *                   hal-science-research.pdf "Battling The Eye"):
 *
 *  Component                        BE detection method                       Mitigated here?
 *  ------------------------------   ----------------------------------------  ---------------
 *  sc.exe driver load               MmUnloadedDrivers + registry scan         Partially — cleared in DriverEntry/Unload;
 *                                                                              full fix: load via KDMapper (no load-path entry)
 *  \Device\KsecComm                 Device enum outside valid kernel module    Partial — device name chosen to blend with
 *                                   / handle stripping via ObRegisterCallbacks kernel security namespace; rename per
 *                                                                              deployment.  DriverObject required (sc.exe
 *                                                                              load path on 25H2; KDMapper returns STATUS_
 *                                                                              NOT_SUPPORTED — device creation skipped)
 *  IoCreateDevice / ExAllocatePool  Pool scan for non-image-backed allocs      Acceptable — DEVICE_OBJECT and IRP stack
 *                                                                              come from system pool (image-backed tags)
 *  System thread start address      PsSetCreateThreadNotifyRoutine check       N/A — we create no threads
 *  PiDDBCacheTable entry            AVL tree scan by TimeDateStamp             Yes — ClearPiDDBCacheTable() (sc.exe path);
 *                                                                              N/A for KDMapper (no entry created)
 *  PE timestamp blacklist           Load-image callback check at image load    N/A for KDMapper — BEDaisy's
 *                                                                              PsSetLoadImageNotifyRoutine fires AFTER
 *                                                                              we're already resident; for sc.exe: patch
 *                                                                              binary on disk + ZeroOwnTimestamp()
 *  MmCopyVirtualMemory              None — kernel-internal, no OB callback     N/A (core bypass); ObRegisterCallbacks
 *                                                                              handle stripping is irrelevant since we
 *                                                                              never call OpenProcess
 *  APC stack walk (RtlWalkFrameChain) .data pointer in ntoskrnl               Yes — FakeWalkFrameChain() returns 0 frames
 *  WDFilterDriverList               WdFilter.sys internal structure            N/A for KDMapper — manual map bypasses
 *                                                                              Windows filter manager registration path
 *  Kernel Event Logs (ETW)          EtwWrite at normal driver load             N/A for KDMapper — manual map bypasses
 *                                                                              MiRegisterBootLoaded / load-path ETW writes
 *  Kernel module integrity check    BEDaisy verifies win32k/hal/ACPI/pci.sys   N/A — we don't patch those modules
 *  Inline hook detection            Scans for int3/JMP at MmGetSystemRoutine   N/A — we use .data pointer replacement,
 *                                                                              not inline hooks; no int3 or JMP written
 *
 * Communication (25H2): DeviceIoControl through \Device\KsecComm.
 *   sc.exe path  — DriverObject provided; used directly for IoCreateDevice.
 *   KDMapper path — DriverObject is NULL; we borrow \Driver\Null's DriverObject via
 *     ObReferenceObjectByName.  null.sys is always loaded and its IRP_MJ_DEVICE_CONTROL
 *     is a trivial stub; \Device\Null behaviour is preserved via pass-through in
 *     DispatchIoctl (DeviceObject != g_pDevice check).  DriverUnload is not called
 *     on the KDMapper path — hooks and the device persist until reboot.
 *
 * Load order: driver must be loaded BEFORE BattlEye — BEDaisy callbacks not yet
 *   registered at our load time so load-image notification is not triggered.
 */

// Release-build logging: LOG() compiles away entirely in non-DBG builds,
// leaving no debug strings or DbgPrint calls in the shipped image.
#if DBG
#define LOG(fmt, ...) DbgPrint(fmt, ##__VA_ARGS__)
#else
#define LOG(fmt, ...) ((void)0)
#endif

// ============================================================
// Kernel structures
// ============================================================

typedef struct _MI_UNLOADED_DRIVER {
    UNICODE_STRING Name;
    PVOID          StartAddress;
    PVOID          EndAddress;
    LARGE_INTEGER  CurrentTime;
} MI_UNLOADED_DRIVER, *PMI_UNLOADED_DRIVER;

// PiDDBCacheTable entry layout (Windows 10 20H1 – Windows 11 23H2).
// The _pad field covers internal ERESOURCE / pool header bytes between LoadStatus
// and the next LIST_ENTRY. If lookup fails silently, verify this layout in WinDbg:
//   dt nt!_PIDDBCACHE_ENTRY
typedef struct _PIDDBCACHE_ENTRY {
    LIST_ENTRY     List;
    UNICODE_STRING DriverName;
    ULONG          TimeDateStamp;
    NTSTATUS       LoadStatus;
    CHAR           _pad[16];
} PIDDBCACHE_ENTRY;

// ============================================================
// Undocumented kernel exports
// ============================================================

extern "C" NTSTATUS NTAPI MmCopyVirtualMemory(
    PEPROCESS SourceProcess, PVOID SourceAddress,
    PEPROCESS TargetProcess, PVOID TargetAddress,
    SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);

extern "C" PVOID NTAPI PsGetProcessSectionBaseAddress(PEPROCESS Process);

// ============================================================
// Device globals
// ============================================================

static PDEVICE_OBJECT   g_pDevice      = nullptr;
// Saved MajorFunction[IRP_MJ_DEVICE_CONTROL] of the driver whose DriverObject we borrowed
// (null.sys on KDMapper path). Restored in DriverUnload / TeardownDevice.
static PDRIVER_DISPATCH g_origDevCtrl  = nullptr;
// The borrowed DriverObject itself — kept referenced until cleanup so we can restore it.
static PDRIVER_OBJECT   g_borrowedDrv  = nullptr;

// ============================================================
// RtlWalkFrameChain hook globals (APC stack-walk bypass — still works on 25H2)
// ============================================================

static void** g_pWalkChainPtr = nullptr;
static void*  g_origWalkChain = nullptr;

// ============================================================
// ntoskrnl base helpers
// ============================================================

// Walk DriverObject->DriverSection to find ntoskrnl base (sc.exe load path).
static PVOID GetNtKernelBase(PDRIVER_OBJECT DriverObject) {
    if (!DriverObject) return nullptr;
    PLDR_DATA_TABLE_ENTRY ldr = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
    if (!ldr) return nullptr;
    UNICODE_STRING ntName;
    RtlInitUnicodeString(&ntName, L"ntoskrnl.exe");
    PLIST_ENTRY head = &ldr->InLoadOrderLinks;
    ULONG guard = 0;
    for (PLIST_ENTRY cur = head->Flink;
         cur && cur != head && ++guard < 512;
         cur = cur->Flink) {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (entry->BaseDllName.Buffer &&
            RtlEqualUnicodeString(&entry->BaseDllName, &ntName, TRUE))
            return entry->DllBase;
    }
    return nullptr;
}

// Derive ntoskrnl base from a known export when DriverObject is NULL (KDMapper load).
// Walks backward in 4 KB steps from the export address looking for the MZ signature.
// Searches up to 0x1000 pages (16 MB) — ntoskrnl on Win11 can exceed 12 MB.
static PVOID GetNtKernelBaseAlt() {
    static const WCHAR* const kExports[] = {
        L"RtlWalkFrameChain",
        L"MmGetPhysicalAddress",
    };
    for (ULONG e = 0; e < ARRAYSIZE(kExports); e++) {
        UNICODE_STRING name;
        RtlInitUnicodeString(&name, kExports[e]);
        PUCHAR fn = (PUCHAR)MmGetSystemRoutineAddress(&name);
        if (!fn) continue;
        PUCHAR page = (PUCHAR)((ULONG_PTR)fn & ~0xFFFULL);
        for (ULONG i = 0; i < 0x1000; i++, page -= 0x1000) {
            if (MmIsAddressValid(page) && *(USHORT*)page == IMAGE_DOS_SIGNATURE)
                return page;
        }
    }
    return nullptr;
}

// ============================================================
// PE helpers / pattern scanner
// ============================================================

static BOOLEAN GetImageSection(PVOID imageBase, const char* name,
                                PUCHAR* outBase, PSIZE_T outSize) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)imageBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PUCHAR)imageBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (strncmp((char*)sec->Name, name, IMAGE_SIZEOF_SHORT_NAME) == 0) {
            *outBase = (PUCHAR)imageBase + sec->VirtualAddress;
            *outSize = (SIZE_T)sec->Misc.VirtualSize;
            return TRUE;
        }
    }
    return FALSE;
}

// Guards against false pattern matches computing garbage RIP-relative addresses.
static BOOLEAN IsKernelPointer(PVOID addr) {
    return (ULONG_PTR)addr >= 0xFFFF800000000000ULL && MmIsAddressValid(addr);
}

// Scan [base, base+size) for a byte pattern. 0xFF bytes are wildcards.
static PUCHAR PatternScan(PUCHAR base, SIZE_T size, const UCHAR* pat, SIZE_T patLen) {
    if (size < patLen) return nullptr;
    for (SIZE_T i = 0; i <= size - patLen; i++) {
        BOOLEAN ok = TRUE;
        for (SIZE_T j = 0; j < patLen; j++) {
            if (pat[j] != 0xFF && base[i + j] != pat[j]) { ok = FALSE; break; }
        }
        if (ok) return base + i;
    }
    return nullptr;
}

// ============================================================
// Trace-clearing helpers (used when loaded via sc.exe)
// ============================================================

static VOID ClearPiDDBCacheTable(PDRIVER_OBJECT DriverObject, PVOID ntBase) {
    PLDR_DATA_TABLE_ENTRY ldr = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
    if (!ldr || !ldr->DllBase) return;
    PIMAGE_NT_HEADERS ntHdr = RtlImageNtHeader(ldr->DllBase);
    if (!ntHdr) return;
    ULONG ts = ntHdr->FileHeader.TimeDateStamp;

    static const UCHAR pat[] = {
        0x48, 0x8B, 0x0D, 0xFF, 0xFF, 0xFF, 0xFF,
        0xE8, 0xFF, 0xFF, 0xFF, 0xFF,
        0x4C, 0x8B, 0xCB,
        0x48, 0x8D, 0x15, 0xFF, 0xFF, 0xFF, 0xFF
    };

    PUCHAR textBase; SIZE_T textSize;
    if (!GetImageSection(ntBase, ".text", &textBase, &textSize)) {
        LOG("[!] ClearPiDDBCacheTable: .text not found\n");
        return;
    }

    PUCHAR match = PatternScan(textBase, textSize, pat, sizeof(pat));
    if (!match) {
        LOG("[!] ClearPiDDBCacheTable: pattern not found — update for this build\n");
        return;
    }

    PVOID*         pLockSlot = (PVOID*)(match +  7 + *(LONG*)(match +  3));
    PRTL_AVL_TABLE pTable    = (PRTL_AVL_TABLE)(match + 22 + *(LONG*)(match + 18));

    if (!IsKernelPointer(pLockSlot) || !IsKernelPointer(pTable)) {
        LOG("[!] ClearPiDDBCacheTable: computed addresses invalid — pattern mismatch for this build\n");
        return;
    }
    PERESOURCE pLock = *(PERESOURCE*)pLockSlot;
    if (!IsKernelPointer(pLock)) {
        LOG("[!] ClearPiDDBCacheTable: PiDDBLock value invalid\n");
        return;
    }

    ExAcquireResourceExclusiveLite(pLock, TRUE);
    PIDDBCACHE_ENTRY search = {};
    search.TimeDateStamp = ts;
    PVOID found = RtlLookupElementGenericTableAvl(pTable, &search);
    if (found) {
        RtlDeleteElementGenericTableAvl(pTable, found);
        LOG("[+] ClearPiDDBCacheTable: removed ts=0x%08X\n", ts);
    } else {
        LOG("[!] ClearPiDDBCacheTable: no entry for ts=0x%08X\n", ts);
    }
    ExReleaseResourceLite(pLock);
}

static VOID ClearMmUnloadedDrivers(PDRIVER_OBJECT DriverObject, PVOID ntBase) {
    static const UCHAR pat[] = { 0x4C, 0x8B, 0x15, 0xFF, 0xFF, 0xFF, 0xFF };

    PUCHAR textBase; SIZE_T textSize;
    if (!GetImageSection(ntBase, ".text", &textBase, &textSize)) return;

    PUCHAR match = PatternScan(textBase, textSize, pat, sizeof(pat));
    if (!match) {
        LOG("[!] ClearMmUnloadedDrivers: pattern not found\n");
        return;
    }

    PVOID* arrSlot = (PVOID*)(match + 7 + *(LONG*)(match + 3));
    if (!IsKernelPointer(arrSlot)) {
        LOG("[!] ClearMmUnloadedDrivers: computed slot address invalid — pattern mismatch\n");
        return;
    }
    PMI_UNLOADED_DRIVER arr = *(PMI_UNLOADED_DRIVER*)arrSlot;
    if (!arr || !IsKernelPointer(arr)) return;

    PLDR_DATA_TABLE_ENTRY ldr = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
    for (ULONG i = 0; i < 50; i++) {
        if (arr[i].Name.Buffer &&
            RtlEqualUnicodeString(&arr[i].Name, &ldr->BaseDllName, TRUE)) {
            RtlZeroMemory(&arr[i], sizeof(MI_UNLOADED_DRIVER));
            LOG("[+] ClearMmUnloadedDrivers: zeroed slot %u\n", i);
        }
    }
}

static VOID ZeroOwnTimestamp(PDRIVER_OBJECT DriverObject) {
    if (!DriverObject) return;
    PLDR_DATA_TABLE_ENTRY ldr = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
    if (!ldr || !ldr->DllBase) return;
    PIMAGE_NT_HEADERS nt = RtlImageNtHeader(ldr->DllBase);
    if (nt) nt->FileHeader.TimeDateStamp = 0;
}

// ============================================================
// Memory access helpers
// ============================================================

static NTSTATUS KernelRead(PEPROCESS Process, PVOID src, PVOID dst, SIZE_T size) {
    SIZE_T bytes = 0;
    __try {
        return MmCopyVirtualMemory(Process, src, PsGetCurrentProcess(), dst,
                                   size, UserMode, &bytes);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return GetExceptionCode(); }
}

static NTSTATUS KernelWrite(PEPROCESS Process, PVOID src, PVOID dst, SIZE_T size) {
    SIZE_T bytes = 0;
    __try {
        return MmCopyVirtualMemory(PsGetCurrentProcess(), src, Process, dst,
                                   size, UserMode, &bytes);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return GetExceptionCode(); }
}

// ============================================================
// Module base lookup — walks target process PEB InMemoryOrderModuleList
// ============================================================

static UINT64 FindModuleBase(PEPROCESS process, const CHAR* name) {
    PVOID pebRaw = PsGetProcessPeb(process);
    if (!pebRaw) return 0;

    KAPC_STATE apcState;
    KeStackAttachProcess(process, &apcState);

    UINT64 result = 0;
    __try {
        UINT64 peb  = (UINT64)pebRaw;
        UINT64 ldr  = *(UINT64*)(peb + 0x18);
        if (!ldr) __leave;

        UINT64 listHead = ldr + 0x20;
        UINT64 flink    = *(UINT64*)listHead;

        for (INT guard = 0; guard < 512 && flink && flink != listHead; guard++) {
            UINT64 entry   = flink - 0x10;
            UINT64 dllBase = *(UINT64*)(entry + 0x30);
            USHORT nameLen = *(USHORT*)(entry + 0x58);
            UINT64 nameBuf = *(UINT64*)(entry + 0x60);

            if (nameBuf && nameLen >= 2 && nameLen <= 512) {
                WCHAR wide[256] = {};
                ULONG copyLen = min((ULONG)nameLen, (ULONG)(sizeof(wide) - sizeof(WCHAR)));
                RtlCopyMemory(wide, (PVOID)nameBuf, copyLen);

                BOOLEAN match = TRUE;
                ULONG wlen = copyLen / sizeof(WCHAR);
                ULONG nlen = (ULONG)strlen(name);
                if (wlen != nlen) {
                    match = FALSE;
                } else {
                    for (ULONG j = 0; j < wlen && match; j++) {
                        WCHAR wc = wide[j];
                        CHAR  nc = name[j];
                        if (wc >= L'A' && wc <= L'Z') wc += 32;
                        if (nc >= 'A'  && nc <= 'Z')  nc += 32;
                        if (wc != (WCHAR)(UCHAR)nc) match = FALSE;
                    }
                }
                if (match) { result = dllBase; __leave; }
            }

            flink = *(UINT64*)flink;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { result = 0; }

    KeUnstackDetachProcess(&apcState);
    return result;
}

// ============================================================
// Comm packet processor — called from IRP dispatch at PASSIVE_LEVEL.
// Packet is in a METHOD_BUFFERED kernel buffer; no ProbeForRead/Write needed.
// ============================================================

static VOID ProcessCommPacket(COMM_PACKET* pkt) {
    PEPROCESS proc = nullptr;

    switch (pkt->Operation) {

    case COMM_OP_READ:
        if (pkt->Size == 0 || pkt->Size > COMM_MAX_SIZE) {
            pkt->Status = STATUS_INVALID_PARAMETER;
            break;
        }
        pkt->Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pkt->ProcessId, &proc);
        if (NT_SUCCESS(pkt->Status)) {
            pkt->Status = KernelRead(proc, (PVOID)pkt->AddressSrc,
                                     (PVOID)pkt->AddressDst, pkt->Size);
            ObDereferenceObject(proc);
        }
        break;

    case COMM_OP_WRITE:
        if (pkt->Size == 0 || pkt->Size > COMM_MAX_SIZE) {
            pkt->Status = STATUS_INVALID_PARAMETER;
            break;
        }
        pkt->Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pkt->ProcessId, &proc);
        if (NT_SUCCESS(pkt->Status)) {
            pkt->Status = KernelWrite(proc, (PVOID)pkt->AddressSrc,
                                      (PVOID)pkt->AddressDst, pkt->Size);
            ObDereferenceObject(proc);
        }
        break;

    case COMM_OP_GET_BASE:
        pkt->Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pkt->ProcessId, &proc);
        if (NT_SUCCESS(pkt->Status)) {
            pkt->AddressDst = (ULONGLONG)PsGetProcessSectionBaseAddress(proc);
            ObDereferenceObject(proc);
            pkt->Status = pkt->AddressDst ? STATUS_SUCCESS : STATUS_NOT_FOUND;
        }
        break;

    case COMM_OP_GET_MODULE:
        pkt->ModuleName[sizeof(pkt->ModuleName) - 1] = '\0';
        pkt->Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pkt->ProcessId, &proc);
        if (NT_SUCCESS(pkt->Status)) {
            UINT64 base = FindModuleBase(proc, pkt->ModuleName);
            ObDereferenceObject(proc);
            if (base) {
                pkt->AddressDst = base;
                pkt->Status     = STATUS_SUCCESS;
            } else {
                pkt->Status = STATUS_NOT_FOUND;
            }
        }
        break;

    default:
        pkt->Status = STATUS_INVALID_PARAMETER;
        break;
    }
}

// ============================================================
// IRP dispatch routines
// ============================================================

static NTSTATUS DispatchCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS DispatchClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS DispatchIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    // When we borrowed null.sys's DriverObject, its other devices (\\Device\\Null)
    // will also route IRP_MJ_DEVICE_CONTROL here. Pass those through to the original
    // handler so null.sys behaviour is unchanged.
    if (DeviceObject != g_pDevice) {
        if (g_origDevCtrl)
            return g_origDevCtrl(DeviceObject, Irp);
        Irp->IoStatus.Status      = STATUS_NOT_SUPPORTED;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_NOT_SUPPORTED;
    }

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS   status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR  info   = 0;

    if (stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_COMM) {
        ULONG inLen  = stack->Parameters.DeviceIoControl.InputBufferLength;
        ULONG outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;

        if (inLen < sizeof(COMM_PACKET) || outLen < sizeof(COMM_PACKET)) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            COMM_PACKET* pkt = (COMM_PACKET*)Irp->AssociatedIrp.SystemBuffer;
            ProcessCommPacket(pkt);
            info   = sizeof(COMM_PACKET);
            status = STATUS_SUCCESS;
        }
    }

    Irp->IoStatus.Status      = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// ============================================================
// Hook — RtlWalkFrameChain (.data, APC stack-walk bypass)
//
// BE's kernel APC calls RtlWalkFrameChain to collect thread call stacks.
// Replacing the .data function pointer with FakeWalkFrameChain returns 0
// frames, preventing BE from seeing any frame that falls outside a loaded
// module. The .data section is writable on all builds including 25H2 —
// HVCI only protects code pages and specifically-designated tables.
// ============================================================

static ULONG FakeWalkFrameChain(PVOID* Callers, ULONG Count, ULONG Flags) {
    UNREFERENCED_PARAMETER(Callers);
    UNREFERENCED_PARAMETER(Count);
    UNREFERENCED_PARAMETER(Flags);
    return 0;
}

// Scan writable ntoskrnl sections for a PVOID equal to the exported
// RtlWalkFrameChain address. Only .data and PAGEDATA are searched — .rdata
// is read-only and InterlockedExchangePointer into it causes a write fault (BSOD).
static void** FindRtlWalkFrameChainPtr(PVOID ntBase) {
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"RtlWalkFrameChain");
    PVOID target = MmGetSystemRoutineAddress(&name);
    if (!target) {
        LOG("[!] FindRtlWalkFrameChainPtr: RtlWalkFrameChain not exported\n");
        return nullptr;
    }

    static const char* const kSections[] = { ".data", "PAGEDATA" };
    for (ULONG s = 0; s < ARRAYSIZE(kSections); s++) {
        PUCHAR base; SIZE_T size;
        if (!GetImageSection(ntBase, kSections[s], &base, &size)) continue;
        for (SIZE_T i = 0; i + sizeof(PVOID) <= size; i += sizeof(PVOID)) {
            if (*(PVOID*)(base + i) == target)
                return (void**)(base + i);
        }
    }

    LOG("[!] FindRtlWalkFrameChainPtr: pointer not found in .data/PAGEDATA\n");
    return nullptr;
}

static VOID InstallWalkChainHook(PVOID ntBase) {
    g_pWalkChainPtr = FindRtlWalkFrameChainPtr(ntBase);
    if (!g_pWalkChainPtr) return;
    g_origWalkChain = InterlockedExchangePointer(g_pWalkChainPtr, (void*)FakeWalkFrameChain);
    LOG("[+] WalkChainHook installed: pPtr=%p orig=%p\n", g_pWalkChainPtr, g_origWalkChain);
}

static VOID RemoveWalkChainHook() {
    if (g_pWalkChainPtr && g_origWalkChain)
        InterlockedExchangePointer(g_pWalkChainPtr, g_origWalkChain);
}

// ============================================================
// Driver entry / unload
// ============================================================

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    RemoveWalkChainHook();

    // Restore borrowed null.sys handler before deleting the device so no IRP
    // can arrive after g_pDevice is gone but before the handler is swapped back.
    if (g_borrowedDrv) {
        g_borrowedDrv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = g_origDevCtrl;
        ObDereferenceObject(g_borrowedDrv);
        g_borrowedDrv = nullptr;
    }

    UNICODE_STRING lnkName = RTL_CONSTANT_STRING(COMM_SYMLINK_NAME);
    IoDeleteSymbolicLink(&lnkName);
    if (g_pDevice) {
        IoDeleteDevice(g_pDevice);
        g_pDevice = nullptr;
    }

    PVOID ntBase = GetNtKernelBase(DriverObject);
    if (ntBase && DriverObject) ClearMmUnloadedDrivers(DriverObject, ntBase);
}

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
                                 _In_ PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    PVOID ntBase = DriverObject ? GetNtKernelBase(DriverObject) : GetNtKernelBaseAlt();

    if (DriverObject) {
        DriverObject->DriverUnload = DriverUnload;

        if (ntBase) {
            ClearPiDDBCacheTable(DriverObject, ntBase);
            ClearMmUnloadedDrivers(DriverObject, ntBase);
        } else {
            LOG("[!] DriverEntry: ntoskrnl base not found — traces not cleared\n");
        }

        ZeroOwnTimestamp(DriverObject);
    }

    // Install APC stack-walk bypass — works regardless of DriverObject.
    if (ntBase) {
        InstallWalkChainHook(ntBase);
    } else {
        LOG("[!] DriverEntry: ntBase unavailable — WalkChainHook not installed\n");
    }

    // Determine which DriverObject to use for device creation:
    //   sc.exe path  — DriverObject is valid; use it directly.
    //   KDMapper path — DriverObject is NULL; borrow \\Driver\\Null's DriverObject.
    //     null.sys is always loaded, its IRP_MJ_DEVICE_CONTROL is a trivial stub,
    //     and creating a device under it does not affect \\Device\\Null behaviour
    //     (our DispatchIoctl passes non-g_pDevice IRPs back to the original handler).
    PDRIVER_OBJECT pDevOwner = DriverObject;

    if (!pDevOwner) {
        UNICODE_STRING nullDrvName = RTL_CONSTANT_STRING(L"\\Driver\\Null");
        NTSTATUS borrowStatus = ObReferenceObjectByName(
            &nullDrvName, OBJ_CASE_INSENSITIVE, nullptr, 0,
            *IoDriverObjectType, KernelMode, nullptr, (PVOID*)&pDevOwner);
        if (!NT_SUCCESS(borrowStatus) || !pDevOwner) {
            LOG("[!] DriverEntry: failed to borrow \\Driver\\Null DriverObject (0x%08X) — comm unavailable\n",
                borrowStatus);
            return STATUS_SUCCESS;  // walk-chain hook is still active
        }
        g_borrowedDrv = pDevOwner;  // kept referenced until TeardownDevice restores it
    }

    pDevOwner->MajorFunction[IRP_MJ_CREATE]  = DispatchCreate;
    pDevOwner->MajorFunction[IRP_MJ_CLOSE]   = DispatchClose;
    g_origDevCtrl = pDevOwner->MajorFunction[IRP_MJ_DEVICE_CONTROL];
    pDevOwner->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;

    UNICODE_STRING devName = RTL_CONSTANT_STRING(COMM_DEVICE_NAME);
    UNICODE_STRING lnkName = RTL_CONSTANT_STRING(COMM_SYMLINK_NAME);

    NTSTATUS status = IoCreateDevice(DriverObject, 0, &devName,
                                     FILE_DEVICE_UNKNOWN, 0, FALSE, &g_pDevice);
    if (!NT_SUCCESS(status)) {
        LOG("[!] DriverEntry: IoCreateDevice failed: 0x%08X\n", status);
        return status;
    }
    g_pDevice->Flags |= DO_BUFFERED_IO;
    g_pDevice->Flags &= ~DO_DEVICE_INITIALIZING;

    status = IoCreateSymbolicLink(&lnkName, &devName);
    if (!NT_SUCCESS(status)) {
        LOG("[!] DriverEntry: IoCreateSymbolicLink failed: 0x%08X\n", status);
        IoDeleteDevice(g_pDevice);
        g_pDevice = nullptr;
        return status;
    }

    LOG("[+] DriverEntry: comm device ready — %S\n", COMM_DEVICE_PATH);
    return STATUS_SUCCESS;
}
```
