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


```
#include <ntifs.h>
#include <ntimage.h>

NTKERNELAPI PCHAR PsGetProcessImageFileName(PEPROCESS Process);
extern POBJECT_TYPE *IoDriverObjectType;

NTKERNELAPI NTSTATUS ObReferenceObjectByName(
    PUNICODE_STRING ObjectName,
    ULONG           Attributes,
    PACCESS_STATE   AccessState,
    ACCESS_MASK     DesiredAccess,
    POBJECT_TYPE    ObjectType,
    KPROCESSOR_MODE AccessMode,
    PVOID           ParseContext,
    PVOID*          Object
);

typedef IMAGE_RUNTIME_FUNCTION_ENTRY RUNTIME_FUNCTION, *PRUNTIME_FUNCTION;

typedef NTSTATUS (NTAPI *pfnRtlAddGrowableFunctionTable)(
    PVOID*            DynamicTable,
    PRUNTIME_FUNCTION FunctionTable,
    ULONG             EntryCount,
    ULONG             MaximumEntryCount,
    ULONG_PTR         RangeBase,
    ULONG_PTR         RangeEnd
);
typedef VOID (NTAPI *pfnRtlDeleteGrowableFunctionTable)(PVOID DynamicTable);

static pfnRtlAddGrowableFunctionTable    g_RtlAddGrowableFunctionTable    = NULL;
static pfnRtlDeleteGrowableFunctionTable g_RtlDeleteGrowableFunctionTable = NULL;

#define DEVICE_NAME     L"\\Device\\WinDiagSvc"
#define SYMLINK_NAME    L"\\DosDevices\\WinDiagSvc"
#define POOL_TAG        'gDwS'

#define IOCTL_READ_MEMORY  CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA10, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA11, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_BASE     CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA12, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_PROCESS  CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA13, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_MODULE   CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA14, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MAX_USER_ADDRESS 0x7FFFFFFFEFFFULL

typedef struct _MEMORY_REQUEST {
    ULONG  ProcessId;
    ULONG  _pad;
    UINT64 Address;
    ULONG  Size;
    ULONG  _pad2;
    UCHAR  Buffer[4096];
} MEMORY_REQUEST, *PMEMORY_REQUEST;

typedef struct _BASE_REQUEST {
    ULONG  ProcessId;
    ULONG  _pad;
    UINT64 BaseAddress;
} BASE_REQUEST, *PBASE_REQUEST;

typedef struct _PROCESS_REQUEST {
    CHAR  Name[256];
    ULONG ProcessId;
    ULONG _pad;
} PROCESS_REQUEST, *PPROCESS_REQUEST;

typedef struct _MODULE_REQUEST {
    ULONG  ProcessId;
    ULONG  _pad;
    CHAR   Name[256];
    UINT64 BaseAddress;
} MODULE_REQUEST, *PMODULE_REQUEST;

NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(PEPROCESS Process);
NTKERNELAPI PVOID PsGetProcessPeb(PEPROCESS Process);
NTKERNELAPI NTSTATUS PsGetProcessExitStatus(PEPROCESS Process);

static BOOLEAN IsProcessAlive(PEPROCESS process) {
    return PsGetProcessExitStatus(process) == STATUS_PENDING;
}

static NTSTATUS ReadAttached(UINT64 address, PVOID dst, ULONG size) {
    if (address == 0 || address > MAX_USER_ADDRESS)
        return STATUS_ACCESS_VIOLATION;

    __try {
        ProbeForRead((PVOID)address, size, 1);
        RtlCopyMemory(dst, (PVOID)address, size);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    return STATUS_SUCCESS;
}

static BOOLEAN StrEqualI(const CHAR* a, const CHAR* b) {
    while (*a && *b) {
        CHAR ca = (CHAR)((*a >= 'A' && *a <= 'Z') ? (*a + 32) : *a);
        CHAR cb = (CHAR)((*b >= 'A' && *b <= 'Z') ? (*b + 32) : *b);
        if (ca != cb) return FALSE;
        a++; b++;
    }
    return (*a == '\0') && (*b == '\0');
}

static BOOLEAN WcsiEqual(const WCHAR* wide, const CHAR* narrow) {
    while (*wide && *narrow) {
        WCHAR w = (WCHAR)((*wide  >= L'A' && *wide  <= L'Z') ? (*wide  + 32) : *wide);
        CHAR  n = (CHAR)((*narrow >= 'A'  && *narrow <= 'Z')  ? (*narrow + 32) : *narrow);
        if (w != (WCHAR)(UCHAR)n) return FALSE;
        wide++;
        narrow++;
    }
    return (*wide == L'\0') && (*narrow == '\0');
}

static UINT64 FindModuleInPeb(PEPROCESS process, const CHAR* moduleName) {
    PVOID pebRaw = PsGetProcessPeb(process);
    if (!pebRaw) return 0;

    if (!IsProcessAlive(process))
        return 0;

    UINT64 peb = (UINT64)pebRaw;
    KAPC_STATE apcState;
    KeStackAttachProcess(process, &apcState);

    UINT64 result = 0;

    __try {
        UINT64 ldr = 0;
        if (!NT_SUCCESS(ReadAttached(peb + 0x18, &ldr, sizeof(ldr))) || !ldr)
            __leave;

        UINT64 listHead = ldr + 0x20;
        UINT64 flink    = 0;
        if (!NT_SUCCESS(ReadAttached(listHead, &flink, sizeof(flink))) || !flink)
            __leave;

        for (int guard = 0; guard < 512 && flink && flink != listHead; guard++) {
            if (flink < 0x10000 || flink > MAX_USER_ADDRESS) break;

            UINT64 entry = flink - 0x10;

            UINT64 dllBase  = 0;
            USHORT nameLen  = 0;
            UINT64 nameBuf  = 0;

            ReadAttached(entry + 0x30, &dllBase,  sizeof(dllBase));
            ReadAttached(entry + 0x58, &nameLen,  sizeof(nameLen));
            ReadAttached(entry + 0x60, &nameBuf,  sizeof(nameBuf));

            if (nameBuf && nameBuf > 0x10000 && nameBuf <= MAX_USER_ADDRESS &&
                nameLen >= 2 && nameLen <= 512) {
                WCHAR wideName[256] = {0};
                USHORT maxNameLen = (USHORT)(sizeof(wideName) - sizeof(WCHAR));
                ULONG readLen = (nameLen < maxNameLen) ? (ULONG)nameLen : (ULONG)maxNameLen;
                if (NT_SUCCESS(ReadAttached(nameBuf, wideName, readLen))) {
                    wideName[readLen / sizeof(WCHAR)] = L'\0';
                    if (WcsiEqual(wideName, moduleName)) {
                        result = dllBase;
                        __leave;
                    }
                }
            }

            UINT64 next = 0;
            if (!NT_SUCCESS(ReadAttached(flink, &next, sizeof(next))))
                break;
            flink = next;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        result = 0;
    }

    KeUnstackDetachProcess(&apcState);
    return result;
}

static PDEVICE_OBJECT g_DeviceObject  = NULL;
static BOOLEAN        g_KdMapped      = FALSE;
static PVOID          g_DynamicTable   = NULL;

static NTSTATUS DispatchCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS DispatchClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS DispatchIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG  ioctl  = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG  inLen  = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG  outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;
    NTSTATUS  status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR info   = 0;
    PEPROCESS process = NULL;

    switch (ioctl) {

    case IOCTL_GET_BASE: {
        if (inLen < sizeof(BASE_REQUEST) || outLen < sizeof(BASE_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL; break;
        }
        PBASE_REQUEST breq = (PBASE_REQUEST)Irp->AssociatedIrp.SystemBuffer;
        if (breq->ProcessId == 0) {
            status = STATUS_INVALID_PARAMETER; break;
        }
        status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)breq->ProcessId, &process);
        if (!NT_SUCCESS(status)) break;

        __try {
            breq->BaseAddress = (UINT64)PsGetProcessSectionBaseAddress(process);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            breq->BaseAddress = 0;
            status = GetExceptionCode();
        }

        ObDereferenceObject(process);
        if (NT_SUCCESS(status)) {
            info   = sizeof(BASE_REQUEST);
            status = STATUS_SUCCESS;
        }
        break;
    }

    case IOCTL_GET_PROCESS: {
        if (inLen < sizeof(PROCESS_REQUEST) || outLen < sizeof(PROCESS_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL; break;
        }
        PPROCESS_REQUEST preq = (PPROCESS_REQUEST)Irp->AssociatedIrp.SystemBuffer;
        preq->Name[sizeof(preq->Name) - 1] = '\0';

        if (preq->Name[0] == '\0') {
            status = STATUS_INVALID_PARAMETER; break;
        }

        preq->ProcessId = 0;

        for (ULONG id = 4; id < 0x40000; id += 4) {
            PEPROCESS p = NULL;
            if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)id, &p)))
                continue;
            if (IsProcessAlive(p)) {
                PCHAR imgName = PsGetProcessImageFileName(p);
                if (imgName && StrEqualI(imgName, preq->Name))
                    preq->ProcessId = id;
            }
            ObDereferenceObject(p);
            if (preq->ProcessId) break;
        }

        status = preq->ProcessId ? STATUS_SUCCESS : STATUS_NOT_FOUND;
        if (NT_SUCCESS(status)) info = sizeof(PROCESS_REQUEST);
        break;
    }

    case IOCTL_GET_MODULE: {
        if (inLen < sizeof(MODULE_REQUEST) || outLen < sizeof(MODULE_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL; break;
        }
        PMODULE_REQUEST mreq = (PMODULE_REQUEST)Irp->AssociatedIrp.SystemBuffer;
        mreq->Name[sizeof(mreq->Name) - 1] = '\0';

        if (mreq->ProcessId == 0 || mreq->Name[0] == '\0') {
            status = STATUS_INVALID_PARAMETER; break;
        }

        mreq->BaseAddress = 0;

        status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)mreq->ProcessId, &process);
        if (!NT_SUCCESS(status)) break;

        mreq->BaseAddress = FindModuleInPeb(process, mreq->Name);
        ObDereferenceObject(process);

        status = mreq->BaseAddress ? STATUS_SUCCESS : STATUS_NOT_FOUND;
        if (NT_SUCCESS(status)) info = sizeof(MODULE_REQUEST);
        break;
    }

    case IOCTL_READ_MEMORY:
    case IOCTL_WRITE_MEMORY: {
        if (inLen < sizeof(MEMORY_REQUEST) || outLen < sizeof(MEMORY_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL; break;
        }
        PMEMORY_REQUEST req = (PMEMORY_REQUEST)Irp->AssociatedIrp.SystemBuffer;

        if (req->Size == 0 || req->Size > sizeof(req->Buffer)) {
            status = STATUS_INVALID_PARAMETER; break;
        }
        if (req->ProcessId == 0) {
            status = STATUS_INVALID_PARAMETER; break;
        }
        if (req->Address == 0 || req->Address > MAX_USER_ADDRESS) {
            status = STATUS_ACCESS_VIOLATION; break;
        }
        if (req->Address + req->Size < req->Address) {
            status = STATUS_ACCESS_VIOLATION; break;
        }
        if (req->Address + req->Size - 1 > MAX_USER_ADDRESS) {
            status = STATUS_ACCESS_VIOLATION; break;
        }

        status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req->ProcessId, &process);
        if (!NT_SUCCESS(status)) break;

        if (!IsProcessAlive(process)) {
            ObDereferenceObject(process);
            status = STATUS_PROCESS_IS_TERMINATING;
            break;
        }

        {
            KAPC_STATE apcState;
            KeStackAttachProcess(process, &apcState);

            __try {
                if (ioctl == IOCTL_READ_MEMORY) {
                    ProbeForRead((PVOID)req->Address, req->Size, 1);
                    RtlCopyMemory(req->Buffer, (PVOID)req->Address, req->Size);
                } else {
                    ProbeForWrite((PVOID)req->Address, req->Size, 1);
                    RtlCopyMemory((PVOID)req->Address, req->Buffer, req->Size);
                }
                status = STATUS_SUCCESS;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                status = GetExceptionCode();
            }

            KeUnstackDetachProcess(&apcState);
        }

        ObDereferenceObject(process);
        if (NT_SUCCESS(status)) info = sizeof(MEMORY_REQUEST);
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status      = status;
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
    if (g_DeviceObject) IoDeleteDevice(g_DeviceObject);
    if (g_DynamicTable && g_RtlDeleteGrowableFunctionTable)
        g_RtlDeleteGrowableFunctionTable(g_DynamicTable);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);

static UINT64 FindImageBase(void) {
    UINT64 addr = ((UINT64)(ULONG_PTR)DriverEntry) & ~(UINT64)0xFFF;
    for (int i = 0; i < 1024; i++, addr -= 0x1000) {
        if (!MmIsAddressValid((PVOID)addr))
            break;
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)addr;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;
        LONG e_lfanew = dos->e_lfanew;
        if (e_lfanew <= 0 || e_lfanew >= 0x10000) continue;
        if (!MmIsAddressValid((PVOID)(addr + (ULONG)e_lfanew))) continue;
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(addr + (ULONG)e_lfanew);
        if (nt->Signature == IMAGE_NT_SIGNATURE)
            return addr;
    }
    return 0;
}

static VOID RegisterExceptionTable(void) {
    UNICODE_STRING addName, delName;
    RtlInitUnicodeString(&addName, L"RtlAddGrowableFunctionTable");
    RtlInitUnicodeString(&delName, L"RtlDeleteGrowableFunctionTable");
    g_RtlAddGrowableFunctionTable    = (pfnRtlAddGrowableFunctionTable)MmGetSystemRoutineAddress(&addName);
    g_RtlDeleteGrowableFunctionTable = (pfnRtlDeleteGrowableFunctionTable)MmGetSystemRoutineAddress(&delName);
    if (!g_RtlAddGrowableFunctionTable) return;

    UINT64 base = FindImageBase();
    if (!base) return;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(base + (ULONG)dos->e_lfanew);
    ULONG imageSize = nt->OptionalHeader.SizeOfImage;

    IMAGE_DATA_DIRECTORY excDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (excDir.VirtualAddress == 0 || excDir.Size == 0)
        return;

    PRUNTIME_FUNCTION funcTable = (PRUNTIME_FUNCTION)(base + excDir.VirtualAddress);
    ULONG entryCount = excDir.Size / sizeof(RUNTIME_FUNCTION);

    g_RtlAddGrowableFunctionTable(
        &g_DynamicTable,
        funcTable,
        entryCount,
        entryCount,
        base,
        base + imageSize
    );
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    if (!DriverObject) {
        // Register .pdata via RtlAddGrowableFunctionTable so the kernel
        // exception dispatcher finds our unwind info. This is what
        // KeInvertedFunctionTable uses on 25H2 — the PsLoadedModuleList
        // trick no longer covers the fast path.
        RegisterExceptionTable();

        // Loaded via kdmapper — borrow \Driver\Null as a real kernel object
        // so IoCreateDevice's internal ObReferenceObject call works correctly.
        UNICODE_STRING nullDrv;
        RtlInitUnicodeString(&nullDrv, L"\\Driver\\Null");
        NTSTATUS st = ObReferenceObjectByName(
            &nullDrv, OBJ_CASE_INSENSITIVE, NULL, 0,
            *IoDriverObjectType, KernelMode, NULL, (PVOID*)&DriverObject);
        if (!NT_SUCCESS(st)) return st;
        g_KdMapped = TRUE;
    }

    UNICODE_STRING devName, symName;
    RtlInitUnicodeString(&devName, DEVICE_NAME);
    RtlInitUnicodeString(&symName, SYMLINK_NAME);

    NTSTATUS status = IoCreateDevice(DriverObject, 0, &devName,
        FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &g_DeviceObject);
    if (!NT_SUCCESS(status)) {
        if (g_KdMapped) ObDereferenceObject(DriverObject);
        return status;
    }

    status = IoCreateSymbolicLink(&symName, &devName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_DeviceObject);
        if (g_KdMapped) ObDereferenceObject(DriverObject);
        return status;
    }

    // Release our borrow — IoCreateDevice holds its own internal reference
    // to the driver object, so it stays alive for the device's lifetime.
    if (g_KdMapped) ObDereferenceObject(DriverObject);

    if (!g_KdMapped)
        DriverObject->DriverUnload = DriverUnload;

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = DispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DispatchClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;

    g_DeviceObject->Flags |= DO_BUFFERED_IO;
    g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    return STATUS_SUCCESS;
}
