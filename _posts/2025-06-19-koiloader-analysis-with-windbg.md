---
tags: CTF
---
## Analysing a KoiLoader / KoiStealer sample with WinDbg

The main focus of this post is to use WinDbg for binary analysis. I have skipped over the first few steps of the execution chain which are JavaScript, PowerShell & Shellcode loaders, which result in the execution of the following binary:

File Name: ciconinejvR.exe
SHA 256: 74b85c502651bae1734849f3ac49d8152a6c0fbb9234083b1384d8cbe3640068

## Initial static analysis with Ghidra

Dropping the executable into a disassembler like Ghidra allows us to review any interesting strings or imports to begin our analysis.
Imports from KERNEL32.dll are noted such as VirtualAlloc and VirtualProtect, which indicate that the binary is going to allocate a space in memory, write to it, and change the permissions preparing for execution.

<img width="350" alt="image" src="https://github.com/user-attachments/assets/c8ae14b9-9581-4e99-9c26-c83e821c9699" />

These imports can be found in Ghidra by viewing the Symbol Tree, an option for which is present on the toolbar at the top of the program. We can then highlight and double click an import to see where it is referenced in the executable.

<img width="1600" alt="image" src="https://github.com/user-attachments/assets/19de60ff-7680-4317-bd0d-fde71fd68654" />

When we navigate to our import of interest, in this case VirtualAlloc, we can review the cross references (XREF) to see how many times VirtualAlloc is called, and in what functions.

<img width="1250" alt="image" src="https://github.com/user-attachments/assets/ddac117e-4ba5-4b0a-a2e2-2056cf298c3b" />

It appears that VirtualAlloc is only present in one function - FUN_00401300. We can click this value to navigate to this function and review it in the decompile window on the left.
We can see on line 37 that VirtualAlloc is called with multiple arguments, and the result of which is stored as _Dst.

<img width="800" alt="image" src="https://github.com/user-attachments/assets/ea55e824-6d2c-4864-98f9-9a53254b6f92" />

We can gather context on what these arguments may be by reviewing Microsoft Documentation for VirtualAlloc

On line 78 we can see that VirtualProtect is being called with _Dst being passed to it as the first argument.

<img width="900" alt="image" src="https://github.com/user-attachments/assets/d2c5c39a-57f0-46b8-b689-2e6fb9d4e341" />

VirtualProtect changes the protection on a region of committed pages in the virtual address space. The first argument that gets passed to it is the address of the starting page of the region of pages whose access protection attributes are to be changed.
_Dst is our area of interest, as it appears very likely that some form of executable code has been written to this address space.
We'll now move over to a debugger to attempt to locate and interrogate this area of memory.

## Debugging ciconinejvR.exe with WinDbg

After loading the executable with WinDbg we use the command "bp $exentry" to set a breakpoint at the entrypoint and "g" to go there.
Now we're going to set a breakpoint at VirtualProtect by using the command "bp VirtualProtect" and "g" to go there.

<img width="900" alt="image" src="https://github.com/user-attachments/assets/61bf8bbc-7ba9-4d41-a678-c68aaddc7c0b" />

We're now at the VirtualProtect API call.
We can review the first argument being passed to VirtualProtect (lpAddress) by querying the EAX register.

<img width="900" alt="image" src="https://github.com/user-attachments/assets/c06de256-60e7-48f9-9f69-0ea70a70f6a2" />

In my case, EAX is pointing to 03030000. We navigate to this address in memory by using the Memory view. 

<img width="900" alt="image" src="https://github.com/user-attachments/assets/1abed962-4baa-4e1e-a732-2073e5aab48c" />

The screenshot above shows the portable executable (PE) file format present at that address in memory. This indicates that a second-stage binary has been unpacked and is going to be executed by our initial binary.
We can dump this memory by using the .writemem command, which requires the arguments FilePath, Base Address, End Address. In my case this is going to be ".writemem C:\Users\User\Desktop\dump.dmp 03030000 0303D000".

## Investigating our new unpacked binary with IDA

Moving on to the binary we've just unpacked (HASH: d950f0e4a597416aa8f4cb0682d29707cc8958b2972ab307b9f34316e806ec4d)
As this binary was pulled from memory, we need to use a tool like pe_unmapper to realign the PE from virtual to raw addresses.

<img width="900" alt="image" src="https://github.com/user-attachments/assets/7562d70e-5977-43ed-8408-ff50e28930da" />

Now I'll load the binary into IDA, look at some interesting strings and take it from there.
Strings can be viewed in IDA by navigating to View > Open subviews > Strings

<img width="900" alt="image" src="https://github.com/user-attachments/assets/ebe3460f-c607-4082-925a-d8f654a48c94" />

The string that caught my eye here was "Jennifer Lopez & Pitbull - On The Floor\r\nBeyonce - Halo"

<img width="900" alt="image" src="https://github.com/user-attachments/assets/7df464a5-1661-44fe-ab59-bb93135b7a3e" />

Similar to Ghidra, we can double click this value and follow the XREF function to see where this string appears in a function. 
Reviewing the rest of this function it appears that values taken from the host are being compared to strings, and if a value is a match, the program will exit. (This function exists at raw address 0x408A00)
This whole function is an anti-analysis / anti-VM/Sandbox check. The program is going to compare known values to be associated with a VM / Sandbox to the values on this host by enumerating it, and if the values match, the program is going to jump to a location that terminates the program.

Towards the top of the function we can see the following instructions: (0x00408A12)

<img width="900" alt="image" src="https://github.com/user-attachments/assets/9c53f4df-c6f4-48fc-a68b-372f41341ea5" />

## Breaking it down: anti-analysis checks

Initially we can see that EnumDisplayDevicesW is called, this is a Windows API that is going to enumerate display devices on the host.

```
mov     [ebp+DisplayDevice.cb], 348h
push    esi             ; dwFlags
push    eax             ; lpDisplayDevice
push    esi             ; iDevNum
push    esi             ; lpDevice
call    edi ; EnumDisplayDevicesW
```

The code then pushes the string "Hypver-V" and the device string "DisplayDevice.DeviceString" onto the stack:
```
push    offset aHyperV  ; "Hyper-V"
lea     eax, [ebp+DisplayDevice.DeviceString]
StrStrIW is then called, which is a function that is going to search for / compare the two strings:
call    ebx ; StrStrIW
```

The result of this function is stored in the EAX register.
If StrStrIW finds the substring "Hyper-V", EAX will hold a non-zero pointer to the location of the substring.
If StrStrIW does not find the substring, EAX will be 0.


Next, the code performs a bitwise AND operation between EAX and itself.
```
test    eax, eax
```
If EAX is non-zero (if the substring was found) then the Zero Flag (ZF) will be cleared (ZF=0).
If EAX is zero (if the substring was not found) then the Zero Flag will be set (ZF=1).


Next, the zero flag is checked. If ZF=0 (Hyper-V was found) then the program will jump to 0x408B55, otherwise, the jnz instruction will not jump and the program will continue to execute the next instruction.
```
jnz     loc_408B55
```















