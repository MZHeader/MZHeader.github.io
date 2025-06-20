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










