---
tags: CTF
---
## Analysing a KoiLoader / KoiStealer sample with WinDbg

The main focus of this post is to use WinDbg for binary analysis. I have skipped over the first few steps of the execution chain which are JavaScript, PowerShell & Shellcode loaders, which result in the execution of the following binary:

File Name: ciconinejvR.exe
SHA 256: 74b85c502651bae1734849f3ac49d8152a6c0fbb9234083b1384d8cbe3640068

Dropping the executable into a disassembler like Ghidra allows us to review any interesting strings or imports to begin our analysis.
Imports from KERNEL32.dll are noted such as VirtualAlloc and VirtualProtect, which indicate that the binary is going to allocate a space in memory, write to it, and change the permissions preparing for execution.

<img width="350" alt="image" src="https://github.com/user-attachments/assets/c8ae14b9-9581-4e99-9c26-c83e821c9699" />

These imports can be found in Ghidra by viewing the Symbol Tree, an option for which is present on the toolbar at the top of the program. We can then highlight and double click an import to see where it is referenced in the executable.

<img width="1400" alt="image" src="https://github.com/user-attachments/assets/19de60ff-7680-4317-bd0d-fde71fd68654" />




