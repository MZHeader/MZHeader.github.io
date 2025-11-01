## Huntress CTF 2025 - Reverse Engineering Challenge Writeups

I try my best to explain how I solve the 4 RE challenges from this years CTF, some of it relied on trial and error / recognising patterns and therefore may not be as technically accurate as i'd like

## NimCrackMe1

SHA 256: 47d7fa30cfeeba6cc42e75e97382ab05002a6cd0ebb4d622156a6af84fda7d5e

**Execution flow:**
Main > NimMain > NimMainInner > NimMainModule > main__crackme_u20

_buildEncodedFlag__crackme_u18_ gets called at **140012c02**, followed by _xorStrings__crackme_u3_ at **140012c6b**

**Dynamic Approach:**
Set a breakpoint at **140012c6b**, step over the function call, review the data in the **R11** register
<img width="623" height="124" alt="image" src="https://github.com/user-attachments/assets/750e1ad3-9023-45a4-9502-1d9851d03151" />

<img width="322" height="29" alt="image" src="https://github.com/user-attachments/assets/afb0ae38-18ad-45a8-8bec-e0b2ce78f7fa" />

<img width="623" height="91" alt="image" src="https://github.com/user-attachments/assets/71d6d329-0854-4f72-b9ca-7d5b17ceee66" />

**Static Approach:**
The _buildEncodedFlag__crackme_u18_ function builds a Nim String of 0x26 (38) bytes in length.

<img width="393" height="68" alt="image" src="https://github.com/user-attachments/assets/adb8d0b0-c8f0-4b3b-961d-d28774f9d7a8" />

The, one byte is written at a time, resulting in the hexadecimal code: 
0x28, 0x05, 0x0C, 0x47, 0x12, 0x4B, 0x15, 0x5C, 0x09, 0x12, 0x17, 0x55,
0x09, 0x4B, 0x42, 0x08, 0x55, 0x5A, 0x45, 0x58, 0x44, 0x57, 0x45, 0x77,
0x5D, 0x54, 0x44, 0x5C, 0x45, 0x13, 0x59, 0x5B, 0x47, 0x42, 0x5E, 0x59,
0x16, 0x5D

This result is stored in var_28

<img width="621" height="300" alt="image" src="https://github.com/user-attachments/assets/f8d3fc86-6bb0-46dd-b1fe-6139d03e16a7" />

And soon, var_98, which is passed to _xorStrings__crackme_u3_ as the 2nd argument

<img width="626" height="133" alt="image" src="https://github.com/user-attachments/assets/1a9a4b9e-9e4a-45a0-9f40-2f2a7cad0d11" />

The first argument is the result, the second is the encoded flag, and the third is the XOR key (length (var_a8) and key (var0_1))

var_a0_1 = &TM__cGo7QGde1ZstH4i7xlaOag_4
TM__cGo7QGde1ZstH4i7xlaOag_4 is a global variable for “Nim is not for malware!”

<img width="685" height="285" alt="image" src="https://github.com/user-attachments/assets/d7fd8a50-6b66-427f-a263-ab96acee1430" />










