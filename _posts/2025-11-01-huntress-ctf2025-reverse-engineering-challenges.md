---
tags: CTF
---

## Huntress CTF 2025 - Reverse Engineering Challenge Writeups

<img width="793" height="609" alt="image" src="https://github.com/user-attachments/assets/489faf9b-6966-4b09-9f74-5cfe4478b390" />

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

## Rust Tickler

SHA 256: df95140548732f34d8cf11b6b9dd7addb31480fab871b7004c7c1e09acfd920b

**Finding main:**
Entry point > FUN_140005424 > FUN_140001790 > FUN_1400011f0

Towards the end of this large function is an undefined function (sub_140001740).

<img width="624" height="76" alt="image" src="https://github.com/user-attachments/assets/ea5575f0-6577-4f33-87d1-422c2ab94231" />

<img width="627" height="42" alt="image" src="https://github.com/user-attachments/assets/fb00a4e7-f5e3-41c9-9c45-5f77f4552e34" />

<img width="626" height="161" alt="image" src="https://github.com/user-attachments/assets/3e0d4b6e-9f65-46b0-b2ce-c9e9b6dd314d" />

We can see a string being XOR’d with 0x51

Replicating this will result in the flag

<img width="613" height="301" alt="image" src="https://github.com/user-attachments/assets/efd75e81-8362-413f-b6bb-82b9ac3b7cad" />

<img width="701" height="112" alt="image" src="https://github.com/user-attachments/assets/d0feea29-44f1-47db-b34b-e38bb79fc07a" />

## Rust Tickler 2

SHA 256: 47d7fa30cfeeba6cc42e75e97382ab05002a6cd0ebb4d622156a6af84fda7d5e

Main > 0x140001350

<img width="625" height="101" alt="image" src="https://github.com/user-attachments/assets/b3cb12e3-cc22-4809-8c5b-c7adaac5d5cf" />

Set a breakpoint for this address in x64dbg:

<img width="625" height="250" alt="image" src="https://github.com/user-attachments/assets/bf807eb2-f6fd-44ab-89b7-05158e255089" />

A few instructions into this function, data gets moved to RDX, and the length of data is moved into RAX

<img width="626" height="94" alt="image" src="https://github.com/user-attachments/assets/12c78e24-d558-4171-86fa-1fdb090db1fe" />

Jump over this instruction in a debugger and  right click the RDX register > Follow in dump to see the data

<img width="622" height="62" alt="image" src="https://github.com/user-attachments/assets/5dd9c3e4-81e6-4f69-bdda-4a9641f908dd" />

<img width="624" height="251" alt="image" src="https://github.com/user-attachments/assets/b4b8b094-a41a-417c-8fe7-ca32caf5291c" />

At 1400013ae, an XOR key is moved into XMM0

<img width="626" height="25" alt="image" src="https://github.com/user-attachments/assets/71f97bda-9f11-4018-9ec1-c8d6dd5379d7" />

An XOR operation then occurs using this key towards i_3 (The data in RDX)

<img width="623" height="178" alt="image" src="https://github.com/user-attachments/assets/3d9bdce2-3447-45fd-b967-8944cb287600" />

This XOR operation is performed in the following loop:

<img width="626" height="106" alt="image" src="https://github.com/user-attachments/assets/25d9b3e7-f014-45d5-aeeb-b72fd3c974b6" />

Partial decrypted data in RDX after the first iteration shows a HNTS header:

<img width="625" height="249" alt="image" src="https://github.com/user-attachments/assets/7f9b3fd4-bb4b-4479-b74e-86abdd41d8f5" />

Set a breakpoint at 1400013E5 and hit it to complete the decryption loop, revealing the decrypted data structure in RDX

<img width="627" height="255" alt="image" src="https://github.com/user-attachments/assets/8f83541e-24b7-463c-b7d8-1e085714f748" />

This decrypted data structure gets passed to function 140003ea0

<img width="618" height="33" alt="image" src="https://github.com/user-attachments/assets/475b90a0-8153-4eee-a505-6e82bfb21018" />

This function is essentially the HNTS data parser, it checks that the data is as expected by checking the magic bytes and creates an indexed array for later lookup

The parsed data structure is moved into the RDX prior to the call to function 140003de0

<img width="628" height="33" alt="image" src="https://github.com/user-attachments/assets/908b952c-3087-48c5-ac99-ec62f0ebe38b" />

<img width="630" height="274" alt="image" src="https://github.com/user-attachments/assets/91d84671-eacd-4b30-8339-84011bc1e143" />

0xAAAAAAAA is then moved into the R8 register

<img width="623" height="34" alt="image" src="https://github.com/user-attachments/assets/85cb975e-4630-4eff-9960-2470ff526a20" />

These values are used as arguments for the call to function 140003de0

<img width="623" height="37" alt="image" src="https://github.com/user-attachments/assets/8327678b-e395-481b-8bf6-0d14924c3d58" />

After passing this function in a debugger, a string is returned:

<img width="606" height="32" alt="image" src="https://github.com/user-attachments/assets/df56de85-0779-4712-b568-fad3cff3f487" />

A similar set up occurs later, where 0xAAAA is moved into R8 and returns another string after a call to 140003de0

<img width="426" height="56" alt="image" src="https://github.com/user-attachments/assets/e03ef126-f4f7-4b75-946e-e67628dff0a0" />

Which returns the string Bingus

<img width="379" height="32" alt="image" src="https://github.com/user-attachments/assets/b8709b72-3f49-4a0f-86d2-91797e59a169" />

So the values being moved to R8 prior to the function call return different strings. They are acting as IDs within the HNTS data structure and return different output depending on the ID provided.

Looking at the HNTS data structure, the IDs are formatted in a pretty recognisable way:

<img width="622" height="252" alt="image" src="https://github.com/user-attachments/assets/4e10e0fe-9d67-42f6-bedb-25c46502a038" />

We already know that AAAAAAAA and AAAA are valid IDs, AAAAA is also later called in the code. The rest of the IDs highlighted in this “zone” are also valid due to their offsets within the structure.

Modifying the R8 register to one of these IDs prior to the function call changes the result

<img width="288" height="224" alt="image" src="https://github.com/user-attachments/assets/87aa9746-1886-43fe-8999-2d9b1bebe761" />

The 7F structure ID will return the flag:

<img width="627" height="36" alt="image" src="https://github.com/user-attachments/assets/1faf784e-ca1e-4b5c-94a3-ca7394f7b7bc" />

## Rust Tickler 3

SHA 256: a4a5b64d72540552c691293f9e988e189674275f6e4743b8d61f299bd6f31fc7

Main function of interest: **1400011f0**

This challenge initially follows a similar format to Rust Tickler 2 where an ID is moved into R8 prior to a function call which results in a different string being returned, for example:

<img width="623" height="61" alt="image" src="https://github.com/user-attachments/assets/2cbedc0c-7d7b-444a-92d8-ed3bf05d049e" />

This results in:

<img width="499" height="34" alt="image" src="https://github.com/user-attachments/assets/41f005f0-dcb0-40b6-8774-01a4aad9defe" />

When we get to ​​1400013C2, there is a conditional jump, where either ID 1338 or 1339 is used

<img width="620" height="33" alt="image" src="https://github.com/user-attachments/assets/830b2a25-2497-4198-801d-291f6ae1d027" />

<img width="551" height="31" alt="image" src="https://github.com/user-attachments/assets/821033c8-d577-4ffe-b253-31bda54f77d5" />

Trial and error tells us that 1338 is the failure, and 1339 is the success, so we’ll set our RIP / patch the ZF / binary to follow that execution path.

Failure / success is determined based on if the provided input is equal to the result of ID 133A

<img width="463" height="221" alt="image" src="https://github.com/user-attachments/assets/f779a206-45da-43cb-b9f1-62cc7d552a20" />

Modifying one of the IDs in R8 prior to the 1423ED7D0 function call will reveal the “answer”:

<img width="622" height="111" alt="image" src="https://github.com/user-attachments/assets/de609d1c-831c-42e8-b0ce-7c9801389e17" />

Continuing to follow execution, we see a path being built: (ID 1348 = Exodus)

<img width="577" height="481" alt="image" src="https://github.com/user-attachments/assets/4bd8f38c-27db-40f1-add7-316182ff82a7" />

<img width="607" height="33" alt="image" src="https://github.com/user-attachments/assets/9c8c0a8e-d8c3-4b87-af72-9ade57d13a73" />

The binary will terminate shortly after this is seen if this directory doesn’t exist.

If the correct “answer” is provided and the above path exists, a file (filename created from ID 1369)

So all we need to do is create this directory and supply the hash when prompted by the executable.

<img width="616" height="185" alt="image" src="https://github.com/user-attachments/assets/5755b794-85c3-4560-8074-33f3510cf21a" />

Stage 2 performs a memcmp to compare supplied input to a known value and if that value matches, the success path is executed.

However, patching the binary to get a success just reveals the message:

<img width="623" height="50" alt="image" src="https://github.com/user-attachments/assets/abb16692-fccb-491c-9673-361453342dbe" />

And there is not much change in execution flow as seen:

<img width="622" height="252" alt="image" src="https://github.com/user-attachments/assets/f2f239fc-0b3b-4055-b0b3-b63661ef4929" />

The answer lies between 140001354 and 1400013c3. This is AES ciphertext, AES key, and AES IV. 

<img width="760" height="282" alt="image" src="https://github.com/user-attachments/assets/d123333d-0f59-480a-adf6-35601d2050b7" />

<img width="595" height="198" alt="image" src="https://github.com/user-attachments/assets/e8735424-2987-4ddc-90c0-bcdca8b90035" />

I believe this data is then passed through further cryptographic functions prior to being used by the memcmp function.

Data_14037d0f8 = cb584b62035d138f77bc9810f00f1a2020700f8fbf0d75dca3fd71085f1467cde9d05f1f83bbc76b7d9beb42f7510095

Data_14037d128 = d4c39486fdf04283f5d96436ba68ea1c4f4194796af82d0f8eed7c12f53fa07c

Data_14037d148 = 539fb31e1cc13442420d039397e91777

These data variables follow that of AES 256, where the cipher is 48 bytes, followed by a 32 byte key and 16 byte IV.

<img width="697" height="254" alt="image" src="https://github.com/user-attachments/assets/48ffca8f-3c18-4829-9c5f-a49937537370" />





























