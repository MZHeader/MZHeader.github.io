---
tags: Binary-Analysis
---


## Overcoming Malware Analysis Evasion - Binary Patching

The process of making changes to a binary and modifying its instruction flow, from a malware analysts perspective, this can be utilised to overcome measures the malware author has put in place to evade analysis, such as detecting if the target is a virtual machine.

## Example 1 - Rock, Paper, Scissors

Taken from the Huntress CTF, this is a good example of how effective binary patching can be.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/6984b703-2d47-4dd2-96a5-ffff3a8f1fe8)

The aim is to win a game of rock, paper, scissors against a program which knows your input.

The first step is to copy the binary to have an original and a copy to which we will make changes.

We'll use Cutter to open the binary in write mode.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/c2873273-e3c7-49bb-b0e1-008483858086)

We identify that it is a Nim binary, and so navigate to the NimMainInner function, and follow that to main__main62.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/177ff89e-d11d-4c6d-a45e-bbad4f30562d)

Following the function we soon find what we're interested in.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/f313d08d-cd8a-4076-859e-b8cd6796abf5)

The program calls a 'determineWinner__main_58' function, followed by a test operation on register AL, and then performs a Conditional Jump (JNE - Jump if Not Equal)

Contextually, and through some conveniently named functions, we know that reversing this jump should mean that winning = losing, and losing = winning

We can reverse the jump by right-clicking the instruction

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/4c0d72af-45db-4781-a3ad-95a10d31c446)

Close Cutter and execute the newly modified binary to see if the outputs have swapped.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/67cd1a41-89fc-4b07-bb92-47609bf8b734)

## Example 2 - Targeted Malware

Also taken from the Huntress CTF, crab rave is a challenge where you need to get a DLL to execute to present the flag.

Upon execution, nothing happens.

Just like before, we'll make a copy of the file, and open it in Cutter with write mode enabled.

Traversing the program we find the 'NtCheckOSArchitecture' function, which, after a series of other functions and instructions, calls a function which injects the flag.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/f7704492-1a10-4202-873e-5eff46590d1a)

_API Calls associated with process injection_

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/06931740-f9f5-42f9-9d96-19a8444f1f49)

Without worrying too much about that, we'll go back to the 'NtCheckOSArchitecture' function and review the instructions in-between the calling of this inject flag function, and the start of NtCheckOSArchitecture.

Multiple whoami functions are called, and the result is compared against a value, if the value does not match what the program is expecting, the payload will not execute.

In this context, whoami is a rust crate used to query the username and hostname.

[https://docs.rs/whoami/latest/whoami/](https://docs.rs/whoami/latest/whoami/) 

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/3fcc8191-ba3b-44c0-a0a5-a5ba7dd65431)

We'll bypass these checks by making note of the address where the inject function is called and changing the very first jump instruction to jump to this address. 

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/06ed8f8d-762b-4650-8500-b7f709730255)

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/d8bffbc7-42d5-4db1-a2c7-7c2c2f268c74)

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/94a06e9e-d141-4dca-8552-02adf78275ff)

Now when we execute the DLL, the payload executes.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/1e0a47ee-c95f-46d7-ab63-7373c250d3c4)

## Example 3 - .NET Binary - Virtualisation Check

This example is taken from my [NJRat](https://mzheader.github.io/2023/11/29/njrat-maldoc.html) blog post.

The binary does a basic check to decide if the host is in a virtualised environment by querying Win32_CacheMemory

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/0310a987-a366-4dde-ae74-d4f754c11fb5)

If there is a value for Win32_CacheMemory, the program assumes the host is not a virtual machine and will execute the next function.

Upon execution in my virtual machine with no changes, nothing happens.

To overcome this, we open the binary in DNSpy, locate the class containing the function, right-click on the class in the assembly explorer and select edit class

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/fe739797-a947-498c-8c21-bd78e7514ea4)

We can simply change 'if (!Program.VM())' to 'if (Program.VM())', so that the binary will only execute if it's running in a virtualised environment.

Once done, click compile, and save to a new binary

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/bb53fd11-93ea-4fe3-a662-be5902ef3ecb)

Now when the binary is executed, the payload executes fully and we see C2 communication and further files being dropped onto the host.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/d86c9549-c979-4f15-9a4b-774dc0f879cc)










