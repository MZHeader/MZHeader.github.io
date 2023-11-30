---
tags: Binary-Analysis
---


## Binary Patching

The process of making changes to a binary and modifying its instruction flow, from a malware analysts perspective, this can be utilised to overcome measures the malware author has put in place to evade analysis, such as detecting if the target is a virtual machine.

## Example 1 - Rock, Paper, Scissors

Taken from the Huntress CTF, this is a good example of how effective binary patching can be.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/6984b703-2d47-4dd2-96a5-ffff3a8f1fe8)

The aim is to win a game of rock, paper, scissors against a program which knows your input.

The first step is to copy the binary to have an original and a copy to which we will make changes.

We'll use Cutter to open the binary in write mode.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/c2873273-e3c7-49bb-b0e1-008483858086)

We quickly identify that it is a Nim binary, and so navigate to the NimMainInner function, and follow that to main__main62.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/177ff89e-d11d-4c6d-a45e-bbad4f30562d)

Following the function we soon find what we're interested in.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/f313d08d-cd8a-4076-859e-b8cd6796abf5)

The program calls a 'determineWinner__main_58' function, followed by a test operation on register AL, and then performs a Conditional Jump (JNE - Jump if Not Equal)

Contextually, and through some conveniently named functions, we know that reversing this jump should mean that winning = losing, and losing = winning

We can reverse the jump by right clicking the instruction

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/4c0d72af-45db-4781-a3ad-95a10d31c446)

