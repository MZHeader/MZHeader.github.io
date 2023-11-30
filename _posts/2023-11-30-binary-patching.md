---
tags: Binary-Analysis
---


## Binary Patching

The process of making changes to a binary and modifying its instruction flow, from a malware analysts perspective, this can be utilised to overcome measures the malware author has put in place to evade analysis, such as detecting if the target is a virtual machine.

## Example 1 - Rock, Paper, Scissors

Taken from the Huntress CTF, this is a good example of how effective binary patching can be.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/6984b703-2d47-4dd2-96a5-ffff3a8f1fe8)

The aim is to win a game of rock, paper, scissors against a program which knows your input.
