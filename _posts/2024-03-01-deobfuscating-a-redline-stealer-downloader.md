---
tags: InfoStealer
---
## Deobfuscating A RedLine Stealer Downloader

This sample is taken from [MalwareBazaar](https://bazaar.abuse.ch/sample/707e623b27d794685b3b0a24d1dafe035274f62535fa67934eb1a4d39d3d9b50/), it compromises of multiple stages and payloads that utilise some interesting obfuscation techniques.
The result is a RedLine Stealer binary, commonly sold on underground forums. The malware harvests information from browsers such as saved credentials, autocomplete data, and credit card information. A system inventory is also taken when running on a target machine, to include details such as the username, location data, hardware configuration, and information regarding installed security software. Recent versions of RedLine added the ability to steal cryptocurrency.

