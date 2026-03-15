---
description: Between May 2024 and January 2026, threat actors have been observed targeting Steam users by uploading malicious games to the Steam platform. At the time of writing, the FBI are currently investigating this. Affected games include BlockBlasters, Chemia, Dashverse/DashFPS, Lampy, Lunara, PirateFi, and Tokenova. In this post, we are reverse engineering PirateFi.
---

## Picking Apart PirateFi: Steam Game Malware

In February 2025, a new game hit the Steam marketplace in beta, titled "PirateFi". The free-to-play game was somewhat underwhelming due to the fact that it was uploaded in order to steal victims' information and hijack user accounts.

The game was taken down from the Steam marketplace, but the change history can be found here: https://steamdb.info/app/3476470/history/

Upon review, **Changelist #27351505** caught my eye due to the following line, showing a heavily embedded vbs script being added:

![Image](https://raw.githubusercontent.com/MZHeader/MZHeader.github.io/refs/heads/main/assets/2026-03-15%2013_30_44-Desktop%20-%20File%20Explorer.png)

This directory within the game files contains several launchers that ultimately execute Pirate.exe.

The directory contains the following files:

| Filename      | Purpose      |
| ------------- | ------------- |
| `piratefi.vbs` | Launches piratefi.bat |
| `piratefi.bat` | Launches batch2.vbs |
| `batch2.vbs` | Launches batch2.bat |
| `batch2.bat` | Launches Pirate.exe |
| `Pirate.exe` | Main Executable Payload |
| `Pirate` | Directory |
| `Engine` | Directory |

Pirate.exe is a InnoSetup executable, the contents of which can be extracted with the following Binary Refinery pipeline:
```
ef Pirate.exe [| xt -j | d2p ]
```
This  will produce three directories - data, embedded and meta.

embedded/script.ps is the PowerShell installer script. It's main purpose is to execute the binary dropped by the installer - 'Howard.exe'.
Prior to doing so, it builds the command 'cmd.exe /C tasklist /FI "IMAGENAME eq <name>" /FO CSV /NH | find /I "<name>"' and searches for the following processes:

| Process | Product |
|---|---|
| `wrsa.exe` | Webroot SecureAnywhere |
| `opssvc.exe` | Malwarebytes |
| `avastui.exe` | Avast |
| `avgui.exe` | AVG |
| `nswscsvc.exe` | Norton/Symantec |
| `sophoshealth.exe` | Sophos |
