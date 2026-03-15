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

## Pirate.exe

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
| `opssvc.exe` | Quick Heal |
| `avastui.exe` | Avast |
| `avgui.exe` | AVG |
| `nswscsvc.exe` | Norton/Symantec |
| `sophoshealth.exe` | Sophos |

If any of these processes are found, the installer Sleeps for 193 seconds before proceeding, a common sandbox evasion technique.

## Howard.exe

I found Howard.exe quite difficult to analyse, but got lucky by setting a breakpoint on VirtualAlloc and identifying an indirect call to the API.

![Image](https://raw.githubusercontent.com/MZHeader/MZHeader.github.io/refs/heads/main/assets/Untitled%203.png)

The return address of the VirtualAlloc call in this case was 02BA0000 - our memory region where a buffer of memory is to be written to.

Setting a memory write breakpoint on this address, we identify a loop where a payload is being written:

![Image](https://raw.githubusercontent.com/MZHeader/MZHeader.github.io/refs/heads/main/assets/Screenshot%202026-03-15%20at%2014.25.07.png)

We can see the full buffer by resuming execution to when the loop completes.
Within the memory buffer are the magic bytes of a PE:

![Image](https://raw.githubusercontent.com/MZHeader/MZHeader.github.io/refs/heads/main/assets/Screenshot%202026-03-15%20at%2014.28.13.png)

To get the next payload, we'll dump this memory region to disk and carve the PE with the following Binary Refinery pipline:

```
ef Howard.exe_memory.bin | carve-pe | dump carved.exe
```

## SmartAssembly

This next stage payload is an assembly packed with SmartAssembly.
De4dot makes the assembly easier to read, with the Main function as follows:
```
		// Token: 0x060000D1 RID: 209 RVA: 0x00006990 File Offset: 0x00004B90
		static void Main()
		{
			byte[] array = null;
			while (array == null)
			{
				try
				{
					array = Class7.smethod_14();
				}
				catch
				{
				}
			}
			Assembly assembly = Class7.smethod_5(array);
			if (assembly != null)
			{
				Type type = Class7.smethod_99("S015sDJkvQDvP3a6cx.UyOmhW05bcEWWnZuqT", assembly);
				if (type != null)
				{
					Class7.smethod_26("AHQt3OKaB", type);
				}
			}
		}
```

smethod_14 takes an encrypted resource and AES decrypts it, it is then loaded and the AHQt3OKaB Method from the UyOmhW05bcEWWnZuqT Class from the S015sDJkvQDvP3a6cx Namespace is invoked.

```
		static byte[] smethod_14()
		{
			byte[] emyrsqaglox = Class1.Emyrsqaglox; // return (byte[])Class1.Cazmb.GetObject("Reydbozimwj", Class1.cultureInfo_0);
			byte[] array;
			using (Aes aes = Aes.Create())
			{
				aes.KeySize = 256;
				aes.Key = Convert.FromBase64String(Class0.string_0); // string_0 = UlPs+RiNkeAQjtjBHi2FZme93GOwtujN9g03qBhA2xM=
				aes.IV = Convert.FromBase64String(Class0.string_1); // string_1 = 8VSGg0PMrhcl1gUkFwmUlg==
				ICryptoTransform cryptoTransform = aes.CreateDecryptor(aes.Key, aes.IV);
				using (MemoryStream memoryStream = new MemoryStream())
				{
					using (MemoryStream memoryStream2 = new MemoryStream(emyrsqaglox))
					{
						using (CryptoStream cryptoStream = new CryptoStream(memoryStream2, cryptoTransform, CryptoStreamMode.Read))
						{
							cryptoStream.CopyTo(memoryStream);
							array = memoryStream.ToArray();
						}
					}
				}
			}
			return array;
		}
```

The embedded, encrypted resource can be decrypted with the following Binary Refinery pipeline:

```
ef Reydbozimwj | aes b64:UlPs+RiNkeAQjtjBHi2FZme93GOwtujN9g03qBhA2xM= -i b64:8VSGg0PMrhcl1gUkFwmUlg== | dump payload.bin
```

This reveals another assembly, this time protected with .NET Reactor...

Work In Progress :)
