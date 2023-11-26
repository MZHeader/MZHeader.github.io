![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/12f777cf-893f-4b24-a4f1-fd4353383f59)---
tags: RATs
---
## Telegram RAT Analysis

The Telegram Bot API is often abused by threat actors as a means of command and control. ToxicEye is a notable group that have been reported using Telegram to distribute ransomware to infected systems.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/fc12c17c-2a8c-4b15-b042-f83659e03b32)

Full command execution can be achieved through the use of Telegram.

The sample we're looking at in this example is a .scr file which was seen masquerading as a payment slip, sent to the victim in a phishing email.

Upon execution, we observed multiple file writes to the 'C:\Users\user\AppData\Local\Temp\ckil' directory.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/0bf995f7-d399-456a-936e-463a76d0dc79)

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/8a9201bf-f17d-408e-9e86-6de272b1198b)

Multiple suspicious files are written to this directory.

Following the execution chain from the initial .scr file, we see a process creation event for wscript with the following command line.
```
"C:\Windows\System32\wscript.exe" Update-fv.q.vbe
```
_Contents of Update-fv.q.vbe_

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/4a4a4200-5a2a-4f83-b010-330336724efc)


The VBE file contains a lot of garbage strings, we can throw it into CyberChef and use the following operators to make more sense of it

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/f79b34b7-4b46-4b70-9692-d173545463dc)

Output:
```
on error resume nextWScript.Sleep n_j_feSub n_j_feWScript.Sleep  8000End Subsivnehjsfs = "vfkxqlmq.xml"iwxjoanjprnnpn = "xohfpemfj.pif"fsmulsdthu = "WScript.Shell" Set cmglbwkfeao = WScript.CreateObject(fsmulsdthu )vumdhedmernke = iwxjoanjprnnpn  " "  sivnehjsfscmglbwkfeao.Run vumdhedmernke
```
A few of the files written previously are referenced, most notably: xohfpemfj.pif, as this is next in the execution chain

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/83be4ee6-d9e6-4668-8b4f-d79cc739d348)

This .pif file is actually an executable which seems to attempt to masquerade as Telegram.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/5d0d8f41-fd8e-4257-8a02-ebe7b0d3d6ab)

Strings indicate this is an AutoIT binary

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/c96e9558-02c7-4f53-b8b9-eed8296c38d8)


There are also some indications of process injection / hollowing present within this binary.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/356e8d2d-5639-4619-a2c9-d67b4ecf9355)

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/689535d5-b927-4d3f-8655-455fc523dbfd)

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/7fc43795-a8dc-4863-8a95-209d9900b6c4)

Back to following the execution chain, we can see that xohfpemfj.pif spawns RegSvcs.exe.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/fc9512dd-b7c5-4e23-a331-cf5f32954bd5)

This is the legitimate Windows binary, but it was created by and used as a means of process hollowing into a legitimate process.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/7a30f6b9-fe1d-4584-bdcb-e82302246e61)

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/b99e8393-d8c9-4ef7-a4ef-f24f9fdf9218)

Using Process Hacker, we can interrogate the memory of this process and try to find some interesting things. We start by filtering for "HTTP" to search for any network traffic, and we do see results for api.telegram.com, so we'll change our filter to Telegram to identify the following strings:

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/5825edf8-3f3d-4b15-bb5d-ff50619cf7e7)

Looks like we're able to get the Bot API Key from one of these strings, which appears to be "6050257799:AAFHIZowkIt9yf7Vbe1qSQ_LYisLTkZAj4c"

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/9e08cf4f-6e37-4918-8133-78b5bcee6f13)

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/6f70ff47-78c0-4673-aaee-0329f8ae55a8)



