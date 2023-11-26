---
tags: Infostealers
---
## Redline Infostealer

RedLine Stealer is a malware available on underground forums for sale apparently as standalone ($100/$150 depending on the version) or also on a subscription basis ($100/month). This malware harvests information from browsers such as saved credentials, autocomplete data, and credit card information.
A system inventory is also taken when running on a target machine, to include details such as the username, location data, hardware configuration, and information regarding installed security software. More recent versions of RedLine added the ability to steal cryptocurrency.
FTP and IM clients are also apparently targeted by this family, and this malware has the ability to upload and download files, execute commands, and periodically send back information about the infected computer.

## Example 1 - Basic Binary

The first example is a fairly straight forward executable. masquerading as Visual Studio.
The sample was taken from [Virustotal](https://www.virustotal.com/gui/file/00027b455d6cdceaa6f4167761bd6e92db768c183c69504ba9dd6e740c29a7a8)

It is a .NET executable so we can load it into DNSpy and take a look.

We can just jump straight into the configuration information by following this function.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/2445aa8f-9ab5-421a-8d4a-caebd3091bb7)

_String Decrypt Function:_

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/185621de-4440-4c79-b61e-8b64ad399400)

_Configuration components:_

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/0312b01c-c8bb-4ccf-8c54-0b3e6d23e37a)


Decrypting the configuration components is a simple XOR function and Base64 decode, which we can use CyberChef for.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/8804ae0b-d56f-48ca-b1ec-ba70c7c64760)

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/5041f69d-9224-4b72-9d72-376e63f2a14a)

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/2931cbc6-e5bc-4311-9cee-f055a0aaf956)

Our C2 for this sample is: **193.233.20[.]23:4123**

Further confirmed through dynamic analysis:

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/b901a6d1-fa26-42dc-a06e-f7dc8bde8dec)


This sample has a SystemInfoHelper module, which is used to collect and exfiltrate the following information from the screenshot:

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/2c9ea060-6df2-4810-a814-fbed07f3a73e)

Further interesting functions include:

**Searching the filesystem for specified directories: Windows, Program Files, Program Files (x86) and Program Data**

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/0b9e592c-b490-4a0e-b135-8612d26a95fe)

**A list of countries where execution is prevented**

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/ee0b8558-4f0a-42ed-9988-75d526cadf6e)










