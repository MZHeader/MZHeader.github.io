## Browser History Investigation With PowerShell

This is a quick script which displays a given users browser history for Chrome, Edge, Firefox, Brave & Oprea, it's run purely with PowerShell so has it's limitations and is nowhere near as granular as browsing the history file in a sqlite browser, but it has it's uses

```powershell
$UserName = "*"
$Profile="*"
$ChromePath = "$Env:systemdrive\Users\$UserName\AppData\Local\Google\Chrome\User Data\$Profile\History"
$FirefoxPath = "$Env:systemdrive\Users\$UserName\AppData\Roaming\Mozilla\Firefox\Profiles\$Profile\places.sqlite"
$EdgePath = "$Env:systemdrive\Users\$UserName\AppData\Local\Microsoft\Edge\User Data\$Profile\History"
$BravePath = "$Env:systemdrive\Users\$UserName\AppData\Local\BraveSoftware\Brave-Browser\User Data\$Profile\History"
$OperaPath = "$Env:systemdrive\Users\$UserName\AppData\Roaming\Opera Software\Opera Stable\$Profile\History"
# Google Chrome history
if (Test-Path -Path $ChromePath) {
echo "`n============================================================== Google Chrome History ==============================================================`n"
$file = Get-Item $ChromePath
echo "Last modified time: $($file.LastWriteTime)`n"
$Regex = "((https?|ftp|file)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|])"
Get-Content -Path $ChromePath | Select-String -AllMatches $Regex | ForEach-Object {
$_.Matches | ForEach-Object {
$_.Value
}
} | Sort-Object -Unique
}
# MS Edge history
if (Test-Path -Path $EdgePath) {
echo "`n============================================================== Microsoft Edge History ==============================================================`n"
$file = Get-Item $EdgePath
echo "Last modified time: $($file.LastWriteTime)`n"
$Regex = "((https?|ftp|file)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|])"
Get-Content -Path $EdgePath | Select-String -AllMatches $Regex | ForEach-Object {
$_.Matches | ForEach-Object {
$_.Value
}
} | Sort-Object -Unique
}
# Mozilla Firefox history
if (Test-Path -Path $FirefoxPath) {
$Profile = Get-ChildItem -Path $FirefoxPath | Select-Object -Last 1
if (Test-Path -Path $FirefoxPath) {
echo "`n============================================================== Mozilla Firefox History ==============================================================`n"
$file = Get-Item $FirefoxPath
echo "Last modified time: $($file.LastWriteTime)`n"
$Regex = "((https?|ftp|file)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|])"
Get-Content -Path $FirefoxPath | Select-String -AllMatches $Regex | ForEach-Object {
$_.Matches | ForEach-Object {
$_.Value
}
} | Sort-Object -Unique
}
}
# Brave Browser history
if (Test-Path -Path $BravePath) {
echo "`n============================================================== Brave History ==============================================================`n"
$file = Get-Item $BravePath
echo "Last modified time: $($file.LastWriteTime)`n"
$Regex = "((https?|ftp|file)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|])"
Get-Content -Path $BravePath | Select-String -AllMatches $Regex | ForEach-Object {
$_.Matches | ForEach-Object {
$_.Value
}
} | Sort-Object -Unique
}
# Opera browser history
if (Test-Path -Path $OperaPath) {
echo "`n============================================================== Opera History ==============================================================`n"
$file = Get-Item $OperaPath
echo "Last modified time: $($file.LastWriteTime)`n"
$Regex = "((https?|ftp|file)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|])"
Get-Content -Path "$OperaPath" | Select-String -AllMatches $Regex | ForEach-Object {
$_.Matches | ForEach-Object {
$_.Value
}
} | Sort-Object -Unique
}
```