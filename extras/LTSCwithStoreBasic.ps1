# For a clean install that's Store friendly, use this script with Windows 11 LTSC (IoT) Enterprise.
# This will install the Store, along with Notepad, Calculator, Snipping Tool and Terminal.

Write-Host "Checking for elevation..." -ForegroundColor Yellow; if (-not ([Security.Principal.WindowsIdentity]::GetCurrent().Groups -match 'S-1-5-32-544')) {
	Start-Process powershell -Args "-f `"$PSCommandPath`"" -v RunAs; exit }
Clear; Set-Location $PSScriptRoot

If (-not (Get-AppxPackage 'Microsoft.WindowsStore')) {
	Write-Output 'Running WSReset...'
	WSReset -i
	
	Write-Output 'Sleeping for 1 minute to allow Store to finish installing components...'
	Start-Sleep -s 60
}

Write-Output 'Ensuring WinGet is updated...'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 
Install-Module PowerShellGet -SkipPublisherCheck -Scope AllUsers -Force -Confirm:$False
Install-PackageProvider NuGet -Scope AllUsers -Force -Confirm:$False
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
Install-Module Microsoft.WinGet.Client -Scope AllUsers -Force -Repository PSGallery -Confirm:$False
try { Import-Module Microsoft.WinGet.Client } catch { throw 'WinGet Failed.' }
Repair-WinGetPackageManager -AllUsers -Force -Latest
winget source update --disable-interactivity

Write-Output 'Installing apps...'
$StoreApps = @(
    '9MSMLRH6LZF3' # Notepad
	'9WZDNCRFHVN5' # Calculator
	'9MZ95KL8MR0L' # Snipping Tool
	'9PCFS5B6T72H' # Paint
    '9N0DX20HK701' # Terminal
)

$StoreApps | % { winget install --id $_ --source msstore -h --accept-package-agreements --accept-source-agreements --disable-interactivity }

If (Get-AppxPackage 'Microsoft.WindowsTerminal') {
	Write-Output 'Setting Windows Terminal as default console host...'
	New-Item -Path 'HKCU:\Console\%%Startup' -Force -ErrorAction SilentlyContinue | Out-Null
	Set-ItemProperty -Path 'HKCU:\Console\%%Startup' -Name 'DelegationConsole' -Value '{2EACA947-7F5F-4CFA-BA87-8F7FBEEFBE69}' -ErrorAction SilentlyContinue
	Set-ItemProperty -Path 'HKCU:\Console\%%Startup' -Name 'DelegationTerminal' -Value '{E12CFF52-A866-4C77-9A90-F570A7AA2C6B}' -ErrorAction SilentlyContinue
}

If ((Get-AppxPackage 'Microsoft.WindowsNotepad') -And (Test-Path 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Notepad.lnk')) {
	Write-Output 'Removing classic Notepad app...'
	Remove-Item 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Notepad.lnk' -Force
	Remove-WindowsCapability -Online -Name Microsoft.Windows.Notepad~~~~0.0.1.0
}

If ((Get-AppxPackage 'Microsoft.WindowsCalculator') -And (Test-Path 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Calculator.lnk')) {
	Write-Output 'Removing old Calculator shortcut...'
	Remove-Item 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Calculator.lnk' -Force
}

If ((Get-AppxPackage 'Microsoft.ScreenSketch') -And (Test-Path 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Snipping Tool.lnk')) {
	Write-Output 'Removing classic Snipping Tool app...'
	Remove-Item 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Snipping Tool.lnk' -Force
	Remove-WindowsCapability -Online -Name Microsoft.Windows.SnippingTool~~~~0.0.1.0
}

If ((Get-AppxPackage 'Microsoft.Paint') -And (Test-Path 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Paint.lnk')) {
	Write-Output 'Removing classic Paint app...'
	Remove-Item 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Paint.lnk' -Force
	Remove-WindowsCapability -Online -Name Microsoft.Windows.MSPaint~~~~0.0.1.0
}

Write-Output 'Finished!'
Pause