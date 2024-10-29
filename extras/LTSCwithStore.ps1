# For a clean install that's Xbox and Store friendly, use this script with Windows 11 LTSC (IoT) Enterprise.
# This will install the Store, along with Notepad, Calculator, Terminal, Xbox and Game Bar.

Write-Output 'Checking for elevation...'
If (-not ([Security.Principal.WindowsIdentity]::GetCurrent().Groups -match 'S-1-5-32-544')) { 
    Start-Process powershell -Args "-f `"$PSCommandPath`"" -v RunAs; Exit 
}

Write-Output 'Running WSReset...'
WSReset -i

Write-Output 'Sleeping for 1 minute to allow Store to finish installing components...'
Start-Sleep -s 60

Write-Output 'Ensuring WinGet is updated...'
if (-not (Get-PackageProvider NuGet -ErrorAction Ignore)) { Install-PackageProvider NuGet -Force }
Install-Module Microsoft.WinGet.Client -Force -Repository PSGallery
Import-Module Microsoft.WinGet.Client
Repair-WinGetPackageManager

Write-Output 'Installing apps...'
$StoreApps = @(
    '9MSMLRH6LZF3' # Notepad
    '9N0DX20HK701' # Terminal
    '9MV0B5HZVK9Z' # Xbox
    '9MWPM2CQNLHN' # Xbox Gaming Services
    '9NZKPSTSNW4P' # Xbox Game Bar
	'9WZDNCRD1HKW' # Xbox Identity Provider
	'9WZDNCRFHVN5' # Calculator
	# '9WZDNCRFJBH4' # Photos
)

$StoreApps | % { winget install --id $_ --source msstore -h --accept-package-agreements --accept-source-agreements --disable-interactivity }

If (Get-AppxPackage 'Microsoft.WindowsTerminal') {
	Write-Output 'Setting Windows Terminal as default console host...'
	Set-ItemProperty 'HKCU:\Console\%%Startup' DelegationConsole '{2EACA947-7F5F-4CFA-BA87-8F7FBEEFBE69}'
	Set-ItemProperty 'HKCU:\Console\%%Startup' DelegationTerminal '{E12CFF52-A866-4C77-9A90-F570A7AA2C6B}'
}

If ((Get-AppxPackage 'Microsoft.WindowsNotepad') -And (Test-Path 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Notepad.lnk')) {
	Write-Output 'Removing old Notepad shortcut...'
	Remove-Item 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Notepad.lnk' -Force
}

If ((Get-AppxPackage 'Microsoft.WindowsCalculator') -And (Test-Path 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Calculator.lnk')) {
	Write-Output 'Removing old Calculator shortcut...'
	Remove-Item 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Calculator.lnk' -Force
}

Write-Output 'Finished!'
Pause