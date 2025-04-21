Write-Host "Checking for elevation..." -ForegroundColor Yellow; if (-not ([Security.Principal.WindowsIdentity]::GetCurrent().Groups -match 'S-1-5-32-544')) {
	Start-Process powershell -Args "-f `"$PSCommandPath`"" -v RunAs; exit }
Clear; Set-Location $PSScriptRoot

do { Write-Host ""; $ssid=Read-Host "Enter SSID"; $xml="Wi-Fi-$ssid.xml"; netsh wlan export profile name="$ssid" folder="." key=clear | Out-Null } until (Test-Path $xml)
Write-Host ""; Write-Host "Exported: $xml" -ForegroundColor Green; Write-Host ""; pause