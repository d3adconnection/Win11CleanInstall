## ## #################### ## ## ##########
# # WINDOWS 11 CLEAN INSTALL # # #########
###########################################
 ####### packaged by d3ad connection #####

## Recommended for use with Windows 11 Pro/Enterprise

# Create a temporary "High Performance" plan by duplicating the normal one
$highPerfGuid = powercfg -duplicatescheme 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c | Select-String -Pattern "Power Scheme GUID: ([\w-]+)" | % { $_.Matches[0].Groups[1].Value }

# Activate the temporary "High Performance" plan
powercfg -setactive $highPerfGuid

# Disable sleep parameters on this temporary plan
@(	"hibernate-timeout-ac", "hibernate-timeout-dc",
    "disk-timeout-ac", "disk-timeout-dc",
    "monitor-timeout-ac", "monitor-timeout-dc",
    "standby-timeout-ac", "standby-timeout-dc"
) | % { powercfg /x -$_ 0 }
###########################################


###########################################
 # # # APP CLEANUP # # # #################
###########################################
# Comment out anything you do not want automatically removed.
$pkgs = (Get-AppxProvisionedPackage -Online)
@(	"MicrosoftTeams",
	"Clipchamp.Clipchamp",
	"MicrosoftCorporationII.MicrosoftFamily",
	"Microsoft.3DBuilder",
	"Microsoft.549981C3F5F10",
	"Microsoft.BingNews",
	"Microsoft.BingWeather",
	"Microsoft.GamingApp",
	"Microsoft.Gethelp",
	"Microsoft.Getstarted",
	"Microsoft.Messaging",
	"Microsoft.WindowsFeedbackHub",
	"Microsoft.WindowsMaps",
	"Microsoft.People",
	"Microsoft.XboxApp",
	"Microsoft.MicrosoftOfficeHub",
	"Microsoft.MicrosoftSolitaireCollection",
	"Microsoft.PowerAutomateDesktop",
	"Microsoft.Office.OneNote",
 	"Microsoft.OutlookForWindows",
	"Microsoft.OneConnect",
	"Microsoft.SkypeApp",
	"Microsoft.Microsoft3DViewer",
	"Microsoft.Paint3D",
	# "Microsoft.Windows.Photos",
	"Microsoft.MSPaint",
	"Microsoft.Wallet",
	"Microsoft.Print3D",
	"Microsoft.MixedReality.Portal",
	"Microsoft.Todos",
	"microsoft.windowscommunicationsapps",
	"Microsoft.WindowsMaps",
	"Microsoft.YourPhone",
	"Microsoft.ZuneMusic",
	"Microsoft.ZuneVideo"
) | % {
	$pkg = ((Get-AppxPackage $_).PackageFullName); if ($pkg) { try { Remove-AppxPackage -Package $pkg -AllUsers; Start-Sleep -s 2 } catch { } }
	$pkg = (($pkgs | ? {$_.Displayname -eq $App}).PackageName); if ($pkg) { try { Remove-AppxProvisionedPackage -PackageName $pkg -AllUsers -Online; Start-Sleep -s 2 } catch { } }
}
###########################################


###########################################
 # # # SCHEDULED TASKS # # # #############
###########################################
## Create scheduled task to auto-check Store updates
Register-ScheduledTask -TaskName "Check for Store app updates" `
  -Description "Automatically checks for Store app updates after a user logs on." `
  -Action (New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-noni -nop -w hidden -c "& { Start-Sleep 10; Get-CimInstance -Namespace Root\cimv2\mdm\dmmap -ClassName MDM_EnterpriseModernAppManagement_AppManagement01 | Invoke-CimMethod -MethodName UpdateScanMethod }"') `
  -Trigger (New-ScheduledTaskTrigger -AtLogon) `
  -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit 00:02:00 -RestartCount 3 -RestartInterval 00:01:00) `
  -User "System"
###########################################


###########################################
 # # # REGISTRY & POLICY TWEAKS # # # ####
###########################################
## Import specialize.reg
$RegFile = (Join-Path $PSScriptRoot "specialize.reg"); if (Test-Path $RegFile) {
	$DefaultUserHive = (Join-Path $Env:SystemDrive "Users\Default\NTUSER.DAT")
	@("load HKLM\UserRegistry $DefaultUserHive","import $RegFile","unload HKLM\UserRegistry") | % { iex "reg $_" }
}
###########################################


###########################################
 # # # FINAL RUN # # # ###################
###########################################
# NTFS optimization (fsutil tweaks from https://github.com/r33int/Windows10-Postinstall)
Get-Volume | ? { $_.FileSystemType -eq 'NTFS' -and $_.DriveLetter } | % { $d = "$($_.DriveLetter):";
	@(	"resource setavailable $d","resource setlog shrink 10 $d",
		"8dot3name strip /f /l nul /s $d","behavior set disable8dot3 $d 1" ) | % { iex "fsutil $_" }
}
@(	"behavior set memoryusage 2","behavior set disablelastaccess 1","behavior set mftzone 2",
	"behavior set disable8dot3 1","8dot3name set 1" ) | % { iex "fsutil $_" }
###########################################


###########################################
# Optimize all volumes
defrag /allvolumes /o

## Switch back to the Balanced power plan
$balancedGuid = powercfg -list | Select-String -Pattern "\((Balanced)\)" | % { $_.Line.Split()[3].Trim('(', ')') }
powercfg -setactive $balancedGuid; powercfg -delete $highPerfGuid

## If no battery is present, disable hibernation and fast startup
if ((@(Get-WmiObject Win32_Battery).count) -eq 0) { powercfg -h off }
###########################################

## Delete self
Remove-Item $MyInvocation.MyCommand.Source -Force