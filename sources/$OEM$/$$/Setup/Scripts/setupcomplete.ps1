## ## #################### ## ## ##########
# # WINDOWS 11 CLEAN INSTALL # # #########
###########################################
 ####### packaged by d3ad connection #####

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
 # # # IMPORT WI-FI PROFILES # # # #######
###########################################

###########################################
# Import any Wi-Fi*.xml files in the Scripts folder
###########################################
Get-ChildItem -Path "$PSScriptRoot\Wi-Fi*.xml" -File | % {Start-Sleep -s 5; netsh wlan add profile filename="$_" user=all; Start-Sleep -s 5 }
###########################################


###########################################
 # # # APP INSTALLS # # # ################
###########################################

###########################################
# This is a good spot to add any apps you want to install
###########################################


###########################################
## Install OneDrive 64-bit for all users
###########################################
## Uncomment this to have OneDrive installed for all users.

# Start-Process "$Env:SystemRoot\System32\OneDriveSetup.exe" -ArgumentList "/allusers" -NoNewWindow -Wait
###########################################


###########################################
 # # # REGISTRY & POLICY TWEAKS # # # ####
###########################################
# Import setupcomplete.reg (if exists)
$RegFile = (Join-Path $PSScriptRoot "setupcomplete.reg"); if (Test-Path $RegFile) {
	$DefaultUserHive = (Join-Path $Env:SystemDrive "Users\Default\NTUSER.DAT")
	@("load HKLM\UserRegistry $DefaultUserHive","import $RegFile","unload HKLM\UserRegistry") | % { iex "reg $_" }
}
###########################################


###########################################
 # # # FINAL CLEANUP # # # ###############
###########################################
# Use this to specify any other files/folders to delete on install.

$FinalCleanup = @(
	# "C:\Temp",
	"C:\Windows.old"
)

# Everything in the Scripts folder is automatically purged.
$FinalCleanup += Get-ChildItem $PSScriptRoot -File | ? { $_.Name -notin "setupcomplete.ps1", "setupcomplete.cmd" } | Select -ep FullName
$FinalCleanup += Get-ChildItem $PSScriptRoot -Directory -Recurse | Select -ep FullName

# Removes everything in one shot
$FinalCleanup | % { if (Test-Path $_) { Remove-Item $_ -Recurse -Force -ErrorAction SilentlyContinue } }
###########################################


###########################################
# Make any initial network connections set as Private
Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private

## Switch back to the Balanced power plan
$balancedGuid = powercfg -list | Select-String -Pattern "\((Balanced)\)" | % { $_.Line.Split()[3].Trim('(', ')') }
powercfg -setactive $balancedGuid; powercfg -delete $highPerfGuid

## If no battery is present, disable hibernation and fast startup
if ((@(Get-WmiObject Win32_Battery).count) -eq 0) { powercfg -h off }
###########################################

## Delete self
Remove-Item $MyInvocation.MyCommand.Source -Force