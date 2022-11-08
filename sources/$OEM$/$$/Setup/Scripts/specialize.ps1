## ######################## ##############
# # WINDOWS 11 CLEAN INSTALL #############
 ############################ ############
######## maintained by d3ad connection ###

# NTFS optimization (fsutil tweaks from https://github.com/r33int/Windows10-Postinstall)
$DriveLetters = (Get-WmiObject -Class Win32_Volume).DriveLetter
ForEach ($Drive in $DriveLetters) {
    If (-not ([string]::IsNullOrEmpty($Drive))) {
        fsutil resource setavailable $Drive
        fsutil resource setlog shrink 10 $Drive
        fsutil 8dot3name strip /f /l nul /s $Drive
        fsutil behavior set disable8dot3 $Drive 1	
    }
}
fsutil behavior set memoryusage 2
fsutil behavior set disablelastaccess 1
fsutil behavior set mftzone 2
fsutil behavior set disable8dot3 1
fsutil 8dot3name set 1

#################################
### APP CLEANUP #################
#################################

$AppsToRemove = @(
	"MicrosoftTeams",
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
	)
ForEach ($App in $AppsToRemove) {
	$PackageFullName = (Get-AppxPackage $App).PackageFullName
	$ProPackageFullName = (Get-AppxProvisionedPackage -online | where {$_.Displayname -eq $App}).PackageName
	if ($PackageFullName) {
		start-sleep -Seconds 5
		remove-AppxPackage -Package $PackageFullName -AllUsers
	}
	if ($ProPackageFullName) {
		start-sleep -Seconds 5 
		Remove-AppxProvisionedPackage -PackageName $ProPackageFullName -AllUsers -Online
	}
}

#################################
### SCHEDULED TASKS #############
#################################

# Create scheduled task to auto-check Store updates
$taskname = "Check for Store app updates"
$taskdescription = "Automatically checks for Store app updates after a user logs on."
$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
  -Argument '-noni -nop -w hidden -c "& { Start-Sleep 10; $update = Get-WmiObject -Namespace root\cimv2\mdm\dmmap -Class MDM_EnterpriseModernAppManagement_AppManagement01; $update.UpdateScanMethod() }"'
$trigger =  New-ScheduledTaskTrigger -AtLogon
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName $taskname -Description $taskdescription -Settings $settings -User "System"

#################################
### REGISTRY TWEAKS #############
#################################

# Offline local account via OOBE\BYPASSNRO (found on MyDigitalLife credit to AveYo)
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /f /v BypassNRO /d 1 /t REG_DWORD

# Mount Default User Account
REG LOAD HKLM\DefaultUser C:\Users\Default\NTUSER.DAT

# Show color on title bars
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\DWM" /v ColorPrevalence /d 1 /t REG_DWORD /f

# Don't show color on start/taskbar
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v ColorPrevalence /d 0 /t REG_DWORD /f

# Remove People from taskbar
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v PeopleBand /d 0 /t REG_DWORD /f
 
# Remove search from taskbar
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Search" /v SearchboxTaskbarMode /d 0 /t REG_DWORD /f
 
# Remove weather/news from taskbar
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Feeds" /v ShellFeedsTaskbarViewMode /d 2 /t REG_DWORD /f

# Remove Widgets from taskbar
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarDa /d 0 /t REG_DWORD /f

# Remove Chat from taskbar
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarMn /d 0 /t REG_DWORD /f

# Hide Edge first run experience
REG ADD "HKLM\DefaultUser\Software\Microsoft\Edge" /v HideFirstRunExperience /d 1 /t REG_DWORD /f

# Disable thumbnail cache
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v DisableThumbnailCache /d 1 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v DisableThumbsDBOnNetworkFolders /d 1 /t REG_DWORD /f

# File Explorer default to This PC
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v LaunchTo /d 1 /t REG_DWORD /f

# File Explorer windows run in separate processes
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v SeparateProcess /d 1 /t REG_DWORD /f

# Show all file extensions by default
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /d 0 /t REG_DWORD /f

# Disable App Startup Delay
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v StartupDelayInMSec /d 0 /t REG_DWORD /f

# Small icon view in Control Panel
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" /v StartupPage /d 1 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" /v AllItemsIconView /d 1 /t REG_DWORD /f

# Disable privacy settings pop up after upgrade
REG ADD "HKLM\DefaultUser\Software\Policies\Microsoft\Windows\OOBE" /v DisablePrivacyExperience /d 1 /t REG_DWORD /f

# Disable start menu suggestions
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /d 0 /t REG_DWORD /f

# Disable Tips
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SoftLandingEnabled /d 0 /t REG_DWORD /f

# Disable System requirements not met message in Settings
REG ADD "HKLM\DefaultUser\Control Panel\UnsupportedHardwareNotificationCache" /v SV1 /t REG_DWORD /d 0 /f
REG ADD "HKLM\DefaultUser\Control Panel\UnsupportedHardwareNotificationCache" /v SV2 /t REG_DWORD /d 0 /f
REG ADD "HKLM\DefaultUser\Control Panel\UnsupportedHardwareNotificationCache" /v SV3 /t REG_DWORD /d 0 /f

# Disable compression on wallpapers
REG ADD "HKLM\DefaultUser\Control Panel\Desktop" /v JPEGImportQuality /t REG_DWORD /d 100 /f

# Disable Auto Account Wizard
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v ScoobeSystemSettingEnabled /d 0 /t REG_DWORD /f

# Disabled Sec and maint popups
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v Enabled /d 0 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows Security Health\State" /v AccountProtection_MicrosoftAccount_Disconnected /d 0 /t REG_DWORD /f

# Show more pins on Start
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_Layout /d 1 /t REG_DWORD /f

# Office customizations
REG ADD "HKLM\DefaultUser\Software\Microsoft\Office\16.0\Common" /v qmenable /d 0 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Office\16.0\Common" /v TurnOffPhotograph /d 1 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Office\16.0\Common" /v PrivacyNoticeShown /d 2 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Office\16.0\Common\General" /v shownfirstrunoptin /d 1 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Office\16.0\Common\General" /v ShownFileFmtPrompt /d 1 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Office\16.0\Common\PTWatson" /v PTWOptIn /d 0 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Office\16.0\FirstRun" /v BootedRTM /d 1 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Office\16.0\FirstRun" /v disablemovie /d 1 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Office\16.0\Registration" /v AcceptAllEulas /d 1 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Office\16.0\Word\Options" /v AllowAutoReadingMode /d 0 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Office\16.0\Word\Options" /v DisableDarkMode /d 1 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Office\16.0\Outlook\Setup" /v SetupOutlookMobileWebPageOpened /d 1 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Office\16.0\Outlook\Options\General" /v DisableOutlookMobileHyperlink /d 1 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Policies\Microsoft\Office\16.0\Outlook\Options\General" /v DisableOutlookMobileHyperlink /d 1 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Policies\Microsoft\Office\16.0\Outlook\Setup" /v SetupOutlookMobileWebPageOpened /d 1 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Office\16.0\Common\Privacy\SettingsStore\Anonymous" /v ConnectedExperiencesNoticeVersion /d 1 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Office\16.0\Common\Privacy\SettingsStore\Anonymous" /v RequiredDiagnosticDataNoticeVersion /d 1 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Office\16.0\Common\Privacy\SettingsStore\Anonymous" /v OptionalDiagnosticDataConsentVersion /d 1 /t REG_DWORD /f

# Unmount Default User Account
REG UNLOAD HKLM\DefaultUser

#################################
#################################

cmd /c start /min cmd /c del /f /q C:\Windows\Setup\Scripts\specialize.ps1 & del /f /q C:\Windows\Setup\Scripts\specialize.ps1