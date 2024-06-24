## ## #################### ## ## ##########
# # WINDOWS 11 CLEAN INSTALL # # #########
###########################################
 ####### packaged by d3ad connection #####

## Recommended for use with Windows 11 Pro/Enterprise

###########################################
 # # # NTFS OPTIMIZATION # # # ###########
###########################################
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
###########################################

###########################################
 # # # APP CLEANUP # # # #################
###########################################

# Comment out anything you do not want automatically removed.

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

###########################################
 # # # SCHEDULED TASKS # # # #############
###########################################

# Create scheduled task to auto-check Store updates
$taskname = "Check for Store app updates"
$taskdescription = "Automatically checks for Store app updates after a user logs on."
$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
  -Argument '-noni -nop -w hidden -c "& { Start-Sleep 10; Get-CimInstance -Namespace Root\cimv2\mdm\dmmap -ClassName MDM_EnterpriseModernAppManagement_AppManagement01 | Invoke-CimMethod -MethodName UpdateScanMethod }"'
$trigger =  New-ScheduledTaskTrigger -AtLogon
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName $taskname -Description $taskdescription -Settings $settings -User "System"
###########################################


## Install OneDrive 64-bit for all users
###########################################

# Comment this out if you do not want OneDrive installed
Start-Process "$Env:SystemRoot\System32\OneDriveSetup.exe" -ArgumentList "/allusers"
###########################################


###########################################
 # # # REGISTRY & POLICY TWEAKS # # # ####
###########################################

# Force offline local account
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\OOBE" /f /v BypassNRO /d 1 /t REG_DWORD

## Mount Default User Account
###########################################
REG LOAD HKLM\DefaultUser C:\Users\Default\NTUSER.DAT


## Login screen customizations
###########################################

# Disable login screen blur
REG ADD "HKLM\Software\Policies\Microsoft\Windows\System" /v DisableAcrylicBackgroundOnLogon /d 1 /t REG_DWORD /f

# Disable first logon animation screen
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableFirstLogonAnimation /d 0 /t REG_DWORD /f
REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v EnableFirstLogonAnimation /d 0 /t REG_DWORD /f
###########################################


## Start menu/taskbar customizations
###########################################

# Show more pins on Start
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_Layout /d 1 /t REG_DWORD /f

# Hide Recommended on Start (only works on Education and Enterprise)
REG ADD "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v HideRecommendedSection /d 1 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Policies\Microsoft\Windows\Explorer" /v HideRecommendedSection /d 1 /t REG_DWORD /f

# Remove search from taskbar + make search local-only
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Search" /v SearchboxTaskbarMode /d 0 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /d 0 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Policies\Microsoft\Windows\Explorer" /v DisableSearchBoxSuggestions  /d 1 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Feeds\DSB" /v ShowDynamicContent /d 0 /t REG_DWORD /f
REG ADD "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v SearchOnTaskbarMode /d 0 /t REG_DWORD /f
REG ADD "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v EnableDynamicContentInWSB /d 0 /t REG_DWORD /f
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /v IsDynamicSearchBoxEnabled /d 0 /t REG_DWORD /f
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Feeds\DSB" /v OpenOnHover /d 0 /t REG_DWORD /f
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Feeds\DSB" /v ShowDynamicContent /d 0 /t REG_DWORD /f

# Remove Copilot from taskbar
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowCopilotButton /d 0 /t REG_DWORD /f

# Remove weather/news from taskbar
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Feeds" /v ShellFeedsTaskbarViewMode /d 2 /t REG_DWORD /f

# Remove Widgets
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarDa /d 0 /t REG_DWORD /f
REG ADD "HKLM\Software\Microsoft\PolicyManager\default\NewsAndInterests\AllowNewsAndInterests" /v value /t REG_DWORD /d 0 /f
REG ADD "HKLM\Software\Policies\Microsoft\Dsh" /v AllowNewsAndInterests /t REG_DWORD /d 0 /f

# Remove Chat from taskbar
REG ADD "HKLM\Software\Policies\Microsoft\Windows\Windows Chat" /v ChatIcon /d 2 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarMn /d 0 /t REG_DWORD /f

# Remove People from taskbar (deprecated?)
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v PeopleBand /d 0 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v CapacityOfPeopleBar /d 0 /t REG_DWORD /f
###########################################


## Window customizations 
###########################################

# Disable Aero Shake
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v DisallowShaking /d 1 /t REG_DWORD /f

# Dark mode registry keys (they don't work but no harm having them here for reference)
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v AppsUseLightTheme /d 0 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v SystemUsesLightTheme /d 0 /t REG_DWORD /f

# Show color on title bars
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\DWM" /v ColorPrevalence /d 1 /t REG_DWORD /f

# Always show scrollbars
REG ADD "HKLM\DefaultUser\Control Panel\Accessibility" /v DynamicScrollbars /d 0 /t REG_DWORD /f
###########################################


## File Explorer customizations
###########################################

# File Explorer default to This PC
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v LaunchTo /d 1 /t REG_DWORD /f

# Add Recycle Bin to navigation pane
REG ADD "HKLM\Software\Classes\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}" /v System.IsPinnedToNameSpaceTree /d 1 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Classes\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}" /v System.IsPinnedToNameSpaceTree /d 1 /t REG_DWORD /f

# Remove Gallery from navigation pane
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\NonEnum" /v "{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" /d 1 /t REG_DWORD /f

# Remove Network from navigation pane
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\NonEnum" /v "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" /d 1 /t REG_DWORD /f

# Remove duplicate drives from navigation pane
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\NonEnum" /v "{F5FB2C77-0E2F-4A16-A381-3E560C68BC83}" /d 1 /t REG_DWORD /f

# Disable recommended section on Home tab
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer" /v ShowRecommendations /d 0 /t REG_DWORD /f

# Show all file extensions by default
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /d 0 /t REG_DWORD /f

# Small icon view in Control Panel
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" /v StartupPage /d 1 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" /v AllItemsIconView /d 1 /t REG_DWORD /f

# Launch Explorer windows in separate processes
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v SeparateProcess /d 1 /t REG_DWORD /f
###########################################


## Microsoft Edge customizations
###########################################

REG ADD "HKLM\DefaultUser\Software\Microsoft\Edge" /v HideFirstRunExperience /d 1 /t REG_DWORD /f
REG ADD "HKLM\Software\Policies\Microsoft\MicrosoftEdge\Main" /v PreventFirstRunPage /d 1 /t REG_DWORD /f
REG ADD "HKLM\Software\Policies\Microsoft\EdgeUpdate" /v CreateDesktopShortcutDefault /d 0 /t REG_DWORD /f
REG ADD "HKLM\Software\Policies\Microsoft\Edge" /v HideFirstRunExperience /t REG_DWORD /d 1 /f
REG ADD "HKLM\Software\Policies\Microsoft\Edge" /v HubsSidebarEnabled /t REG_DWORD /d 0 /f
REG ADD "HKLM\Software\Policies\Microsoft\Edge" /v SpotlightExperiencesAndRecommendationsEnabled /t REG_DWORD /d 0 /f
REG ADD "HKLM\Software\Policies\Microsoft\Edge" /v ShowAcrobatSubscriptionButton /t REG_DWORD /d 0 /f
REG ADD "HKLM\Software\Policies\Microsoft\Edge" /v NewTabPageContentEnabled /t REG_DWORD /d 0 /f
REG ADD "HKLM\Software\Policies\Microsoft\Edge" /v NewTabPageHideDefaultTopSites /t REG_DWORD /d 1 /f
REG ADD "HKLM\Software\Policies\Microsoft\Edge" /v NewTabPageQuickLinksEnabled /t REG_DWORD /d 0 /f
REG ADD "HKLM\Software\Policies\Microsoft\Edge" /v ShowPDFDefaultRecommendationsEnabled /t REG_DWORD /d 0 /f
REG ADD "HKLM\Software\Policies\Microsoft\Edge" /v DefaultBrowserSettingsCampaignEnabled /t REG_DWORD /d 0 /f
REG ADD "HKLM\Software\Policies\Microsoft\Edge" /v ShowRecommendationsEnabled /t REG_DWORD /d 0 /f
REG ADD "HKLM\Software\Policies\Microsoft\Edge" /v PersonalizationReportingEnabled /t REG_DWORD /d 0 /f
REG ADD "HKLM\Software\Policies\Microsoft\Edge" /v TextPredictionEnabled /t REG_DWORD /d 0 /f
REG ADD "HKLM\Software\Policies\Microsoft\Edge" /v ComposeInlineEnabled /t REG_DWORD /d 0 /f
REG ADD "HKLM\Software\Policies\Microsoft\Edge" /v SearchInSidebarEnabled /t REG_DWORD /d 2 /f
REG ADD "HKLM\Software\Policies\Microsoft\Edge" /v UploadFromPhoneEnabled /t REG_DWORD /d 0 /f
REG ADD "HKLM\Software\Policies\Microsoft\Edge" /v UrlDiagnosticDataEnabled /t REG_DWORD /d 0 /f
REG ADD "HKLM\Software\Policies\Microsoft\Edge" /v DiagnosticData /t REG_DWORD /d 0 /f
REG ADD "HKLM\Software\Policies\Microsoft\Edge" /v TabServicesEnabled /t REG_DWORD /d 0 /f
REG ADD "HKLM\Software\Policies\Microsoft\Edge" /v ShowDownloadsToolbarButton /t REG_DWORD /d 1 /f
REG ADD "HKLM\Software\Policies\Microsoft\Edge\Recommended" /v StartupBoostEnabled /t REG_DWORD /d 0 /f
REG ADD "HKLM\Software\Policies\Microsoft\Edge\Recommended" /v QuickSearchShowMiniMenu /t REG_DWORD /d 0 /f
REG ADD "HKLM\Software\Policies\Microsoft\Edge\Recommended" /v VisualSearchEnabled /t REG_DWORD /d 0 /f
REG ADD "HKLM\Software\Policies\Microsoft\Edge\Recommended" /v PinBrowserEssentialsToolbarButton /t REG_DWORD /d 0 /f
REG ADD "HKLM\Software\Policies\Microsoft\Edge\Recommended" /v EdgeShoppingAssistantEnabled /t REG_DWORD /d 0 /f
REG ADD "HKLM\Software\Policies\Microsoft\Edge\Recommended" /v WalletDonationEnabled /t REG_DWORD /d 0 /f
###########################################


## Backend Customizations
###########################################
# Disable background profile sign in on restart (not to be confused with Autologon)
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableAutomaticRestartSignOn /d 1 /t REG_DWORD /f

# Disable thumbnail cache
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v DisableThumbnailCache /d 1 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v DisableThumbsDBOnNetworkFolders /d 1 /t REG_DWORD /f

# Disable compression on wallpapers
REG ADD "HKLM\DefaultUser\Control Panel\Desktop" /v JPEGImportQuality /t REG_DWORD /d 0x00000064 /f

# Reduce delay for startup apps
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v StartupDelayInMSec /d 0 /t REG_DWORD /f

# Reduce app forced shutdown delay
REG ADD "HKLM\DefaultUser\Control Panel\Desktop" /v HungAppTimeout /d "1000" /t REG_SZ /f

# Disable auto-installing Store apps
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Communications" /v ConfigureChatAutoInstall /d 0 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /d 0 /t REG_DWORD /f
REG DELETE "HKLM\Software\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\DevHomeUpdate" /va /f
REG DELETE "HKLM\Software\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate" /va /f

# Disable account nags on Start menu & settings
REG ADD "HKLM\DefaultUser\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_AccountNotifications /d 0 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Microsoft\Windows\CurrentVersion\SystemSettings\AccountNotifications" /v DisableAccountNotifications /d 1 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Policies\Microsoft\Windows\CurrentVersion\AccountNotifications" /v DisableAccountNotifications /d 1 /t REG_DWORD /f

# Disable new app installed association notifications
REG ADD "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v NoNewAppAlert /d 1 /t REG_DWORD /f

# Disable tips and suggestions
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_IrisRecommendations /d 0 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSyncProviderNotifications /d 0 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /d 0 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SoftLandingEnabled /d 0 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-310093Enabled /d 0 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338388Enabled /d 0 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338389Enabled /d 0 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338393Enabled /d 0 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353694Enabled /d 0 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353696Enabled /d 0 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353698Enabled /d 0 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.ActionCenter.SmartOptOut" /v Enabled /d 0 /t REG_DWORD /f

# Disable lock screen tips but keep Spotlight functional (maybe?)
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v ContentDeliveryAllowed /d 1 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v RotatingLockScreenEnabled /d 1 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v RotatingLockScreenOverlayEnabled /d 0 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338387Enabled /d 0 /t REG_DWORD /f

# Disable System requirements not met message in Settings (deprecated?)
REG ADD "HKLM\DefaultUser\Control Panel\UnsupportedHardwareNotificationCache" /v SV1 /t REG_DWORD /d 0 /f
REG ADD "HKLM\DefaultUser\Control Panel\UnsupportedHardwareNotificationCache" /v SV2 /t REG_DWORD /d 0 /f
REG ADD "HKLM\DefaultUser\Control Panel\UnsupportedHardwareNotificationCache" /v SV3 /t REG_DWORD /d 0 /f

# Disable full screen pop ups on login
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v ScoobeSystemSettingEnabled /d 0 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Policies\Microsoft\Windows\OOBE" /v DisablePrivacyExperience /d 1 /t REG_DWORD /f

# Disable unneeded security and maintenance notifications
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows Security Health\State" /v AccountProtection_MicrosoftAccount_Disconnected /d 0 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v Enabled /d 0 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.Suggested" /v Enabled /d 0 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.BackupReminder" /v Enabled /d 0 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.CapabilityAccess" /v Enabled /d 0 /t REG_DWORD /f

# Hide Defender summary & enhanced notifications
REG ADD "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /v DisableEnhancedNotifications /t REG_DWORD /d 1 /f
REG ADD "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Notifications" /v DisableEnhancedNotifications /t REG_DWORD /d 1 /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows Defender Security Center\Virus and threat protection" /v SummaryNotificationDisabled /d 1 /t REG_DWORD /f

# Diagnostic data settings
REG ADD "HKLM\DefaultUser\Software\Microsoft\Input\TIPC" /v Enabled /d 0 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /d 0 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Privacy" /v TailoredExperiencesWithDiagnosticDataEnabled /d 0 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Policies\Microsoft\Windows\CloudContent" /v DisableTailoredExperiencesWithDiagnosticData /d 1 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v ShowedToastAtLevel /d 1 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Siuf\Rules" /v NumberOfSIUFInPeriod /d 0 /t REG_DWORD /f

# Force disable Windows Recall (not typically available on x86 PCs)
REG ADD "HKLM\Software\Policies\Microsoft\Windows\WindowsAI" /v DisableAIDataAnalysis /d 1 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Policies\Microsoft\Windows\WindowsAI" /v DisableAIDataAnalysis /d 1 /t REG_DWORD /f

###########################################


## Attempt to block more BS advertising (and malware looking pop ups)
###########################################
# This attempts to block the BGAUpsell.exe pop ups from being deployed by locking the folder path down.
# All permissions except for Administrators to view and modify folder permissions are removed.
# These pop ups advertise Bing, Copilot, and other AI features, especially if you use Chrome.
# This is a shot in the dark, it can be easily reversed by Microsoft.
$folderPath = "C:\Windows\Temp\MUBSTemp"
if (Test-Path $folderPath) { Remove-Item -Path $folderPath -Recurse -Force }
New-Item -Path $folderPath -ItemType Directory
$acl = New-Object System.Security.AccessControl.DirectorySecurity
# Get the SID for the Administrators group
$AdministratorsGroupSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
# Disable inheritance and remove all existing permissions
$acl.SetAccessRuleProtection($true, $false)
# Set up the access rule for Administrators (only modify permissions and read permissions)
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $AdministratorsGroupSID, 
    "ReadPermissions, ChangePermissions", 
    "ContainerInherit, ObjectInherit", 
    "None", 
    "Allow")
# Add the access rule to the ACL
$acl.AddAccessRule($accessRule)
# Set the ACL to the folder
Set-Acl -Path $folderPath -AclObject $acl
###########################################


## Office customizations
###########################################

# Default Word to standard white document mode
REG ADD "HKLM\DefaultUser\Software\Microsoft\Office\16.0\Word\Options" /v DisableDarkMode /d 1 /t REG_DWORD /f

# Disable auto opening attachments in Reading View
REG ADD "HKLM\DefaultUser\Software\Microsoft\Office\16.0\Word\Options" /v AllowAutoReadingMode /d 0 /t REG_DWORD /f

# Disable first-run prompts
REG ADD "HKLM\DefaultUser\Software\Microsoft\Office\16.0\Common" /v qmenable /d 0 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Office\16.0\Common" /v TurnOffPhotograph /d 1 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Office\16.0\Common" /v PrivacyNoticeShown /d 2 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Office\16.0\Common\General" /v shownfirstrunoptin /d 1 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Office\16.0\Common\General" /v ShownFileFmtPrompt /d 1 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Office\16.0\Common\PTWatson" /v PTWOptIn /d 0 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Office\16.0\FirstRun" /v BootedRTM /d 1 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Office\16.0\FirstRun" /v disablemovie /d 1 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Office\16.0\Registration" /v AcceptAllEulas /d 1 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Office\16.0\Common\Privacy\SettingsStore\Anonymous" /v ConnectedExperiencesNoticeVersion /d 1 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Office\16.0\Common\Privacy\SettingsStore\Anonymous" /v RequiredDiagnosticDataNoticeVersion /d 1 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Office\16.0\Common\Privacy\SettingsStore\Anonymous" /v OptionalDiagnosticDataConsentVersion /d 1 /t REG_DWORD /f

# Disable Outlook Mobile prompts
REG ADD "HKLM\DefaultUser\Software\Microsoft\Office\16.0\Outlook\Setup" /v SetupOutlookMobileWebPageOpened /d 1 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Office\16.0\Outlook\Options\General" /v DisableOutlookMobileHyperlink /d 1 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Policies\Microsoft\Office\16.0\Outlook\Options\General" /v DisableOutlookMobileHyperlink /d 1 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Policies\Microsoft\Office\16.0\Outlook\Setup" /v SetupOutlookMobileWebPageOpened /d 1 /t REG_DWORD /f
###########################################


## OneDrive refinement 
###########################################

# Remove 32-bit user OneDrive installer
REG DELETE "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Run" /v OneDriveSetup /f

# OneDrive for Business Team Site instant auto mount (QoL tweak for Enterprise/Education environments)
REG ADD "HKLM\DefaultUser\Software\Microsoft\OneDrive\Accounts\Business1" /v TimerAutoMount /d 1 /t REG_QWORD /f
###########################################


## Unmount Default User Account
###########################################
REG UNLOAD HKLM\DefaultUser


###########################################
 # # # FINAL RUN # # # ###################
###########################################

# Optimize all volumes
defrag /allvolumes /o


###########################################

Remove-Item $MyInvocation.MyCommand.Source -Force
