@echo off
TITLE Windows Customization Deployment

REM TASKKILL /IM explorer.exe /F

REM Hide duplicate disk drives in File Explorer
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\NonEnum" /v "{F5FB2C77-0E2F-4A16-A381-3E560C68BC83}" /d 1 /t REG_DWORD /f

REM Hide Network from File Explorer
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\NonEnum" /v "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" /d 1 /t REG_DWORD /f

REM Hide Edge first run experience
REG ADD "HKLM\Software\Microsoft\Edge" /v HideFirstRunExperience /d 1 /t REG_DWORD /f
REG ADD "HKLM\Software\Policies\Microsoft\Edge" /v HideFirstRunExperience /d 1 /t REG_DWORD /f
REG ADD "HKLM\Software\Policies\Microsoft\MicrosoftEdge\Main" /v PreventFirstRunPage /d 1 /t REG_DWORD /f
REG ADD "HKLM\Software\Policies\Microsoft\MicrosoftEdge\Main" /v AllowPrelaunch /d 0 /t REG_DWORD /f

REM Disable WMP first run prompts
REG ADD "HKLM\Software\Policies\Microsoft\WindowsMediaPlayer" /v GroupPrivacyAcceptance /d 1 /t REG_DWORD /f
REG ADD "HKLM\Software\Microsoft\MediaPlayer\Preferences" /v FirstTime /d 1 /t REG_DWORD /f
REG ADD "HKLM\Software\Microsoft\MediaPlayer\Preferences" /v AcceptedEULA /d 1 /t REG_DWORD /f

REM More Windows 10 BS
REG ADD "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /d 1 /t REG_DWORD /f
REG ADD "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /d 1 /t REG_DWORD /f
REG ADD "HKLM\Software\Policies\Microsoft\Windows\Windows Feeds" /v EnableFeeds /d 0 /t REG_DWORD /f
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\OOBE" /v DisableVoice /d 1 /t REG_DWORD /f

REM Disable Automatic Restart Sign On
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableAutomaticRestartSignOn /d 1 /t REG_DWORD /f

REM Show Ribbon as default (W10)
REG ADD "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v ExplorerRibbonStartsMinimized /d 4 /t REG_DWORD /f

REM Allow non-admins to install printer drivers
REG ADD "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v RestrictDriverInstallationToAdministrators /d 0 /t REG_DWORD /f

REM Disable login screen blur
REG ADD "HKLM\Software\Policies\Microsoft\Windows\System" /v DisableAcrylicBackgroundOnLogon /d 1 /t REG_DWORD /f

REM Disable settings tips
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v AllowOnlineTips /d 0 /t REG_DWORD /f

REM Disable auto network device discovery
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" /v AutoSetup /d 0 /t REG_DWORD /f
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Public" /v AutoSetup /d 0 /t REG_DWORD /f
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Domain" /v AutoSetup /d 0 /t REG_DWORD /f

REM Disable installing Chat and Teams (W11)
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Communications" /v ConfigureChatAutoInstall /d 0 /t REG_DWORD /f

REM Show color on title bars
REG ADD "HKCU\Software\Microsoft\Windows\DWM" /v ColorPrevalence /d 1 /t REG_DWORD /f

REM Show color on start/taskbar
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v ColorPrevalence /d 0 /t REG_DWORD /f

REM Remove People from taskbar (W10)
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v PeopleBand /d 0 /t REG_DWORD /f

REM Remove search from taskbar
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v SearchboxTaskbarMode /d 0 /t REG_DWORD /f

REM Remove Widgets from taskbar (W11)
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarDa /d 0 /t REG_DWORD /f

REM Remove Chat from taskbar (W11)
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarMn /d 0 /t REG_DWORD /f

REM Hide Edge first run experience
REG ADD "HKCU\Software\Microsoft\Edge" /v HideFirstRunExperience /d 1 /t REG_DWORD /f
REG ADD "HKCU\Software\Policies\Microsoft\Edge" /v HideFirstRunExperience /d 1 /t REG_DWORD /f

REM Disable thumbnail cache
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v DisableThumbnailCache /d 1 /t REG_DWORD /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v DisableThumbsDBOnNetworkFolders /d 1 /t REG_DWORD /f

REM File Explorer default to This PC
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v LaunchTo /d 1 /t REG_DWORD /f

REM File Explorer windows run in separate processes
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v SeparateProcess /d 1 /t REG_DWORD /f

REM Show all file extensions by default
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /d 0 /t REG_DWORD /f

REM Show more pins by default (W11)
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_Layout /d 1 /t REG_DWORD /f

REM Disable App Startup Delay
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v StartupDelayInMSec /d 0 /t REG_DWORD /f

REM Small icon view in Control Panel
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" /v StartupPage /d 1 /t REG_DWORD /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" /v AllItemsIconView /d 1 /t REG_DWORD /f

REM Disable start menu suggestions (W10)
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /d 0 /t REG_DWORD /f

REM Disable Tips (W10)
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SoftLandingEnabled /d 0 /t REG_DWORD /f

REM Disable Auto Account Wizard (W10)
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v ScoobeSystemSettingEnabled /d 0 /t REG_DWORD /f

REM Disabled Sec and maint popups (W10)
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v Enabled /d 0 /t REG_DWORD /f
REG ADD "HKCU\Software\Microsoft\Windows Security Health\State" /v AccountProtection_MicrosoftAccount_Disconnected /d 0 /t REG_DWORD /f

REM Dark Mode as Default
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v SystemUsesLightTheme /d 0 /t REG_DWORD /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v AppsUseLightTheme /d 0 /t REG_DWORD /f

REM Office customizations
REG ADD "HKCU\Software\Microsoft\Office\16.0\Common" /v qmenable /d 0 /t REG_DWORD /f
REG ADD "HKCU\Software\Microsoft\Office\16.0\Common" /v TurnOffPhotograph /d 1 /t REG_DWORD /f
REG ADD "HKCU\Software\Microsoft\Office\16.0\Common" /v PrivacyNoticeShown /d 2 /t REG_DWORD /f
REG ADD "HKCU\Software\Microsoft\Office\16.0\Common\General" /v shownfirstrunoptin /d 1 /t REG_DWORD /f
REG ADD "HKCU\Software\Microsoft\Office\16.0\Common\General" /v ShownFileFmtPrompt /d 1 /t REG_DWORD /f
REG ADD "HKCU\Software\Microsoft\Office\16.0\Common\PTWatson" /v PTWOptIn /d 0 /t REG_DWORD /f
REG ADD "HKCU\Software\Microsoft\Office\16.0\FirstRun" /v BootedRTM /d 1 /t REG_DWORD /f
REG ADD "HKCU\Software\Microsoft\Office\16.0\FirstRun" /v disablemovie /d 1 /t REG_DWORD /f
REG ADD "HKCU\Software\Microsoft\Office\16.0\Registration" /v AcceptAllEulas /d 1 /t REG_DWORD /f
REG ADD "HKCU\Software\Microsoft\Office\16.0\Word\Options" /v AllowAutoReadingMode /d 0 /t REG_DWORD /f
REG ADD "HKCU\Software\Microsoft\Office\16.0\Word\Options" /v DisableDarkMode /d 1 /t REG_DWORD /f
REG ADD "HKCU\Software\Microsoft\Office\16.0\Outlook\Setup" /v SetupOutlookMobileWebPageOpened /d 1 /t REG_DWORD /f
REG ADD "HKCU\Software\Microsoft\Office\16.0\Outlook\Options\General" /v DisableOutlookMobileHyperlink /d 1 /t REG_DWORD /f
REG ADD "HKCU\Software\Policies\Microsoft\Office\16.0\Outlook\Options\General" /v DisableOutlookMobileHyperlink /d 1 /t REG_DWORD /f
REG ADD "HKCU\Software\Policies\Microsoft\Office\16.0\Outlook\Setup" /v SetupOutlookMobileWebPageOpened /d 1 /t REG_DWORD /f
REG ADD "HKCU\Software\Microsoft\Office\16.0\Common\Privacy\SettingsStore\Anonymous" /v ConnectedExperiencesNoticeVersion /d 1 /t REG_DWORD /f
REG ADD "HKCU\Software\Microsoft\Office\16.0\Common\Privacy\SettingsStore\Anonymous" /v RequiredDiagnosticDataNoticeVersion /d 1 /t REG_DWORD /f
REG ADD "HKCU\Software\Microsoft\Office\16.0\Common\Privacy\SettingsStore\Anonymous" /v OptionalDiagnosticDataConsentVersion /d 1 /t REG_DWORD /f

REM Show color on title bars
REG ADD "HKU\CurrentUsersDefault\Software\Microsoft\Windows\DWM" /v ColorPrevalence /d 1 /t REG_DWORD /f

REM Show color on start/taskbar
REG ADD "HKU\CurrentUsersDefault\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v ColorPrevalence /d 0 /t REG_DWORD /f

REM Remove People from taskbar (W10)
REG ADD "HKU\CurrentUsersDefault\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v PeopleBand /d 0 /t REG_DWORD /f

REM Remove search from taskbar
REG ADD "HKU\CurrentUsersDefault\Software\Microsoft\Windows\CurrentVersion\Search" /v SearchboxTaskbarMode /d 0 /t REG_DWORD /f

REM Remove Widgets from taskbar (W11)
REG ADD "HKU\CurrentUsersDefault\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarDa /d 0 /t REG_DWORD /f

REM Remove Chat from taskbar (W11)
REG ADD "HKU\CurrentUsersDefault\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarMn /d 0 /t REG_DWORD /f

REM Hide Edge first run experience
REG ADD "HKU\CurrentUsersDefault\Software\Microsoft\Edge" /v HideFirstRunExperience /d 1 /t REG_DWORD /f
REG ADD "HKU\CurrentUsersDefault\Software\Policies\Microsoft\Edge" /v HideFirstRunExperience /d 1 /t REG_DWORD /f

REM Disable thumbnail cache
REG ADD "HKU\CurrentUsersDefault\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v DisableThumbnailCache /d 1 /t REG_DWORD /f
REG ADD "HKU\CurrentUsersDefault\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v DisableThumbsDBOnNetworkFolders /d 1 /t REG_DWORD /f

REM File Explorer default to This PC
REG ADD "HKU\CurrentUsersDefault\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v LaunchTo /d 1 /t REG_DWORD /f

REM File Explorer windows run in separate processes
REG ADD "HKU\CurrentUsersDefault\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v SeparateProcess /d 1 /t REG_DWORD /f

REM Show all file extensions by default
REG ADD "HKU\CurrentUsersDefault\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /d 0 /t REG_DWORD /f

REM Show more pins by default (W11)
REG ADD "HKU\CurrentUsersDefault\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_Layout /d 1 /t REG_DWORD /f

REM Disable App Startup Delay
REG ADD "HKU\CurrentUsersDefault\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v StartupDelayInMSec /d 0 /t REG_DWORD /f

REM Small icon view in Control Panel
REG ADD "HKU\CurrentUsersDefault\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" /v StartupPage /d 1 /t REG_DWORD /f
REG ADD "HKU\CurrentUsersDefault\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" /v AllItemsIconView /d 1 /t REG_DWORD /f

REM Disable start menu suggestions (W10)
REG ADD "HKU\CurrentUsersDefault\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /d 0 /t REG_DWORD /f

REM Disable Tips (W10)
REG ADD "HKU\CurrentUsersDefault\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SoftLandingEnabled /d 0 /t REG_DWORD /f

REM Disable Auto Account Wizard (W10)
REG ADD "HKU\CurrentUsersDefault\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v ScoobeSystemSettingEnabled /d 0 /t REG_DWORD /f

REM Disabled Sec and maint popups (W10)
REG ADD "HKU\CurrentUsersDefault\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v Enabled /d 0 /t REG_DWORD /f
REG ADD "HKU\CurrentUsersDefault\Software\Microsoft\Windows Security Health\State" /v AccountProtection_MicrosoftAccount_Disconnected /d 0 /t REG_DWORD /f

REM Dark Mode as Default
REG ADD "HKU\CurrentUsersDefault\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v SystemUsesLightTheme /d 0 /t REG_DWORD /f
REG ADD "HKU\CurrentUsersDefault\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v AppsUseLightTheme /d 0 /t REG_DWORD /f

REM Office customizations
REG ADD "HKU\CurrentUsersDefault\Software\Microsoft\Office\16.0\Common" /v qmenable /d 0 /t REG_DWORD /f
REG ADD "HKU\CurrentUsersDefault\Software\Microsoft\Office\16.0\Common" /v TurnOffPhotograph /d 1 /t REG_DWORD /f
REG ADD "HKU\CurrentUsersDefault\Software\Microsoft\Office\16.0\Common" /v PrivacyNoticeShown /d 2 /t REG_DWORD /f
REG ADD "HKU\CurrentUsersDefault\Software\Microsoft\Office\16.0\Common\General" /v shownfirstrunoptin /d 1 /t REG_DWORD /f
REG ADD "HKU\CurrentUsersDefault\Software\Microsoft\Office\16.0\Common\General" /v ShownFileFmtPrompt /d 1 /t REG_DWORD /f
REG ADD "HKU\CurrentUsersDefault\Software\Microsoft\Office\16.0\Common\PTWatson" /v PTWOptIn /d 0 /t REG_DWORD /f
REG ADD "HKU\CurrentUsersDefault\Software\Microsoft\Office\16.0\FirstRun" /v BootedRTM /d 1 /t REG_DWORD /f
REG ADD "HKU\CurrentUsersDefault\Software\Microsoft\Office\16.0\FirstRun" /v disablemovie /d 1 /t REG_DWORD /f
REG ADD "HKU\CurrentUsersDefault\Software\Microsoft\Office\16.0\Registration" /v AcceptAllEulas /d 1 /t REG_DWORD /f
REG ADD "HKU\CurrentUsersDefault\Software\Microsoft\Office\16.0\Word\Options" /v AllowAutoReadingMode /d 0 /t REG_DWORD /f
REG ADD "HKU\CurrentUsersDefault\Software\Microsoft\Office\16.0\Word\Options" /v DisableDarkMode /d 1 /t REG_DWORD /f
REG ADD "HKU\CurrentUsersDefault\Software\Microsoft\Office\16.0\Outlook\Setup" /v SetupOutlookMobileWebPageOpened /d 1 /t REG_DWORD /f
REG ADD "HKU\CurrentUsersDefault\Software\Microsoft\Office\16.0\Outlook\Options\General" /v DisableOutlookMobileHyperlink /d 1 /t REG_DWORD /f
REG ADD "HKU\CurrentUsersDefault\Software\Policies\Microsoft\Office\16.0\Outlook\Options\General" /v DisableOutlookMobileHyperlink /d 1 /t REG_DWORD /f
REG ADD "HKU\CurrentUsersDefault\Software\Policies\Microsoft\Office\16.0\Outlook\Setup" /v SetupOutlookMobileWebPageOpened /d 1 /t REG_DWORD /f
REG ADD "HKU\CurrentUsersDefault\Software\Microsoft\Office\16.0\Common\Privacy\SettingsStore\Anonymous" /v ConnectedExperiencesNoticeVersion /d 1 /t REG_DWORD /f
REG ADD "HKU\CurrentUsersDefault\Software\Microsoft\Office\16.0\Common\Privacy\SettingsStore\Anonymous" /v RequiredDiagnosticDataNoticeVersion /d 1 /t REG_DWORD /f
REG ADD "HKU\CurrentUsersDefault\Software\Microsoft\Office\16.0\Common\Privacy\SettingsStore\Anonymous" /v OptionalDiagnosticDataConsentVersion /d 1 /t REG_DWORD /f

REM Mount Default User Account
REG LOAD HKLM\DefaultUser C:\Users\Default\NTUSER.DAT

REM Show color on title bars
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\DWM" /v ColorPrevalence /d 1 /t REG_DWORD /f

REM Show color on start/taskbar
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v ColorPrevalence /d 0 /t REG_DWORD /f

REM Remove People from taskbar (W10)
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v PeopleBand /d 0 /t REG_DWORD /f

REM Remove search from taskbar
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Search" /v SearchboxTaskbarMode /d 0 /t REG_DWORD /f

REM Remove Widgets from taskbar (W11)
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarDa /d 0 /t REG_DWORD /f

REM Remove Chat from taskbar (W11)
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarMn /d 0 /t REG_DWORD /f

REM Hide Edge first run experience
REG ADD "HKLM\DefaultUser\Software\Microsoft\Edge" /v HideFirstRunExperience /d 1 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Policies\Microsoft\Edge" /v HideFirstRunExperience /d 1 /t REG_DWORD /f

REM Disable thumbnail cache
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v DisableThumbnailCache /d 1 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v DisableThumbsDBOnNetworkFolders /d 1 /t REG_DWORD /f

REM File Explorer default to This PC
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v LaunchTo /d 1 /t REG_DWORD /f

REM File Explorer windows run in separate processes
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v SeparateProcess /d 1 /t REG_DWORD /f

REM Show all file extensions by default
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /d 0 /t REG_DWORD /f

REM Disable App Startup Delay
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v StartupDelayInMSec /d 0 /t REG_DWORD /f

REM Small icon view in Control Panel
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" /v StartupPage /d 1 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" /v AllItemsIconView /d 1 /t REG_DWORD /f

REM Disable start menu suggestions (W10)
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /d 0 /t REG_DWORD /f

REM Disable Tips (W10)
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SoftLandingEnabled /d 0 /t REG_DWORD /f

REM Disable Auto Account Wizard (W10)
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v ScoobeSystemSettingEnabled /d 0 /t REG_DWORD /f

REM Disabled Sec and maint popups (W10)
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v Enabled /d 0 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows Security Health\State" /v AccountProtection_MicrosoftAccount_Disconnected /d 0 /t REG_DWORD /f

REM Run SetupComplete on new users
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v !SetupComplete /d "cmd /c start /min /abovenormal PowerShell -ExecutionPolicy Bypass -NoLogo -Noninteractive -NoProfile -WindowStyle Hidden -File %WINDIR%\Setup\Scripts\SetupComplete.ps1" /t REG_SZ /f

REM Dark Mode as Default
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v SystemUsesLightTheme /d 0 /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v AppsUseLightTheme /d 0 /t REG_DWORD /f

REM Office customizations
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

REM Unmount Default User Account
REG UNLOAD HKLM\DefaultUser

DEL /F /Q "%USERPROFILE%\Desktop\Microsoft Edge.lnk"
DEL /F /Q "%SYSTEMDRIVE%\Users\Public\Desktop\Microsoft Edge.lnk"

CLS

ECHO.
ECHO Please leave this window open for customizations to complete...

START /min /abovenormal PowerShell -ExecutionPolicy Bypass -NoLogo -Noninteractive -NoProfile -WindowStyle Hidden -File %WINDIR%\Setup\Scripts\SetupComplete.ps1

REM Make sure we exit
EXIT
EXIT