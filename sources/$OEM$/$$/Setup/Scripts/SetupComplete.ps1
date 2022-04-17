function Show-Notification {
    [cmdletbinding()]
    Param (
        [string]
        $ToastTitle,
        [string]
        [parameter(ValueFromPipeline)]
        $ToastText
    )

    [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
    $Template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)

    $RawXml = [xml] $Template.GetXml()
    ($RawXml.toast.visual.binding.text|where {$_.id -eq "1"}).AppendChild($RawXml.CreateTextNode($ToastTitle)) > $null
    ($RawXml.toast.visual.binding.text|where {$_.id -eq "2"}).AppendChild($RawXml.CreateTextNode($ToastText)) > $null

    $SerializedXml = New-Object Windows.Data.Xml.Dom.XmlDocument
    $SerializedXml.LoadXml($RawXml.OuterXml)

    $Toast = [Windows.UI.Notifications.ToastNotification]::new($SerializedXml)
    $Toast.Tag = "PowerShell"
    $Toast.Group = "PowerShell"
    $Toast.ExpirationTime = [DateTimeOffset]::Now.AddMinutes(1)
	$Toast.ExpiresOnReboot = $true
	$Toast.Priority = [Windows.UI.Notifications.ToastNotificationPriority]::High

    $Notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("PowerShell")
    $Notifier.Show($Toast);
}

# Refresh theme
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v SystemUsesLightTheme /d 0 /t REG_DWORD /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v AppsUseLightTheme /d 0 /t REG_DWORD /f
REG ADD "HKCU\Software\Microsoft\Windows\DWM" /v ColorPrevalence /d 1 /t REG_DWORD /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v ColorPrevalence /d 0 /t REG_DWORD /f

$imgPath=$Env:windir + "\Web\Wallpaper\Windows\img19.jpg"
$code = @' 
using System.Runtime.InteropServices; 
namespace Win32{ 
    
     public class Wallpaper{ 
        [DllImport("user32.dll", CharSet=CharSet.Auto)] 
         static extern int SystemParametersInfo (int uAction , int uParam , string lpvParam , int fuWinIni) ; 
         
         public static void SetWallpaper(string thePath){ 
            SystemParametersInfo(20,0,thePath,3); 
         }
    }
 } 
'@

add-type $code
[Win32.Wallpaper]::SetWallpaper($imgPath)

$Apps = @(
	"MicrosoftTeams",
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
	"Microsoft.Office.OneNote",
	"Microsoft.OneConnect",
	"Microsoft.SkypeApp",
	"Microsoft.Microsoft3DViewer",
	"Microsoft.Paint3D",
	"Microsoft.Windows.Photos",
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

Foreach ($App in $Apps) {
	
	$Pins =	@(
		"Microsoft Edge",
		"Microsoft Store"
	)
	Foreach ($Pin in $Pins) {
		((New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() | ?{$_.Name -eq $Pin}).Verbs() | ?{$_.Name.replace('&','') -match 'Unpin from taskbar'} | %{$_.DoIt(); $exec = $true}
	}
	
	$PackageFullName = (Get-AppxPackage $App).PackageFullName
	$ProPackageFullName = (Get-AppxProvisionedPackage -online | where {$_.Displayname -eq $App}).PackageName
	
	if ($PackageFullName) {
		start-sleep -Seconds 5
		remove-AppxPackage -Package $PackageFullName -AllUsers
		Show-Notification -ToastTitle "Windows is still cleaning up in the background" -ToastText "We are still cleaning up the built-in Windows apps. Please don't log off, turn off or restart your computer."
	}
	
	if ($ProPackageFullName) {
		start-sleep -Seconds 5 
		Remove-AppxProvisionedPackage -PackageName $ProPackageFullName -AllUsers -Online
	}
}

$taskname = "Initiate Store App Updates"
$taskdescription = "Initiate Store App Updates after startup"
$action = New-ScheduledTaskAction -Execute 'Powershell.exe' `
  -Argument '-Noninteractive -NoProfile -WindowStyle Hidden -Command "& { Start-Sleep 10; $update = Get-WmiObject -Namespace root\cimv2\mdm\dmmap -Class MDM_EnterpriseModernAppManagement_AppManagement01; $update.UpdateScanMethod() }"'
$trigger =  New-ScheduledTaskTrigger -AtStartup -RandomDelay (New-TimeSpan -minutes 3)
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName $taskname -Description $taskdescription -Settings $settings -User "System"

Show-Notification -ToastTitle "Windows is ready to use!" -ToastText "You can now use your computer normally. Enjoy!"

Start-Sleep 10
$update = Get-WmiObject -Namespace root\cimv2\mdm\dmmap -Class MDM_EnterpriseModernAppManagement_AppManagement01
$update.UpdateScanMethod()
Start-Sleep 10
$update.UpdateScanMethod()