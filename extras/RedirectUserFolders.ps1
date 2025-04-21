do {
    $driveLetter = Read-Host "Enter a drive letter (A-Z)"
    $drivePath = "$driveLetter`:"

    if (!(Test-Path $drivePath)) {
        Write-Host "Drive $drivePath does not exist." -ForegroundColor Red
        continue
    }

    $fs = (Get-Volume -DriveLetter $driveLetter.ToUpper() -ErrorAction SilentlyContinue).FileSystem
    if ($fs -ne "NTFS") {
        Write-Host "Drive $drivePath is not NTFS (found $fs)." -ForegroundColor Red
        continue
    }

    $confirm = Read-Host "Use drive $drivePath? (Y/N)"
} while ($confirm -notmatch '^[Yy]$')

$targetRoot = "$driveLetter`:\"


$folders = @{
    "Desktop"        = "$targetRoot\Desktop"
    "Personal"       = "$targetRoot\Documents"
    "{374DE290-123F-4565-9164-39C4925E467B}" = "$targetRoot\Downloads"
    "My Music"       = "$targetRoot\Music"
    "My Pictures"    = "$targetRoot\Pictures"
    "My Video"       = "$targetRoot\Videos"
    "{4C5C32FF-BB9D-43b0-B5B4-2D72E54EAAA4}" = "$targetRoot\Saved Games"
}

$defaultPaths = @{
    "Desktop"        = "$env:USERPROFILE\Desktop"
    "Personal"       = "$env:USERPROFILE\Documents"
    "{374DE290-123F-4565-9164-39C4925E467B}" = "$env:USERPROFILE\Downloads"
    "My Music"       = "$env:USERPROFILE\Music"
    "My Pictures"    = "$env:USERPROFILE\Pictures"
    "My Video"       = "$env:USERPROFILE\Videos"
    "{4C5C32FF-BB9D-43b0-B5B4-2D72E54EAAA4}" = "$env:USERPROFILE\Saved Games"
}

function Set-RegistryExpandString {
    param (
        [string]$ValueName,
        [string]$ValueData
    )

    $regKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey(
        "Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders", $true
    )

    if ($regKey) {
        $regKey.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::ExpandString)
        $regKey.Close()
    } else {
        throw "Unable to open registry key for writing."
    }
}

foreach ($regName in $folders.Keys) {
    $newPath = $folders[$regName]
    $sourcePath = $null

    if (-not (Test-Path $newPath)) {
        New-Item -ItemType Directory -Path $newPath | Out-Null
    }

    try {
        $regProps = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
        if ($regProps.PSObject.Properties.Name -contains $regName) {
            $currentRaw = $regProps.$regName
            $sourcePath = [Environment]::ExpandEnvironmentVariables($currentRaw)
        } else {
            $sourcePath = $defaultPaths[$regName]
            Write-Host "Registry key '$regName' not found. Using default: $sourcePath"
        }
    } catch {
        $sourcePath = $defaultPaths[$regName]
        Write-Host "Failed to read registry for '$regName'. Using default: $sourcePath"
    }

    if ($sourcePath -eq $newPath) {
        Write-Host "$regName is already redirected. Skipping."
        continue
    }

    if ([string]::IsNullOrWhiteSpace($sourcePath)) {
        Write-Host "Source path for '$regName' is empty. Skipping."
        continue
    }

    if (Test-Path $sourcePath) {
        try {
            Write-Host "Moving files from '$sourcePath' to '$newPath'..."
            Copy-Item -Path "$sourcePath\*" -Destination $newPath -Recurse -Force -ErrorAction Stop
        } catch {
            Write-Warning "Failed to copy from '$sourcePath' to '$newPath'"
        }

        try {
            Remove-Item -Path $sourcePath -Recurse -Force -ErrorAction Stop
            Write-Host "Deleted original folder: $sourcePath"
        } catch {
            Write-Warning "Failed to delete original folder: $sourcePath"
        }
    } else {
        Write-Host "Source folder '$sourcePath' does not exist. Skipping file move for $regName."
    }

    Set-RegistryExpandString -ValueName $regName -ValueData $newPath
    Write-Host "Registry updated for $regName"
}

Write-Host "Restarting Explorer to apply changes..."
Stop-Process -Name explorer -Force
Start-Process explorer.exe

Write-Host "All folders redirected successfully."
