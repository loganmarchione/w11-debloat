################################################################################
# Script starts here
################################################################################

# Set script to stop on first error
$ErrorActionPreference = "Stop"

# Create a log file
$logFile = "$env:USERPROFILE\Desktop\Windows11_Debloat_Log.txt"
Start-Transcript -Path $logFile -Force

# Download and execute helper functions
try {
    $helpersUrl = "https://raw.githubusercontent.com/loganmarchione/w11-debloat/refs/heads/split/functions.ps1"
    $helpersScript = Invoke-WebRequest -UseBasicParsing -Uri $helpersUrl
    Invoke-Expression $helpersScript.Content
    Write-Status "Helper functions loaded successfully"
} catch {
    Write-Host "Failed to load helper functions: $_" -ForegroundColor Red
    Exit 1
}

# Check for Windows 11
Test-Windows11

# Check for admin privileges
# Test-AdminPrivilege
# Write-Status "Administrator privileges confirmed"

Update-WingetSources

# Create a hashtable of debloat options - set to $true to enable
$options = @{
    # System settings
    "SetRegion"                = $true   # Set region to US
    "SetTimezone"              = $true   # Set timezone to Eastern
    "SetCulture"               = $true   # Set culture to en-US
    "SetDateFormat"            = $true   # Set date format to yyyy-MM-dd
    "EnableDarkTheme"          = $true   # Enable dark theme

    # App removal
    "RemoveOneDrive"           = $true   # Remove OneDrive
    "RemoveXboxApps"           = $true   # Remove Xbox apps
    "RemoveBloatware"          = $true   # Remove bloatware

    # Explorer settings
    "ShowFileExtensions"       = $true   # Show file extensions
    "ShowHiddenFiles"          = $true   # Show hidden files
    "HideSyncNotifications"    = $true   # Hide sync provider notifications
    "OpenToThisPC"             = $true   # Open File Explorer to This PC
    "HideRecentFiles"          = $true   # Hide recently used files
    "HideFrequentFolders"      = $true   # Hide frequently used folders
    "HideOfficeFiles"          = $true   # Hide files from Office.com

    # Start Menu
    "HideRecentlyAddedApps"    = $true   # Hide recently added apps
    "HideRecentlyOpenedItems"  = $true   # Hide recently opened items
    "HideRecommendations"      = $true   # Hide recommendations
    
    # Taskbar
    "AlignTaskbarLeft"         = $true   # Align taskbar to the left
    "HideSearchBox"            = $true   # Hide search box
    "HideTaskViewButton"       = $true   # Hide Task View button
}

########################################
# System settings
########################################
if ($options["SetRegion"]) {
    Write-Status "Setting region to US..."
    Set-WinHomeLocation -GeoID 244
    # Can see current setting by running: Get-WinHomeLocation
}

if ($options["SetTimezone"]) {
    Write-Status "Setting timezone to Eastern Standard Time..."
    Set-TimeZone -Name "Eastern Standard Time"
    # Can see current setting by running: Get-TimeZone
}

if ($options["SetCulture"]) {
    Write-Status "Setting culture to en-US..."
    Set-Culture -CultureInfo en-US
    # Can see current setting by running: Get-Culture
}

if ($options["SetDateFormat"]) {
    Write-Status "Setting date format to yyyy-MM-dd..."
    Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name sShortDate -Value "yyyy-MM-dd"
}

if ($options["EnableDarkTheme"]) {
    Write-Status "Enabling dark theme..."
    Invoke-RegCommand 'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d 0 /f'
    Invoke-RegCommand 'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t REG_DWORD /d 0 /f'
}

########################################
# App Removal
########################################
if ($options["RemoveOneDrive"]) {
    Remove-OneDrive
}

if ($options["RemoveXboxApps"]) {
    Write-Status "Removing Xbox Apps..."
    $apps = @(
        "Microsoft.GamingApp_8wekyb3d8bbwe",
        "Microsoft.Xbox.TCUI_8wekyb3d8bbwe",
        "Microsoft.XboxIdentityProvider_8wekyb3d8bbwe",
        "Microsoft.XboxSpeechToTextOverlay_8wekyb3d8bbwe"
    )
    
    foreach ($app in $apps) {
        winget uninstall $app --accept-source-agreements
    }
}

if ($options["RemoveBloatware"]) {
    Write-Status "Removing bloatware apps..."

    $apps = @(
        "Microsoft.Copilot"
    )

    foreach ($app in $apps) {
        Write-Status "Removing $app..."
        try {
            Get-AppxPackage -Name $app -ErrorAction SilentlyContinue | Remove-AppxPackage -ErrorAction SilentlyContinue
            Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $app | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
        } catch {
            # Continue even if there's an error
        }
    }

    # Apparently these can only be removed with winget
    $apps = @(
        "Microsoft.BingSearch_8wekyb3d8bbwe",
        "Microsoft.PowerAutomateDesktop_8wekyb3d8bbwe",
        "Windows Web Experience Pack"
    )

    foreach ($app in $apps) {
        winget uninstall $app --accept-source-agreements
    }
}

########################################
# Explorer settings
########################################
if ($options["ShowFileExtensions"]) {
    Write-Status "Showing file extensions..."
    Invoke-RegCommand 'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f'
}

if ($options["ShowHiddenFiles"]) {
    Write-Status "Showing hidden files..."
    Invoke-RegCommand 'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f'
}

if ($options["HideSyncNotifications"]) {
    Write-Status "Hiding sync provider notifications..."
    Invoke-RegCommand 'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d 0 /f'
}

if ($options["OpenToThisPC"]) {
    Write-Status "Setting File Explorer to open to This PC..."
    Invoke-RegCommand 'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d 1 /f'
}

if ($options["HideRecentFiles"]) {
    Write-Status "Hiding recently used files..."
    Invoke-RegCommand 'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d 0 /f'
}

if ($options["HideFrequentFolders"]) {
    Write-Status "Hiding frequently used folders..."
    Invoke-RegCommand 'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowFrequent" /t REG_DWORD /d 0 /f'
}

if ($options["HideOfficeFiles"]) {
    Write-Status "Hiding files from Office.com..."
    Invoke-RegCommand 'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowCloudFilesInQuickAccess" /t REG_DWORD /d 0 /f'
}

########################################
# Start Menu
########################################
if ($options["HideRecentlyAddedApps"]) {
    Write-Status "Hiding recently added apps..."
    Invoke-RegCommand 'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Start" /v "ShowRecentList" /t REG_DWORD /d 0 /f'
}

if ($options["HideRecentlyOpenedItems"]) {
    Write-Status "Hiding recently opened items..."
    Invoke-RegCommand 'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d 0 /f'
}

if ($options["HideRecommendations"]) {
    Write-Status "Hiding recommendations..."
    Invoke-RegCommand 'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_IrisRecommendations" /t REG_DWORD /d 0 /f'
}

########################################
# Taskbar
########################################
if ($options["AlignTaskbarLeft"]) {
    Write-Status "Aligning taskbar to the left..."
    Invoke-RegCommand 'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAl" /t REG_DWORD /d 0 /f'
}

if ($options["HideSearchBox"]) {
    Write-Status "Hiding search box..."
    Invoke-RegCommand 'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f'
}

if ($options["HideTaskViewButton"]) {
    Write-Status "Hiding Task View button..."
    Invoke-RegCommand 'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d 0 /f'
}

########################################
# Final action
########################################
Restart-Explorer
Stop-Transcript
Write-Status "Script complete! Find the log at: $logFile"
Write-Status "It's recommended to restart your computer for all changes to take effect."