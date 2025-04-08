################################################################################
# Functions
################################################################################
function Write-Status {
    param(
        [string]$Message,
        [System.ConsoleColor]$ForegroundColor = [System.ConsoleColor]::Cyan,
        [System.ConsoleColor]$BackgroundColor = $Host.UI.RawUI.BackgroundColor
    )
    Write-Host "[$((Get-Date).ToString('HH:mm:ss'))] $Message" -ForegroundColor $ForegroundColor -BackgroundColor $BackgroundColor
}

function Test-Windows11 {
    $info = [Environment]::OSVersion.Version
    $Major = $info.Major
    if ($info.Build -ge 22000) {
        $Major = 11
    }
    $OSVersion = [System.Version]::new($Major, $info.Minor, $info.Build)
    Write-Status ("Windows Version: {0}.{1}.{2}" -f $OSVersion.Major, $OSVersion.Minor, $OSVersion.Build)

    if ($Major -lt 11) {
        Write-Status "This script is designed for Windows 11. Current OS version: Windows $Major" -ForegroundColor Red
        return $false
    }
    return $true
}

function Test-AdminPrivileges {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Status "This script requires administrator privileges. Please run as administrator." -ForegroundColor Red
        Exit 1
    }
}

function Invoke-RegCommand {
    param([string]$Command)
    try {
        Invoke-Expression "cmd /c $Command" | Out-Null
        return $true
    }
    catch {
        Write-Status "Error executing: $Command" -ForegroundColor Red
        Write-Status $_.Exception.Message -ForegroundColor Red
        return $false
    }
}

################################################################################
# Script starts here
################################################################################

# Get the ID and security principal of the current user account
$myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)

# Set script to stop on first error
$ErrorActionPreference = "Stop"

# Create a log file
$logFile = "$env:USERPROFILE\Desktop\Windows11_Debloat_Log.txt"
Start-Transcript -Path $logFile -Force

# Check for Windows 11
if (-not (Test-Windows11)) {
    Write-Status "Exiting script as this is not Windows 11." -ForegroundColor Red
    Exit 1
}

# Check for admin privileges
Test-AdminPrivileges
Write-Status "Administrator privileges confirmed"

# Create a hashtable of debloat options - set to $true to enable
$options = @{
    # System settings
    "SetRegion"                = $true   # Set region to US
    "SetTimezone"              = $true   # Set timezone to Eastern
    "SetCulture"               = $true   # Set culture to en-US
    "DisableHibernation"       = $true   # Disable hibernation
    "SetDateFormat"            = $true   # Set date format to yyyy-MM-dd
    "EnableDarkTheme"          = $true   # Enable dark theme

    # App Removal
    "DisableRecall"            = $true   # Disable Recall feature
    "RemoveOneDrive"           = $true   # Remove OneDrive
    "RemoveBingSearch"         = $true   # Remove Bing Search
    "RemovePowerAutomate"      = $true   # Remove PowerAutomate
    "RemoveXboxApps"           = $true   # Remove Xbox apps
    "RemoveWidgets"            = $true   # Remove widgets
    "RemoveBloatware"          = $true   # Remove bloatware

    # Explorer settings
    "ShowFileExtensions"       = $true   # Show file extensions
    "ShowHiddenFiles"          = $true   # Show hidden files
    "HideSyncNotifications"    = $true   # Hide sync provider notifications
    "OpenToThisPC"             = $true   # Open File Explorer to This PC
    "HideRecentFiles"          = $true   # Hide recently used files
    "HideFrequentFolders"      = $true   # Hide frequently used folders
    "HideOfficeFiles"          = $true   # Hide files from Office.com
    "RestoreContextMenu"       = $true   # Restore classic context menu
    
    # Start Menu
    "HideRecentlyAddedApps"    = $true   # Hide recently added apps
    "HideRecentlyOpenedItems"  = $true   # Hide recently opened items
    "HideRecommendations"      = $true   # Hide recommendations
    
    # Taskbar
    "AlignTaskbarLeft"         = $true   # Align taskbar to the left
    "HideSearchBox"            = $true   # Hide search box
    "HideTaskViewButton"       = $true   # Hide Task View button
    
    # Final Action
    "RestartComputer"          = $false  # Restart computer when done
}

########################################
# System settings
########################################
if ($options["SetRegion"]) {
    Write-Status "Setting region to US..."
    Set-WinHomeLocation -GeoID 244
}

if ($options["SetTimezone"]) {
    Write-Status "Setting timezone to Eastern Standard Time..."
    Set-TimeZone -Name "Eastern Standard Time"
}

if ($options["SetCulture"]) {
    Write-Status "Setting culture to en-US..."
    Set-Culture -CultureInfo en-US
}

if ($options["DisableHibernation"]) {
    Write-Status "Disabling hibernation..."
    powercfg.exe /hibernate off
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
if ($options["DisableRecall"]) {
    Write-Status "Disabling Recall feature..."
    $RecallEnabled = Get-WindowsOptionalFeature -Online -FeatureName "Recall"
    if ($RecallEnabled.State -eq "Enabled") {
        Disable-WindowsOptionalFeature -FeatureName "Recall" -Online -NoRestart | Out-Null
    } else {
        Write-Status "Recall feature already disabled"
    }
}

if ($options["RemoveOneDrive"]) {
    Write-Status "Removing OneDrive..."
    winget uninstall "Microsoft.OneDrive" --accept-source-agreements
}

if ($options["RemoveBingSearch"]) {
    Write-Status "Removing Bing Search..."
    winget uninstall "Microsoft.BingSearch_8wekyb3d8bbwe" --accept-source-agreements
}

if ($options["RemovePowerAutomate"]) {
    Write-Status "Removing PowerAutomate..."
    winget uninstall "Microsoft.PowerAutomateDesktop_8wekyb3d8bbwe" --accept-source-agreements
}

if ($options["RemoveXboxApps"]) {
    Write-Status "Removing Xbox Apps..."
    $xboxApps = @(
        "Microsoft.GamingApp_8wekyb3d8bbwe",
        "Microsoft.Xbox.TCUI_8wekyb3d8bbwe",
        "Microsoft.XboxIdentityProvider_8wekyb3d8bbwe",
        "Microsoft.XboxSpeechToTextOverlay_8wekyb3d8bbwe"
    )
    
    foreach ($app in $xboxApps) {
        winget uninstall $app --accept-source-agreements
    }
}

if ($options["RemoveWidgets"]) {
    Write-Status "Removing Widgets..."
    winget uninstall "Windows Web Experience Pack" --accept-source-agreements
}

if ($options["RemoveBloatware"]) {
    Write-Status "Removing bloatware apps..."
    
    $Bloatware = @(
        "*ACGMediaPlayer*"
        "*ActiproSoftwareLLC*"
        "*AdobePhotoshopExpress*"
        "*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
        "*BubbleWitch3Saga*"
        "*CandyCrush*"
        "*Clipchamp*"
        "*Dolby*"
        "*Duolingo-LearnLanguagesforFree*"
        "*EclipseManager*"
        "*Facebook*"
        "*Flipboard*"
        "*HiddenCity*"
        "*HiddenCityMysteryofShadows*"
        "*HotspotShieldFreeVPN*"
        "*Hulu*"
        "*LinkedInforWindows*"
        "*Microsoft.Advertising.Xaml*"
        "*MicrosoftStickyNotes*"
        "*Netflix*"
        "*OneCalendar*"
        "*OutlookForWindows*"
        "*Paint*"
        "*PandoraMediaInc*"
        "*QuickAssist*"
        "*Royal Revolt*"
        "*Speed Test*"
        "*Sway*"
        "*Twitter*"
        "*Viber*"
        "*Windows.Photos*"
        "*WindowsSoundRecorder*"
        "*Wunderlist*"
        "*windowscamera*"
        "Microsoft.3DBuilder"
        "Microsoft.549981C3F5F10_8wekyb3d8bbwe"
        "Microsoft.AppConnector"
        "Microsoft.BingFoodAndDrink"
        "Microsoft.BingFinance"
        "Microsoft.BingHealthAndFitness"
        "Microsoft.BingNews"
        "Microsoft.BingSports"
        "Microsoft.BingTravel"
        "Microsoft.BingTranslator"
        "Microsoft.BingWeather"
        "Microsoft.CommsPhone"
        "Microsoft.ConnectivityStore"
        "Microsoft.Copilot"
        "Microsoft.Getstarted"
        "Microsoft.GetHelp"
        "Microsoft.Messaging"
        "Microsoft.Microsoft3DViewer"
        "Microsoft.MicrosoftOfficeHub"
        "Microsoft.MicrosoftSolitaireCollection"
        "Microsoft.NetworkSpeedTest"
        "Microsoft.Office.Lens"
        "Microsoft.Office.OneNote"
        "Microsoft.Office.Sway"
        "Microsoft.OneConnect"
        "Microsoft.OneDriveSync"
        "Microsoft.People"
        "Microsoft.Print3D"
        "Microsoft.ScreenSketch"
        "Microsoft.SkypeApp"
        "Microsoft.Todos"
        "Microsoft.Wallet"
        "Microsoft.WindowsAlarms"
        "Microsoft.WindowsFeedbackHub"
        "Microsoft.WindowsMaps"
        "Microsoft.WindowsPhone"
        "Microsoft.XboxGamingOverlay"
        "Microsoft.YourPhone"
        "Microsoft.ZuneMusic"
        "Microsoft.ZuneVideo"
        "Microsoft.windowscommunicationsapps"
        "MicrosoftTeams*"
    )
    
    foreach ($Bloat in $Bloatware) {
        Write-Status "Removing $Bloat..."
        try {
            Get-AppxPackage -AllUsers -Name $Bloat -ErrorAction SilentlyContinue | Remove-AppxPackage -ErrorAction SilentlyContinue
            Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
        } catch {
            # Continue even if there's an error
        }
    }
    
    Write-Status "Bloatware removal completed"
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
    Invoke-RegCommand 'reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d 0 /f'
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

if ($options["RestoreContextMenu"]) {
    Write-Status "Restoring classic context menu..."
    try {
        # Direct registry approach instead of using reg.exe
        if (-not (Test-Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}")) {
            New-Item -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" -Force | Out-Null
        }

        if (-not (Test-Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32")) {
            New-Item -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Force | Out-Null
        }

        # Set the default value to empty string
        Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Name "(Default)" -Value "" -Force

        Write-Status "Classic context menu restored successfully."
    } catch {
        Write-Status "Error restoring classic context menu: $_" -ForegroundColor Red
    }
}

########################################
# Start Menu
########################################
if ($options["HideRecentlyAddedApps"]) {
    Write-Status "Hiding recently added apps..."
    Invoke-RegCommand 'reg add "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "HideRecentlyAddedApps" /t REG_DWORD /d 1 /f'
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
# Refresh Explorer
Write-Status "Refreshing Explorer to apply changes..."
Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
Start-Process explorer

# Finish
Write-Status "Debloat complete!"
Stop-Transcript

# Restart if selected
if ($options["RestartComputer"]) {
    Write-Status "Restarting computer in 10 seconds..."
    Start-Sleep -Seconds 10
    Restart-Computer -Force
} else {
    Write-Status "Script complete! Find the log at: $logFile"
    Write-Status "It's recommended to restart your computer for all changes to take effect."
}