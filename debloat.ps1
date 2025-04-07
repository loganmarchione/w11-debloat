# Windows 11 Debloat Script (Optimized)

# Get the ID and security principal of the current user account
$myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)

# Set script to stop on first error
$ErrorActionPreference = "Stop"

# Create a log file
$logFile = "$env:USERPROFILE\Desktop\Windows11_Debloat_Log.txt"
Start-Transcript -Path $logFile -Force

function Write-Status {
    param([string]$Message)
    Write-Host "[$((Get-Date).ToString('HH:mm:ss'))] $Message" -ForegroundColor Cyan
}

function Test-AdminPrivileges {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "This script requires administrator privileges. Please run as administrator." -ForegroundColor Red
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
        Write-Host "Error executing: $Command" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        return $false
    }
}

# Check for admin privileges
Test-AdminPrivileges
Write-Status "Administrator privileges confirmed"

# Create a hashtable of debloat options - set to $true to enable
$options = @{
    # System
    "SetRegion"                = $true   # Set region to US
    "SetTimezone"              = $true   # Set timezone to Eastern (run `Get-TimeZone -ListAvailable` to see all)
    "SetCulture"               = $true   # Set culture to en-US
    "DisableHibernation"       = $true   # Disable hibernation
    "DisableRecall"            = $true   # Disable Recall feature
    "SetDateFormat"            = $true   # Set date format to yyyy-MM-dd
    "EnableDarkTheme"          = $true   # Enable dark theme
    
    # Explorer
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
    
    # App Removal
    "RemoveWidgets"            = $true   # Remove widgets
    "RemoveOneDrive"           = $true   # Remove OneDrive
    "RemoveBingSearch"         = $true   # Remove Bing Search
    "RemovePowerAutomate"      = $true   # Remove PowerAutomate
    "RemoveXboxApps"           = $true   # Remove Xbox apps
    "RemoveCopilot"            = $true   # Remove Copilot
    "RemoveBloatware"          = $true   # Remove all bloatware
    
    # Final Action
    "RestartComputer"          = $false  # Restart computer when done
}

#################################################
# SYSTEM SETTINGS
#################################################
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

if ($options["DisableRecall"]) {
    Write-Status "Disabling Recall feature..."
    $RecallEnabled = Get-WindowsOptionalFeature -Online -FeatureName "Recall"
    if ($RecallEnabled.State -eq "Enabled") {
        Disable-WindowsOptionalFeature -FeatureName "Recall" -Online -NoRestart | Out-Null
    } else {
        Write-Status "Recall feature already disabled"
    }
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

#################################################
# EXPLORER SETTINGS
#################################################
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
        Write-Host "Error restoring classic context menu: $_" -ForegroundColor Red
    }
}

#################################################
# START MENU SETTINGS
#################################################
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

#################################################
# TASKBAR SETTINGS
#################################################
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

#################################################
# APP REMOVAL
#################################################
if ($options["RemoveWidgets"]) {
    Write-Status "Removing Widgets..."
    winget uninstall "windows web experience pack" --accept-source-agreements
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

if ($options["RemoveCopilot"]) {
    Write-Status "Removing Copilot..."
    try {
        Get-AppxPackage -AllUsers -Name Microsoft.Copilot | Remove-AppxPackage
    } catch {
        Write-Host "Error removing Copilot: $_" -ForegroundColor Yellow
    }
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

    $removedCount = 0
    $totalCount = $Bloatware.Count
    
    foreach ($Bloat in $Bloatware) {
        $removedCount++
        $percentComplete = [math]::Round(($removedCount / $totalCount) * 100)
        Write-Progress -Activity "Removing Bloatware" -Status "$Bloat" -PercentComplete $percentComplete
        
        try {
            Get-AppxPackage -AllUsers -Name $Bloat -ErrorAction SilentlyContinue | Remove-AppxPackage -ErrorAction SilentlyContinue
            Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
        } catch {
            # Continue even if there's an error
        }
    }
    
    Write-Progress -Activity "Removing Bloatware" -Completed
    Write-Status "Bloatware removal completed"
}

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
