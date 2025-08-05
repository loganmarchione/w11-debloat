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
Test-AdminPrivilege
Write-Status "Administrator privileges confirmed"

Update-WingetSources

# Create a hashtable of debloat options - set to $true to enable
$options = @{
    # System settings
    "DisableHibernation"       = $true   # Disable hibernation

    # App Removal
    "DisableRecall"            = $true   # Disable Recall feature
    "DisableNotepadAI"         = $true   # Disable Notepad AI features
    "RemoveOneDrive"           = $true   # Remove OneDrive
    "RemoveWidgets"            = $true   # Remove widgets
    "RemoveBloatware"          = $true   # Remove bloatware

    # Explorer settings
    "RestoreContextMenu"       = $true   # Restore classic context menu
    "NewLogoutShortcut"        = $true   # Create logout shortcut on public desktop
}

########################################
# System settings
########################################
if ($options["DisableHibernation"]) {
    Write-Status "Disabling hibernation..."
    powercfg.exe /hibernate off
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

if ($options["DisableNotepadAI"]) {
    Write-Status "Disabling Notepad AI features..."
    Invoke-RegCommand 'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\WindowsNotepad" /v "DisableAIFeatures" /t REG_DWORD /d 1 /f'
}

if ($options["RemoveOneDrive"]) {
    Remove-OneDrive

    # Remove OneDrive from Explorer sidebar
    Write-Status "Removing OneDrive from Explorer..."
    Invoke-RegCommand 'reg add "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 0 /f'
    Invoke-RegCommand 'reg add "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 0 /f'
}

if ($options["RemoveWidgets"]) {
    Write-Status "Removing Widgets..."
    Invoke-RegCommand 'reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\PolicyManager\default\NewsAndInterests" /v "AllowNewsAndInterests" /t REG_DWORD /d 0 /f'
    Invoke-RegCommand 'reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Dsh" /v "AllowNewsAndInterests" /t REG_DWORD /d 0 /f'
}

if ($options["RemoveBloatware"]) {
    Write-Status "Removing bloatware apps..."
    
    $apps = @(
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
    
    foreach ($app in $apps) {
        Write-Status "Removing $app..."
        try {
            Get-AppxPackage -AllUsers -Name $app -ErrorAction SilentlyContinue | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
            Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $app | Remove-AppxProvisionedPackage -AllUsers -Online -ErrorAction SilentlyContinue
        } catch {
            # Continue even if there's an error
        }
    }
}

########################################
# Explorer settings
########################################
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

if ($options["NewLogoutShortcut"]) {
    New-LogoutShortcutOnPublicDesktop
}

########################################
# Final action
########################################
Restart-Explorer
Stop-Transcript
Write-Status "Script complete! Find the log at: $logFile"
Write-Status "It's recommended to restart your computer for all changes to take effect."