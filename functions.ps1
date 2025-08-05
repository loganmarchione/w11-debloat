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
        Exit 1
    }

    Write-Status "Windows 11 detected - continuing with script"
}

function Test-AdminPrivilege {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Status "This script requires administrator privileges. Please run as administrator." -ForegroundColor Red
        Exit 1
    }
}

function Invoke-RegCommand {
    param([string]$Command)
    try {
        $result = Invoke-Expression "cmd /c $Command 2>&1"
        if ($LASTEXITCODE -ne 0) {
            Write-Status "Error executing: $Command" -ForegroundColor Red
            Write-Status "Output: $result" -ForegroundColor Red
            return $false
        }
        return $true
    }
    catch {
        Write-Status "Error executing: $Command" -ForegroundColor Red
        Write-Status $_.Exception.Message -ForegroundColor Red
        return $false
    }
}

function New-LogoutShortcutOnPublicDesktop {
    Write-Status "Creating logout shortcut on all users' desktops..."

    # Create shortcut on Public desktop (visible to all users)
    $PublicDesktop = "$env:Public\Desktop"
    $ShortcutFile = "$PublicDesktop\Logout.lnk"

    $TargetFile = "$env:SystemRoot\System32\logoff.exe"
    $WScriptShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
    $Shortcut.TargetPath = $TargetFile
    $Shortcut.Description = "Log out of Windows"
    $Shortcut.IconLocation = "shell32.dll,27" # Logoff icon
    $Shortcut.Save()

    Write-Status "Logout shortcut created at: $ShortcutFile" -ForegroundColor Green
}

function Update-WingetSources {
    Write-Status "Updating Winget sources..."
    winget source update
    # Need to do this accept the terms to use the MS Store
    winget list --accept-source-agreements | Out-Null
}

function Restart-Explorer {
    # Refresh Explorer
    Write-Status "Refreshing Explorer to apply changes..."
    Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    Start-Process explorer
}

function Remove-OneDrive {
    Write-Status "Removing OneDrive..."

    # Try to terminate OneDrive process if running
    Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

    # Try multiple methods to uninstall OneDrive
    try {
        # Run the OneDrive uninstaller directly
        if (Test-Path "$env:SystemRoot\SysWOW64\OneDriveSetup.exe") {
            Write-Status "Running OneDrive uninstaller (64-bit)..."
            & "$env:SystemRoot\SysWOW64\OneDriveSetup.exe" /uninstall
        } elseif (Test-Path "$env:SystemRoot\System32\OneDriveSetup.exe") {
            Write-Status "Running OneDrive uninstaller (32-bit)..."
            & "$env:SystemRoot\System32\OneDriveSetup.exe" /uninstall
        }

        # Wait for the uninstaller to complete
        Start-Sleep -Seconds 5

        # Remove leftover OneDrive folder if it exists
        if (Test-Path "$env:USERPROFILE\OneDrive") {
            Write-Status "Removing OneDrive folder..."
            Remove-Item -Path "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Status "Error removing OneDrive: $_" -ForegroundColor Red
    }
}