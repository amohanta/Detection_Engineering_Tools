# ============================
#  Sysinternals + SleuthKit Installer
#  Target: C:\tools\Sysinternals
# ============================

$baseFolder = "C:\tools\Sysinternals"

# Tools & URLs
$tools = @{
    "ProcessExplorer" = "https://download.sysinternals.com/files/ProcessExplorer.zip"
    "ProcMon"         = "https://download.sysinternals.com/files/ProcessMonitor.zip"
    "Autoruns"        = "https://download.sysinternals.com/files/Autoruns.zip"
    "Strings"         = "https://download.sysinternals.com/files/Strings.zip"
    "SleuthKit"       = "https://github.com/sleuthkit/sleuthkit/releases/download/sleuthkit-4.14.0/sleuthkit-4.14.0-win32.zip"
}

# Create Base Folder
if (!(Test-Path -Path $baseFolder)) {
    Write-Host "Creating folder: $baseFolder"
    New-Item -ItemType Directory -Path $baseFolder -Force | Out-Null
}

# Download + Extract Each Tool
foreach ($tool in $tools.Keys) {
    $url = $tools[$tool]
    $zipFile = "$baseFolder\$tool.zip"
    $destFolder = "$baseFolder\$tool"

    Write-Host "`n[*] Downloading $tool ..."
    Invoke-WebRequest -Uri $url -OutFile $zipFile -UseBasicParsing

    Write-Host "[*] Extracting $tool ..."
    if (!(Test-Path -Path $destFolder)) {
        New-Item -ItemType Directory -Path $destFolder -Force | Out-Null
    }

    Expand-Archive -Path $zipFile -DestinationPath $destFolder -Force

    Remove-Item $zipFile -Force
    Write-Host "[+] Installed: $tool"
}

Write-Host "`n=============================="
Write-Host " Installation Complete!"
Write-Host " Tools available in: C:\tools\Sysinternals"
Write-Host "=============================="
