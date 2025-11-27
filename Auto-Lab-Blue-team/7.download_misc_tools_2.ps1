# ===================== Setup =====================
# Define tools directory
$toolsDir = "C:\Tools"
New-Item -Path $toolsDir -ItemType Directory -Force | Out-Null

# ===================== 7-Zip Install =====================
$sevenZipDir = "C:\Program Files\7-Zip"
$sevenZipExe = Join-Path $sevenZipDir "7z.exe"

if (-Not (Test-Path $sevenZipExe)) {
    Write-Host "`nInstalling 7-Zip..."
    $sevenZipInstaller = "$env:TEMP\7zip.exe"
    Invoke-WebRequest -Uri "https://www.7-zip.org/a/7z2301-x64.exe" -OutFile $sevenZipInstaller
    Start-Process -FilePath $sevenZipInstaller -ArgumentList "/S" -Wait
    Remove-Item $sevenZipInstaller
} else {
    Write-Host "7-Zip is already installed."
}

# Function to extract using 7-Zip
function Extract-With7Zip {
    param (
        [string]$zipPath,
        [string]$extractTo
    )

    if (-Not (Test-Path $extractTo)) {
        New-Item -Path $extractTo -ItemType Directory -Force | Out-Null
    }

    & "$sevenZipExe" x "$zipPath" -o"$extractTo" -y | Out-Null
}

# ===================== System Informer (ZIP) =====================
$sysInformerZip = "$env:TEMP\systeminformer.zip"
$sysInformerUrl = "https://github.com/winsiderss/systeminformer/releases/download/v3.2.25011.2103/systeminformer-3.2.25011-release-bin.zip"

Invoke-WebRequest -Uri $sysInformerUrl -OutFile $sysInformerZip
Extract-With7Zip -zipPath $sysInformerZip -extractTo "$toolsDir\SystemInformer"
Remove-Item $sysInformerZip

# ===================== Sysinternals Tools =====================
$sysinternals = @(
    @{ name = "ProcessExplorer"; url = "https://download.sysinternals.com/files/ProcessExplorer.zip"; dest = "$toolsDir\ProcessExplorer" },
    @{ name = "Autoruns";         url = "https://download.sysinternals.com/files/Autoruns.zip";         dest = "$toolsDir\Autoruns" },
    @{ name = "Procmon";          url = "https://download.sysinternals.com/files/ProcessMonitor.zip";   dest = "$toolsDir\Procmon" }
)

foreach ($tool in $sysinternals) {
    $zipPath = "$env:TEMP\$($tool.name).zip"
    Invoke-WebRequest -Uri $tool.url -OutFile $zipPath
    Extract-With7Zip -zipPath $zipPath -extractTo $tool.dest
    Remove-Item $zipPath
}



# ===================== FakeNet-NG =====================
$fakenetZip = "$env:TEMP\fakenet.zip"
$fakenetUrl = "https://github.com/mandiant/flare-fakenet-ng/releases/download/v3.5/fakenet3.5.zip"
Invoke-WebRequest -Uri $fakenetUrl -OutFile $fakenetZip
Extract-With7Zip -zipPath $fakenetZip -extractTo "$toolsDir\FakeNet-NG"
Remove-Item $fakenetZip



Write-Host "`n? All tools installed or extracted in C:\Tools"
