# ============================
# Download & Extract RegRipper 3.0
# ============================

# Variables
$folderPath = "C:\tools\RegRipper"
$zipUrl = "https://github.com/keydet89/RegRipper3.0/archive/refs/heads/master.zip"
$zipFile = "$folderPath\RegRipper.zip"

# Create folder if not exists
if (!(Test-Path -Path $folderPath)) {
    Write-Host "[+] Creating folder: $folderPath"
    New-Item -ItemType Directory -Path $folderPath -Force | Out-Null
}

# Download ZIP
Write-Host "[+] Downloading RegRipper 3.0..."
Invoke-WebRequest -Uri $zipUrl -OutFile $zipFile -UseBasicParsing

# Extract ZIP
Write-Host "[+] Extracting files..."
Expand-Archive -Path $zipFile -DestinationPath $folderPath -Force

# Delete ZIP
Remove-Item $zipFile -Force

# Optional: Move extracted content from the inside folder to the main folder
$innerFolder = Join-Path $folderPath "RegRipper3.0-master"
if (Test-Path $innerFolder) {
    Write-Host "[+] Flattening folder structure..."
    Move-Item -Path "$innerFolder\*" -Destination $folderPath -Force
    Remove-Item $innerFolder -Recurse -Force
}

Write-Host "[OK] RegRipper installation complete. Files located at: $folderPath"
