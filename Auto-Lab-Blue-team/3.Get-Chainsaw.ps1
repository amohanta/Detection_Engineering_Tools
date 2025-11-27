# Set folder path
$chainsawPath = "C:\tools\Chainsaw"

# Create folder if it doesn't exist
if (!(Test-Path $chainsawPath)) {
    New-Item -ItemType Directory -Path $chainsawPath | Out-Null
}

# Latest Chainsaw release download URL
$zipUrl = "https://github.com/WithSecureLabs/chainsaw/releases/latest/download/chainsaw_x86_64-pc-windows-msvc.zip"
$zipFile = "$chainsawPath\chainsaw.zip"

Write-Host "Downloading Chainsaw..."
Invoke-WebRequest -Uri $zipUrl -OutFile $zipFile

Write-Host "Extracting Chainsaw..."
Expand-Archive -Path $zipFile -DestinationPath $chainsawPath -Force

# Remove ZIP file
Remove-Item $zipFile

Write-Host "Chainsaw installed successfully in C:\tools\Chainsaw"
