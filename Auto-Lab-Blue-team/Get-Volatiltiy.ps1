# Define variables
$folderPath = "C:\tools\Volatility"
$zipUrl = "https://downloads.volatilityfoundation.org/releases/2.6/volatility_2.6_win64_standalone.zip"
$zipFile = "$folderPath\volatility.zip"

# Create folder if it doesn't exist
if (!(Test-Path -Path $folderPath)) {
    Write-Host "Creating folder: $folderPath"
    New-Item -ItemType Directory -Path $folderPath -Force | Out-Null
}

# Download the ZIP file
Write-Host "Downloading Volatility 2..."
Invoke-WebRequest -Uri $zipUrl -OutFile $zipFile -UseBasicParsing

# Extract ZIP file
Write-Host "Extracting files..."
Expand-Archive -Path $zipFile -DestinationPath $folderPath -Force

# Remove ZIP file after extraction (optional)
Remove-Item $zipFile -Force

Write-Host "Volatility 2 download and extraction complete!"
Write-Host "volatility.exe is located in $folderPath"
