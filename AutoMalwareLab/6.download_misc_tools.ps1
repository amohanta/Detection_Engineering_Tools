# Create directories
New-Item -Path "C:\tools" -ItemType Directory -Force
New-Item -Path "C:\tools\trid" -ItemType Directory -Force
New-Item -Path "C:\tools\OpenARK" -ItemType Directory -Force

# Function to download raw GitHub content
function Download-GitHubRawFile {
    param (
        [string]$GitHubUrl,
        [string]$Destination
    )
    # Convert GitHub URL to raw format
    $rawUrl = $GitHubUrl -replace "github\.com", "raw.githubusercontent.com" -replace "/blob/", "/"
    Invoke-WebRequest -Uri $rawUrl -OutFile $Destination
}

# Step 1: Download two EXEs to C:\tools
Download-GitHubRawFile "https://github.com/amohanta/Malware_Analysis_Tools-third_party/blob/main/bintext/bintext.exe" "C:\tools\bintext.exe"
Download-GitHubRawFile "https://github.com/amohanta/Malware_Analysis_Tools-third_party/blob/main/COM-Object-View/COMView.exe" "C:\tools\COMView.exe"

# Step 3: Download and extract CryptoTester.zip
$cryptoZip = "C:\tools\CryptoTester.zip"
Invoke-WebRequest "https://github.com/Demonslay335/CryptoTester/releases/download/v1.7.2.0/CryptoTester.zip" -OutFile $cryptoZip
Expand-Archive -Path $cryptoZip -DestinationPath "C:\tools" -Force
Remove-Item $cryptoZip

# Step 4: Download TrID files
Download-GitHubRawFile "https://github.com/angerangel/TrIDGUI2/blob/master/trid.exe" "C:\tools\trid\trid.exe"
Download-GitHubRawFile "https://github.com/angerangel/TrIDGUI2/blob/master/triddefs.trd" "C:\tools\trid\triddefs.trd"

# Step 5: Download and extract OpenArk
$openArkZip = "C:\tools\OpenArk.zip"
Invoke-WebRequest "https://github.com/BlackINT3/OpenArk/releases/download/v1.3.8/OpenArk-v1.3.8.zip" -OutFile $openArkZip
Expand-Archive -Path $openArkZip -DestinationPath "C:\tools\OpenARK" -Force
Remove-Item $openArkZip

# Step 6: Download and silently install ExplorerSuite
$explorerSuiteInstaller = "C:\tools\ExplorerSuite.exe"
Invoke-WebRequest "https://ntcore.com/files/ExplorerSuite.exe" -OutFile $explorerSuiteInstaller
Start-Process -FilePath $explorerSuiteInstaller -ArgumentList "/SILENT" -Wait
