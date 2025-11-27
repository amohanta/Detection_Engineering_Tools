# -------------------------------------------------------------------------------------------------
# Auto-bypass ExecutionPolicy: If not already running in Bypass mode, re-launch this script
# -------------------------------------------------------------------------------------------------
if ($env:PSExecutionPolicyPreference -ne "Bypass" -and $MyInvocation.InvocationName -ne "") {
    Write-Output "Restarting script with ExecutionPolicy Bypass..."
    powershell -ExecutionPolicy Bypass -File $MyInvocation.MyCommand.Definition
    exit
}

# -------------------------------------------------------------------------------------------------
# Setup paths
# -------------------------------------------------------------------------------------------------
$downloadDir       = "$env:TEMP\java_downloads"
$ghidraExtractDir  = "C:\tools\Ghidra"
$jdkUrl            = "https://download.oracle.com/java/24/latest/jdk-24_windows-x64_bin.exe"
$jreUrl            = "https://sdlc-esd.oracle.com/ESD6/JSCDL/jdk/8u451-b10/8a1589aa0fe24566b4337beee47c2d29/jre-8u451-windows-x64.exe?GroupName=JSC&FilePath=/ESD6/JSCDL/jdk/8u451-b10/8a1589aa0fe24566b4337beee47c2d29/jre-8u451-windows-x64.exe&BHost=javadl.sun.com&File=jre-8u451-windows-x64.exe&AuthParam=1748780666_483bee7a7e268aded9bf580285b82bd5&ext=.exe"
$ghidraUrl         = "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.3.2_build/ghidra_11.3.2_PUBLIC_20250415.zip"

$jdkInstaller      = "$downloadDir\jdk-24.exe"
$jreInstaller      = "$downloadDir\jre-8u451.exe"
$ghidraZip         = "$downloadDir\ghidra.zip"

# -------------------------------------------------------------------------------------------------
# Create directories
# -------------------------------------------------------------------------------------------------
New-Item -Path $downloadDir -ItemType Directory -Force | Out-Null
New-Item -Path $ghidraExtractDir -ItemType Directory -Force | Out-Null

# -------------------------------------------------------------------------------------------------
# Download files
# -------------------------------------------------------------------------------------------------
Write-Output "`nDownloading JDK 24..."
Invoke-WebRequest -Uri $jdkUrl -OutFile $jdkInstaller

Write-Output "Downloading JRE 8u451..."
Invoke-WebRequest -Uri $jreUrl -OutFile $jreInstaller

Write-Output "Downloading Ghidra..."
Invoke-WebRequest -Uri $ghidraUrl -OutFile $ghidraZip

# -------------------------------------------------------------------------------------------------
# Install JDK and JRE silently
# -------------------------------------------------------------------------------------------------
Write-Output "`nInstalling JDK 24 silently..."
Start-Process -FilePath $jdkInstaller -ArgumentList "/s" -Wait

Write-Output "Installing JRE 8u451 silently..."
Start-Process -FilePath $jreInstaller -ArgumentList "/s" -Wait

# -------------------------------------------------------------------------------------------------
# Extract Ghidra
# -------------------------------------------------------------------------------------------------
Write-Output "`nExtracting Ghidra to $ghidraExtractDir..."
Expand-Archive -LiteralPath $ghidraZip -DestinationPath $ghidraExtractDir -Force

# -------------------------------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------------------------------
Write-Output "`nCleaning up installer files..."
Remove-Item $jdkInstaller, $jreInstaller, $ghidraZip -Force

# -------------------------------------------------------------------------------------------------
# Done
# -------------------------------------------------------------------------------------------------
Write-Output "`n✅ All tasks completed successfully. Ghidra extracted. Java installed."
