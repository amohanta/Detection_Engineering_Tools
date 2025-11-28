# PowerShell script to collect user + system registry hives and MFT
# Copies locked files using RawDiskCopy_x64.exe or RawDiskCopy_x86.exe
# Output: C:\Forensics\

# -------------------------
# Detect correct RawDiskCopy executable
# -------------------------
$RawCopy = if ([Environment]::Is64BitOperatingSystem) {
    ".\RawDiskCopy_x64.exe"
} else {
    ".\RawDiskCopy_x86.exe"
}

# -------------------------
# Output directory
# -------------------------
$OutDir = "C:\Forensics"

if (-not (Test-Path $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir | Out-Null
}

Write-Host "[+] Using RawDiskCopy: $RawCopy"
Write-Host "[+] Output Folder: $OutDir"
Write-Host ""

# -------------------------
# User profile path
# -------------------------
$UserPath = $env:USERPROFILE

# -------------------------
# Collect NTUSER files
# -------------------------
$UserArtifacts = @(
    "NTUSER.DAT",
    "NTUSER.DAT.LOG1",
    "NTUSER.DAT.LOG2"
)

# Add NTUSER.DAT.LOG* (LOG3, LOG4, etc.)
$UserLogs = Get-ChildItem -Path "$UserPath" -Filter "NTUSER.DAT.LOG*" -ErrorAction SilentlyContinue
foreach ($log in $UserLogs) {
    if ($UserArtifacts -notcontains $log.Name) {
        $UserArtifacts += $log.Name
    }
}

Write-Host "[+] Collecting User Registry Artifacts..."
foreach ($file in $UserArtifacts) {
    $Source = Join-Path $UserPath $file
    $Dest   = Join-Path $OutDir $file

    if (Test-Path $Source) {
        Write-Host "    -> $file"
        & $RawCopy "$Source" "$Dest"
    }
}

# -------------------------
# Collect System Registry Hives
# -------------------------
Write-Host "`n[+] Collecting SYSTEM Registry Hives..."

$SysHivePath = "C:\Windows\System32\Config"

$SystemArtifacts = @(
    "SYSTEM",
    "SYSTEM.LOG1",
    "SYSTEM.LOG2",
    "SAM",
    "SAM.LOG1",
    "SAM.LOG2",
    "SECURITY",
    "SECURITY.LOG1",
    "SECURITY.LOG2",
    "SOFTWARE",
    "SOFTWARE.LOG1",
    "SOFTWARE.LOG2"
)

foreach ($file in $SystemArtifacts) {
    $Source = Join-Path $SysHivePath $file
    $Dest   = Join-Path $OutDir $file

    if (Test-Path $Source) {
        Write-Host "    -> $file"
        & $RawCopy "$Source" "$Dest"
    }
}

# -------------------------
# Copy $MFT
# Correct path: C:\$MFT
# -------------------------
Write-Host "`n[+] Collecting $MFT..."

$MFT_Source = "C:\$MFT"
$MFT_Dest   = Join-Path $OutDir "MFT.bin"

& $RawCopy "$MFT_Source" "$MFT_Dest"

Write-Host "`n[+] Acquisition Complete!"
Write-Host "[+] All files stored in $OutDir"
