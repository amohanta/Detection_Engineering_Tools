# ----------------------------------------------
# RAW DISK FORENSICS COLLECTION SCRIPT
# Collects:
#   - NTUSER.* (all logs)
#   - SYSTEM/SAM/SOFTWARE/SECURITY hives + logs
#   - $MFT
#   - UsnJrnl:$J, $Max and ADS DATA streams
#
# Output: C:\Forensics\
# ----------------------------------------------

# Detect correct RawDiskCopy executable
$RawCopy = if ([Environment]::Is64BitOperatingSystem) {
    ".\RawDiskCopy_x64.exe"
} else {
    ".\RawDiskCopy_x86.exe"
}

Write-Host "[+] Using RawDiskCopy: $RawCopy"

# Output directory
$OutDir = "C:\Forensics"
if (-not (Test-Path $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir | Out-Null
}

Write-Host "[+] Output Folder: $OutDir"
Write-Host ""

# ----------------------------------------------
# Collect User NTUSER Files
# ----------------------------------------------
$UserPath = $env:USERPROFILE

Write-Host "[+] Collecting User Registry Artifacts..."

# NTUSER base files
$UserArtifacts = @(
    "NTUSER.DAT",
    "NTUSER.DAT.LOG1",
    "NTUSER.DAT.LOG2"
)

# Add any extra NTUSER.DAT.LOG*
$ExtraUserLogs = Get-ChildItem -Path "$UserPath" -Filter "NTUSER.DAT.LOG*" -ErrorAction SilentlyContinue
foreach ($log in $ExtraUserLogs) {
    if ($UserArtifacts -notcontains $log.Name) {
        $UserArtifacts += $log.Name
    }
}

foreach ($file in $UserArtifacts) {
    $Source = Join-Path $UserPath $file
    $Dest   = Join-Path $OutDir $file

    if (Test-Path $Source) {
        Write-Host "    -> $file"
        & $RawCopy "$Source" "$Dest"
    }
}

# ----------------------------------------------
# Collect UsrClass.dat Registry Hive
# ----------------------------------------------
Write-Host "`n[+] Collecting UsrClass.dat Registry Hive..."

# UsrClass.dat base directory
$UsrClassDir = Join-Path $env:LOCALAPPDATA "Microsoft\Windows"

# Files to collect
$UsrClassFiles = @(
    "UsrClass.dat",
    "UsrClass.dat.LOG1",
    "UsrClass.dat.LOG2"
)

# Add extra UsrClass.dat.LOG* files if present (LOG3, LOG4, etc.)
$ExtraUsrLogs = Get-ChildItem -Path $UsrClassDir -Filter "UsrClass.dat.LOG*" -ErrorAction SilentlyContinue
foreach ($log in $ExtraUsrLogs) {
    if ($UsrClassFiles -notcontains $log.Name) {
        $UsrClassFiles += $log.Name
    }
}

foreach ($file in $UsrClassFiles) {
    $Source = Join-Path $UsrClassDir $file
    $Dest   = Join-Path $OutDir $file

    if (Test-Path $Source) {
        Write-Host "    -> $file"
        & $RawCopy "$Source" "$Dest"
    }
}

# ----------------------------------------------
# Collect MAIN SYSTEM HIVES
# ----------------------------------------------
Write-Host "`n[+] Collecting System Registry Hives..."

$SysHivePath = "C:\Windows\System32\Config"
$SystemArtifacts = @(
    "SYSTEM", "SYSTEM.LOG1", "SYSTEM.LOG2",
    "SAM",    "SAM.LOG1",    "SAM.LOG2",
    "SECURITY", "SECURITY.LOG1", "SECURITY.LOG2",
    "SOFTWARE", "SOFTWARE.LOG1", "SOFTWARE.LOG2"
)

foreach ($file in $SystemArtifacts) {
    $Source = Join-Path $SysHivePath $file
    $Dest   = Join-Path $OutDir $file

    if (Test-Path $Source) {
        Write-Host "    -> $file"
        & $RawCopy "$Source" "$Dest"
    }
}

# ----------------------------------------------
# Copy $MFT
# ----------------------------------------------
Write-Host "`n[+] Collecting $MFT..."

$MFT_Source = "C:\$MFT"
$MFT_Dest   = Join-Path $OutDir "MFT.bin"

& $RawCopy "$MFT_Source" "$MFT_Dest"

# ----------------------------------------------
# Collect USN Journal ADS Files
# ----------------------------------------------
Write-Host "`n[+] Collecting USN Journal..."

# Correct NTFS metadata folder
$ExtendPath = "C:\`$Extend"

# File name (escaped)
$Usn = "`$UsnJrnl"

# Final absolute NTFS paths (FULLY ESCAPED)
$USN_J_Source        = "$ExtendPath\${Usn}:`$J"
$USN_Max_Source      = "$ExtendPath\${Usn}:`$Max"
$USN_J_Data_Source   = "$ExtendPath\${Usn}:`$J:`$DATA"
$USN_Max_Data_Source = "$ExtendPath\${Usn}:`$Max:`$DATA"

# Destinations
$USN_J_Dest        = Join-Path $OutDir "UsnJrnl_J.bin"
$USN_Max_Dest      = Join-Path $OutDir "UsnJrnl_Max.bin"
$USN_J_Data_Dest   = Join-Path $OutDir "UsnJrnl_J_DATA.bin"
$USN_Max_Data_Dest = Join-Path $OutDir "UsnJrnl_Max_DATA.bin"

Write-Host "    -> UsnJrnl:`$J"
& $RawCopy "$USN_J_Source" "$USN_J_Dest"

Write-Host "    -> UsnJrnl:`$Max"
& $RawCopy "$USN_Max_Source" "$USN_Max_Dest"

Write-Host "    -> UsnJrnl:`$J:`$DATA"
& $RawCopy "$USN_J_Data_Source" "$USN_J_Data_Dest"

Write-Host "    -> UsnJrnl:`$Max:`$DATA"
& $RawCopy "$USN_Max_Data_Source" "$USN_Max_Data_Dest"
