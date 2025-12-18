# UserAssist Registry Parser for PowerShell
# Directly parses HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist
# Based on: https://github.com/Awad93/Userassist_parser/blob/main/userassist_parser.py
# Updated: 2025-12-18

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$RegistryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputDir = ".\UserAssist_Analysis_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
)

# Global collections to store parsed data
$script:KEYS = @()
$script:UEME = @()

# Known GUIDs for UserAssist categories
$EXE_Files_GUID = "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}"
$LNK_Files_GUID = "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}"

# Function to decode ROT13
function Decode-ROT13 {
    param([string]$Encoded)
    
    $decoded = ""
    foreach ($char in $Encoded.ToCharArray()) {
        if ($char -match '[A-Za-z]') {
            $base = if ($char -cmatch '[A-Z]') { [byte][char]'A' } else { [byte][char]'a' }
            $rot13 = ([byte][char]$char - $base + 13) % 26 + $base
            $decoded += [char]$rot13
        } else {
            $decoded += $char
        }
    }
    return $decoded
}

# Function to convert FILETIME to DateTime
function ConvertFrom-FileTime {
    param([long]$FileTime)
    
    if ($FileTime -eq 0) { return $null }
    
    try {
        # Windows FileTime epoch starts from January 1, 1601 (100-nanosecond intervals)
        $epoch = Get-Date -Year 1601 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0
        $ticks = $FileTime * 10  # Convert to ticks (100-nanosecond intervals)
        $dateTime = $epoch.AddTicks($ticks)
        return $dateTime.ToUniversalTime()
    }
    catch {
        Write-Warning "Error converting FILETIME: $_"
        return $null
    }
}

# Function to convert focus time to human readable format
function ConvertFrom-FocusTime {
    param([int]$FocusTime)
    
    $milliseconds = $FocusTime % 1000
    $totalSeconds = [Math]::Floor($FocusTime / 1000)
    $seconds = $totalSeconds % 60
    $totalMinutes = [Math]::Floor($totalSeconds / 60)
    $minutes = $totalMinutes % 60
    $totalHours = [Math]::Floor($totalMinutes / 60)
    $hours = $totalHours % 24
    $days = [Math]::Floor($totalHours / 24)
    
    return @{
        Days = $days
        Hours = $hours
        Minutes = $minutes
        Seconds = $seconds
        Milliseconds = $milliseconds
        HumanReadable = "$days" + "d, " + "$hours" + "h, " + "$minutes" + "m, " + "$seconds" + "s, " + "$milliseconds" + "ms"
    }
}

# Function to create dictionary from UserAssist registry
function Get-UserAssistDictionary {
    param([string]$RegPath)
    
    Write-Host "[+] Accessing UserAssist registry path: $RegPath" -ForegroundColor Green
    
    if (-not (Test-Path $RegPath)) {
        Write-Error "UserAssist registry path not found: $RegPath"
        Write-Host "Trying alternative paths..." -ForegroundColor Yellow
        
        # Try alternative paths
        $altPaths = @(
            "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
        )
        
        foreach ($altPath in $altPaths) {
            if (Test-Path $altPath) {
                $RegPath = $altPath
                Write-Host "[+] Found alternative path: $RegPath" -ForegroundColor Green
                break
            }
        }
        
        if (-not (Test-Path $RegPath)) {
            Write-Error "Could not find UserAssist registry key. User may not have any UserAssist data."
            return @()
        }
    }
    
    $appsList = @()
    
    try {
        # Get all GUID subkeys
        $uaSubkeys = Get-ChildItem -Path $RegPath -ErrorAction Stop
        
        if ($uaSubkeys.Count -eq 0) {
            Write-Host "[-] No GUID subkeys found in UserAssist registry." -ForegroundColor Yellow
            return @()
        }
        
        Write-Host "[+] Found $($uaSubkeys.Count) GUID subkeys" -ForegroundColor Green
        
        foreach ($subkey in $uaSubkeys) {
            $guid = $subkey.PSChildName
            $countPath = Join-Path $subkey.PSPath "Count"
            
            if (Test-Path $countPath) {
                $countKey = Get-Item -Path $countPath -ErrorAction SilentlyContinue
                
                if ($countKey) {
                    $values = $countKey.GetValueNames()
                    
                    if ($values.Count -gt 0) {
                        Write-Host "  Processing GUID: $guid ($($values.Count) entries)" -ForegroundColor Cyan
                        
                        $guidKeys = @{}
                        $apps = @{}
                        
                        foreach ($valueName in $values) {
                            try {
                                $data = $countKey.GetValue($valueName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                                $decodedName = Decode-ROT13 -Encoded $valueName
                                
                                if ($data -is [byte[]]) {
                                    $apps[$decodedName] = $data
                                }
                                else {
                                    Write-Verbose "Skipping non-binary data for value: $valueName"
                                }
                            }
                            catch {
                                Write-Warning "Error processing value '$valueName' in $guid : $_"
                            }
                        }
                        
                        if ($apps.Count -gt 0) {
                            $guidKeys[$guid] = $apps
                            $appsList += $guidKeys
                        }
                    }
                }
            }
        }
        
        if ($appsList.Count -eq 0) {
            Write-Host "[-] No valid UserAssist data found in registry." -ForegroundColor Yellow
        }
        else {
            Write-Host "[+] Collected data from $($appsList.Count) GUIDs with binary data" -ForegroundColor Green
        }
        
        return $appsList
    }
    catch {
        Write-Error "Error accessing registry: $_"
        return @()
    }
}

# Function to parse UserAssist values
function Parse-UserAssistValues {
    param([array]$Data)
    
    Write-Host "[+] Parsing Programs UserAssist values..." -ForegroundColor Green
    
    foreach ($guidDict in $Data) {
        $workingGuid = ($guidDict.Keys | Select-Object -First 1)
        
        foreach ($appDict in $guidDict.Values) {
            foreach ($appName in $appDict.Keys) {
                $rawData = $appDict[$appName]
                
                # Skip UEME_CTLSESSION for now (handled separately)
                if ($appName -eq "UEME_CTLSESSION") { continue }
                
                # Parse based on data length
                switch ($rawData.Length) {
                    16 {
                        # Windows XP format: 16 bytes
                        try {
                            $sessionId = [BitConverter]::ToUInt32($rawData, 0)
                            $runCount = [BitConverter]::ToUInt32($rawData, 4)
                            $lastUsed = [BitConverter]::ToUInt64($rawData, 8)
                            $lastUsedDate = ConvertFrom-FileTime -FileTime $lastUsed
                            
                            $entry = [PSCustomObject]@{
                                GUID = $workingGuid
                                Path = $appName
                                SessionID = $sessionId
                                RunCount = $runCount
                                FocusCount = ""
                                FocusTimeMs = ""
                                FocusTimeHumanReadable = ""
                                LastUsedDateUTC = if ($lastUsedDate) { $lastUsedDate.ToString("yyyy-MM-ddTHH:mm:ss.fffZ") } else { "" }
                                LastUsedLocal = if ($lastUsedDate) { $lastUsedDate.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") } else { "" }
                                RewriteCounter = ""
                                'r0 value[0]' = ""
                                'r0 value[1]' = ""
                                'r0 value[2]' = ""
                                'r0 value[3]' = ""
                                'r0 value[4]' = ""
                                'r0 value[5]' = ""
                                'r0 value[6]' = ""
                                'r0 value[7]' = ""
                                'r0 value[8]' = ""
                                'r0 value[9]' = ""
                                Unknown = ""
                                DataSize = "16 bytes (WinXP)"
                            }
                            
                            $script:KEYS += $entry
                        }
                        catch {
                            Write-Warning "Error parsing 16-byte data for '$appName': $_"
                        }
                    }
                    
                    72 {
                        # Windows 7+ format: 72 bytes
                        try {
                            $sessionId = [BitConverter]::ToUInt32($rawData, 0)
                            $runCount = [BitConverter]::ToUInt32($rawData, 4)
                            $focusCount = [BitConverter]::ToUInt32($rawData, 8)
                            $focusTimeMs = [BitConverter]::ToUInt32($rawData, 12)
                            
                            # Parse r0 values (10 float values at offset 16)
                            $r0Values = @()
                            for ($i = 0; $i -lt 10; $i++) {
                                $r0Values += [BitConverter]::ToSingle($rawData, 16 + ($i * 4))
                            }
                            
                            $rewriteCounter = [BitConverter]::ToUInt32($rawData, 56)
                            $lastUsed = [BitConverter]::ToUInt64($rawData, 60)
                            $lastUsedDate = ConvertFrom-FileTime -FileTime $lastUsed
                            $unknown = [BitConverter]::ToUInt32($rawData, 68)
                            
                            $focusTimeHuman = ConvertFrom-FocusTime -FocusTime $focusTimeMs
                            
                            $entry = [PSCustomObject]@{
                                GUID = $workingGuid
                                Path = $appName
                                SessionID = $sessionId
                                RunCount = $runCount
                                FocusCount = $focusCount
                                FocusTimeMs = $focusTimeMs
                                FocusTimeHumanReadable = $focusTimeHuman.HumanReadable
                                LastUsedDateUTC = if ($lastUsedDate) { $lastUsedDate.ToString("yyyy-MM-ddTHH:mm:ss.fffZ") } else { "" }
                                LastUsedLocal = if ($lastUsedDate) { $lastUsedDate.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") } else { "" }
                                RewriteCounter = $rewriteCounter
                                'r0 value[0]' = $r0Values[0]
                                'r0 value[1]' = $r0Values[1]
                                'r0 value[2]' = $r0Values[2]
                                'r0 value[3]' = $r0Values[3]
                                'r0 value[4]' = $r0Values[4]
                                'r0 value[5]' = $r0Values[5]
                                'r0 value[6]' = $r0Values[6]
                                'r0 value[7]' = $r0Values[7]
                                'r0 value[8]' = $r0Values[8]
                                'r0 value[9]' = $r0Values[9]
                                Unknown = $unknown
                                DataSize = "72 bytes (Win7+)"
                            }
                            
                            $script:KEYS += $entry
                        }
                        catch {
                            Write-Warning "Error parsing 72-byte data for '$appName': $_"
                        }
                    }
                    
                    default {
                        Write-Verbose "Skipping entry with unsupported data length ($($rawData.Length) bytes) for: $appName"
                    }
                }
            }
        }
    }
    
    Write-Host "[+] Parsed $($script:KEYS.Count) UserAssist entries" -ForegroundColor Green
}

# Function to parse UEME_CTLSESSION values
function Parse-UEMEValues {
    param([array]$Data)
    
    Write-Host "[+] Parsing UEME_CTLSESSION values..." -ForegroundColor Green
    
    $uemeCount = 0
    
    foreach ($guidDict in $Data) {
        $workingGuid = ($guidDict.Keys | Select-Object -First 1)
        
        foreach ($appDict in $guidDict.Values) {
            if ($appDict.ContainsKey("UEME_CTLSESSION")) {
                $rawData = $appDict["UEME_CTLSESSION"]
                $uemeCount++
                
                if ($rawData.Length -ge 1600) {  # Minimum expected size
                    try {
                        # Parse the structure: <4i3i520s3i520s3i520s
                        $sessionId = [BitConverter]::ToUInt32($rawData, 0)
                        $totalLaunches = [BitConverter]::ToUInt32($rawData, 4)
                        $totalSwitches = [BitConverter]::ToUInt32($rawData, 8)
                        $totalUserTime = [BitConverter]::ToUInt32($rawData, 12)
                        
                        # Parse three NMax executable paths (UTF-16 strings)
                        $executablePaths = @()
                        
                        # First executable path starts at offset 24 (after 4i + 3i)
                        for ($i = 0; $i -lt 3; $i++) {
                            $stringOffset = 24 + ($i * 532)  # 3i + 520s for each block
                            $stringBytes = $rawData[$stringOffset..($stringOffset + 519)]
                            
                            # Convert UTF-16 bytes to string
                            $string = [System.Text.Encoding]::Unicode.GetString($stringBytes)
                            # Remove null terminator
                            $cleanString = $string -replace "`0", ""
                            $executablePaths += $cleanString.Trim()
                        }
                        
                        # Create UEME session object
                        $uemeSession = @{
                            GUID = $workingGuid
                            Stats = @{
                                SessionID = $sessionId
                                TotalLaunches = $totalLaunches
                                TotalSwitches = $totalSwitches
                                TotalUserTime = $totalUserTime
                                TotalUserTimeHuman = (ConvertFrom-FocusTime -FocusTime $totalUserTime).HumanReadable
                            }
                            NMax = @(
                                @{
                                    RunCount = [BitConverter]::ToUInt32($rawData, 16)
                                    FocusCount = [BitConverter]::ToUInt32($rawData, 20)
                                    FocusTime = [BitConverter]::ToUInt32($rawData, 24)
                                    FocusTimeHuman = (ConvertFrom-FocusTime -FocusTime ([BitConverter]::ToUInt32($rawData, 24))).HumanReadable
                                    ExecutablePath = $executablePaths[0]
                                },
                                @{
                                    RunCount = [BitConverter]::ToUInt32($rawData, 548)
                                    FocusCount = [BitConverter]::ToUInt32($rawData, 552)
                                    FocusTime = [BitConverter]::ToUInt32($rawData, 556)
                                    FocusTimeHuman = (ConvertFrom-FocusTime -FocusTime ([BitConverter]::ToUInt32($rawData, 556))).HumanReadable
                                    ExecutablePath = $executablePaths[1]
                                },
                                @{
                                    RunCount = [BitConverter]::ToUInt32($rawData, 1080)
                                    FocusCount = [BitConverter]::ToUInt32($rawData, 1084)
                                    FocusTime = [BitConverter]::ToUInt32($rawData, 1088)
                                    FocusTimeHuman = (ConvertFrom-FocusTime -FocusTime ([BitConverter]::ToUInt32($rawData, 1088))).HumanReadable
                                    ExecutablePath = $executablePaths[2]
                                }
                            )
                            DataSize = "$($rawData.Length) bytes"
                        }
                        
                        $script:UEME += $uemeSession
                    }
                    catch {
                        Write-Warning "Error parsing UEME_CTLSESSION data: $_"
                    }
                }
                else {
                    Write-Warning "UEME_CTLSESSION data too small ($($rawData.Length) bytes), expected at least 1600 bytes"
                }
            }
        }
    }
    
    Write-Host "[+] Parsed $uemeCount UEME_CTLSESSION entries" -ForegroundColor Green
}

# Function to get application name from path
function Get-AppNameFromPath {
    param([string]$Path)
    
    $appNames = @{
        'notepad' = 'Notepad'
        'cmd' = 'Command Prompt'
        'powershell' = 'PowerShell'
        'winword' = 'Microsoft Word'
        'excel' = 'Microsoft Excel'
        'outlook' = 'Microsoft Outlook'
        'powerpnt' = 'PowerPoint'
        'chrome' = 'Google Chrome'
        'firefox' = 'Firefox'
        'msedge' = 'Microsoft Edge'
        'explorer' = 'File Explorer'
        'calc' = 'Calculator'
        'mspaint' = 'Paint'
        'regedit' = 'Registry Editor'
        'taskmgr' = 'Task Manager'
        'control' = 'Control Panel'
        'mmc' = 'Microsoft Management Console'
    }
    
    $fileName = [System.IO.Path]::GetFileNameWithoutExtension($Path).ToLower()
    
    if ($appNames.ContainsKey($fileName)) {
        return $appNames[$fileName]
    }
    
    # Return formatted filename
    return ($fileName -replace '_', ' ' -replace '-', ' ').Trim()
}

# Function to display results in console
function Show-Results {
    if ($script:KEYS.Count -gt 0) {
        Write-Host ""
        Write-Host "==========================================" -ForegroundColor Cyan
        Write-Host "         USERASSIST ANALYSIS RESULTS" -ForegroundColor Cyan
        Write-Host "==========================================" -ForegroundColor Cyan
        
        # Group by GUID for summary
        $guidGroups = $script:KEYS | Group-Object GUID
        
        Write-Host "Summary by GUID:" -ForegroundColor Yellow
        foreach ($group in $guidGroups) {
            $guidName = if ($group.Name -eq $EXE_Files_GUID) { "Executable Files" }
                       elseif ($group.Name -eq $LNK_Files_GUID) { "Shortcut Files" }
                       else { $group.Name }
            
            Write-Host "  $guidName : $($group.Count) entries" -ForegroundColor White
        }
        
        # Show most frequently executed programs
        Write-Host ""
        Write-Host "Top 10 Most Executed Programs:" -ForegroundColor Yellow
        
        $topPrograms = $script:KEYS | 
            Where-Object { $_.RunCount -gt 0 } | 
            Sort-Object -Property RunCount -Descending | 
            Select-Object -First 10 |
            ForEach-Object {
                $appName = Get-AppNameFromPath -Path $_.Path
                if ([string]::IsNullOrEmpty($appName)) { $appName = [System.IO.Path]::GetFileName($_.Path) }
                
                [PSCustomObject]@{
                    Application = $appName
                    Executions = $_.RunCount
                    LastUsed = $_.LastUsedLocal
                    FocusTime = $_.FocusTimeHumanReadable
                    GUID = if ($_.GUID -eq $EXE_Files_GUID) { "Executables" }
                          elseif ($_.GUID -eq $LNK_Files_GUID) { "Shortcuts" }
                          else { "Other" }
                }
            }
        
        $topPrograms | Format-Table -AutoSize
        
        # Show recently used programs
        Write-Host ""
        Write-Host "Recently Used Programs (Last 30 days):" -ForegroundColor Yellow
        
        $recentPrograms = $script:KEYS | 
            Where-Object { $_.LastUsedDateUTC -and 
                          (Get-Date $_.LastUsedDateUTC) -gt (Get-Date).AddDays(-30) } |
            Sort-Object -Property LastUsedDateUTC -Descending |
            Select-Object -First 10 |
            ForEach-Object {
                $appName = Get-AppNameFromPath -Path $_.Path
                if ([string]::IsNullOrEmpty($appName)) { $appName = [System.IO.Path]::GetFileName($_.Path) }
                
                [PSCustomObject]@{
                    Application = $appName
                    LastUsed = $_.LastUsedLocal
                    Executions = $_.RunCount
                    DaysAgo = [Math]::Round(((Get-Date) - (Get-Date $_.LastUsedDateUTC)).TotalDays, 1)
                }
            }
        
        if ($recentPrograms.Count -gt 0) {
            $recentPrograms | Format-Table -AutoSize
        } else {
            Write-Host "  No programs used in the last 30 days." -ForegroundColor Gray
        }
    }
}

# Main function
function Main {
    param([string]$RegistryPath, [string]$OutputDir)
    
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "    UserAssist Registry Parser" -ForegroundColor Cyan
    Write-Host "    Direct HKCU Registry Analysis" -ForegroundColor Cyan
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
    Write-Host ""
    
    # Create output directory if it doesn't exist
    if (-not (Test-Path $OutputDir)) {
        try {
            New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
            Write-Host "[+] Created output directory: $OutputDir" -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to create output directory: $_"
            exit 1
        }
    }
    else {
        Write-Host "[+] Output directory exists: $OutputDir" -ForegroundColor Yellow
    }
    
    # Create dictionary of ROT-13 decoded UA keys and values
    $apps = Get-UserAssistDictionary -RegPath $RegistryPath
    
    if ($apps.Count -eq 0) {
        Write-Host "[-] No UserAssist data found in registry." -ForegroundColor Red
        Write-Host "    This could mean:" -ForegroundColor Yellow
        Write-Host "    1. UserAssist tracking is disabled" -ForegroundColor White
        Write-Host "    2. No programs have been executed" -ForegroundColor White
        Write-Host "    3. Registry key doesn't exist for current user" -ForegroundColor White
        exit 1
    }
    
    # Parse UEME values
    Parse-UEMEValues -Data $apps
    
    # Parse UserAssist values
    Parse-UserAssistValues -Data $apps
    
    # Show results in console
    Show-Results
    
    # Export data to files
    Write-Host ""
    Write-Host "[+] Exporting data to files..." -ForegroundColor Green
    
    # Export UserAssist data to CSV
    $csvPath = Join-Path $OutputDir "UserAssistData_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if ($script:KEYS.Count -gt 0) {
        $exportData = $script:KEYS | ForEach-Object {
            $appName = Get-AppNameFromPath -Path $_.Path
            if ([string]::IsNullOrEmpty($appName)) { $appName = [System.IO.Path]::GetFileName($_.Path) }
            
            $_ | Select-Object @{Name='Application';Expression={$appName}},
                               @{Name='Filename';Expression={[System.IO.Path]::GetFileName($_.Path)}},
                               Path, GUID, RunCount, FocusCount, FocusTimeMs, FocusTimeHumanReadable,
                               LastUsedDateUTC, LastUsedLocal, SessionID, RewriteCounter, DataSize
        }
        
        $exportData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Host "[+] Exported $($script:KEYS.Count) UserAssist entries to: $csvPath" -ForegroundColor Green
    }
    else {
        Write-Host "[-] No UserAssist entries to export." -ForegroundColor Yellow
    }
    
    # Export UEME data to JSON
    $jsonPath = Join-Path $OutputDir "UEME_CTLSESSION_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    if ($script:UEME.Count -gt 0) {
        $script:UEME | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
        Write-Host "[+] Exported $($script:UEME.Count) UEME_CTLSESSION entries to: $jsonPath" -ForegroundColor Green
    }
    else {
        Write-Host "[-] No UEME_CTLSESSION data to export." -ForegroundColor Yellow
    }
    
    # Create a summary report - FIXED SECTION
    $summaryPath = Join-Path $OutputDir "UserAssist_Summary_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    
    # Build summary content piece by piece
    $summaryContent = @"
USERASSIST ANALYSIS REPORT
==========================
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Registry Path: $RegistryPath

SUMMARY
=======
Total UserAssist Entries: $($script:KEYS.Count)
Total UEME Sessions: $($script:UEME.Count)

DATA BREAKDOWN
==============
"@

    # Add data breakdown
    $dataBreakdown = $script:KEYS | Group-Object DataSize | ForEach-Object { "  $($_.Name): $($_.Count) entries" }
    $summaryContent += "`n" + ($dataBreakdown -join "`n")

    $summaryContent += @"

TOP EXECUTED PROGRAMS
=====================
"@

    # Add top executed programs
    if ($script:KEYS.Count -gt 0) {
        $top5Lines = @()
        $top5 = $script:KEYS | 
            Where-Object { $_.RunCount -gt 0 } | 
            Sort-Object -Property RunCount -Descending | 
            Select-Object -First 5
        
        foreach ($entry in $top5) {
            $appName = Get-AppNameFromPath -Path $entry.Path
            if ([string]::IsNullOrEmpty($appName)) { $appName = [System.IO.Path]::GetFileName($entry.Path) }
            $top5Lines += "  ${appName}: $($entry.RunCount) executions (Last: $($entry.LastUsedLocal))"
        }
        $summaryContent += "`n" + ($top5Lines -join "`n")
    } else {
        $summaryContent += "`n  No execution data found"
    }

    $summaryContent += @"

OUTPUT FILES
============
CSV Data: $(Split-Path $csvPath -Leaf)
JSON Data: $(Split-Path $jsonPath -Leaf)
"@

    # Write summary to file
    $summaryContent | Out-File -FilePath $summaryPath -Encoding UTF8
    Write-Host "[+] Created summary report: $summaryPath" -ForegroundColor Green
    
    # Display final summary
    Write-Host ""
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "              PARSING COMPLETE" -ForegroundColor Cyan
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "Total UserAssist Entries Found: $($script:KEYS.Count)" -ForegroundColor White
    Write-Host "Total UEME Sessions Found: $($script:UEME.Count)" -ForegroundColor White
    Write-Host "Output Directory: $OutputDir" -ForegroundColor White
    Write-Host "Analysis Complete: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
    Write-Host ""
}

# Execute main function
try {
    Main -RegistryPath $RegistryPath -OutputDir $OutputDir
}
catch {
    Write-Error "Script execution failed: $_"
    exit 1
}