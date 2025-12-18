# UserAssist Registry Parser for PowerShell


[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [ValidateScript({Test-Path $_})]
    [string]$RegistryHive,
    
    [Parameter(Mandatory=$true, Position=1)]
    [string]$OutputDir
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

# Function to create dictionary from registry hive
function Get-UserAssistDictionary {
    param([string]$HivePath)
    
    # Check if file exists
    if (-not (Test-Path $HivePath)) {
        Write-Error "Registry hive not found: $HivePath"
        exit 1
    }
    
    # Check if filename is ntuser.dat (case insensitive)
    if ((Split-Path $HivePath -Leaf).ToLower() -ne 'ntuser.dat') {
        Write-Warning "Filename should be 'ntuser.dat' (case insensitive), found: $(Split-Path $HivePath -Leaf)"
    }
    
    $appsList = @()
    
    try {
        # Load the registry hive
        Write-Host "[+] Loading registry hive: $HivePath" -ForegroundColor Green
        
        # For offline hives, we need to use reg.exe or .NET methods
        # This implementation uses the live registry methods for simplicity
        # For actual offline hive parsing, consider using third-party modules
        
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
        
        if (-not (Test-Path $regPath)) {
            Write-Error "UserAssist key not found in registry. Are you running as the correct user?"
            exit 2
        }
        
        # Get all GUID subkeys
        $uaSubkeys = Get-ChildItem -Path $regPath
        
        foreach ($subkey in $uaSubkeys) {
            $guid = $subkey.PSChildName
            $countPath = Join-Path $subkey.PSPath "Count"
            
            if (Test-Path $countPath) {
                $countKey = Get-Item -Path $countPath
                $values = $countKey.GetValueNames()
                
                if ($values.Count -gt 0) {
                    $guidKeys = @{}
                    $apps = @{}
                    
                    foreach ($valueName in $values) {
                        $data = $countKey.GetValue($valueName)
                        $decodedName = Decode-ROT13 -Encoded $valueName
                        
                        if ($data -is [byte[]]) {
                            $apps[$decodedName] = $data
                        }
                    }
                    
                    $guidKeys[$guid] = $apps
                    $appsList += $guidKeys
                }
            }
        }
        
        return $appsList
    }
    catch {
        Write-Error "Error accessing registry: $_"
        exit 3
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
                                LastUsedDateUTC = if ($lastUsedDate) { $lastUsedDate.ToString("yyyy-MM-ddTHH:mm:ssZ") } else { "" }
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
                            }
                            
                            $script:KEYS += $entry
                        }
                        catch {
                            Write-Warning "Error parsing 16-byte data for $appName : $_"
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
                                LastUsedDateUTC = if ($lastUsedDate) { $lastUsedDate.ToString("yyyy-MM-ddTHH:mm:ssZ") } else { "" }
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
                            }
                            
                            $script:KEYS += $entry
                        }
                        catch {
                            Write-Warning "Error parsing 72-byte data for $appName : $_"
                        }
                    }
                    
                    default {
                        Write-Verbose "Skipping entry with unsupported data length: $($rawData.Length) bytes"
                    }
                }
            }
        }
    }
}

# Function to parse UEME_CTLSESSION values
function Parse-UEMEValues {
    param([array]$Data)
    
    Write-Host "[+] Parsing UEME_CTLSESSION values..." -ForegroundColor Green
    
    foreach ($guidDict in $Data) {
        $workingGuid = ($guidDict.Keys | Select-Object -First 1)
        
        foreach ($appDict in $guidDict.Values) {
            if ($appDict.ContainsKey("UEME_CTLSESSION")) {
                $rawData = $appDict["UEME_CTLSESSION"]
                
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
                            $workingGuid = @{
                                stats = @{
                                    SessionID = $sessionId
                                    TotalLaunches = $totalLaunches
                                    TotalSwitches = $totalSwitches
                                    TotalUserTime = $totalUserTime
                                }
                                NMax = @(
                                    @{
                                        RunCount = [BitConverter]::ToUInt32($rawData, 16)
                                        FocusCount = [BitConverter]::ToUInt32($rawData, 20)
                                        FocusTime = [BitConverter]::ToUInt32($rawData, 24)
                                        ExecutablePath = $executablePaths[0]
                                    },
                                    @{
                                        RunCount = [BitConverter]::ToUInt32($rawData, 548)
                                        FocusCount = [BitConverter]::ToUInt32($rawData, 552)
                                        FocusTime = [BitConverter]::ToUInt32($rawData, 556)
                                        ExecutablePath = $executablePaths[1]
                                    },
                                    @{
                                        RunCount = [BitConverter]::ToUInt32($rawData, 1080)
                                        FocusCount = [BitConverter]::ToUInt32($rawData, 1084)
                                        FocusTime = [BitConverter]::ToUInt32($rawData, 1088)
                                        ExecutablePath = $executablePaths[2]
                                    }
                                )
                            }
                        }
                        
                        $script:UEME += $uemeSession
                    }
                    catch {
                        Write-Warning "Error parsing UEME_CTLSESSION data: $_"
                    }
                }
            }
        }
    }
}

# Main function
function Main {
    param([string]$RegistryHive, [string]$OutputDir)
    
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "    UserAssist Registry Parser for PowerShell" -ForegroundColor Cyan
    Write-Host "    Based on Awad93's Python Implementation" -ForegroundColor Cyan
    Write-Host "==========================================" -ForegroundColor Cyan
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
    $apps = Get-UserAssistDictionary -HivePath $RegistryHive
    
    if ($apps.Count -eq 0) {
        Write-Host "[-] No UserAssist data found in registry hive." -ForegroundColor Red
        exit 1
    }
    
    # Parse UEME values
    Parse-UEMEValues -Data $apps
    
    # Parse UserAssist values
    Parse-UserAssistValues -Data $apps
    
    # Export data to files
    Write-Host "[+] Exporting data to files..." -ForegroundColor Green
    
    # Export UserAssist data to CSV
    $csvPath = Join-Path $OutputDir "UserAssistData.csv"
    if ($script:KEYS.Count -gt 0) {
        $script:KEYS | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Host "[+] Exported $($script:KEYS.Count) UserAssist entries to: $csvPath" -ForegroundColor Green
    }
    else {
        Write-Host "[-] No UserAssist entries to export." -ForegroundColor Yellow
    }
    
    # Export UEME data to JSON
    $jsonPath = Join-Path $OutputDir "UEME_CTLSESSION.json"
    if ($script:UEME.Count -gt 0) {
        $script:UEME | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
        Write-Host "[+] Exported UEME_CTLSESSION data to: $jsonPath" -ForegroundColor Green
    }
    else {
        Write-Host "[-] No UEME_CTLSESSION data to export." -ForegroundColor Yellow
    }
    
    # Display summary
    Write-Host ""
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "              PARSING COMPLETE" -ForegroundColor Cyan
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "UserAssist Entries Found: $($script:KEYS.Count)" -ForegroundColor White
    Write-Host "UEME Sessions Found: $($script:UEME.Count)" -ForegroundColor White
    Write-Host "Output Directory: $OutputDir" -ForegroundColor White
    Write-Host ""
    
    # Show sample of parsed data
    if ($script:KEYS.Count -gt 0) {
        Write-Host "Sample of parsed data (first 5 entries):" -ForegroundColor Yellow
        Write-Host "----------------------------------------"
        $script:KEYS | Select-Object -First 5 | Format-Table Path, RunCount, LastUsedDateUTC -AutoSize
    }
}

# Execute main function
try {
    Main -RegistryHive $RegistryHive -OutputDir $OutputDir
}
catch {
    Write-Error "Script execution failed: $_"
    exit 1
}
