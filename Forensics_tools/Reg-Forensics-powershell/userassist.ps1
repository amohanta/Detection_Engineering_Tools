# UserAssist Debug Parser - Simple Version
$RegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"

Write-Host "UserAssist Debug Parser" -ForegroundColor Cyan
Write-Host "=" * 60
Write-Host "Registry Path: $RegPath"
Write-Host "Time: $(Get-Date -Format 'HH:mm:ss')"
Write-Host ""

# Check if path exists
Write-Host "[1] Checking if registry path exists..." -ForegroundColor Yellow
if (Test-Path $RegPath) {
    Write-Host "  ✓ Path exists" -ForegroundColor Green
} else {
    Write-Host "  ✗ Path NOT FOUND: $RegPath" -ForegroundColor Red
    Write-Host "  Trying alternative format..." -ForegroundColor Yellow
    
    $altPath = "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
    if (Test-Path $altPath) {
        Write-Host "  ✓ Found alternative path: $altPath" -ForegroundColor Green
        $RegPath = $altPath
    } else {
        Write-Host "  ✗ No UserAssist registry key found!" -ForegroundColor Red
        exit
    }
}

# Get GUID subkeys
Write-Host ""
Write-Host "[2] Getting GUID subkeys..." -ForegroundColor Yellow
try {
    $subkeys = Get-ChildItem -Path $RegPath -ErrorAction Stop
    Write-Host "  Found $($subkeys.Count) GUID subkeys" -ForegroundColor Green
    
    if ($subkeys.Count -eq 0) {
        Write-Host "  No GUIDs found in UserAssist" -ForegroundColor Yellow
        exit
    }
    
    # Show each GUID
    foreach ($key in $subkeys) {
        Write-Host "  GUID: $($key.PSChildName)" -ForegroundColor Gray
    }
}
catch {
    Write-Host "  Error getting subkeys: $_" -ForegroundColor Red
    exit
}

# Check Count subkeys
Write-Host ""
Write-Host "[3] Checking Count subkeys..." -ForegroundColor Yellow
$totalEntries = 0

foreach ($subkey in $subkeys) {
    $countPath = Join-Path $subkey.PSPath "Count"
    
    if (Test-Path $countPath) {
        $countKey = Get-Item -Path $countPath
        $values = $countKey.GetValueNames()
        
        Write-Host "  GUID: $($subkey.PSChildName) has $($values.Count) values" -ForegroundColor Gray
        
        if ($values.Count -gt 0) {
            # Show first few value names
            $sampleCount = [Math]::Min(3, $values.Count)
            Write-Host "    Sample values:" -ForegroundColor DarkGray
            for ($i = 0; $i -lt $sampleCount; $i++) {
                Write-Host "      - $($values[$i])" -ForegroundColor DarkGray
            }
            
            $totalEntries += $values.Count
        }
    } else {
        Write-Host "  GUID: $($subkey.PSChildName) has NO Count subkey" -ForegroundColor DarkYellow
    }
}

Write-Host ""
Write-Host "[4] Summary:" -ForegroundColor Yellow
Write-Host "  Total GUIDs: $($subkeys.Count)" -ForegroundColor White
Write-Host "  Total registry values: $totalEntries" -ForegroundColor White

if ($totalEntries -eq 0) {
    Write-Host ""
    Write-Host "⚠ No UserAssist data found!" -ForegroundColor Red
    Write-Host "Possible reasons:" -ForegroundColor Yellow
    Write-Host "  1. UserAssist might be disabled" -ForegroundColor White
    Write-Host "  2. No programs have been executed yet" -ForegroundColor White
    Write-Host "  3. Registry permissions issue" -ForegroundColor White
    Write-Host ""
    Write-Host "Try running PowerShell as Administrator" -ForegroundColor Cyan
    exit
}

# ROT13 Decoder
function Decode-ROT13 {
    param([string]$Encoded)
    $decoded = ""
    foreach ($char in $Encoded.ToCharArray()) {
        if ($char -match '[A-Za-z]') {
            $base = if ($char -cmatch '[A-Z]') { 65 } else { 97 }
            $rot13 = ([byte][char]$char - $base + 13) % 26 + $base
            $decoded += [char]$rot13
        } else {
            $decoded += $char
        }
    }
    return $decoded
}

# Now parse actual data
Write-Host ""
Write-Host "[5] Parsing actual data..." -ForegroundColor Yellow
$results = @()

foreach ($subkey in $subkeys) {
    $countPath = Join-Path $subkey.PSPath "Count"
    
    if (Test-Path $countPath) {
        $countKey = Get-Item -Path $countPath
        $values = $countKey.GetValueNames()
        
        foreach ($valueName in $values) {
            try {
                $data = $countKey.GetValue($valueName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                
                if ($data -is [byte[]]) {
                    $decodedName = Decode-ROT13 -Encoded $valueName
                    
                    # Skip UEME_CTLSESSION
                    if ($decodedName -eq "UEME_CTLSESSION") { continue }
                    
                    # Parse 72-byte format (Windows 7+)
                    if ($data.Length -eq 72) {
                        $runCount = [BitConverter]::ToUInt32($data, 4)
                        
                        if ($runCount -gt 0) {  # Only show programs that have been run
                            $lastUsed = [BitConverter]::ToInt64($data, 60)
                            
                            if ($lastUsed -gt 0) {
                                try {
                                    $lastUsedDate = [DateTime]::FromFileTime($lastUsed)
                                    $daysAgo = [Math]::Round(([DateTime]::Now - $lastUsedDate).TotalDays, 1)
                                    
                                    $appName = [System.IO.Path]::GetFileNameWithoutExtension($decodedName)
                                    if ([string]::IsNullOrEmpty($appName)) { $appName = "Unknown" }
                                    
                                    $result = [PSCustomObject]@{
                                        Application = $appName
                                        FullPath = $decodedName
                                        RunCount = $runCount
                                        LastUsed = $lastUsedDate.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
                                        DaysAgo = $daysAgo
                                        GUID = $subkey.PSChildName
                                    }
                                    
                                    $results += $result
                                }
                                catch {
                                    # Skip date conversion errors
                                }
                            }
                        }
                    }
                }
            }
            catch {
                # Skip individual errors
            }
        }
    }
}

# Display results
Write-Host ""
Write-Host "[6] Results:" -ForegroundColor Yellow

if ($results.Count -eq 0) {
    Write-Host "  No executable programs found in UserAssist data." -ForegroundColor Yellow
    Write-Host "  All entries might have 0 run count or invalid timestamps." -ForegroundColor Gray
} else {
    Write-Host "  Found $($results.Count) programs with execution history:" -ForegroundColor Green
    Write-Host ""
    
    # Group by application name (case-insensitive)
    $groupedResults = $results | Group-Object { $_.Application.ToLower() } | ForEach-Object {
        $first = $_.Group | Sort-Object RunCount -Descending | Select-Object -First 1
        $first
    }
    
    # Sort by most recent
    $sortedResults = $groupedResults | Sort-Object DaysAgo | Select-Object -First 20
    
    $sortedResults | Format-Table @{Name="Application";Expression={$_.Application}}, 
                                   @{Name="Last Used";Expression={$_.LastUsed}}, 
                                   @{Name="Executions";Expression={$_.RunCount}}, 
                                   @{Name="Days Ago";Expression={$_.DaysAgo}} -AutoSize
    
    # Export to CSV
    $csvFile = "UserAssist_Simple_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $sortedResults | Export-Csv -Path $csvFile -NoTypeInformation
    Write-Host ""
    Write-Host "✓ Results exported to: $csvFile" -ForegroundColor Green
}

Write-Host ""
Write-Host "=" * 60
Write-Host "Debug complete!" -ForegroundColor Cyan
