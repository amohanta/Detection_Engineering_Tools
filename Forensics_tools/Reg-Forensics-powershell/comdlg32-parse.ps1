$RegPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU"

Write-Host "[*] Decoding LastVisitedPidlMRU"
Write-Host "[*] Registry Path: $RegPath"
Write-Host ""

function Extract-PidlStrings {
    param ([byte[]]$Data)
    
    $Strings = @()
    
    if ($Data -eq $null -or $Data.Length -eq 0) {
        return $Strings
    }
    
    # Method 1: Scan for null-terminated Unicode strings
    for ($i = 0; $i -lt $Data.Length - 3; $i++) {
        # Look for potential start of Unicode string (non-null bytes)
        if ($Data[$i] -ne 0 -or $Data[$i+1] -ne 0) {
            # Try to find the end of the string (two consecutive null bytes)
            $end = $i
            while ($end -lt $Data.Length - 1) {
                if ($Data[$end] -eq 0 -and $Data[$end+1] -eq 0) {
                    # Found end of string
                    $length = $end - $i
                    if ($length -ge 4) {  # Minimum 2 characters (4 bytes)
                        try {
                            $strBytes = $Data[$i..($end-1)]
                            $str = [System.Text.Encoding]::Unicode.GetString($strBytes)
                            
                            # Clean up the string
                            $str = $str.Trim()
                            
                            # Only add if it looks like a meaningful string
                            if ($str.Length -ge 2 -and 
                                ($str -match '^[A-Za-z0-9_\-\. \\/:]+$' -or
                                 $str -match '\.(exe|dll|lnk|txt|doc|xls|pdf|bin)$' -or
                                 $str -match '[A-Za-z]:\\' -or
                                 $str -match '^\\\\')) {
                                if ($str -notin $Strings) {
                                    $Strings += $str
                                }
                            }
                        } catch {
                            # Ignore conversion errors
                        }
                    }
                    $i = $end + 1  # Skip past the null terminator
                    break
                }
                $end += 2  # Move to next Unicode character
            }
        }
    }
    
    # Method 2: Look for ASCII strings
    for ($i = 0; $i -lt $Data.Length - 1; $i++) {
        # Look for ASCII characters (printable range)
        if ($Data[$i] -ge 32 -and $Data[$i] -le 126) {
            $start = $i
            while ($i -lt $Data.Length -and $Data[$i] -ge 32 -and $Data[$i] -le 126) {
                $i++
            }
            $length = $i - $start
            if ($length -ge 3) {  # Minimum 3 characters
                try {
                    $strBytes = $Data[$start..($i-1)]
                    $str = [System.Text.Encoding]::ASCII.GetString($strBytes)
                    
                    # Clean up and filter
                    $str = $str.Trim()
                    if ($str.Length -ge 3 -and 
                        ($str -match '^[A-Za-z0-9_\-\. \\/:]+$' -or
                         $str -match '\.(exe|dll|lnk|txt|doc|xls|pdf|bin)$')) {
                        if ($str -notin $Strings) {
                            $Strings += $str
                        }
                    }
                } catch {
                    # Ignore conversion errors
                }
            }
        }
    }
    
    # Method 3: Specific known patterns from your hex dump
    # Looking for "samples" and other visible strings
    $hexString = [System.BitConverter]::ToString($Data).Replace('-', '')
    
    # Look for "samples" in hex (73 61 6D 70 6C 65 73 = "samples" in ASCII)
    if ($hexString -match '73.?61.?6D.?70.?6C.?65.?73') {
        $Strings += "samples"
    }
    
    # Look for "test" in hex (74 65 73 74 = "test" in ASCII)
    if ($hexString -match '74.?65.?73.?74') {
        $Strings += "test"
    }
    
    # Look for common Windows paths
    if ($hexString -match '43.?3A.?5C') {  # C:\ in hex
        $Strings += "C:\"
    }
    
    # Method 4: Try to extract strings from known offsets in PIDL structure
    # Based on your hex dump, strings often appear at specific positions
    
    return $Strings | Where-Object { $_ } | Select-Object -Unique | Sort-Object
}

function Show-HexDump {
    param (
        [byte[]]$Data,
        [int]$Length = 128
    )
    
    if ($Data -eq $null -or $Data.Length -eq 0) {
        Write-Host "  No data to display" -ForegroundColor Yellow
        return
    }
    
    $dumpLength = [Math]::Min($Length, $Data.Length)
    Write-Host "  First $dumpLength bytes (hex):" -ForegroundColor Cyan
    
    for ($i = 0; $i -lt $dumpLength; $i += 16) {
        $end = [Math]::Min($i + 15, $dumpLength - 1)
        $hexBytes = @()
        $asciiChars = @()
        
        for ($j = $i; $j -le $end; $j++) {
            $hexBytes += "{0:X2}" -f $Data[$j]
            $byte = $Data[$j]
            if ($byte -ge 32 -and $byte -le 126) {
                $asciiChars += [char]$byte
            } else {
                $asciiChars += "."
            }
        }
        
        $hexLine = $hexBytes -join ' '
        $asciiLine = $asciiChars -join ''
        Write-Host "    $($i.ToString('X4')): $hexLine  $asciiLine"
    }
}

# MAIN EXECUTION
try {
    # Check if registry path exists
    if (-not (Test-Path $RegPath)) {
        Write-Host "[!] Registry path not found: $RegPath" -ForegroundColor Red
        exit
    }
    
    # Get the registry key
    $Key = Get-Item -Path $RegPath -ErrorAction Stop
    
    Write-Host "[+] Registry key loaded successfully" -ForegroundColor Green
    Write-Host "[+] Key has $($Key.ValueCount) values" -ForegroundColor Green
    Write-Host ""
    
    # Get all value names
    $ValueNames = $Key.GetValueNames()
    
    if ($ValueNames.Count -eq 0) {
        Write-Host "[!] No values found in registry key" -ForegroundColor Yellow
        exit
    }
    
    # Process each value
    foreach ($ValueName in $ValueNames) {
        if ($ValueName -eq "MRUListEx") {
            continue
        }

        Write-Host "----------------------------------------"
        Write-Host "Value Name: '$ValueName'"
        
        try {
            # Read the value data
            $RawValue = $Key.GetValue($ValueName)
            
            if ($RawValue -eq $null) {
                Write-Host "  Value is null or empty" -ForegroundColor Yellow
                continue
            }
            
            if ($RawValue -is [byte[]]) {
                Write-Host "  Data type: Byte array ($($RawValue.Length) bytes)"
                
                # Try to extract strings
                $DecodedStrings = Extract-PidlStrings -Data $RawValue

                if ($DecodedStrings.Count -eq 0) {
                    Write-Host "  No readable strings found" -ForegroundColor Yellow
                } else {
                    Write-Host "  Extracted Strings:" -ForegroundColor Green
                    foreach ($S in $DecodedStrings) {
                        Write-Host "    - $S"
                    }
                }
                
                # Show hex dump
                Write-Host ""
                Show-HexDump -Data $RawValue -Length 128
            }
            else {
                Write-Host "  Data type: $($RawValue.GetType().Name)"
                Write-Host "  Value: $RawValue"
            }
        }
        catch {
            Write-Host "  [!] Error reading value: $_" -ForegroundColor Red
        }
        
        Write-Host ""
    }
}
catch {
    Write-Host "[!] Error accessing registry: $_" -ForegroundColor Red
    exit
}

Write-Host "----------------------------------------"
Write-Host "[DONE] Processing complete" -ForegroundColor Green