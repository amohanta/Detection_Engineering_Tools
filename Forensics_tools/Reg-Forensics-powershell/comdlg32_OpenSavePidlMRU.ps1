# Define the extensions you want to process
$ExtensionsToProcess = @("exe", "7z", "apk", "jpeg", "docx", "txt", "pdf", "zip", "rar", "png")

$RegBasePath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU"

Write-Host "[*] Decoding OpenSavePidlMRU for specific extensions" -ForegroundColor Cyan
Write-Host "[*] Processing extensions: $($ExtensionsToProcess -join ', ')"
Write-Host ""

# Hex dump function - COMMENTED OUT (enable when needed)
<#
function Show-HexDump {
    param (
        [byte[]]$Data,
        [int]$BytesPerLine = 16,
        [int]$MaxBytes = 512
    )
    
    if ($Data -eq $null -or $Data.Length -eq 0) {
        Write-Host "    No data to display" -ForegroundColor Yellow
        return
    }
    
    $dumpLength = [Math]::Min($MaxBytes, $Data.Length)
    
    Write-Host "    Hex dump ($dumpLength of $($Data.Length) bytes):" -ForegroundColor Cyan
    
    for ($i = 0; $i -lt $dumpLength; $i += $BytesPerLine) {
        $hexLine = @()
        $asciiLine = @()
        
        $lineBytes = [Math]::Min($BytesPerLine, $dumpLength - $i)
        
        for ($j = 0; $j -lt $lineBytes; $j++) {
            $byte = $Data[$i + $j]
            $hexLine += "{0:X2}" -f $byte
            
            if ($byte -ge 32 -and $byte -le 126) {
                $asciiLine += [char]$byte
            } else {
                $asciiLine += "."
            }
        }
        
        # Pad the hex line if needed
        while ($hexLine.Count -lt $BytesPerLine) {
            $hexLine += "  "
            $asciiLine += " "
        }
        
        $hexOutput = $hexLine -join ' '
        $asciiOutput = $asciiLine -join ''
        
        Write-Host "    $($i.ToString('X4')): $hexOutput  |$asciiOutput|"
    }
    
    if ($Data.Length -gt $MaxBytes) {
        Write-Host "    ... (truncated, total $($Data.Length) bytes)" -ForegroundColor DarkGray
    }
}
#>

function Extract-StringsFromBinary {
    param ([byte[]]$Data)
    
    $strings = @()
    
    if ($Data -eq $null -or $Data.Length -lt 4) {
        return $strings
    }
    
    # Try to find Unicode strings (UTF-16LE)
    $i = 0
    while ($i -lt $Data.Length - 3) {
        # Check for potential Unicode string (non-null char)
        if (($Data[$i] -ne 0 -or $Data[$i+1] -ne 0)) {
            $start = $i
            $j = $i
            
            # Find end of string (two null bytes)
            while ($j -lt $Data.Length - 1) {
                if ($Data[$j] -eq 0 -and $Data[$j+1] -eq 0) {
                    $length = $j - $start
                    if ($length -ge 4) { # At least 2 chars
                        try {
                            $strBytes = New-Object byte[] $length
                            [Array]::Copy($Data, $start, $strBytes, 0, $length)
                            $str = [System.Text.Encoding]::Unicode.GetString($strBytes)
                            $str = $str.Trim()
                            
                            # Filter meaningful strings
                            if ($str.Length -ge 2 -and 
                                !$str.Contains("`0") -and 
                                !$str.Contains("`n") -and 
                                !$str.Contains("`r") -and
                                ($str -match '^[A-Za-z]:\\' -or 
                                 $str -match '^\\\\' -or
                                 $str -match '^[A-Za-z0-9]' -and $str.Length -ge 4)) {
                                if ($str -notin $strings) {
                                    $strings += $str
                                }
                            }
                        } catch {
                            # Ignore conversion errors
                        }
                    }
                    $i = $j + 2
                    break
                }
                $j += 2
            }
        }
        $i++
    }
    
    # Try to find ASCII strings
    $i = 0
    while ($i -lt $Data.Length) {
        if ($Data[$i] -ge 32 -and $Data[$i] -le 126) {
            $start = $i
            while ($i -lt $Data.Length -and $Data[$i] -ge 32 -and $Data[$i] -le 126) {
                $i++
            }
            $length = $i - $start
            if ($length -ge 4) { # At least 4 chars
                try {
                    $strBytes = New-Object byte[] $length
                    [Array]::Copy($Data, $start, $strBytes, 0, $length)
                    $str = [System.Text.Encoding]::ASCII.GetString($strBytes)
                    $str = $str.Trim()
                    
                    if ($str.Length -ge 4 -and 
                        !$str.Contains("`0") -and 
                        ($str -match '^[A-Za-z]:\\' -or 
                         $str -match '^\\\\' -or
                         $str -match '\.(exe|dll|txt|doc|pdf|jpg|png|zip|rar|7z|apk)$')) {
                        if ($str -notin $strings) {
                            $strings += $str
                        }
                    }
                } catch {
                    # Ignore conversion errors
                }
            }
        }
        $i++
    }
    
    return $strings | Sort-Object -Unique
}

# MAIN EXECUTION
try {
    # Process each specified extension
    foreach ($ext in $ExtensionsToProcess) {
        $RegPath = Join-Path $RegBasePath $ext
        
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "[*] Processing: .$ext" -ForegroundColor White
        Write-Host "    Registry Path: $RegPath" -ForegroundColor DarkGray
        
        # Check if the extension key exists
        if (-not (Test-Path $RegPath)) {
            Write-Host "    [!] Registry path not found (no MRU entries for .$ext)" -ForegroundColor Yellow
            Write-Host ""
            continue
        }
        
        try {
            # Get the registry key
            $Key = Get-Item -Path $RegPath -ErrorAction Stop
            
            # Get all value names
            $ValueNames = $Key.GetValueNames()
            
            # Filter out MRUListEx and sort numeric values
            $NumericValues = $ValueNames | Where-Object { $_ -match '^\d+$' } | Sort-Object { [int]$_ }
            $OtherValues = $ValueNames | Where-Object { $_ -notmatch '^\d+$' -and $_ -ne "" }
            
            Write-Host "    Found $($NumericValues.Count) numeric values, $($OtherValues.Count) other values"
            Write-Host ""
            
            # Process numeric values first (1, 2, 3, etc.)
            $totalBytes = 0
            $totalStrings = 0
            
            foreach ($ValueName in $NumericValues) {
                Write-Host "    --- Value: $ValueName ---" -ForegroundColor Yellow
                
                try {
                    $RawValue = $Key.GetValue($ValueName)
                    
                    if ($RawValue -eq $null) {
                        Write-Host "      [NULL or empty value]" -ForegroundColor DarkGray
                        Write-Host ""
                        continue
                    }
                    
                    if ($RawValue -is [byte[]]) {
                        $totalBytes += $RawValue.Length
                        Write-Host "      Type: Binary ($($RawValue.Length) bytes)" -ForegroundColor Green
                        
                        # Hex dump - COMMENTED OUT (uncomment when needed)
                        # Show-HexDump -Data $RawValue -MaxBytes 256
                        
                        # Try to extract strings
                        $extractedStrings = Extract-StringsFromBinary -Data $RawValue
                        
                        if ($extractedStrings.Count -gt 0) {
                            $totalStrings += $extractedStrings.Count
                            Write-Host "      Extracted strings ($($extractedStrings.Count) found):" -ForegroundColor Cyan
                            foreach ($str in $extractedStrings) {
                                Write-Host "        - $str" -ForegroundColor White
                            }
                        } else {
                            Write-Host "      No readable strings found" -ForegroundColor DarkGray
                        }
                    }
                    else {
                        Write-Host "      Type: $($RawValue.GetType().Name)" -ForegroundColor Green
                        Write-Host "      Value: $RawValue" -ForegroundColor White
                    }
                    
                    Write-Host ""
                    
                } catch {
                    Write-Host "      [!] Error reading value '$ValueName': $_" -ForegroundColor Red
                    Write-Host ""
                }
            }
            
            # Process other values (like MRUListEx)
            if ($OtherValues.Count -gt 0) {
                Write-Host "    --- Other Values ---" -ForegroundColor Magenta
                
                foreach ($ValueName in $OtherValues) {
                    if ($ValueName -eq "") { continue }
                    
                    Write-Host "    Value: $ValueName" -ForegroundColor DarkCyan
                    
                    try {
                        $RawValue = $Key.GetValue($ValueName)
                        
                        if ($RawValue -is [byte[]]) {
                            Write-Host "      Type: Binary ($($RawValue.Length) bytes)" -ForegroundColor Green
                            
                            # For MRUListEx, try to interpret as 32-bit integers
                            if ($ValueName -eq "MRUListEx" -and $RawValue.Length -ge 4) {
                                Write-Host "      MRUListEx (decoded as 32-bit integers):" -ForegroundColor Cyan
                                $intList = @()
                                for ($i = 0; $i -lt $RawValue.Length; $i += 4) {
                                    if ($i + 3 -lt $RawValue.Length) {
                                        $intValue = [BitConverter]::ToInt32($RawValue, $i)
                                        if ($intValue -ne -1) { # -1 indicates end of list
                                            $intList += $intValue
                                        }
                                    }
                                }
                                if ($intList.Count -gt 0) {
                                    Write-Host "        Order: $($intList -join ', ')" -ForegroundColor White
                                } else {
                                    Write-Host "        [Empty or all -1 values]" -ForegroundColor DarkGray
                                }
                            }
                        }
                        else {
                            Write-Host "      Type: $($RawValue.GetType().Name)" -ForegroundColor Green
                            Write-Host "      Value: $RawValue" -ForegroundColor White
                        }
                        
                    } catch {
                        Write-Host "      [!] Error: $_" -ForegroundColor Red
                    }
                    
                    Write-Host ""
                }
            }
            
            # Summary for this extension
            Write-Host "    Summary for extension .$($ext):" -ForegroundColor Green
            Write-Host "      - Numeric values: $($NumericValues.Count)" -ForegroundColor White
            Write-Host "      - Total bytes processed: $totalBytes" -ForegroundColor White
            Write-Host "      - Strings extracted: $totalStrings" -ForegroundColor White
            
        } catch {
            Write-Host "    [!] Error processing extension .$($ext) : $($_.Exception.Message)" -ForegroundColor Red
        }
        
        Write-Host ""
        Write-Host ""
    }
    
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "[DONE] Processing complete" -ForegroundColor Green
    Write-Host "Processed $($ExtensionsToProcess.Count) extensions" -ForegroundColor White
    
} catch {
    Write-Host "[!] Error: $($_.Exception.Message)" -ForegroundColor Red
    exit
}