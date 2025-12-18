# RecentDocs Registry Parser with Log File Output
$RegPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"

# Log file path
$LogFile = "recentdocs_logs.txt"
$ConsoleOutput = $true  # Set to $false if you only want log file output

Write-Host "Recent Documents Registry Analysis" -ForegroundColor Cyan
Write-Host "=" * 70
Write-Host "Path: $RegPath"
Write-Host "Log file: $((Get-Location).Path)\$LogFile"
Write-Host ""

# Function to write to both console and log file
function Write-Log {
    param(
        [string]$Message,
        [string]$Color = "White",
        [switch]$NoNewLine = $false
    )
    
    if ($ConsoleOutput) {
        if ($NoNewLine) {
            Write-Host $Message -ForegroundColor $Color -NoNewline
        } else {
            Write-Host $Message -ForegroundColor $Color
        }
    }
    
    # Always write to log file
    if ($NoNewLine) {
        $Message | Out-File -FilePath $LogFile -Append -NoNewline
    } else {
        $Message | Out-File -FilePath $LogFile -Append
    }
}

# Clear existing log file
"" | Out-File -FilePath $LogFile -Force
Write-Log "Recent Documents Analysis - $(Get-Date)" -Color Cyan
Write-Log "=" * 70 -Color Cyan
Write-Log ""

if (-not (Test-Path $RegPath)) {
    Write-Log "[ERROR] Registry path does not exist!" -Color Red
    exit
}

function Extract-FilePathFromBinary {
    param([byte[]]$Data)
    
    if (-not $Data -or $Data.Length -eq 0) { return $null }
    
    # Look for Unicode strings with path patterns
    for ($i = 0; $i -lt $Data.Length - 20; $i += 2) {
        # Look for drive letter pattern (C:, D:, etc.)
        if ($i + 4 -lt $Data.Length) {
            $char1 = [char]$Data[$i]
            $char2 = [char]$Data[$i+1]
            
            # Check for drive letter pattern like "C:" in Unicode
            if ($char2 -eq 0 -and $char1 -match '[A-Z]' -and $Data[$i+2] -eq 58 -and $Data[$i+3] -eq 0) {
                # Found drive letter, now try to extract the full path
                $start = $i
                while ($i -lt $Data.Length - 1 -and ($Data[$i] -ne 0 -or $Data[$i+1] -ne 0)) {
                    $i += 2
                }
                $length = $i - $start
                if ($length -ge 10) {  # At least 5 characters
                    try {
                        $strBytes = $Data[$start..($i-1)]
                        $path = [System.Text.Encoding]::Unicode.GetString($strBytes)
                        $path = $path.Trim()
                        
                        # Validate it looks like a path
                        if ($path -match '^[A-Za-z]:\\' -or $path -match '^\\\\') {
                            return $path
                        }
                    } catch { }
                }
            }
        }
    }
    
    # Method 2: Try to find any readable Unicode string
    $strings = @()
    for ($i = 0; $i -lt $Data.Length - 1; $i += 2) {
        if ($Data[$i] -ne 0 -or $Data[$i+1] -ne 0) {
            $start = $i
            while ($i -lt $Data.Length - 1 -and ($Data[$i] -ne 0 -or $Data[$i+1] -ne 0)) {
                $i += 2
            }
            $length = $i - $start
            if ($length -ge 4) {
                try {
                    $strBytes = $Data[$start..($i-1)]
                    $str = [System.Text.Encoding]::Unicode.GetString($strBytes)
                    $str = $str.Trim()
                    if ($str.Length -ge 3 -and $str -match '[A-Za-z0-9_\-\.\\/:]') {
                        $strings += $str
                    }
                } catch { }
            }
        }
    }
    
    # Return the most likely path
    foreach ($str in $strings) {
        if ($str -match '[A-Za-z]:\\' -or $str -match '^\\\\') {
            return $str
        }
    }
    
    if ($strings.Count -gt 0) {
        return $strings[0]
    }
    
    return $null
}

try {
    # Start logging
    Write-Log "[+] Starting analysis at $(Get-Date -Format 'HH:mm:ss')" -Color Green
    
    # Get extension subkeys
    $extensions = Get-ChildItem -Path $RegPath | Where-Object { $_.PSChildName -match '^\.' }
    
    if ($extensions.Count -eq 0) {
        Write-Log "[INFO] No extension subkeys found." -Color Yellow
        exit
    }
    
    Write-Log "[+] Found $($extensions.Count) file extensions" -Color Green
    Write-Log ""
    
    $allDocuments = @()
    $processedCount = 0
    
    foreach ($extKey in $extensions) {
        $extName = $extKey.PSChildName
        
        # Get document entries (skip MRUListEx)
        $valueNames = $extKey.GetValueNames() | Where-Object { $_ -ne "MRUListEx" }
        
        if ($valueNames.Count -eq 0) {
            continue
        }
        
        Write-Log "Processing $extName ($($valueNames.Count) entries)..." -Color Cyan
        
        foreach ($valueName in $valueNames) {
            try {
                $data = $extKey.GetValue($valueName)
                
                if ($data -is [byte[]]) {
                    $filePath = Extract-FilePathFromBinary -Data $data
                    
                    if ($filePath) {
                        $fileName = [System.IO.Path]::GetFileName($filePath)
                        
                        $docInfo = [PSCustomObject]@{
                            Extension = $extName
                            FileName = $fileName
                            FullPath = $filePath
                            RegistryIndex = $valueName
                            DataSize = $data.Length
                            LastModified = $extKey.LastWriteTime
                        }
                        
                        $allDocuments += $docInfo
                        $processedCount++
                    }
                }
            }
            catch {
                Write-Log "  ? Error processing $valueName" -Color DarkGray
            }
        }
    }
    
    # Write results to log file
    Write-Log ""
    Write-Log "=" * 70 -Color Green
    Write-Log "RECENT DOCUMENTS FOUND" -Color Green
    Write-Log "=" * 70 -Color Green
    Write-Log "Total documents found: $processedCount" -Color Cyan
    Write-Log "Analysis completed at: $(Get-Date)" -Color Cyan
    Write-Log ""
    
    if ($allDocuments.Count -eq 0) {
        Write-Log "[INFO] No documents were extracted from binary data." -Color Yellow
    }
    else {
        # Group by extension and sort
        $groupedDocs = $allDocuments | Group-Object Extension | Sort-Object Name
        
        Write-Log "Found $($allDocuments.Count) documents across $($groupedDocs.Count) extensions" -Color Cyan
        Write-Log ""
        
        # Write detailed results to log file
        foreach ($group in $groupedDocs) {
            Write-Log "?" * 60 -Color DarkGray
            Write-Log "EXTENSION: $($group.Name) ($($group.Count) documents)" -Color Yellow
            Write-Log "?" * 60 -Color DarkGray
            Write-Log ""
            
            # Sort by filename
            $sortedDocs = $group.Group | Sort-Object FileName
            
            $counter = 1
            foreach ($doc in $sortedDocs) {
                Write-Log "$counter. $($doc.FileName)" -Color White
                Write-Log "   Path: $($doc.FullPath)" -Color Gray
                Write-Log "   Registry Index: $($doc.RegistryIndex)" -Color Gray
                Write-Log "   Data Size: $($doc.DataSize) bytes" -Color Gray
                Write-Log "   Last Modified: $($doc.LastModified)" -Color Gray
                Write-Log ""
                $counter++
            }
        }
        
        # Summary table
        Write-Log "=" * 70 -Color Green
        Write-Log "SUMMARY BY EXTENSION" -Color Green
        Write-Log "=" * 70 -Color Green
        Write-Log ""
        
        $summary = @()
        foreach ($group in $groupedDocs) {
            $summary += [PSCustomObject]@{
                Extension = $group.Name
                Documents = $group.Count
                TotalSize = ($group.Group | Measure-Object -Property DataSize -Sum).Sum
            }
        }
        
        # Write summary table to log
        $summary | Sort-Object -Property Documents -Descending | Format-Table -AutoSize | Out-String | Out-File -FilePath $LogFile -Append
        
        # Also export to CSV
        $csvPath = "recentdocs_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $allDocuments | Select-Object Extension, FileName, FullPath, RegistryIndex, DataSize, LastModified | 
            Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        
        Write-Log ""
        Write-Log "CSV export created: $csvPath" -Color Green
    }
}
catch {
    $errorMsg = "[ERROR] An error occurred: $_"
    Write-Log $errorMsg -Color Red
    $errorMsg | Out-File -FilePath $LogFile -Append
}

Write-Log ""
Write-Log "=" * 70 -Color Cyan
Write-Log "Analysis complete! Log saved to: $LogFile" -Color Cyan
Write-Log "=" * 70 -Color Cyan

# Show final message
if ($ConsoleOutput) {
    Write-Host ""
    Write-Host "? Analysis complete!" -ForegroundColor Green
    Write-Host "? Log file created: $((Get-Location).Path)\$LogFile" -ForegroundColor Green
    
    # Show last few lines of log file
    if (Test-Path $LogFile) {
        Write-Host ""
        Write-Host "Last 10 lines of log file:" -ForegroundColor Cyan
        Get-Content $LogFile -Tail 10 | ForEach-Object {
            Write-Host "  $_" -ForegroundColor Gray
        }
    }
}