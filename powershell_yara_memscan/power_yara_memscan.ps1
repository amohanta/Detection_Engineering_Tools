# Define log file path
$logFile = "scan_results_all_processes.txt"

# Clear previous log (optional, remove if you want to append)
if (Test-Path $logFile) { Remove-Item $logFile }

# Get all running processes and scan each one
Get-Process | ForEach-Object { 
    # Build process info header
    $output = @"
`n============ Scanning Process ============
PID: $($_.Id)
Name: $($_.Name)
#CommandLine: $((Get-CimInstance Win32_Process -Filter "ProcessId = $($_.Id)").CommandLine)
Scanning...
"@

    # Print to console
    Write-Host $output

    # Run YARA scan and capture output
    $scanResult = & "E:\\yaratest\\yara32.exe" "E:\\yaratest\\rules.yar" $_.Id 2>&1

    # Check if YARA found any matches (non-empty result typically indicates detection)
    $detected = $false
    $detectionRules = @()
    
    if ($scanResult -and $scanResult -notmatch "error|warning" -and $scanResult.Trim() -ne "") {
        $detected = $true
        # Extract rule names from YARA output (one rule per line typically)
        $detectionRules = $scanResult -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
    }

    # Print detection message if found
    if ($detected) {
        foreach ($rule in $detectionRules) {
            $detectionMessage = "detected => $rule - $($_.Id)"
            Write-Host $detectionMessage -ForegroundColor Red
        }
    }

    # Print YARA results to console
    Write-Host $scanResult

    # Combine output and scan results, then write to file
    $fullOutput = $output + "`n" + $scanResult + "`n========================================`n"
    $fullOutput | Out-File -FilePath $logFile -Append

    # Print separator to console
    Write-Host "`n========================================"
}

Write-Host "`nScanning completed. Results saved to: $logFile"
