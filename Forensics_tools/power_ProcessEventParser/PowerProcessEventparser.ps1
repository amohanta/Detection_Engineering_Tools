# Process Audit Logger - Robust Filtering Version
# Run as Administrator

$excludedProcesses = @(
    "conhost.exe", "svchost.exe", "RuntimeBroker.exe", "dllhost.exe",
    "backgroundTaskHost.exe", "SearchUI.exe", "Widgets.exe", 
    "StartMenuExperienceHost.exe", "TextInputHost.exe", "ctfmon.exe",
    "SecurityHealthSystray.exe", "ShellExperienceHost.exe",
    "ApplicationFrameHost.exe", "fontdrvhost.exe", "winlogon.exe",
    "csrss.exe", "wininit.exe", "services.exe", "lsass.exe", "wevtutil.exe"
)

$outputPath = "C:\temp\ProcessAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"

# Create output directory if it doesn't exist
$outputDir = Split-Path $outputPath -Parent
if (!(Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force
}

try {
    $events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688; StartTime=(Get-Date).AddHours(-24)} -ErrorAction Stop
    
    $filteredEvents = @()
    $excludedCount = 0
    
    foreach ($event in $events) {
        try {
            $processPath = $event.Properties[5].Value
            $processName = [System.IO.Path]::GetFileName($processPath)
            
            # Case-insensitive comparison
            if ($excludedProcesses -contains $processName) {
                $excludedCount++
                continue
            }
            
            # Alternative: case-insensitive contains
            $isExcluded = $false
            foreach ($excluded in $excludedProcesses) {
                if ($processName -ieq $excluded) {
                    $isExcluded = $true
                    break
                }
            }
            
            if ($isExcluded) {
                $excludedCount++
                continue
            }
            
            $filteredEvents += [PSCustomObject]@{
                TimeCreated = $event.TimeCreated
                ProcessName = $processName
                ProcessPath = $processPath
                CommandLine = $event.Properties[8].Value
                ProcessId = $event.Properties[4].Value
                User = $event.Properties[1].Value
                ParentProcess = $event.Properties[13].Value
                LogonId = $event.Properties[3].Value
            }
        }
        catch {
            Write-Warning "Error processing event: $_"
        }
    }
    
    # Export to CSV
    $filteredEvents | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8
    
    # Debug information
    Write-Host "`n=== DEBUG INFORMATION ===" -ForegroundColor Cyan
    Write-Host "Total events: $($events.Count)" -ForegroundColor White
    Write-Host "Excluded count: $excludedCount" -ForegroundColor Yellow
    Write-Host "Final count: $($filteredEvents.Count)" -ForegroundColor Green
    
    # Show what's actually in the data
    Write-Host "`nMost common processes in original data:" -ForegroundColor Yellow
    $events | ForEach-Object { 
        try { [System.IO.Path]::GetFileName($_.Properties[5].Value) } catch { "Unknown" } 
    } | Group-Object | Sort-Object Count -Descending | Select-Object -First 10 | Format-Table Name, Count -AutoSize
    
    if ($filteredEvents.Count -gt 0) {
        Write-Host "`nMost common processes after filtering:" -ForegroundColor Green
        $filteredEvents | Group-Object ProcessName | Sort-Object Count -Descending | Select-Object -First 10 | Format-Table Name, Count -AutoSize
    }
    
    Write-Host "Output file: $outputPath" -ForegroundColor Cyan
    
}
catch {
    Write-Error "Failed to query events: $_"
}
