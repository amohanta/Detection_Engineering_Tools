<#
.SYNOPSIS
    Procmon CSV filter and summary generator
.DESCRIPTION
    Filters Procmon CSV logs to keep:
    - WriteFile
    - CreateFile (only if corresponding WriteFile exists)
    - RegSetValue
    - RegCreateKey (only if corresponding RegSetValue exists)
    Excludes RegSetInfoKey.  
    Generates a summary with unique paths and process creation mapping (parent ? child).  
    Shows Process Name along with PID in summary.
.AUTHOR
    Abhijit Mohanta
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$InputCsv
)

# Generate output file paths
$outputCsv = [System.IO.Path]::ChangeExtension($InputCsv, $null) + "-filtered.csv"
$summaryTxt = [System.IO.Path]::ChangeExtension($InputCsv, $null) + "-summary.txt"

# ---------------- READ CSV ----------------
# Ignore comment lines starting with ';'
$cleanLines = Get-Content -Path $InputCsv | Where-Object { $_ -notmatch '^\s*;' }

if ($cleanLines.Count -eq 0) {
    Write-Host "CSV file is empty or only contains comments."
    exit
}

# Read CSV with headers
$data = $cleanLines | ConvertFrom-Csv

if (-not $data) {
    Write-Host "CSV file could not be parsed correctly."
    exit
}

# Detect column names
$csvColumns = $data[0].PSObject.Properties.Name

# Use second column as Process Name if exists
if ($csvColumns.Count -ge 2) {
    $procNameCol = $csvColumns[1]
} else {
    $procNameCol = $csvColumns[0]
}

# ---------------- FILTER PHASE ----------------

# WriteFile operations
$writeFiles = $data | Where-Object { $_.Operation -eq "WriteFile" }

# CreateFile operations that correspond to WriteFile
$writeTargets = $writeFiles | ForEach-Object { "$($_.$procNameCol)|$($_.Path)" } | Sort-Object -Unique
$createWithWrite = $data | Where-Object {
    $_.Operation -eq "CreateFile" -and ("$($_.$procNameCol)|$($_.Path)" -in $writeTargets)
}

# Registry operations
$regSetValues = $data | Where-Object { $_.Operation -eq "RegSetValue" }
$setValueTargets = $regSetValues | ForEach-Object { "$($_.$procNameCol)|$($_.Path)" } | Sort-Object -Unique
$regCreateKeys = $data | Where-Object {
    $_.Operation -eq "RegCreateKey" -and ("$($_.$procNameCol)|$($_.Path)" -in $setValueTargets)
}

$registryOps = $data | Where-Object { $_.Operation -match "RegSet" -and $_.Operation -ne "RegSetInfoKey" }

# Combine filtered operations
$filtered = $writeFiles + $createWithWrite + $registryOps + $regCreateKeys

# Include Process Start events for mapping parent-child relationships
$processStarts = $data | Where-Object { $_.Operation -eq "Process Start" }

# Sort filtered CSV by Time (first column)
$filtered = $filtered | Sort-Object { $_.PSObject.Properties.Value[0] }
$filtered | Export-Csv -Path $outputCsv -NoTypeInformation
Write-Host "Filtered CSV saved to: $outputCsv"

# ---------------- SUMMARY PHASE ----------------

# Group by Process Name and PID
$grouped = $filtered | Group-Object -Property $procNameCol, PID

$summary = @()

foreach ($group in $grouped) {
    $procName = if ($group.Group[0].$procNameCol) { $group.Group[0].$procNameCol.Trim() } else { "<Unknown>" }
    $procId   = $group.Group[0].PID

    $summary += "========================================="
    $summary += "Process Name: $procName    PID: $procId"
    $summary += "========================================="

    # Detect parent process if available
    $parentInfo = $processStarts | Where-Object { $_.PID -eq $procId }
    if ($parentInfo) {
        $parentName = if ($parentInfo.$procNameCol) { $parentInfo.$procNameCol.Trim() } else { "<Unknown>" }
        $parentPid  = $parentInfo.ParentPID
        if ($parentPid) {
            $summary += "Created By: $parentName    PID: $parentPid"
        }
    }

    # Unique paths by operation
    $writePaths = ($group.Group | Where-Object { $_.Operation -eq "WriteFile" }).Path | Sort-Object -Unique
    $createPaths = ($group.Group | Where-Object { $_.Operation -eq "CreateFile" }).Path | Sort-Object -Unique
    $regPaths = ($group.Group | Where-Object { $_.Operation -eq "RegSetValue" }).Path | Sort-Object -Unique

    if ($writePaths) {
        $summary += "`n[WriteFile Paths]"
        $summary += $writePaths
    }

    if ($createPaths) {
        $summary += "`n[CreateFile Paths]"
        $summary += $createPaths
    }

    if ($regPaths) {
        $summary += "`n[RegSetValue Paths]"
        $summary += $regPaths
    }

    # Check if process created any child processes
    $childProcesses = $processStarts | Where-Object { $_.ParentPID -eq $procId }
    if ($childProcesses) {
        $summary += "`n[Child Processes Created]"
        foreach ($child in $childProcesses) {
            $childName = if ($child.$procNameCol) { $child.$procNameCol.Trim() } else { "<Unknown>" }
            $summary += "Process Name: $childName    PID: $($child.PID)"
        }
    }

    $summary += "`n"
}

# Write summary to file
$summary | Out-File -FilePath $summaryTxt -Encoding UTF8
Write-Host "Summary saved to: $summaryTxt"
