# ==============================
# Procmon CSV Parser with MITRE Mapping
# ==============================

# Print author name and script name

param (
    [Parameter(Position=0, Mandatory=$true)]
    [string]$CsvFile
)

$author = "Abhijit Mohanta"
$scriptName = $MyInvocation.MyCommand.Name
Write-Host "Author: $author"
Write-Host "Script Name: $scriptName"
Write-Host "-----------------------------------"

# Output file
$OutputCsv = "filtered_" + (Split-Path $CsvFile -Leaf)

# Load CSV (Procmon exports are usually UTF-16, fallback to UTF-8)
try {
    $data = Import-Csv -Path $CsvFile -Encoding UTF8
} catch {
    $data = Import-Csv -Path $CsvFile -Encoding Unicode
}

# ==============================
# Separate operations
# ==============================

# Registry operations
$RegistryOps = $data | Where-Object { $_.Operation -in @("RegSetValue", "RegCreateKey") }

# File operations
$WriteOps   = $data | Where-Object { $_.Operation -eq "WriteFile" }
$WritePaths = $WriteOps.Path | Sort-Object -Unique
$CreateOps  = $data | Where-Object { $_.Operation -eq "CreateFile"} # -and ($_.Path -in $WritePaths) }

$FileOps = $WriteOps + $CreateOps

# ==============================
# Merge
# ==============================
$Filtered = $RegistryOps + $FileOps

# ==============================
# Add MITRE Mapping Column
# ==============================
foreach ($row in $Filtered) {
    $mitre = ""

    if ($row.Operation -like "Reg*") {
        # Registry Persistence
        if ($row.Path -match "CurrentVersion\\Run" -or $row.Path -match "CurrentVersion\\RunOnce") {
            $mitre = "T1547.001 (Registry Run Keys / Startup Folder)"
        }
        elseif ($row.Path -match "CurrentVersion\\Policies\\Explorer\\Run") {
            $mitre = "T1547.001 (Registry Explorer Run Key)"
        }
        elseif ($row.Path -match "CurrentVersion\\RunServices" -or $row.Path -match "CurrentVersion\\RunServicesOnce") {
            $mitre = "T1547.001 (Registry RunServices Keys)"
        }
        elseif ($row.Path -match "CurrentVersion\\Winlogon\\Shell") {
            $mitre = "T1547.004 (Winlogon Shell Modification)"
        }
        elseif ($row.Path -match "CurrentVersion\\Winlogon\\Userinit") {
            $mitre = "T1547.004 (Winlogon Userinit Modification)"
        }
        elseif ($row.Path -match "CurrentVersion\\Winlogon\\Notify") {
            $mitre = "T1547.004 (Winlogon Notify DLL)"
        }
        elseif ($row.Path -match "CurrentVersion\\Image File Execution Options") {
            $mitre = "T1546.012 (Image File Execution Options Injection)"
        }
        elseif ($row.Path -match "CurrentVersion\\ShellServiceObjectDelayLoad") {
            $mitre = "T1547.009 (SSODL Persistence)"
        }
        elseif ($row.Path -match "CurrentVersion\\AppInit_DLLs") {
            $mitre = "T1546.010 (AppInit DLLs Injection)"
        }
    }

    if ($row.Operation -like "*File") {
        # File-based Persistence
        if ($row.Path -match "\\Startup\\") {
            $mitre = "T1547.001 (Startup Folder Persistence)"
        }
        elseif ($row.Path -match "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup") {
            $mitre = "T1547.001 (User Startup Folder Persistence)"
        }
        elseif ($row.Path -match "key3\.db" -or $row.Path -match "key4\.db") {
            $mitre = "Credential Stealer (Firefox key DB files)"
        }
        elseif ($row.Path -match "Login Data" -or $row.Path -match "Cookies.sqlite") {
            $mitre = "Credential/Session Stealer (Chrome/Edge DB files)"
        }
    }

    # Add as new property
    $row | Add-Member -NotePropertyName "MITRE_Technique" -NotePropertyValue $mitre -Force
}

# Preserve original order (based on "Time of Day" if present)
if ($Filtered -and $Filtered[0].PSObject.Properties.Name -contains "Time of Day") {
    $Filtered = $Filtered | Sort-Object { [datetime]($_."Time of Day") }
}

# Export
$Filtered | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8

Write-Output "Registry Ops: $($RegistryOps.Count)"
Write-Output "File Ops: $($FileOps.Count)"
Write-Output "[*] Filtered CSV with MITRE mapping written to $OutputCsv"

# ==============================
# Parse the Output CSV and Print neatly
# ==============================
Write-Host "`n=== MITRE Matches (from $OutputCsv) ==="

$parsed = Import-Csv -Path $OutputCsv

foreach ($row in $parsed) {
    if ($row.MITRE_Technique -ne "") {
        Write-Output "Time of Day : $($row.'Time of Day')"
        Write-Output "Process Name: $($row.'Process Name')"
        Write-Output "PID         : $($row.PID)"
        Write-Output "Operation   : $($row.Operation)"
        Write-Output "Path        : $($row.Path)"
        Write-Output "MITRE       : $($row.MITRE_Technique)"
        Write-Output "----------------------------------------"
    }
}
