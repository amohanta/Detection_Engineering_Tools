# Procmon CSV Filter and Summary Generator

A PowerShell script to filter and summarize Procmon CSV logs for Windows malware analysis, reverse engineering, and process activity tracking. 

This script helps security analysts, malware researchers, and incident responders quickly identify file, registry, and process activities from Procmon logs.

---

## Features

- Filters Procmon CSV logs to include:
  - `WriteFile` operations
  - `CreateFile` operations (only if corresponding `WriteFile` exists)
  - `RegSetValue` operations
  - `RegCreateKey` operations (only if corresponding `RegSetValue` exists)
  - `Process Start` operations (Process creation)
- Excludes `RegSetInfoKey` operations
- Generates a **filtered CSV** with only relevant events
- Generates a **summary report** including:
  - Process Name and PID
  - Parent process information
  - Child processes created
  - Unique file paths for WriteFile, CreateFile, and registry operations
- Handles CSV files with comment lines starting with `;`
- Sorts filtered events by timestamp
- Fully dynamic, detects process name column automatically
- No special characters in the output

---

## Requirements

- PowerShell 5.1 or later
- Windows operating system
- Procmon CSV log exported with headers

---

## Usage

1. Clone this repository or download the script `procmon_csv_filter.ps1`.
2. Open PowerShell and navigate to the directory containing the script.
3. Run the script:

```powershell
.\procmon_csv_filter.ps1 -InputCsv "Path\To\ProcmonLog.csv"
