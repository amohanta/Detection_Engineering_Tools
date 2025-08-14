# Power-EVTXtoCSV

![Power-EVTXtoCSV Banner](https://i.imgur.com/7YwO3PR.png)

**Power-EVTXtoCSV** is a PowerShell-based forensic utility designed to parse Windows `.evtx` event log files into structured CSV format for easier analysis in Excel, SIEMs, or custom incident response tools.

## Features
- Parses **all fields** from both the `System` and `EventData` sections of EVTX files.
- Automatically extracts **attributes** (e.g., `SystemTime`, `ProcessID`, `ThreadID`) and stores them as separate CSV columns.
- Handles **named** and **unnamed** EventData fields.
- Exports clean `.csv` output ready for filtering and analysis.
- Simple **command-line usage** with one required parameter (EVTX file path).
- Works on single EVTX files (can be extended to process folders in bulk).

## Usage
```powershell
powershell -ExecutionPolicy Bypass -File Power-EVTXtoCSV.ps1 "C:\Forensics\Security.evtx"

Example Output:
=============================================
   Power-EVTXtoCSV - Full EVTX to CSV Parser
   Author : Abhijit Mohanta
   Input  : C:\Forensics\Security.evtx
=============================================

[*] Parsing C:\Forensics\Security.evtx ...
[+] Parsing complete.
[+] Output saved to C:\Forensics\Security.csv
Output

The CSV output includes:

EventID, ProviderName, ComputerName, Level, Keywords, and all System fields.

All EventData fields extracted by their actual schema names (or numbered if unnamed).

Attribute values like TimeCreated_SystemTime, Execution_ProcessID, Execution_ThreadID.

Requirements

Windows PowerShell 5.1 (works on PowerShell 7+ with Get-WinEvent support)

Windows Vista or later (EVTX parsing support)

Author

Abhijit Mohanta
