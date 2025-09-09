EvtxECmd CSV Filter

A simple Python script to filter Windows Event Logs exported by Eric Zimmerman's EvtxECmd.exe
EvtxECmd converts .evtx event log files into .csv.
This script helps you filter those .csv files by Event ID(s) and generate a smaller, focused CSV for analysis.

🔧 Requirements

Python 3.x (recommended)

EvtxECmd.exe (to generate the initial CSV)

**Usage**

**First, export an event log using EvtxECmd.exe:**
EvtxECmd.exe -f Security.evtx --csv out_folder

**This will produce a CSV file like:**
out_folder\Security_EvtxECmd_Output.csv


**Run the filter script:**
python3 filter_events.py <input.csv> <output.csv> <event_ids>

python3 filter_events.py Security_EvtxECmd_Output.csv filtered.csv 4688,4696,4624

