

# 🧩 Forensics Artifact Generator

## 📘 Overview
**Forensics Artifact Generator** is a Windows executable that simulates real-world user and system activities to generate common **Windows forensic artifacts**.  
It is intended for forensic investigators, analysts, and students who want to study and practice **forensic timeline reconstruction** and **artifact correlation** using open-source tools.

---

## 🧠 Purpose
To generate realistic forensic artifacts on a test system that can later be collected and analyzed to:
- Learn how forensic tools extract evidence.
- Practice building forensic timelines.
- Understand which Windows components record different types of activity.

---

## 🧾 Actions Performed
The program performs benign actions that leave traces in Windows forensic artifacts.

| Action | Description | Artifacts Generated |
|--------|--------------|---------------------|
| File Creation | Creates text/log files under C:\ForensicTest | MFT, USN Journal |
| File Deletion | Deletes one file | MFT, USN Journal |
| Registry Modification | Creates registry key HKCU\Software\ForensicTest | Registry Hive changes |
| Process Execution | Executes notepad.exe | Prefetch |
| LNK Creation | Creates shortcut on Desktop | LNK artifact |
| Directory Creation | Creates C:\ForensicTest\Logs | File system timestamps |
| Timestamp Updates | Access and modification of files | MFT timestamp changes |

---

## 🧩 Artifacts Generated

| Artifact | Typical Path | Parser Tool |
|-----------|---------------------|--------------------------------|
| Prefetch Files | C:\Windows\Prefetch\ | PECmd.exe |
| Amcache | C:\Windows\AppCompat\Programs\Amcache.hve | AmcacheParser.exe |
| Shimcache | C:\Windows\System32\config\SYSTEM | AppCompatCacheParser.exe |
| MFT | C:\$MFT | MFTECmd.exe |
| Event Logs | C:\Windows\System32\winevt\Logs\ | EvtxECmd.exe |
| LNK Files | C:\Users\<User>\Desktop\ForensicShortcut.lnk | LECmd.exe |
| Registry Changes | HKCU\Software\ForensicTest | Registry Explorer, RegRipper |

---

## ⚙️ Usage

1. Run the executable as a normal user.
2. It automatically creates test files and registry entries.
3. Artifacts are generated across system components.
4. Use forensic tools to parse and analyze them.

Example Directory Created:
```
C:\ForensicTest\
├── testfile.txt
├── temp.log
├── Logs\
└── ForensicShortcut.lnk (on Desktop)
```

---

## 🧰 Recommended Forensic Tools

| Tool | Purpose | Source |
|------|----------|--------|
| PECmd | Parse Prefetch files | https://ericzimmerman.github.io/ |
| AmcacheParser | Parse Amcache hive | https://ericzimmerman.github.io/ |
| MFTECmd | Parse MFT | https://ericzimmerman.github.io/ |
| EvtxECmd | Parse Event Logs | https://ericzimmerman.github.io/ |
| LECmd | Parse LNK Files | https://ericzimmerman.github.io/ |
| AppCompatCacheParser | Parse Shimcache | https://ericzimmerman.github.io/ |

---

## 🧪 Example Use Case

1. Run `ForensicsArtifactGenerator.exe`.
2. Collect artifacts with:
```
PECmd.exe -d "C:\Windows\Prefetch" --csv "C:\Output\Prefetch.csv"
MFTECmd.exe -f "C:\$MFT" --csv "C:\Output\MFT.csv"
EvtxECmd.exe -d "C:\Windows\System32\winevt\Logs" --csv "C:\Output\EVTX.csv"
```
3. Merge into timeline:
```
log2timeline.py timeline.dump "C:\Evidence"
psort.py -o L2tcsv -w master_timeline.csv timeline.dump
```

---

## ⚠️ Disclaimer
This tool is for **educational and forensic research** use only.  
Do **not** execute it on production systems.
