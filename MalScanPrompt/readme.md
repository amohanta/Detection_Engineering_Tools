# MalScanPrompt

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Windows-blue?style=for-the-badge&logo=windows" alt="Platform">
  <img src="https://img.shields.io/badge/Language-C++-00599C?style=for-the-badge&logo=cplusplus" alt="Language">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Version-1.0-orange?style=for-the-badge" alt="Version">
</p>

<p align="center">
  <b>Windows Malware Analysis & Detection Tool</b><br>
  A command-line tool for detecting code injection, process anomalies, and DLL hijacking
</p>

---

```
  +========================================================================+
  |                                                                        |
  |  ##   ##   ####   ##       #####   #####   ####   ##   ##              |
  |  ### ###  ##  ## ##      ##      ##      ##  ##  ###  ##               |
  |  ## # ##  ###### ##       ####   ##      ######  ## # ##               |
  |  ##   ##  ##  ## ##          ##  ##      ##  ##  ##  ###               |
  |  ##   ##  ##  ## ###### #####    #####  ##  ##  ##   ##                |
  |                                                                        |
  |  #####  #####    ####   ##   ##  #####  ######                         |
  |  ##  ## ##  ##  ##  ##  ### ###  ##  ##   ##                           |
  |  #####  #####   ##  ##  ## # ##  #####    ##                           |
  |  ##     ##  ##  ##  ##  ##   ##  ##       ##                           |
  |  ##     ##   ##  ####   ##   ##  ##       ##                           |
  |                                                                        |
  |                    MalScanPrompt v1.0                                  |
  +========================================================================+
```

## 📖 About

**MalScanPrompt** is a lightweight, interactive Windows malware analysis tool designed for security researchers, incident responders, and malware analysts. It provides real-time detection of:

- 🔴 **Code Injection** - Detect injected code in process memory (RWX regions, unbacked executable memory, shellcode signatures)
- 🔴 **Process Anomalies** - Identify suspicious process counts, parent-child relationship violations
- 🔴 **DLL Hijacking** - Find potential DLL hijacking attempts
- 🔴 **Unusual Locations** - Detect processes running from Temp/AppData folders

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **Memory Scanning** | Scans process memory for RWX regions, PE headers, shellcode patterns |
| 🌳 **Process Tree** | Visualize process hierarchy with timestamps |
| 🔐 **Mutex Enumeration** | List named/unnamed mutexes (useful for malware identification) |
| ⚡ **Timeout Control** | Configurable timeouts to handle hung processes |
| 🎨 **Colored Output** | Easy-to-read color-coded results |
| ⌨️ **Abort Support** | Press ESC/Q to abort long-running scans |

## 🚀 Quick Start

### Building

```bash
# Using Visual Studio Developer Command Prompt
cl /O2 /W3 MalScanPrompt.cpp /link psapi.lib ntdll.lib

# Using MinGW
g++ -O2 MalScanPrompt.cpp -o MalScanPrompt.exe -lpsapi -lntdll
```

### Running

```bash
# Run as Administrator for full access
MalScanPrompt.exe
```

## 📋 Commands

### Process Listing

| Command | Description |
|---------|-------------|
| `list-process` | List all running processes |
| `list-tree` | Show process tree hierarchy |
| `list-process-v` | Detailed process information |
| `list-dll <pid>` | List DLLs loaded by a process |
| `list-mutex <pid>` | List mutex handles for a process |

### Code Injection Scanning

| Command | Description |
|---------|-------------|
| `process-inject <pid> [-pt N] [-rt N]` | Scan a single process for injection |
| `system-inject [-pt N] [-rt N]` | Scan ALL processes system-wide |
| `dump-mem <pid> <addr>` | Dump memory region to file |

### Process Anomaly Detection

| Command | Description |
|---------|-------------|
| `detect-all` | Run all anomaly checks |
| `check-count` | Check critical process counts (lsass, csrss, services) |
| `check-parent` | Check parent-child relationships (svchost → services.exe) |
| `check-location` | Find processes in Temp/AppData folders |
| `check-DLL-hijack` | Detect potential DLL hijacking |

### Options

| Option | Description |
|--------|-------------|
| `-pt N` | Process timeout in seconds (default: 5) |
| `-rt N` | Region timeout in seconds (default: 2) |

### Controls

| Key | Action |
|-----|--------|
| `ESC` / `Q` | Abort current scan |
| `exit` | Exit program |

## 💡 Usage Examples

### Scan All Processes for Code Injection
```
MalScanPrompt> system-inject -pt 5 -rt 2
```

### Scan Specific Process
```
MalScanPrompt> process-inject 1234 -pt 10
```

### Dump Suspicious Memory Region
```
MalScanPrompt> dump-mem 1234 0x7FF00000
```

### Run All Anomaly Checks
```
MalScanPrompt> detect-all
```

### View Process Tree
```
MalScanPrompt> list-tree
```

## 🔍 Detection Signatures

MalScanPrompt detects the following suspicious patterns:

| Signature | Description | Severity |
|-----------|-------------|----------|
| `4D 5A` | PE Header (MZ) | 🔴 Critical |
| `55 8B EC` | x86 Function Prologue | 🔴 Critical |
| `55 48 8B EC` | x64 Function Prologue | 🔴 Critical |
| `E8 00 00 00 00` | Shellcode GetEIP (call $+5) | 🔴 Critical |
| `FC E8` | Metasploit shikata_ga_nai | 🔴 Critical |
| `64 A1 30 00 00 00` | PEB Access x86 (fs:[0x30]) | 🔴 Critical |
| `65 48 8B 04 25 60` | PEB Access x64 (gs:[0x60]) | 🔴 Critical |
| `4D 5A 41 52 55 48` | Cobalt Strike Beacon | 🔴 Critical |
| `90 90 90 90 90` | NOP Sled | 🟡 Warning |
| `48 31 C9` | xor rcx,rcx (shellcode) | 🟡 Warning |

### Adding Custom Signatures

Edit the `g_Signatures` array in the source code:

```c
BYTE_SIGNATURE g_Signatures[] = {
    // Add your custom patterns here:
    { {0xAA, 0xBB, 0xCC, 0xDD}, 4, "My custom pattern", TRUE },
    // ...
    { {0}, 0, NULL, FALSE }  // End marker - DO NOT REMOVE
};
```

## 📸 Screenshots

### System-Wide Injection Scan
```
+============================================+
|    System-Wide Code Injection Scanner      |
+============================================+
Timeouts: 5 sec/process, 2 sec/region
Press ESC or Q to abort

Scanning process "notepad.exe" pid = 1234

  *** HIGHLY SUSPICIOUS ***
    Memory Address = 0x00007FF6A1230000
    Permissions = RWX
    Region Size = 64.00 KB (65536 bytes)
    Type = Private
    Reason = Private-Commit RWX region
    Signature = PE Header (MZ)
    [Use 'dump-mem 1234 0x00007FF6A1230000' to dump]

    HEX                                              | ASCII
    ------------------------------------------------ | ----------------
    4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 | MZ..............
    b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 | ........@.......
```

### Process Tree View
```
=== Process Tree ===

 [System] (4, 2024-01-15 10:30:00)
  |-- smss.exe (456, 2024-01-15 10:30:01)
  |-- csrss.exe (567, 2024-01-15 10:30:02)
  +-- wininit.exe (678, 2024-01-15 10:30:03)
       |-- services.exe (789, 2024-01-15 10:30:04)
       |    |-- svchost.exe (890, 2024-01-15 10:30:05)
       |    +-- svchost.exe (901, 2024-01-15 10:30:06)
       +-- lsass.exe (912, 2024-01-15 10:30:07)
```

## ⚠️ Requirements

- **OS**: Windows 7/8/10/11 (x64 recommended)
- **Privileges**: Administrator (for full process access)
- **Dependencies**: None (standalone executable)

## 🛡️ Disclaimer

This tool is intended for **legitimate security research, incident response, and educational purposes only**. Always obtain proper authorization before scanning systems you do not own. The authors are not responsible for misuse of this tool.

## 👨‍💻 Author

**Abhijit Mohanta**

- 📚 Author of *"Malware Analysis and Detection Engineering"* (Apress)
- 📚 Author of *"Preventing Ransomware"* (Packt)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 Changelog

### v1.0 (2024)
- Initial release
- Code injection detection
- Process anomaly detection
- DLL hijacking detection
- Mutex enumeration
- Process tree visualization
- Configurable timeouts
- Abort support (ESC/Q)

---

<p align="center">
  <b>⭐ Star this repository if you find it useful! ⭐</b>
</p>
