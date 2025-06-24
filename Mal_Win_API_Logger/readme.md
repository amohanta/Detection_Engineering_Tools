![API Logger Screenshot](images/Logo.png)

# 🛡️Malware Win32 API Logger (MalWinAPILogger)

A lightweight **Win32 API Logger** .This tool enables real-time dynamic API logging for **32 bit and 64 bit native Windows executables**, designed especially for malware analysts, reverse engineers, and blue teamers. Unlike sandbox-based tools, this is a **standalone command-line utility** that captures the actual API's called by malware which can be an input from Dynamic Analysis and **Reverse Engineering**.

---
## 🌟 Unique Features

- ✅ **Standalone command-line tool** — No sandbox setup needed
- ✅ **Captures API calls from malware-created processes**  
  via `CreateProcessA`, `CreateProcessW`
- ✅ **Captures API calls from injected processes**  
  via `OpenProcess` (e.g., process hollowing, DLL injection)
- ✅ **Useful to observe Packed Malware Process** 
     - ✅ **Prevents malware from terminating the process** — keeps it alive for extended inspection 
     - ✅ **Preserves memory freed by `VirtualFree()`** — useful for capturing unpacked/decrypted code
 - ✅ **Logs return address** - You can check in Debugger the address(see the previous instruction) from where API was called. Useful for **Reverse Engineers**. Make sure DLL can move is disabled in exe
- ✅ **Sleep Acceleration - nullifies Sleep() Call API's- Malwares use for Anti-Sandboxing**
- ✅ **Dumps Crypto API Key(CryptExportKey, CryptImportKey)BLOBs which can be used in analying Ransomware ** 
- ✅ **dumps memory  (greater than size 25 KB) which is used by memory data movement API's , memcpy to disk useful in analying runtime generated code, shellcodes etc**  
- ✅ **Logs saved with .OpenWithNotepad extension to Prevent Ransomware from encrypting log files**   

---

## 🚀 How to Use

1. **Place Files Together**  
   Ensure the following files are in the same directory:
   - `Mal_Win_API_Logger_<x86/x64>.exe`
   - `APIHook_<x86/x64>.dll`

2. **Run from Administrator Command Prompt**
   ```bash
   Mal_Win_API_Logger_<x86/x64>.exe <exe_name>
   ```

   This will:
   - Copy `APIHook_<x86/x64> dll` into `C:\HOOKDLL`
   - Launch the target executable with injected DLL
   - Begin logging API calls to `C:\DLLLogs`. Logs saved with .OpenWithNotepad extension to Prevent Ransomware from encrypting log files
   - memory dumps and Crypto API BLOB's dumped to `C:\MalMemDumps`
---

## 📄 Log Format

Logs are saved to:

```
C:\DLLLogs
```

Each log file is named:

```
<process_name>_PID-<pid>_TimeStamp-<YYYYMMDD>_<HHMMSS>.txt
```

**Example:**
```
mini.exe_PID-9252_TimeStamp-20250616_133024.txt
```

- `mini.exe`: Name of the target executable  
- `9252`: Process ID  
- `20250616`: Date (YYYYMMDD)  
- `133024`: Time (HHMMSS, 24-hour format)

Each log contains timestamped API calls with parameter details.

**Tutorials:**
- Basic Usage - https://www.youtube.com/watch?v=jh3T1y5C42Q&t=14s
- Unpacking Warzone RAT - https://www.youtube.com/watch?v=xlIZUpjuAjo
---

🔧 Supported API Functions

📁 **kernel32.dll**
- `ExitProcess`
- `CreateProcessA`
- `CreateProcessW`
- `WinExec`
- `OpenProcess`
- `VirtualAlloc`
- `VirtualAllocEx`
- `VirtualFree`
- `WriteProcessMemory`
- `CreateRemoteThread`
- `CreateFileA`
- `CreateFileW`
- `WriteFile`
- `CreateMutexA`
- `CreateMutexW`
- `CreateDirectoryA`
- `CreateDirectoryW`
- `FindFirstFileA`
- `FindFirstFileW`
- `FindNextFileA`
- `FindNextFileW`
- `CloseHandle`
- `ReadFile`
- `GetProcAddress`
- `LoadLibraryA`
- `LoadLibraryW`
- `VirtualProtect`
- `CreateToolhelp32Snapshot`
- `Process32FirstW`
- `Process32NextW`
- `Module32FirstW`
- `Module32NextW`

---

📁 **advapi32.dll**
- `RegCreateKeyExA`
- `RegCreateKeyExW`
- `RegSetValueExA`
- `RegSetValueExW`
- `OpenSCManagerA`
- `OpenSCManagerW`
- `CreateServiceA`
- `CreateServiceW`
- `StartServiceA`
- `StartServiceW`
- `DeleteService`
- `OpenProcessToken`
- `DuplicateTokenEx`

---

📁 **ws2_32.dll**
- `WSAStartup`

---

📁 **winhttp.dll**
- `WinHttpOpen`
- `WinHttpConnect`
- `WinHttpOpenRequest`
- `WinHttpSendRequest`

---

📁 **wininet.dll**
- `InternetOpenA`
- `InternetOpenW`
- `InternetConnectA`
- `InternetConnectW`
- `HttpOpenRequestA`
- `HttpOpenRequestW`
- `InternetReadFile`


---

📁 **ntdll.dll**
- `ZwTerminateProcess`
- `RtlMoveMemory`
- `RtlCopyMemory`

---

📁 **msvcrt.dll**
- `memcpy`
- `memmove`
- `memset`
- `memcmp`
  
## ⚠️ Limitations
- ❌ Does **not support .NET/managed binaries**


---

## 🧪 Ideal Use Cases

- Reverse engineering and behavioral analysis of native malware
- Extracting decrypted/unpacked payloads from memory
- Teaching API hooking, process injection, and logging techniques
- Lightweight dynamic analysis outside of sandbox environments

---

## 📁 Folder Structure

```
├── Mal_Win_API_Logger_x86.exe     → Injector & launcher 32 bit
├── APIHook_x86.dll                → API logger DLL 32 bit
├── Mal_Win_API_Logger_x64.exe     → Injector & launcher 64 bit
├── APIHook_x64.dll                → API logger DLL 64 bit
├── C:\HOOKDLL                     → DLL dropped here during run
├── C:\DLLLogs                     → Log files generated here
├── C:\MalMemDumps                 → memory dumps and Crypto API BLOB dumped here


```

---

## 🧭 Future Plans

- [ ] 64-bit support
- [ ] - Support More API's - Nt API's

---

> ⚠️ **Disclaimer:** This tool is strictly intended for **educational and malware research purposes only**. Use responsibly and at your own risk.
> ## 📄 License and Copyright

© Abhijit Mohanta

This work is protected under copyright. You may view, use, and share the contents for **educational and personal purposes only**.

❌ **Commercial use is strictly prohibited** without explicit permission from the author.
