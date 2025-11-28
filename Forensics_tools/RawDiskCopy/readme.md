
# RawDiskCopy

A lightweight Windows raw disk–level acquisition tool inspired by RawCopy.  
Supports **x86 and x64**, enabling raw copying of locked system files such as registry hives and the NTFS Master File Table (MFT).

---

## 🔥 Features
- Copy locked files using raw disk access  
- Supports **x86** and **x64** builds  
- Forensic‑safe (read‑only access)  
- Simple CLI usage  
- Includes full automation script: **RawDiskCopy.ps1**

---

## 📁 Binaries
| Architecture | File |
|--------------|----------------------|
| x64          | `RawDiskCopy_x64.exe` |
| x86          | `RawDiskCopy_x86.exe` |

---

## 🚀 Usage

### Copy NTUSER.DAT
```cmd
RawDiskCopy_x64.exe "C:\Users\John\NTUSER.DAT" "C:\Forensics\NTUSER.DAT"
```

---

## 📜 PowerShell Collection Script  
A full artifact collector is included as:  
```
RawDiskCopy.ps1
```

The script automatically:

✔ Detects x86/x64 RawDiskCopy  
✔ Creates `C:\Forensics\` if missing  
✔ Copies:
- User registry artifacts  
  - `NTUSER.DAT`, `NTUSER.DAT.LOG1`, `NTUSER.DAT.LOG2`, etc.  
- System registry hives  
  - `SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY` + all `.LOG1/.LOG2` files  
- **NTFS $MFT**  
  - From: `C:\$MFT`

---

## ▶ Run the script
```
powershell -ExecutionPolicy Bypass -File .\RawDiskCopy.ps1
```

---

## 📂 Example Output
```
C:\Forensics    NTUSER.DAT
    NTUSER.DAT.LOG1
    SOFTWARE
    SYSTEM
    SAM
    SECURITY
    MFT.bin
```

---

## 🏗 Build Information
- Language: **VC++**  
- Platform: **x86 & x64**  
- OS: Windows 7 → Windows 11  

---

## 🙌 Credits
Inspired by RawCopy — https://github.com/jschicht/RawCopy

---

## 📜 License
Choose your preferred license (MIT recommended).
