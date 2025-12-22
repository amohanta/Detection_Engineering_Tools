
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



### copy other artifacts
```cmd

RawDiskCopy_x64.exe "%USERPROFILE%\NTUSER.DAT" NTUSER.DAT
RawDiskCopy_x64.exe "%USERPROFILE%\NTUSER.DAT.LOG1" NTUSER.DAT.LOG1
RawDiskCopy_x64.exe "%USERPROFILE%\NTUSER.DAT.LOG2" NTUSER.DAT.LOG2

RawDiskCopy_x64.exe "%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat" UsrClass.dat
RawDiskCopy_x64.exe "%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat.LOG1" UsrClass.dat.LOG1
RawDiskCopy_x64.exe "%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat.LOG2" UsrClass.dat.LOG2

RawDiskCopy_x64.exe "C:\Windows\System32\config\SYSTEM" SYSTEM
RawDiskCopy_x64.exe "C:\Windows\System32\config\SYSTEM.LOG1" SYSTEM.LOG1
RawDiskCopy_x64.exe "C:\Windows\System32\config\SYSTEM.LOG2" SYSTEM.LOG2

RawDiskCopy_x64.exe "C:\Windows\System32\config\SOFTWARE" SOFTWARE
RawDiskCopy_x64.exe "C:\Windows\System32\config\SOFTWARE.LOG1" SOFTWARE.LOG1
RawDiskCopy_x64.exe "C:\Windows\System32\config\SOFTWARE.LOG2" SOFTWARE.LOG2

RawDiskCopy_x64.exe "C:\Windows\System32\config\SAM" SAM
RawDiskCopy_x64.exe "C:\Windows\System32\config\SAM.LOG1" SAM.LOG1
RawDiskCopy_x64.exe "C:\Windows\System32\config\SAM.LOG2" SAM.LOG2

RawDiskCopy_x64.exe "C:\Windows\System32\config\SECURITY" SECURITY
RawDiskCopy_x64.exe "C:\Windows\System32\config\SECURITY.LOG1" SECURITY.LOG1
RawDiskCopy_x64.exe "C:\Windows\System32\config\SECURITY.LOG2" SECURITY.LOG2

RawDiskCopy_x64.exe "C:\Windows\System32\config\DEFAULT" DEFAULT
RawDiskCopy_x64.exe "C:\Windows\System32\config\DEFAULT.LOG1" DEFAULT.LOG1
RawDiskCopy_x64.exe "C:\Windows\System32\config\DEFAULT.LOG2" DEFAULT.LOG2

RawDiskCopy_x64.exe "C:\Windows\System32\sru\SRUDB.dat" SRUDB.dat
RawDiskCopy_x64.exe "C:\Windows\System32\sru\SRUDB.jfm" SRUDB.jfm
RawDiskCopy_x64.exe "C:\Windows\System32\sru\*.regtrans-ms" SRU_regtrans
RawDiskCopy_x64.exe "C:\Windows\System32\sru\*.blf" SRU_BLF

RawDiskCopy_x64.exe "C:\Windows\System32\config\RegBack\SYSTEM" SYSTEM_RegBack
RawDiskCopy_x64.exe "C:\Windows\System32\config\RegBack\SOFTWARE" SOFTWARE_RegBack
RawDiskCopy_x64.exe "C:\Windows\System32\config\RegBack\SAM" SAM_RegBack
RawDiskCopy_x64.exe "C:\Windows\System32\config\RegBack\SECURITY" SECURITY_RegBack
RawDiskCopy_x64.exe "C:\Windows\System32\config\RegBack\DEFAULT" DEFAULT_RegBack

============================================================
RawDiskCopyx64.exe C:$Extend$UsnJrnl:$J:$DATA $Extend$UsnJrnl$J$DATA
RawDiskCopy_x64.exe C:\$MFT $MFT_2
RawDiskCopy_x64.exe C:\$MFTMirr $MFTMirr
RawDiskCopy_x64.exe C:\$MFT::$BITMAP $MFT__$BITMAP
```

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
