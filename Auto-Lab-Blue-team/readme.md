# 🧪 AutoBlueTeamLabsetup  

**AutoBlueTeamLabsetup ** is a collection of PowerShell scripts that automates the setup of a **Windows Blue Team Lab Setup** inside a VM.  
It installs and configures commonly used malware analysis and reverse engineering tools with minimal manual effort.  

⚠️ **Warning:**  
- This project is for **educational and research purposes only**.  
- Run inside an **isolated VM** – never on your host system.  
- Disable **Windows Defender real-time protection** before execution (otherwise tools may be quarantined/removed).  

---

## 🚀 Features  

- Disables Windows Defender & automatic updates for stable lab operation  
- Creates a clean folder structure for analysis tools  
- Installs essential tools:    
- Installs dependencies:  
- Includes custom utilities:  
  - Memory dumper  
  - Misc malware analysis helpers  

---

## 📜 Script Execution Order  

Run the scripts in the following order:  

1. `disable_defender.ps1.txt` – Disable Windows Defender  <- remove .txt extenion of the file
2. `disable_autoupdates.ps1.txt` – Disable Windows auto-updates   <-  remove .txt extenion of the file
3. `Get-Chainsaw.ps1` - install chainsaw
4. `Get-NirsoftTools.ps1` - install nirsoft tools
5. `Get-RegRipper.ps1` get regripper tool
6. `Get-Sysinternals-All-in-One.ps1`
7. `download_misc_tools_2.ps1` – Download additional tools (set 2)  
8. `Get-Volatiltiy.ps1` - install volatility
9. `Ghidra_install_2_.ps1` – Install Ghidra  
 

---

## 🛠️ Usage  

1. Clone or download this repository into your **Windows VM**.  
2. Disable **real-time protection** in Defender.  
3. **Open PowerShell as Administrator. ** 
4. Run each script in order:  

```powershell as admin
Set-ExecutionPolicy Bypass -Scope Process -Force
ren .\1.disable_defender.ps1.txt .\1.disable_defender.ps1
ren .\2.disable_autoupdates.ps1.txt .\2.disable_autoupdates.ps1
.\1.disable_defender.ps1
.\2.disable_autoupdates.ps1

reboot system. Launch powershell again
start powershell as admin
in porweshell prompt execute => Set-ExecutionPolicy Bypass -Scope Process -Force
execute rest of the powershell script



===========
Afer installation take a VMWare Snapshot


...


