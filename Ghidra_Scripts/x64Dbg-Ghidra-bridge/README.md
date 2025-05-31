## 🔄 x64dbg ↔ Ghidra Sync Bridge

This repository contains two lightweight scripts that create a **live synchronization bridge between x64dbg and Ghidra**, enabling seamless navigation across both tools during reverse engineering and debugging sessions.

---

### 📜 Description

The system includes:

1. **`x64dbg-Sync_EIP_sender.py`**\
   A Python script designed to run inside **x64dbg** using the [`x64dbgpython`](https://github.com/ElvisBlue/x64dbgpython)[ plugin](https://github.com/ElvisBlue/x64dbgpython). It continuously reads the current instruction pointer (EIP/RIP) of the debugged process and sends it via TCP to Ghidra every second.

2. **`Ghidra_Sync_Listener.py`**\
   A Ghidra script that acts as a TCP listener. Upon receiving addresses from x64dbg, it uses Ghidra’s `GoToService` to automatically navigate to those addresses in the disassembly or decompiler view.

---

### ⚙️ Requirements

- **x64dbg** with the **[x64dbgpython](https://github.com/ElvisBlue/x64dbgpython)**[ plugin](https://github.com/ElvisBlue/x64dbgpython)
- **Ghidra** (any modern version)
- Python 3.8 (required by x64dbgpython)
- Localhost TCP communication (default: `127.0.0.1:2222`)

---

### 🚀 How It Works

- The x64dbg script sends the current instruction pointer (EIP/RIP) to Ghidra every second.
- The Ghidra listener receives it and auto-navigates to the corresponding address.
- This provides live sync between dynamic execution (in x64dbg) and static analysis (in Ghidra).

---

### 🧪 Usage Instructions

1. **In Ghidra**

   - Open your program.
   - Run `Ghidra_Sync_Listener.py` from the Script Manager or Script Console.
   - It starts listening on `127.0.0.1:2222`.

2. **In x64dbg**

   - Open your target binary.
   - Go to `Plugins > x64dbgpython > Console`.
   - Paste and run `x64dbg-Sync_EIP_sender.py`.

3. **Live Sync**

   - As the process runs in x64dbg, Ghidra will follow the control flow in real time.

---

### 📂 Files

- `x64dbg-Sync_EIP_sender.py` – CIP sender (x64dbg side)
- `Ghidra_Sync_Listener.py` – Address listener and navigator (Ghidra side)

---

### 📜 License

```
© 2025 Abhijit Mohanta. All rights reserved.
This project is provided for educational and research use only.
```
