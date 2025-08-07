
**ProcPEB-parse** is a lightweight tool written in C++ that parses the **Process Environment Block (PEB)** of a running process using its **Process ID (PID)**. It demonstrates how to access internal Windows structures to retrieve fields such as the `BeingDebugged` flag, which is commonly used to detect whether a process is being debugged.

---

## 🚀 Features

- 🕵️ Detects if the target process is being debugged (`BeingDebugged` flag in PEB)
- 📦 Retrieves the `ImageBaseAddress` of the process
- 🧠 Demonstrates how to access the PEB of a remote process
- 🪛 Minimal and educational — ideal for reverse engineers and learners

---

## 🖥️ Usage

```bash
ProcPEB-parse.exe <PID>
