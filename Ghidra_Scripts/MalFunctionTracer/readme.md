# MalFunctionTracer
**Demo: https://youtu.be/WdxvBd83Ehc**
## 🚀 Trace User-Defined Functions in Malware — Simplified Dynamic Code Flow Mapping

While traditional tools log API calls, it's hard to trace user-defined functions. Reverse engineers need tools that expose **which user-defined functions actually execute at runtime**, helping reconstruct a malware's real logic.

**MalTracer** bridges that gap, without relying on complex instrumentation frameworks like Intel PIN or DynamoRIO.

---

## 🎯 What This Tool Does

- **Ghidra Script**:  
  Generates an x64dbg script by extracting addresses of all user-defined functions in the binary.

- **Generated x64dbg Script**:  
  - Automatically sets breakpoints on each identified user-defined function.
  - Logs each function hit during malware execution, exposing actual runtime code paths.

---

## 💡 Why This Matters

- Trace **execution flow** and shows which user defined functions were called at runtime
- Requires **no complex setup** – leverages existing tools (Ghidra + x64dbg).
- Focus directly on malware’s **core logic**.

---

## 📚 Workflow Overview
- Make sure that the **"DLL can Move"**, in optional Header of PE file is disabled
- 
1. **Static Phase (Ghidra):**
   - Load the malware sample in Ghidra.
   - Run the provided Ghidra script.
   - Script will generate an x64dbg `.txt` script file with breakpoints on all user-defined functions.

3. **Dynamic Phase (x64dbg):**  
   - Load the target binary in x64dbg.
   - Run the generated x64dbg script (`Script Windows -> Load Script -> Paste -> run`).
   - As the malware executes, x64dbg logs each function entry, showing actual code flow.

---

## 🔨 Tools Used

- [Ghidra](https://ghidra-sre.org) — For static analysis and function extraction.
- [x64dbg](https://x64dbg.com) — For runtime breakpointing and logging.

---

## 📂 Files

- `MaFunctionTracer.py -  The Ghidra script that generates the x64dbg script.

- `generated_trace_script.txt`:  
  Example of an x64dbg script produced by the tool.

---

## 👥 Who Should Use This?

- Malware Reverse Engineers  
- Detection Engineers  
- Threat Researchers  

Anyone who wants to **trace malware’s core logic** without the overhead of heavy instrumentation frameworks.

---

## 📣 Upcoming

I'll soon release:
- The complete Ghidra script.
- Example x64dbg breakpoint scripts.

---

## 🚀 Stay Tuned!

Simplify your dynamic malware analysis with **MalFunctionTracer**.

---

#MalwareAnalysis #ReverseEngineering #Ghidra #x64dbg #MalwareResearch #CodeFlow #DetectionEngineering #CyberSecurity #DynamicAnalysis
