#@author Abhijit Mohanta
#@category Analysis
#@keybinding 
#@menupath 
#@toolbar 

"""
Ghidra script to:
1. Extract all function addresses starting with 'FUN_'.
2. Generate a x64dbg breakpoint script (x64DbgScript.txt).
3. Overwrite existing file.
4. Open the script file after generation.
"""

import os
import subprocess

print("[+] Script started.")
print("MalFunctionTracer by Abhijit Mohanta")


# Step 1: Collect all function addresses whose names start with 'FUN_'
addresses = []

function_manager = currentProgram.getFunctionManager()
functions = function_manager.getFunctions(True)

for func in functions:
    name = func.getName()
    if name.startswith("FUN_"):
        addresses.append(func.getEntryPoint().getOffset())

# Define output file path
home_path = os.path.expanduser("~")
final_script_path = os.path.join(home_path, "x64DbgScript.txt")

# Step 2: Generate the breakpoint script content
def generate_script(addr_list):
    script_lines = []
    for addr in addr_list:
        script_lines.append("bp 0x{:08X}".format(addr))
        script_lines.append("log \"[+] Breakpoint hit at 0x{:08X}\"".format(addr))
    return "\n".join(script_lines)

bp_script = generate_script(addresses)

# Step 3: Write x64dbg script (overwriting any existing file)
with open(final_script_path, "w") as f:
    f.write("// === x64dbg Auto-Generated Breakpoint Script ===\n")
    f.write("// Author: Abhijit Mohanta\n\n")
    f.write("cls\n")
    f.write("bc\n\n")
    f.write(bp_script)

# Step 4: Open the generated script in Notepad
try:
    subprocess.Popen(["notepad.exe", final_script_path])
except Exception as e:
    print("[!] Failed to open script file: " + str(e))

# Done
print("[+] Found %d functions starting with 'FUN_'" % len(addresses))
print("[+] x64DbgScript.txt saved to: " + final_script_path)
print("[+] Opened x64DbgScript.txt in Notepad.")
