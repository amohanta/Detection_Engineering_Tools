#@author 
#@category Search
#@menupath Search.Byte Pattern Wildcard
#@toolbar 

from ghidra.program.model.mem import MemoryAccessException
from ghidra.util.task import ConsoleTaskMonitor
from java.io import File, IOException
from java.awt import Desktop
import os

# --- Pattern Parsing ---
def parse_pattern(pattern_str):
    """Parses pattern string like '90 ?? 90' into bytes and wildcard positions."""
    tokens = pattern_str.strip().split()
    pattern_bytes = []
    wildcards = []

    for i, token in enumerate(tokens):
        if token == "??" or token == "?":
            pattern_bytes.append(0x00)  # dummy value
            wildcards.append(i)
        else:
            pattern_bytes.append(int(token, 16))
    return pattern_bytes, wildcards

# --- Pattern Matching ---
def match_pattern(memory, addr, pattern_bytes, wildcards):
    try:
        for i in range(len(pattern_bytes)):
            if i in wildcards:
                continue
            byte = memory.getByte(addr.add(i)) & 0xFF
            if byte != pattern_bytes[i]:
                return False
        return True
    except MemoryAccessException:
        return False

# --- Main Script ---
def run():
    pattern_str = askString("Byte Pattern Search", "Enter byte pattern (e.g., '90 ?? 90 90'):")
    if not pattern_str:
        print("No pattern entered.")
        return

    pattern_bytes, wildcards = parse_pattern(pattern_str)
    pattern_len = len(pattern_bytes)

    memory = currentProgram.getMemory()
    monitor = ConsoleTaskMonitor()

    # Output path: use user home directory or temp
    output_dir = os.path.expanduser("~")  # or use getState().getProject().getProjectLocator().getProjectDir() for project dir
    output_path = os.path.join(output_dir, "ghidra_pattern_matches.txt")
    
    try:
        f = open(output_path, "w")
    except IOError:
        popup("Failed to create output file.")
        return

    print("[*] Searching for pattern: {}\n".format(pattern_str))
    f.write("Pattern: {}\n\n".format(pattern_str))

    total_matches = 0
    for block in memory.getBlocks():
        addr = block.getStart()
        end = block.getEnd().subtract(pattern_len - 1)

        while addr.compareTo(end) <= 0:
            if monitor.isCancelled():
                f.close()
                return

            if match_pattern(memory, addr, pattern_bytes, wildcards):
                total_matches += 1
                matched_bytes = []
                for i in range(pattern_len):
                    try:
                        b = memory.getByte(addr.add(i)) & 0xFF
                        matched_bytes.append("{:02X}".format(b))
                    except:
                        matched_bytes.append("??")
                f.write("Match at {}: {}\n".format(addr, " ".join(matched_bytes)))
                print("[+] Match at: {}".format(addr))

            addr = addr.add(1)

    f.write("\nTotal matches: {}\n".format(total_matches))
    f.close()

    if total_matches == 0:
        popup("No matches found.")
    else:
        popup("Found {} match(es).\nOpening result file...".format(total_matches))
        try:
            Desktop.getDesktop().open(File(output_path))
        except:
            popup("Couldn't open file. See output at:\n{}".format(output_path))

run()
