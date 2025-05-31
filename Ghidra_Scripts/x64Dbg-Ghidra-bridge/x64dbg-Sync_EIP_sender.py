# ------------------------------------------------------------------------------
# x64dbg to Ghidra CIP Sender
#
# This script runs inside x64dbg using the py_x64dbg plugin. It continuously
# reads the current instruction pointer (CIP) and sends it every second
# to a remote listener (e.g., Ghidra script) over a TCP connection.
#
# © 2025 Abhijit Mohanta. All rights reserved.
# ------------------------------------------------------------------------------

import socket
import time
from x64dbg import Register  # Import Register module from py_x64dbg

# Configuration: IP address and port of the listener (Ghidra or similar)
HOST = '127.0.0.1'
PORT = 2222

# ------------------------------------------------------------------------------
# Get current instruction pointer (CIP)
# Tries different function/attribute names to be compatible with 32-bit and 64-bit
# EIP/RIP is used depending on architecture
# ------------------------------------------------------------------------------
def get_cip():
    for attr in ["GetCIP", "GetEIP", "GetRip", "EIP", "RIP"]:
        if hasattr(Register, attr):
            cip = getattr(Register, attr)
            if callable(cip):
                cip = cip()
            return cip
    return None

# ------------------------------------------------------------------------------
# Continuously send CIP (instruction pointer) to remote listener over TCP
# ------------------------------------------------------------------------------
def send_eip_loop():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))  # Connect to Ghidra listener
        while True:
            cip = get_cip()
            if cip is None:
                print("[-] Failed to get current instruction pointer")
                break
            msg = f"0x{cip:X}\n"  # Format the address in hex
            s.sendall(msg.encode('utf-8'))  # Send to listener
            time.sleep(1)  # Delay between sends

# ------------------------------------------------------------------------------
# Entry point: starts the background loop to send CIP values
# ------------------------------------------------------------------------------
send_eip_loop()
