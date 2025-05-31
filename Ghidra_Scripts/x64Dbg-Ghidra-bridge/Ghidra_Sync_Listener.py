# --------------------------------------------------------------------------
# Remote Address Navigation Listener for Ghidra
# 
# This script starts a background socket server that listens for incoming
# address strings over a TCP connection. When an address is received, 
# it safely navigates to that address within Ghidra using its UI thread.
#
# © 2025 Abhijit Mohanta. All rights reserved.
# --------------------------------------------------------------------------

#@author Abhijit Mohanta
#@category RemoteControl
#@keybinding
#@menupath
#@toolbar

import socket
import threading
import datetime
from java.lang import Runnable
from ghidra.util import Swing
from ghidra.app.services import GoToService

# ---------------------------
# Configuration Section
# ---------------------------
HOST = '127.0.0.1'  # Localhost - only local connections accepted
PORT = 2222         # Port to listen on for incoming commands

# -------------------------------------------------------------------------
# Runnable class for safely navigating to an address on the Ghidra UI thread
# -------------------------------------------------------------------------
class GotoAddressRunnable(Runnable):
    def __init__(self, address_str, tool, program):
        self.address_str = address_str
        self.tool = tool
        self.program = program

    def run(self):
        try:
            # Convert the string address to Ghidra's address object
            addr_factory = self.program.getAddressFactory()
            address = addr_factory.getAddress(self.address_str)

            if address:
                # Use GoToService to navigate to the specified address
                goto_service = self.tool.getService(GoToService)
                if goto_service:
                    navigatable = goto_service.getDefaultNavigatable()
                    goto_service.goTo(navigatable, address)
                    print("[+] Navigated to address: {}".format(address))
                else:
                    print("[-] GoToService not available")
            else:
                print("[-] Invalid address: {}".format(self.address_str))
        except Exception as e:
            print("[!] Exception navigating to address:", e)

# -------------------------------------------------------------------------
# Function to run in a separate thread that listens for incoming connections
# -------------------------------------------------------------------------
def command_listener():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(1)  # Allow only 1 queued connection
    print("[*] Listening on {}:{}...".format(HOST, PORT))

    while True:
        try:
            conn, addr = server.accept()
            print("[*] Connection from {}".format(addr))
            conn.settimeout(5.0)  # Prevent hanging on dead sockets

            buffer = ""
            while True:
                try:
                    data = conn.recv(1024)
                    if not data:
                        break  # Connection closed
                    buffer += data.decode('utf-8')

                    # Process each line of data (each expected to be an address)
                    while '\n' in buffer:
                        line, buffer = buffer.split('\n', 1)
                        address_str = line.strip()
                        if address_str:
                            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
                            print("[{}] Address received: {}".format(timestamp, address_str))
                            # Navigate on Ghidra's UI thread
                            Swing.runLater(GotoAddressRunnable(address_str, state.getTool(), currentProgram))
                except socket.timeout:
                    continue  # Ignore timeouts and keep connection alive
        except Exception as e:
            print("[!] Error handling connection:", e)

# -------------------------------------------------------------------------
# Start the background listener thread
# -------------------------------------------------------------------------
listener_thread = threading.Thread(target=command_listener)
listener_thread.setDaemon(True)  # Ensure it exits with Ghidra
listener_thread.start()

print("[*] Ghidra x64dbg listener started in background. Waiting for connections...")
