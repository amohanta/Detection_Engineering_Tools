# -*- coding: utf-8 -*-
# --------------------------------------------------------------------------
# Remote Address Navigation Listener for Ghidra with GUI Control and Restart
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
from javax.swing import (JFrame, JTextArea, JScrollPane, JButton, JPanel,
                         BoxLayout, SwingUtilities, JLabel, JTextField)
from java.awt import BorderLayout, Dimension
from ghidra.util import Swing
from ghidra.app.services import GoToService

# Globals
log_area = None
server_thread = [None]
server_socket = [None]
server_running = [False]
listener_gui_instance = [None]
port_field = [None]
current_port = [2222]  # Default port

# ------------------------------
# Navigation class for Ghidra
# ------------------------------
class GotoAddressRunnable(Runnable):
    def __init__(self, address_str, tool, program):
        self.address_str = address_str
        self.tool = tool
        self.program = program

    def run(self):
        try:
            addr_factory = self.program.getAddressFactory()
            address = addr_factory.getAddress(self.address_str)
            if address:
                goto_service = self.tool.getService(GoToService)
                if goto_service:
                    navigatable = goto_service.getDefaultNavigatable()
                    goto_service.goTo(navigatable, address)
                    log_text("[+] Navigated to: {}".format(address))
                else:
                    log_text("[-] GoToService not available.")
            else:
                log_text("[-] Invalid address: {}".format(self.address_str))
        except Exception as e:
            log_text("[!] Exception navigating to address: {}".format(str(e)))

# ------------------------------
# Logging utility
# ------------------------------
def log_text(text):
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    message = "[{}] {}\n".format(timestamp, text)

    class LogRunnable(Runnable):
        def run(self):
            if log_area:
                log_area.append(message)
                log_area.setCaretPosition(log_area.getDocument().getLength())
            else:
                print(message)

    SwingUtilities.invokeLater(LogRunnable())

# ------------------------------
# TCP listener thread function
# ------------------------------
def command_listener(port):
    server_running[0] = True
    server_socket[0] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_socket[0].bind(("127.0.0.1", port))
        server_socket[0].listen(5)
        server_socket[0].settimeout(1.0)  # Timeout every 1 sec for stop checks
        log_text("[*] Listening on 127.0.0.1:{}...".format(port))

        while server_running[0]:
            try:
                conn, addr = server_socket[0].accept()
                log_text("[*] Connection from {}".format(addr))
                conn.settimeout(5.0)
                buffer = ""

                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    buffer += data.decode('utf-8')

                    while '\n' in buffer:
                        line, buffer = buffer.split('\n', 1)
                        address_str = line.strip()
                        if address_str:
                            log_text("Address received: {}".format(address_str))
                            Swing.runLater(GotoAddressRunnable(address_str, state.getTool(), currentProgram))
                conn.close()
            except socket.timeout:
                continue  # Timeout reached, check if still running
            except Exception as e:
                if server_running[0]:
                    log_text("[!] Error: {}".format(str(e)))
                break
    except Exception as e:
        log_text("[!] Server failed to start: {}".format(str(e)))
    finally:
        try:
            server_socket[0].close()
        except:
            pass
        server_socket[0] = None
        server_running[0] = False
        log_text("[*] Server stopped.")

# ------------------------------
# GUI Class
# ------------------------------
class ListenerGUI(JFrame):
    def __init__(self):
        super(ListenerGUI, self).__init__("Remote Address Listener")
        self.setLayout(BorderLayout())
        self.setPreferredSize(Dimension(600, 380))
        self.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)

        global log_area, port_field
        log_area = JTextArea()
        log_area.setEditable(False)
        scroll_pane = JScrollPane(log_area)
        self.add(scroll_pane, BorderLayout.CENTER)

        control_panel = JPanel()
        control_panel.setLayout(BoxLayout(control_panel, BoxLayout.Y_AXIS))

        # Port input panel
        port_panel = JPanel()
        port_label = JLabel("Port:")
        port_field = JTextField(str(current_port[0]), 10)
        port_panel.add(port_label)
        port_panel.add(port_field)

        # Buttons panel
        button_panel = JPanel()
        self.start_btn = JButton("Start Server", actionPerformed=self.start_server)
        self.stop_btn = JButton("Stop Server", actionPerformed=self.stop_server)
        self.restart_btn = JButton("Restart Server", actionPerformed=self.restart_server)

        self.stop_btn.setEnabled(False)
        self.restart_btn.setEnabled(False)

        button_panel.add(self.start_btn)
        button_panel.add(self.stop_btn)
        button_panel.add(self.restart_btn)

        control_panel.add(port_panel)
        control_panel.add(button_panel)
        self.add(control_panel, BorderLayout.SOUTH)

        self.pack()
        self.setVisible(True)

    def start_server(self, event):
        if server_running[0]:
            log_text("[*] Server already running.")
            return

        try:
            port = int(port_field.getText().strip())
            if port < 1 or port > 65535:
                log_text("[!] Invalid port number.")
                return
            current_port[0] = port
        except:
            log_text("[!] Invalid port format.")
            return

        log_text("[*] Starting server on port {}...".format(current_port[0]))
        t = threading.Thread(target=command_listener, args=(current_port[0],))
        t.setDaemon(True)
        server_thread[0] = t
        t.start()

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.restart_btn.setEnabled(True)

    def stop_server(self, event):
        if server_running[0]:
            log_text("[*] Stopping server...")
            server_running[0] = False
            try:
                if server_socket[0]:
                    server_socket[0].close()
            except:
                pass

            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.restart_btn.setEnabled(False)
        else:
            log_text("[*] Server already stopped.")

    def restart_server(self, event):
        log_text("[*] Restarting server...")
        self.stop_server(event)

        # Small delay to ensure socket is closed properly
        import time
        time.sleep(0.5)

        self.start_server(event)

# ------------------------------
# Runnable wrapper to launch GUI
# ------------------------------
class LaunchGUIRunnable(Runnable):
    def run(self):
        gui = ListenerGUI()
        listener_gui_instance[0] = gui

# ------------------------------
# Launch the GUI
# ------------------------------
SwingUtilities.invokeLater(LaunchGUIRunnable())
log_text("[*] GUI loaded. Choose port and click 'Start Server'.")
