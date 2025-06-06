#@author Abhijit
#@category RemoteControl

import socket
import threading
import datetime
from java.lang import Runnable
from javax.swing import JFrame, JTextArea, JScrollPane, JButton, JPanel, BoxLayout, SwingUtilities
from java.awt import BorderLayout, Dimension
from ghidra.util import Swing
from ghidra.app.services import GoToService

HOST = '127.0.0.1'
PORT = 2222

# Globals
stop_server_flag = [False]
server_socket = [None]
server_thread = [None]
server_running = [False]

# GUI logger
def log_text(text):
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    message = "[{}] {}\n".format(timestamp, text)
    def update():
        log_area.append(message)
        log_area.setCaretPosition(log_area.getDocument().getLength())
    SwingUtilities.invokeLater(update)

# Ghidra navigation runnable
class GotoAddressRunnable(Runnable):
    def __init__(self, address_str, tool, program):
        self.address_str = address_str
        self.tool = tool
        self.program = program

    def run(self):
        try:
            address = self.program.getAddressFactory().getAddress(self.address_str)
            if address:
                goto_service = self.tool.getService(GoToService)
                if goto_service:
                    navigatable = goto_service.getDefaultNavigatable()
                    goto_service.goTo(navigatable, address)
                    log_text("[+] Navigated to: {}".format(address))
                else:
                    log_text("[-] GoToService not available")
            else:
                log_text("[-] Invalid address: {}".format(self.address_str))
        except Exception as e:
            log_text("[!] Exception: {}".format(str(e)))

# Server thread
def command_listener():
    server_running[0] = True
    stop_server_flag[0] = False

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(5)
        server_socket[0] = s
        log_text("[*] Listening on {}:{}...".format(HOST, PORT))

        while not stop_server_flag[0]:
            s.settimeout(1.0)
            try:
                conn, addr = s.accept()
                log_text("[*] Connection from {}".format(addr))
                conn.settimeout(2.0)
                buffer = ""

                while True:
                    try:
                        data = conn.recv(1024)
                        if not data:
                            break
                        buffer += data.decode('utf-8')
                        while '\n' in buffer:
                            line, buffer = buffer.split('\n', 1)
                            address_str = line.strip()
                            if address_str:
                                log_text("[>] Received: {}".format(address_str))
                                Swing.runLater(GotoAddressRunnable(address_str, state.getTool(), currentProgram))
                    except socket.timeout:
                        break
                    except Exception as e:
                        log_text("[!] Receive error: {}".format(str(e)))
                        break

                conn.close()
            except socket.timeout:
                continue
            except Exception as e:
                log_text("[!] Accept error: {}".format(str(e)))
    except Exception as e:
        log_text("[!] Server error: {}".format(str(e)))
    finally:
        try:
            if server_socket[0]:
                server_socket[0].close()
        except:
            pass
        server_socket[0] = None
        server_running[0] = False
        log_text("[*] Server stopped.")

# GUI
class ListenerGUI(JFrame):
    def __init__(self):
        super(ListenerGUI, self).__init__("Remote Address Listener")
        self.setLayout(BorderLayout())
        self.setPreferredSize(Dimension(520, 320))
        self.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)

        global log_area
        log_area = JTextArea()
        log_area.setEditable(False)
        scroll = JScrollPane(log_area)
        self.add(scroll, BorderLayout.CENTER)

        self.start_btn = JButton("Start Server", actionPerformed=self.start_server)
        self.stop_btn = JButton("Stop Server", actionPerformed=self.stop_server)
        self.stop_btn.setEnabled(False)

        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.X_AXIS))
        panel.add(self.start_btn)
        panel.add(self.stop_btn)
        self.add(panel, BorderLayout.SOUTH)

        self.pack()
        self.setVisible(True)

    def start_server(self, event):
        if server_running[0]:
            log_text("[!] Server already running.")
            return
        stop_server_flag[0] = False
        log_text("[*] Starting server thread...")
        t = threading.Thread(target=command_listener)
        t.setDaemon(True)
        server_thread[0] = t
        t.start()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

    def stop_server(self, event):
        if not server_running[0]:
            log_text("[!] Server is not running.")
            return
        log_text("[*] Stopping server...")
        stop_server_flag[0] = True
        try:
            if server_socket[0]:
                server_socket[0].close()
        except:
            pass
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

# Run GUI
class GUIRunnable(Runnable):
    def run(self):
        ListenerGUI()

SwingUtilities.invokeLater(GUIRunnable())
