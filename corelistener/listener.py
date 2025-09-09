# shadowsploit/core/listener.py
import socket
import threading
from corelistener import session_handler

listener_socket = None
listener_thread = None
running = False

def start_listener(lhost, lport):
    """Start a TCP listener to catch reverse shells"""
    global listener_socket, listener_thread, running
    if running:
        print("[-] Listener already running")
        return
    listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener_socket.bind((lhost, lport))
    listener_socket.listen(5)
    running = True
    print(f"[*] Listener started on {lhost}:{lport}")

    def accept_connections():
        while running:
            try:
                conn, addr = listener_socket.accept()
                session_handler.add_session(conn, addr)
            except:
                break

    listener_thread = threading.Thread(target=accept_connections, daemon=True)
    listener_thread.start()

def stop_listener():
    """Stop the listener"""
    global listener_socket, running
    if not running:
        print("[-] No active listener")
        return
    running = False
    try:
        listener_socket.close()
    except:
        pass
    listener_socket = None
    print("[*] Listener stopped")
