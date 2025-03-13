import sys
import socket
import struct

def detect_os(target_ip, port):
    # Create a raw socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.settimeout(5)

    # Craft a TCP packet with a specific payload
    packet = struct.pack('!HHIIBBHHH', 0, 0, 0, 0, 0, 0, 0, 0, 0)

    try:
        # Send the packet to the target IP and port
        sock.sendto(packet, (target_ip, port))

        # Receive the response
        response = sock.recv(1024)

        # Check the response for specific OS signatures
        if b'Windows' in response:
            if b'Windows NT 10.0' in response:
                return 'Windows 10'
            elif b'Windows NT 6.3' in response:
                return 'Windows 8.1'
            elif b'Windows NT 6.2' in response:
                return 'Windows 8'
            elif b'Windows NT 6.1' in response:
                return 'Windows 7'
            elif b'Windows NT 6.0' in response:
                return 'Windows Vista'
            elif b'Windows NT 5.1' in response:
                return 'Windows XP'
            else:
                return 'Windows (Unknown Version)'
        elif b'Linux' in response:
            if b'Ubuntu' in response:
                return 'Ubuntu'
            elif b'Debian' in response:
                return 'Debian'
            elif b'CentOS' in response:
                return 'CentOS'
            else:
                return 'Linux (Unknown Distribution)'
        elif b'macOS' in response:
            if b'10.15' in response:
                return 'macOS 10.15'
            elif b'10.14' in response:
                return 'macOS 10.14'
            elif b'10.13' in response:
                return 'macOS 10.13'
            else:
                return 'macOS (Unknown Version)'
        else:
            return 'Unknown'
    except socket.timeout:
        return 'No response'
    finally:
        sock.close()

def scan_os(host, ports):
    for port in ports:
        os_info = detect_os(host, port)
        print(f"Host: {host} - Port: {port} - OS: {os_info}")
        save_result(f"Host: {host} - Port: {port} - OS: {os_info}\n")

def scan_host(host):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, 80))
        if result == 0:
            print(f"Host: {host} is up")
            save_result(f"Host: {host} is up\n")
        else:
            print(f"Host: {host} is down")
            save_result(f"Host: {host} is down\n")
        sock.close()
    except socket.gaierror:
        print(f"Host: {host} is down")
        save_result(f"Host: {host} is down\n")

def scan_range(start_ip, end_ip):
    for i in range(int(start_ip.split('.')[-1]), int(end_ip.split('.')[-1]) + 1):
        host = '.'.join(start_ip.split('.')[:-1]) + '.' + str(i)
        scan_host(host)

def scan_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            print(f"Port {port} on {host} is open")
            save_result(f"Port {port} on {host} is open\n")
        else:
            print(f"Port {port} on {host} is closed")
            save_result(f"Port {port} on {host} is closed\n")
        sock.close()
    except socket.gaierror:
        print(f"Port {port} on {host} is closed")
        save_result(f"Port {port} on {host} is closed\n")

def scan_ports(host, ports):
    for port in ports:
        scan_port(host, int(port))

def scan_website(website):
    # Placeholder for website scanning
    print(f"Scanning {website}")
    save_result(f"Scanning {website}\n")

def save_result(result):
    with open('result_scscanner.txt', 'a') as file:
        file.write(result)

def print_help():
    print("Usage: db_scscanner.py [option] [arguments]")
    print("Options:")
    print("  -h, --help           Display this help message")
    print("  -p, --port           Scan specific ports on a host")
    print("  -o, --os             Scan for the operating system of a host")
    print("  -w, --website        Scan a website for good information")
    print("Arguments:")
    print("  [host]               Single host IP address or range (e.g., 10.11.1.0 or 10.11.1.1-254)")
    print("  [port]               Single port number or comma-separated list of ports (e.g., 80 or 7,22,80,8080)")
    print("  [website]            Website URL (e.g., example.com)")

def display_results():
    with open('result_scscanner.txt', 'r') as file:
        print(file.read())

if __name__ == "__main__":
    args = sys.argv[1:]
    if len(args) == 0 or args[0] in ['-h', '--help']:
        print_help()
    elif len(args) == 1:
        if args[0].count('.') == 3:
            scan_host(args[0])
        elif '-' in args[0]:
            start_ip, end_ip = args[0].split('-')
            scan_range(start_ip, end_ip)
        elif args[0] == 'results':
            display_results()
        else:
            print("Invalid argument")
    elif len(args) == 2:
        if args[0].startswith('-p=') or args[0] in ['-p', '--port']:
            ports = args[0].replace('-p=', '').split(',')
            host = args[1]
            scan_ports(host, ports)
        elif args[0] in ['-o', '--os']:
            host = args[1]
            ports = [7, 21, 22, 80, 8080]  # Specify the ports to scan
            scan_os(host, ports)
        elif args[0] in ['-w', '--website']:
            scan_website(args[1])
        else:
            print("Invalid argument")
    else:
        print("Invalid number of arguments")