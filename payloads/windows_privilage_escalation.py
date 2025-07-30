#!/usr/bin/env python3
import subprocess

HEADER = """
============================================================
            Windows Privilege Escalation Scanner
============================================================
"""

def run_cmd(desc, cmd):
    print(f"\n[+] {desc}")
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, universal_newlines=True)
        print(output.strip())
    except subprocess.CalledProcessError:
        print("[-] Command failed or no output")

def main():
    print(HEADER)

    run_cmd("Current user", "whoami")
    run_cmd("User groups", "whoami /groups")
    run_cmd("System info", "systeminfo")
    run_cmd("Scheduled Tasks", "schtasks /query /fo LIST /v")
    run_cmd("Services running as SYSTEM or with weak permissions", "wmic service get name, startname")
    run_cmd("Checking for writable directories in PATH environment variable",
            "powershell -command \"Get-ChildItem Env:Path | ForEach-Object { $_.Value.Split(';') } | ForEach-Object { Get-Acl $_ }\"")
    run_cmd("Checking for alwaysInstallElevated registry keys",
            "reg query HKLM\\Software\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated")
    run_cmd("Checking for vulnerable unquoted service paths",
            "powershell -command \"Get-WmiObject win32_service | Where-Object { $_.PathName -and $_.PathName -notmatch '^\\\".*\\\"$' -and $_.PathName -match ' ' } | Select-Object Name,PathName\"")
    run_cmd("Sticky keys exploit presence", "dir C:\\Windows\\System32\\sethc.exe")
    run_cmd("Checking PATH environment variable for writable directories", "echo %PATH%")

    print("\n[!] Done. Review results for potential privilege escalation vectors.")

if __name__ == "__main__":
    main()
