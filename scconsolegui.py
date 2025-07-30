import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
import subprocess
import threading
import os
from PIL import Image, ImageTk
import io
import sys

if not 'SUDO_UID' in os.environ.keys():
    print("Please try running SC-Console GUI with sudo.")
    exit()

# Declare logs_input as global *before* creating the class
global logs_input

class SCFrameworkGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("ShadowSploit - GUI")
        self.root.geometry("500x600")
        self.root.configure(bg="#333333")

        try:
            image = Image.open("images/shadowsploit_icon.png")
            photo = ImageTk.PhotoImage(image)
            self.root.iconphoto(False, photo)
        except FileNotFoundError:
            print("Icon file not found. Using default icon.")
        except Exception as e:
            print(f"Icon setting error: {e}")

        self.top_buttons_frame = None
        self.bottom_buttons_frame = None

        # Store button styles
        self.button_style = {
            "bg": "#555555",
            "fg": "#FFFFFF",
            "padx": 10,
            "pady": 5,
            "relief": tk.FLAT,
            "borderwidth": 0,
            "font": ("Arial", 10)
        }

        self.selected_exploit = None
        self.target = None
        global logs_input

        # Dictionary mapping exploits to descriptions
        self.exploit_descriptions = {
            "site/vuln-curl-website": "Exploit targeting vulnerable curl implementations on websites.",
            "exploit/ssh-version": "Checks SSH server versions for known vulnerabilities.",
            "linux/vulnerability-find": "Scans Linux systems for common vulnerabilities.",
            "site/reverse_http": "Sets up a reverse HTTP shell for remote access.",
            "osx/kernal_xnu_ip_fragment_privesc": "Privilege escalation exploit targeting OSX kernel XNU IP fragment vulnerability.",
            "osx/kernal_xnu_ip_fragment_privesc_2": "Alternative OSX kernel privilege escalation exploit variant.",
            "multi/pop3-pass": "Extracts POP3 passwords from vulnerable servers.",
            "site/information-gather": "Gathers information from target websites.",
            "server/extract_table_db_column": "Extracts database table columns from vulnerable servers.",
            "auxiliary/robots_txt": "Scans for sensitive files listed in robots.txt.",
            "auxiliary/wordpress-scan": "Scans WordPress sites for common vulnerabilities.",
            "auxiliary/title": "Retrieves the title of a web page for reconnaissance.",
            "auxiliary/apache_mod_status": "Checks Apache mod_status for server info exposure.",
            "scanner/vnc-none-auth": "Scans for VNC servers with no authentication.",
            "auxiliary/web-spider": "Crawls websites to map their structure.",
            "auxiliary/ftp-anonymous": "Checks FTP servers for anonymous login access.",
            "multi/nmap-version-detection": "Uses Nmap to detect service versions on the target.",
            "auxiliary/sqli-xss-vuln": "Detects SQL Injection and XSS vulnerabilities.",
            "auxiliary/find-login-fields": "Finds login fields on web pages.",
            "auxiliary/hashdetect": "Detects hash types in collected data.",
            "sniffer/SSLstrip": "Performs SSL stripping attacks on network traffic.",
            "dos/ble-dos": "Denial of Service attack targeting BLE devices.",
            "auxiliary/webdav_scanner": "Scans for WebDAV enabled servers.",
            "auxiliary/base64_decrypt": "Decodes Base64 encoded data.",
            "auxiliary/dnsenum": "Enumerates DNS records for the target domain.",
            "auxiliary/findns": "Finds nameservers for domains.",
            "auxiliary/lbdetect": "Detects load balancers in front of web servers.",
            "auxiliary/http-version": "Checks HTTP version supported by the server.",
            "scanner/WAF_Checker": "Checks for presence of Web Application Firewalls.",
            "scanner/ping_ip_site": "Pings IP or site to check availability.",
            "sniffer/inspect_traffic": "Inspects network traffic for analysis.",
            "auxiliary/drupal-scan": "Scans target to see if it is running on Drupal.",
            "auxiliary/ping-mssql": "Try to detect MSSQL version.",
            "auxiliary/smtp-version": "Try to detect SMTP vulnerabilities.",
            "php/POST-request": "it trys to upload exploit.php to target site and give a command execution.",
            "php/WordPress_Core_6-2_Directory_Traversal": "WordPress Core 6.2 - Directory Traversal.",
            "scanner/server-scanner": "This module trys to get target server and php version.",
            "scanner/vnc-none-auth": "This module try to detect if VNC server is running on target.",
            "multi/nmap-version-detection": "Try detect target version using Nmap.",
            "scanner/csrf_token_detect": "This module will find csrf token on tagret form."
        }

        self.create_main_window()

    def create_main_window(self):
        # Clear the main window content
        for widget in self.root.winfo_children():
            widget.destroy()

        self.top_buttons_frame = tk.Frame(self.root, bg="#333333")
        self.top_buttons_frame.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

        self.quit_button = tk.Button(self.top_buttons_frame, text="Quit", command=self.exit_application, **self.button_style)
        self.quit_button.pack(side=tk.LEFT, padx=(0, 5))

        self.target_button = tk.Button(self.top_buttons_frame, text="Target", command=self.target_action, **self.button_style)
        self.target_button.pack(side=tk.LEFT, padx=5)

        self.tools_button = tk.Button(self.top_buttons_frame, text="Tools", command=self.tools_action, **self.button_style)
        self.tools_button.pack(side=tk.LEFT, padx=5)

        self.help_button = tk.Button(self.top_buttons_frame, text="Help", command=self.help_action, **self.button_style)
        self.help_button.pack(side=tk.LEFT, padx=5)

        self.start_top_button = tk.Button(self.top_buttons_frame, text="Start", command=self.start_exploit, **self.button_style)
        self.start_top_button.pack(side=tk.LEFT, padx=5)

        output_label = tk.Label(self.root, text="Output", bg="#333333", fg="#FFFFFF", font=("Arial", 10))
        output_label.pack(side=tk.TOP, anchor=tk.W, padx=5, pady=(5, 0))

        global logs_input
        logs_input = tk.Text(self.root, bg="#444444", fg="#FFFFFF", height=25, width=80, relief=tk.FLAT, borderwidth=0)
        logs_input.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.logs_input = logs_input

        self.bottom_buttons_frame = tk.Frame(self.root, bg="#333333")
        self.bottom_buttons_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=5)

        self.start_bottom_button = tk.Button(self.bottom_buttons_frame, text="Start", command=self.start_exploit, **self.button_style)
        self.start_bottom_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = tk.Button(self.bottom_buttons_frame, text="Stop", command=self.stop_action, **self.button_style)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        self.save_output_button = tk.Button(self.bottom_buttons_frame, text="Save Output", command=self.save_logs_as, **self.button_style)
        self.save_output_button.pack(side=tk.LEFT, padx=5)

        self.clear_output_button = tk.Button(self.bottom_buttons_frame, text="Clear Output", command=self.clear_logs, **self.button_style)
        self.clear_output_button.pack(side=tk.LEFT, padx=5)

    def target_action(self):
        # Ask the user for the target IP or URL
        target = simpledialog.askstring("Target", "Enter target IP/URL/HASH/INTERFACE:")
        if target:
            self.target = target
            self.logs_input.insert(tk.END, f"Target set: {target}\n")
            self.logs_input.see(tk.END)

    def tools_action(self):
        self.root.withdraw()
        self.create_tools_window()

    def create_tools_window(self):
        tools_window = tk.Toplevel(self.root)
        tools_window.title("Select Exploit")
        tools_window.configure(bg="#333333")
        tools_window.geometry("400x350")  # Slightly taller to fit description

        # Frame for listbox and scrollbar
        list_frame = tk.Frame(tools_window, bg="#333333")
        list_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Scrollbar
        scrollbar = tk.Scrollbar(list_frame, orient=tk.VERTICAL)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Listbox with exploits
        self.exploit_listbox = tk.Listbox(list_frame, bg="#444444", fg="#FFFFFF",
                                          font=("Arial", 10), selectmode=tk.SINGLE,
                                          yscrollcommand=scrollbar.set)
        self.exploit_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Attach scrollbar to listbox
        scrollbar.config(command=self.exploit_listbox.yview)

        # List of exploits
        exploits = list(self.exploit_descriptions.keys())

        for exploit in exploits:
            self.exploit_listbox.insert(tk.END, exploit)

        # Description label below the listbox
        self.description_label = tk.Label(tools_window, text="Select an exploit to see its description.",
                                          bg="#333333", fg="#FFFFFF", wraplength=380, justify=tk.LEFT)
        self.description_label.pack(side=tk.TOP, fill=tk.X, padx=5, pady=(0, 10))

        # Bind selection event to update description
        def on_exploit_select(event):
            selection = self.exploit_listbox.curselection()
            if selection:
                exploit_name = self.exploit_listbox.get(selection)
                desc = self.exploit_descriptions.get(exploit_name, "No description available.")
                self.description_label.config(text=desc)

        self.exploit_listbox.bind('<<ListboxSelect>>', on_exploit_select)

        # Select button to confirm selection
        select_button = tk.Button(tools_window, text="Select", command=lambda: self.select_exploit_from_list(tools_window), **self.button_style)
        select_button.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=5)

        # Back button to return without selection
        back_button = tk.Button(tools_window, text="Back", command=lambda: self.back_to_main(tools_window), **self.button_style)
        back_button.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=(0,5))

    def select_exploit_from_list(self, tools_window):
        try:
            selection_index = self.exploit_listbox.curselection()
            if not selection_index:
                messagebox.showwarning("Selection Error", "Please select an exploit from the list.")
                return
            exploit = self.exploit_listbox.get(selection_index)
            self.selected_exploit = exploit
            self.logs_input.insert(tk.END, f"Selected exploit: {exploit}\n")
            self.logs_input.see(tk.END)
            tools_window.destroy()
            self.root.deiconify()
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def help_action(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        self.create_help_window()

    def create_help_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        help_frame = tk.Frame(self.root, bg="#333333")
        help_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=5, pady=5)

        help_text = """
        Help Menu of ShadowSploit - GUI
        -----------------------------------
        - Select "Target" to enter the target IP or URL.
        - Select "Tools" to choose an exploit from the list.
        - Use the "Start" buttons to begin the exploit.
        - Use the "Stop" button to halt the exploit.
        - Use "Save Output" to save the logs to a file.
        - Use "Clear Output" to clear the log area.

        -! The exploits will timeout after 100 second.

                       -* 40 exploits *-
        """

        help_label = tk.Label(help_frame, text=help_text, bg="#333333", fg="#FFFFFF", font=("Arial", 10), justify=tk.LEFT)
        help_label.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=10)

        back_button = tk.Button(self.root, text="Back", command=self.create_main_window, **self.button_style)
        back_button.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=5)

    def stop_action(self):
        self.logs_input.insert(tk.END, "Stop button clicked\n")
        self.logs_input.see(tk.END)

    def run_exploit(self, exploit_path):
        self.selected_exploit = exploit_path
        timeout = 100

        command = ["sudo", "python3", f"exploits/{self.selected_exploit}.py"]

        try:
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE)

            self.logs_input.insert(tk.END, f"Running: {' '.join(command)}\n")
            self.logs_input.see(tk.END)

            if self.target:
                target_bytes = (self.target + "\n").encode(sys.stdout.encoding, errors='replace')
                process.stdin.write(target_bytes)
                process.stdin.flush()
                self.logs_input.insert(tk.END, f"Inputting to script: {self.target}\n")
                self.logs_input.see(tk.END)
            process.stdin.close()

            def read_output(pipe, is_error=False):
                try:
                    for line in io.TextIOWrapper(pipe, encoding=sys.stdout.encoding, errors='replace'):
                        self.logs_input.insert(tk.END, line)
                        self.logs_input.see(tk.END)
                except Exception as e:
                    error_message = f"Error reading output: {e}\n"
                    self.logs_input.insert(tk.END, error_message)
                    self.logs_input.see(tk.END)
                    print(error_message)

            stdout_thread = threading.Thread(target=read_output, args=(process.stdout,))
            stderr_thread = threading.Thread(target=read_output, args=(process.stderr, True))
            stdout_thread.daemon = True
            stderr_thread.daemon = True
            stdout_thread.start()
            stderr_thread.start()

            process.wait(timeout=timeout)

            rc = process.returncode
            self.logs_input.insert(tk.END, f"Exploit finished with return code: {rc}\n")
            self.logs_input.see(tk.END)

            if rc != 0:
                self.logs_input.insert(tk.END, "Exploit may have encountered an error.\n")
                self.logs_input.see(tk.END)

        except subprocess.TimeoutExpired:
            self.logs_input.insert(tk.END, f"Exploit timed out after {timeout} seconds.\n")
            self.logs_input.see(tk.END)
            if process.poll() is None:
                process.kill()
        except Exception as e:
            self.logs_input.insert(tk.END, f"An error occurred while running the exploit: {e}\n")
            self.logs_input.see(tk.END)
            print(f"Outer exception: {e}")

    def start_exploit(self):
        if not self.selected_exploit:
            messagebox.showerror("Error", "Please select an Exploit from the Tools menu and then start.")
            return

        if not self.target:
            messagebox.showerror("Error", "Please set a Target first.")
            return

        threading.Thread(target=self.run_exploit, args=(self.selected_exploit,)).start()

    def back_to_main(self, window):
        window.destroy()
        self.root.deiconify()

    def clear_logs(self):
        self.logs_input.delete("1.0", tk.END)

    def save_logs_as(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if file_path:
            with open(file_path, "w") as file:
                file.write(self.logs_input.get("1.0", tk.END))

    def exit_application(self):
        self.root.destroy()

global logs_input

root = tk.Tk()
app = SCFrameworkGUI(root)
root.mainloop()
