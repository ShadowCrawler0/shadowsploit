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
        self.root.title("SC Framework")
        self.root.geometry("500x600")
        self.root.configure(bg="#333333")

        try:
            image = Image.open("images/SCframework-icon.png")
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
        target = simpledialog.askstring("Target", "Enter target IP or URL:")
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

        # Main Frame
        tools_frame = tk.Frame(tools_window, bg="#333333")
        tools_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # List of exploits
        exploits = [
            "sc-gui/vuln-curl-website.py",
            "sc-gui/ssh-version.py",
            "sc-gui/vulnerability-find.py",
            "sc-gui/os_detector.py",
            "sc-gui/port-scan.py",
            "sc-gui/reverse_http.py",
            "sc-gui/kernal_xnu_ip_fragment_privesc.py",
            "sc-gui/kernal_xnu_ip_fragment_privesc_2.py",
            "sc-gui/pop3-pass.py",
            "sc-gui/information-gather.py",
            "sc-gui/extract_table_db_column.py",
            "sc-gui/robots_txt.py",
            "sc-gui/wordpress-scan.py",
            "sc-gui/title.py",
            "sc-gui/apache_mod_status.py",
            "sc-gui/vnc-none-auth.py",
            "sc-gui/web-spider.py",
            "sc-gui/ftp-anonymous.py",
            "sc-gui/nmap-version-detection.py",
            "sc-gui/sqli-xss-vuln.py"
        ]

        for exploit in exploits:
            exploit_button = tk.Button(tools_frame, text=exploit, command=lambda ex=exploit: self.select_exploit(ex, tools_window), **self.button_style)
            exploit_button.pack(side=tk.TOP, fill=tk.X, padx=2, pady=2)

        back_button = tk.Button(tools_window, text="Back", command=lambda: self.back_to_main(tools_window), **self.button_style)
        back_button.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=5)

    def select_exploit(self, exploit, tools_window):
        self.selected_exploit = exploit
        self.logs_input.insert(tk.END, f"Selected exploit: {exploit}\n")
        self.logs_input.see(tk.END)
        tools_window.destroy()
        self.root.deiconify()


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
        Help Menu of SC Framework - GUI
        -----------------------------------
        - Select "Target" to enter the target IP or URL.
        - Select "Tools" to choose an exploit from the list.
        - Use the "Start" buttons to begin the exploit.
        - Use the "Stop" button to halt the exploit.
        - Use "Save Output" to save the logs to a file.
        - Use "Clear Output" to clear the log area.

        -! The exploits will timeout after 100 second.

                       -* 17 exploits *-
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

        command = ["sudo", "python3", f"exploits/{self.selected_exploit}"]

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
# Initialize logs_input before creating the GUI
# logs_input = tk.Text(root, bg="#444444", fg="#FFFFFF", height=25, width=80, relief=tk.FLAT, borderwidth=0)

app = SCFrameworkGUI(root)
# Start the main event loop
root.mainloop()
