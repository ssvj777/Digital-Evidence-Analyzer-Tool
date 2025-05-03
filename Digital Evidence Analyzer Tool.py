import os
import wmi
import wx
import wx.adv
import winreg
import platform
import subprocess
import win32evtlog
import tkinter as tk
from tkinter.scrolledtext import ScrolledText
from tkinter import ttk, filedialog, messagebox
import ttkbootstrap as ttk
from ttkbootstrap import Style
from datetime import datetime
from prettytable import PrettyTable
from fpdf import FPDF



def open_application_module_1():
    def fetch_wifi_credentials():
        """Fetch WiFi profiles and their detailed information."""
        try:
            profiles_data = subprocess.check_output(
                'netsh wlan show profiles', shell=True, encoding='unicode_escape'
            )
            profiles = [
                line.split(":")[1].strip() for line in profiles_data.splitlines() if "All User Profile" in line
            ]

            wifi_info = []
            for profile in profiles:
                try:
                    profile_info_cmd = f'netsh wlan show profile "{profile}" key=clear'
                    profile_info = subprocess.check_output(
                        profile_info_cmd, shell=True, encoding='unicode_escape'
                    )

                    password_line = [
                        line.split(":")[1].strip() for line in profile_info.splitlines() if "Key Content" in line
                    ]
                    password = password_line[0] if password_line else "No Password"

                    auth_line = [
                        line.split(":")[1].strip() for line in profile_info.splitlines() if "Authentication" in line
                    ]
                    authentication = auth_line[0] if auth_line else "Unknown"

                    encrypt_line = [
                        line.split(":")[1].strip() for line in profile_info.splitlines() if "Cipher" in line
                    ]
                    encryption = encrypt_line[0] if encrypt_line else "Unknown"

                    interface_line = [
                        line.split(":")[1].strip() for line in profile_info.splitlines() if "Interface name" in line
                    ]
                    interface = interface_line[0] if interface_line else "Unknown"

                    wifi_info.append((profile, password, authentication, encryption, interface))
                except subprocess.CalledProcessError:
                    wifi_info.append((profile, "[Could not retrieve]", "Unknown", "Unknown", "Unknown"))
            return wifi_info
        except Exception as e:
            messagebox.showerror("Error", f"Failed to retrieve WiFi credentials: {e}")
            return []

    def display_wifi_credentials():
        """Display WiFi credentials in the output area."""
        wifi_info = fetch_wifi_credentials()
        output_text.config(state=tk.NORMAL)
        output_text.delete(1.0, tk.END)

        output_text.tag_configure("label", font=("Courier", 11), foreground="white")
        output_text.tag_configure("profile", font=("Courier", 11), foreground="cyan")
        output_text.tag_configure("password", font=("Courier", 11), foreground="green")

        if wifi_info:
            for profile, password, authentication, encryption, interface in wifi_info:
                output_text.insert(tk.END, "📡 WiFi Name: ", "label")
                output_text.insert(tk.END, f"{profile}\n", "profile")
                output_text.insert(tk.END, "  🔑 Password: ", "label")
                output_text.insert(tk.END, f"{password}\n", "password")
                output_text.insert(tk.END, "      Authentication: ", "label")
                output_text.insert(tk.END, f"{authentication}\n", "profile")
                output_text.insert(tk.END, "      Encryption: ", "label")
                output_text.insert(tk.END, f"{encryption}\n", "profile")
                output_text.insert(tk.END, "      Interface: ", "label")
                output_text.insert(tk.END, f"{interface}\n\n", "profile")
        else:
            output_text.insert(tk.END, "No WiFi credentials found.", "label")

        output_text.config(state=tk.DISABLED)


    def clear_output():
        """Clear the output area."""
        output_text.config(state=tk.NORMAL)
        output_text.delete(1.0, tk.END)
        output_text.config(state=tk.DISABLED)

    def download_results():
        """Save WiFi credentials to a PDF file in tabular format."""
        wifi_info = fetch_wifi_credentials()
        if not wifi_info:
            messagebox.showwarning("No Data", "No WiFi credentials found to save.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF Files", "*.pdf")],
            title="Save Results"
        )

        if not file_path:
            return

        try:
            pdf = FPDF()
            pdf.set_auto_page_break(auto=True, margin=15)
            pdf.add_page()
            
            # Title
            pdf.set_font("Arial", style="B", size=16)
            pdf.cell(200, 10, "WiFi Credentials Report", ln=True, align="C")
            pdf.ln(10)

            # Table Header
            pdf.set_font("Arial", style="B", size=10)
            headers = ["WiFi Name", "Password", "Authentication", "Encryption", "Interface"]
            widths = [40, 30, 40, 30, 40]
            for header, width in zip(headers, widths):
                pdf.cell(width, 10, header, border=1, align="C")
            pdf.ln()

            # Table Rows
            pdf.set_font("Arial", size=8)
            for profile, password, authentication, encryption, interface in wifi_info:
                pdf.cell(40, 10, profile, border=1, align="C")
                pdf.cell(30, 10, password if password else "N/A", border=1, align="C")
                pdf.cell(40, 10, authentication, border=1, align="C")
                pdf.cell(30, 10, encryption, border=1, align="C")
                pdf.cell(40, 10, interface, border=1, align="C")
                pdf.ln()

            pdf.output(file_path)
            messagebox.showinfo("Success", f"Results saved successfully as:\n{file_path}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to save PDF: {e}")

    root = tk.Toplevel()
    root.title("📶 VJ's WiFi Credentials Viewer")
    root.geometry("750x500")
    root.resizable(False, False)
    style = Style(theme="cyborg")

    main_frame = ttk.Frame(root, padding=10)
    main_frame.pack(fill=tk.BOTH, expand=True)

    label = ttk.Label(main_frame, text="📶 WiFi Credentials Viewer", font=("Helvetica", 17, "bold"), foreground="green", bootstyle="dark")
    label.pack(pady=5)

    button_frame = ttk.Frame(main_frame, padding=10)
    button_frame.pack(fill="x", padx=10, pady=10)

    fetch_button = ttk.Button(button_frame, text="🔍 Fetch WiFi Credentials", command=display_wifi_credentials, width=28, bootstyle="primary-outline")
    fetch_button.pack(side="left", padx=5, pady=5)

    download_button = ttk.Button(button_frame, text="📥 Download Results", command=download_results, width=28, bootstyle="success-outline")
    download_button.pack(side="left", padx=5, pady=5)

    clear_button = ttk.Button(button_frame, text="🗑️Clear Output", command=clear_output, width=28, bootstyle="danger-outline")
    clear_button.pack(side="left", padx=5, pady=5)

    output_text = ScrolledText(main_frame, wrap=tk.WORD, height=20, bg="#121212", fg="white", font=("Courier", 10))
    output_text.pack(fill="both", expand=True, padx=10, pady=10)
    output_text.config(state=tk.DISABLED)

    root.mainloop()


def open_application_module_2():
    class USBDeviceManager:
        def __init__(self, output_preview):
            self.output_preview = output_preview
            self.usb_devices_info = []

        def get_friendly_time(self, wmi_time):
            if wmi_time:
                try:
                    dt = datetime.datetime.strptime(wmi_time.split('.')[0], '%Y%m%d%H%M%S')
                    return dt.strftime("%Y-%m-%d %H:%M:%S")
                except:
                    return "Unknown Time"
            return "Unknown Time"

        def list_usb_devices(self):
            try:
                self.usb_devices_info.clear()
                c = wmi.WMI()

                for disk in c.Win32_DiskDrive():
                    if "USB" in disk.PNPDeviceID:
                        device_name = disk.Caption or "Unknown USB Storage"
                        device_id = disk.PNPDeviceID
                        insert_time = self.get_friendly_time(disk.CreationDate)
                        self.usb_devices_info.append(
                            (f"Storage Device: {device_name}\n",
                             f"Serial: {device_id}\n",
                             f"Insertion Time: {insert_time}\n"
                             f"{'-' * 40}\n")
                        )

                for usb in c.Win32_PnPEntity():
                    if "USB" in usb.PNPDeviceID:
                        device_name = usb.Caption or "Unknown Device"
                        device_id = usb.PNPDeviceID
                        self.usb_devices_info.append(
                            (f"Device: {device_name}\n",
                             f"Serial: {device_id}\n",
                             f"{'-' * 40}\n")
                        )
            except Exception as e:
                messagebox.showerror("Error", f"Failed to retrieve USB devices: {e}")

        def update_output_preview(self):
            self.output_preview.config(state=tk.NORMAL)
            self.output_preview.delete(1.0, tk.END)
            self.output_preview.tag_configure("serial_tag", foreground="cyan", font=("Courier", 10, "bold"))

            if self.usb_devices_info:
                self.output_preview.insert(tk.END, "USB Devices:\n", "label")
                for device in self.usb_devices_info:
                    self.output_preview.insert(tk.END, device[0]) 
                    self.output_preview.insert(tk.END, device[1], "serial_tag") 
                    self.output_preview.insert(tk.END, device[2]) 
            else:
                self.output_preview.insert(tk.END, "No USB device data available.\n")
            self.output_preview.config(state=tk.DISABLED)

        def preview_usb_devices(self):
            self.list_usb_devices()
            self.update_output_preview()

    class SystemInfo:
        def get_system_info(self):
            system_data = platform.uname()
            return (f"System: {system_data.system}\n"
                    f"Node Name: {system_data.node}\n"
                    f"Release: {system_data.release}\n"
                    f"Version: {system_data.version}\n"
                    f"Machine: {system_data.machine}\n"
                    f"Processor: {system_data.processor}\n"
                    f"RAM: {self.get_system_ram()} GB\n"
                    f"Disk: {self.get_disk_space()} GB Free\n")

        def get_system_ram(self):
            c = wmi.WMI()
            for sys in c.Win32_ComputerSystem():
                return round(float(sys.TotalPhysicalMemory) / (1024 ** 3), 2)
            return 0

        def get_disk_space(self):
            c = wmi.WMI()
            total_free_space = sum(float(disk.FreeSpace) / (1024 ** 3) for disk in c.Win32_LogicalDisk(DriveType=3))
            return round(total_free_space, 2)

    def display_system_info():
        sys_info = SystemInfo()
        info = sys_info.get_system_info()
        output_text.config(state=tk.NORMAL)
        output_text.delete(1.0, tk.END)

        output_text.tag_configure("label", font=("Courier", 11), foreground="white")
        output_text.tag_configure("info", font=("Courier", 11), foreground="cyan")

        for line in info.splitlines():
            key, value = line.split(": ", 1)
            output_text.insert(tk.END, f"{key}: ", "label")
            output_text.insert(tk.END, f"{value}\n", "info")
        output_text.config(state=tk.DISABLED)

    def clear_output():
        output_text.config(state=tk.NORMAL)
        output_text.delete(1.0, tk.END)
        output_text.config(state=tk.DISABLED)

    def download_results():
        sys_info = SystemInfo()
        info = sys_info.get_system_info()
        usb_manager.list_usb_devices()

        if not info.strip() and not usb_manager.usb_devices_info:
            messagebox.showwarning("No Data", "No data found to save.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF Files", "*.pdf")],
            title="Save Results"
        )
        if not file_path:
            return
        try:
            pdf = FPDF()
            pdf.set_auto_page_break(auto=True, margin=15)
            pdf.add_page()

            pdf.set_font("Arial", style="B", size=16)
            pdf.cell(200, 10, "System Information Report", ln=True, align="C")
            pdf.ln(10)

            pdf.set_font("Arial", style="B", size=14)
            pdf.cell(0, 10, "System Information:", ln=True)
            pdf.set_font("Arial", size=12)
            for line in info.split('\n'):
                pdf.cell(0, 10, line, ln=True)
            pdf.ln(10)

            pdf.set_font("Arial", style="B", size=14)
            pdf.cell(0, 10, "USB Devices:", ln=True)
            pdf.ln(5)
            pdf.set_font("Arial", style="B", size=12)
            pdf.cell(65, 10, "Device Name", border=1, align='C')
            pdf.cell(125, 10, "Serial Number", border=1, align='C')
            pdf.ln(10)

            pdf.set_font("Arial", size=12)
            for device_info in usb_manager.usb_devices_info:
                device_name = device_info[0] if len(device_info) > 0 else "Unknown Device"
                serial_number = device_info[1] if len(device_info) > 1 else "N/A"

                pdf.cell(65, 10, device_name, border=1)
                pdf.cell(125, 10, serial_number, border=1)
                pdf.ln(10)

            pdf.output(file_path)
            messagebox.showinfo("Success", f"Results saved successfully as:\n{file_path}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to save PDF: {e}")

    root = tk.Toplevel()
    root.title("📀 VJ's System Information Viewer")
    root.geometry("750x500")
    root.resizable(False, False)
    style = Style(theme="cyborg")

    main_frame = ttk.Frame(root, padding=10)
    main_frame.pack(fill=tk.BOTH, expand=True)

    label = ttk.Label(main_frame, text="📀 System Information Viewer", font=("Helvetica", 17, "bold"), foreground="green")
    label.pack(pady=5)

    button_frame = ttk.Frame(main_frame, padding=10)
    button_frame.pack(fill="x", padx=10, pady=10)

    fetch_button = ttk.Button(button_frame, text="📅 List USB Devices", command=lambda: usb_manager.preview_usb_devices(), width=22, bootstyle="primary-outline")
    fetch_button.pack(side="left", padx=5, pady=5)

    usb_button = ttk.Button(button_frame, text="🔍 Display System Info", command=display_system_info, width=22, bootstyle="primary-outline")
    usb_button.pack(side="left", padx=5, pady=5)

    download_button = ttk.Button(button_frame, text="📥 Download Results", command=download_results, width=22, bootstyle="success-outline")
    download_button.pack(side="left", padx=5, pady=5)

    clear_button = ttk.Button(button_frame, text="🗑️ Clear Output", command=clear_output, width=22, bootstyle="danger-outline")
    clear_button.pack(side="left", padx=5, pady=5)

    output_text = ScrolledText(main_frame, wrap=tk.WORD, height=15, bg="#121212", fg="white", font=("Courier", 10))
    output_text.pack(fill="both", expand=True, padx=10, pady=10)
    output_text.config(state=tk.DISABLED)
    usb_manager = USBDeviceManager(output_text)
    root.mainloop()



def open_application_module_3():
    server = "localhost"
    logtype = "Security"
    flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    def QueryEventLog(eventID, filename):
        logs = []
        if filename == "None":
            h = win32evtlog.OpenEventLog(server, logtype)
        else:
            h = win32evtlog.OpenBackupEventLog(server, filename)
        while True:
            events = win32evtlog.ReadEventLog(h, flags, 0)
            if events:
                for event in events:
                    if event.EventID & 0xFFFF == eventID:
                        logs.append(event)
            else:
                break
        return logs

    def CountSuccessfulLogins(filename="None"):
        successful_logins = 0
        events = QueryEventLog(4624, filename)
        for event in events:
            successful_logins += 1
        return successful_logins

    def show_successful_logins(filename="None"):
        total_successful_logins = CountSuccessfulLogins(filename)

        login_table = PrettyTable()
        login_table.field_names = ["Total Successful Logins"]
        login_table.add_row([total_successful_logins])
        login_table_output = login_table.get_string()

        output_text.config(state=tk.NORMAL)
        output_text.delete("1.0", tk.END)
        insert_success_colored_text(login_table_output)
        output_text.config(state=tk.DISABLED)

        alert2 = run_analysis_alerts(filename)
        output_text.config(state=tk.NORMAL)
        insert_alert_colored_text(alert2)
        output_text.config(state=tk.DISABLED)

    def insert_success_colored_text(login_table_output):
        output_text.tag_configure("header", foreground="green", font=("Helvetica", 12, "bold"))
        output_text.tag_configure("data", foreground="white")

        output_text.insert(tk.END, "\n✅ Total Successful Logins:\n", "header")
        output_text.insert(tk.END, login_table_output + "\n\n", "data")

    def DetectBruteForce(filename="None"):
        failures = {}
        events = QueryEventLog(4625, filename)
        
        for event in events:
            if int(event.StringInserts[10]) in [2, 8, 10]:
                account = event.StringInserts[1]
                timestamp_dt = event.TimeGenerated
                formatted_timestamp = timestamp_dt.strftime("%d-%m-%Y %H:%M:%S")
                if account in failures:
                    failures[account].append(formatted_timestamp)
                else:
                    failures[account] = [formatted_timestamp]
        return failures

    def show_failed_logins(filename="None"):
        failures = DetectBruteForce(filename)
        failures_table = PrettyTable()
        failures_table.field_names = ["Account", "Failed Login Count", "Timestamps"]
        for account, timestamps in failures.items():
            failures_table.add_row([account, len(timestamps), "\n".join(timestamps)])
        failures_table_output = failures_table.get_string()

        output_text.config(state=tk.NORMAL)
        output_text.delete("1.0", tk.END)
        insert_failed_colored_text(failures_table_output)
        output_text.config(state=tk.DISABLED)

        alert2 = run_analysis_alerts(filename)
        output_text.config(state=tk.NORMAL)
        insert_alert_colored_text(alert2)
        output_text.config(state=tk.DISABLED)

    def insert_failed_colored_text(failures_table_output):
        output_text.tag_configure("header", foreground="green", font=("Helvetica", 12, "bold"))
        output_text.tag_configure("data", foreground="White")

        output_text.insert(tk.END, "\n🚨 ***Failed Login Attempts*** 🚨 \n", "header")
        output_text.insert(tk.END, failures_table_output + "\n\n", "data")

    def AlertOnContinuousFailures(failures, threshold=3):
        alerts = []     
        for account, timestamps in failures.items():
            if len(timestamps) >= threshold:
                timestamps_dt = [datetime.strptime(ts, "%d-%m-%Y %H:%M:%S") for ts in timestamps]
                i = 0
                while i < len(timestamps_dt) - 1:
                    attempt_group = [timestamps_dt[i]]
                    for j in range(i + 1, len(timestamps_dt)):
                        if (timestamps_dt[j] - attempt_group[0]).total_seconds() <= 60:
                            attempt_group.append(timestamps_dt[j])
                        else:
                            break    
                    if len(attempt_group) >= threshold:
                        formatted_attempts = [ts.strftime("%d-%m-%Y %H:%M:%S") for ts in attempt_group]
                        alerts.append((account, formatted_attempts))
                        i += len(attempt_group)
                    else:
                        i += 1
        return alerts

    def run_analysis_alert(filename="None"):
        failures = DetectBruteForce(filename)
        alerts = AlertOnContinuousFailures(failures)
        alerts_table = PrettyTable()
        alerts_table.field_names = ["Account", "Alert Timestamps"]
        if alerts:
            for account, timestamps in alerts:
                alerts_table.add_row([account, "\n".join(timestamps)])
            messagebox.showerror("Alert!", "🚨 Brute Force Attack Detected!")
            alerts_output = alerts_table.get_string()
        else:
            alerts_output = "\n✅ No Brute Force Event Detected..."
        return alerts_output

    def run_analysis_alerts(filename="None"):
        failures = DetectBruteForce(filename)
        alert = AlertOnContinuousFailures(failures)
        alert_table = PrettyTable()
        alert_table.field_names = ["Account", "Alert Timestamps"]
        if alert:
            for account, timestamps in alert:
                alert_table.add_row([account, "\n".join(timestamps)])
            alert2 = alert_table.get_string()
        else:
            alert2 = "\n✅ No Brute Force Event Detected..."
        return alert2

    def insert_alert_colored_text(alerts_output):
        output_text.tag_configure("header", foreground="green", font=("Helvetica", 11, "bold"))
        output_text.tag_configure("data", foreground="white")
        output_text.tag_configure("alert", foreground="white")
        output_text.tag_configure("end", foreground="red", font=("Helvetica", 11, "bold"))

        if "No Brute Force Event Detected..." in alerts_output:
            output_text.insert(tk.END, alerts_output, "end")
        else:
            output_text.insert(tk.END, "\nAlert!, 🚨 Brute Force Attack Detected!!!\n", "header")
            output_text.insert(tk.END, alerts_output, "alert")
            output_text.insert(tk.END, "\n🚨 **Consider changing passwords and reviewing security settings** 🚨\n", "end")

    def open_file():
        filename = filedialog.askopenfilename(title="Select Event Log File", filetypes=[("Event Log Files", "*.evtx"), ("All Files", "*.*")])
        if filename:
            output_text.config(state=tk.NORMAL)
            output_text.delete("1.0", tk.END)
            output_text.config(state=tk.DISABLED)

            alerts_output = run_analysis_alert(filename)
            output_text.config(state=tk.NORMAL)
            insert_alert_colored_text(alerts_output)
            output_text.config(state=tk.DISABLED)

            main_frame.grid_rowconfigure(2, weight=1)
            main_frame.grid_columnconfigure(0, weight=1)
            main_frame.grid_columnconfigure(1, weight=1)
            btn_success.config(state=tk.NORMAL, command=lambda: show_successful_logins(filename))
            btn_failed.config(state=tk.NORMAL, command=lambda: show_failed_logins(filename))
        else:
            messagebox.showwarning("No file selected", "Please select a valid event log file.")

    def analyze_live_log():
        try:
            output_text.config(state=tk.NORMAL)
            output_text.delete("1.0", tk.END)

            alerts_output = run_analysis_alert()
            output_text.config(state=tk.NORMAL)
            insert_alert_colored_text(alerts_output)
            output_text.config(state=tk.DISABLED)

            main_frame.grid_rowconfigure(2, weight=1)
            main_frame.grid_columnconfigure(0, weight=1)
            main_frame.grid_columnconfigure(1, weight=1)

            btn_success.config(state=tk.NORMAL, command=lambda: show_successful_logins())
            btn_failed.config(state=tk.NORMAL, command=lambda: show_failed_logins())
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def clear_output():
        output_text.config(state=tk.NORMAL)
        output_text.delete(1.0, tk.END)
        output_text.config(state=tk.DISABLED)

    import re
    import tkinter as tk
    from tkinter import messagebox, filedialog
    from fpdf import FPDF

    def clean_text(text):
        """ Remove emojis and special characters from text, keeping alphanumeric, spaces, colons, slashes, and hyphens. """
        return re.sub(r'[^\w\s:/-]', '', text)

    class PDF(FPDF):
        def header(self):
            self.set_font("Arial", "B", 14)
            self.cell(200, 10, "Event Log Analysis Report", ln=True, align="C")
            self.ln(10)

        def add_table(self, title, data, col_widths):
            """ Adds a table to the PDF with a title and formatted rows """
            if not data:
                return
            
            self.set_font("Arial", "B", 12)
            self.cell(0, 10, title, ln=True)
            self.ln(5)

            # Table headers (first row)
            self.set_font("Arial", "B", 10)
            for col, width in col_widths.items():
                self.cell(width, 8, col, border=1, align="C")
            self.ln()

            # Table content (remaining rows)
            self.set_font("Arial", size=10)
            for row in data:
                for i, col in enumerate(col_widths.keys()):
                    self.cell(list(col_widths.values())[i], 8, row[i], border=1, align="C")
                self.ln()
            self.ln(5)

    def download_results():
        text_content = output_text.get(1.0, tk.END).strip()
        if not text_content:
            messagebox.showwarning("No Data", "No log data available to save.")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".pdf",
                                                filetypes=[("PDF Files", "*.pdf")],
                                                title="Save Results")
        if not file_path:
            return

        try:
            pdf = PDF()
            pdf.set_auto_page_break(auto=True, margin=15)
            pdf.add_page()

            sections = {
                "Successful Logins": [],
                "Brute Force Attempts": [],
                "Failed Logins": []
            }

            lines = text_content.split("\n")
            current_section = None

            for line in lines:
                clean_line = clean_text(line).strip()

                if "Total Successful Logins" in clean_line:
                    current_section = "Successful Logins"
                elif "Brute Force" in clean_line:
                    current_section = "Brute Force Attempts"
                elif "Failed Login Attempts" in clean_line:
                    current_section = "Failed Logins"

                if current_section and clean_line:
                    sections[current_section].append(clean_line)

            # Define table columns and widths
            table_structures = {
                "Successful Logins": (["Count"], {"Count": 40}),
                "Brute Force Attempts": (["Account", "Date & Time"], {"Account": 100, "Date & Time": 100}),
                "Failed Logins": (["Account", "Date & Time"], {"Account": 50, "Date & Time": 100})
            }

            # Process data into structured table rows
            formatted_data = {key: [] for key in sections.keys()}

            for section, data in sections.items():
                if not data:
                    continue
                
                if section == "Successful Logins":
                    formatted_data[section] = [[data[-1].split(":")[-1].strip()]]  # Extract count only
                else:
                    for line in data[1:]:  # Skip header
                        parts = line.split()  # Split line by space
                        if len(parts) >= 2:
                            formatted_data[section].append([" ".join(parts[:-2]), " ".join(parts[-2:])])

            # Add tables to PDF
            for section, (headers, col_widths) in table_structures.items():
                pdf.add_table(section, formatted_data[section], col_widths)

            pdf.output(file_path)
            messagebox.showinfo("Success", f"Results saved successfully as:\n{file_path}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to save PDF: {e}")

    root = tk.Toplevel()
    root.title("🔍 VJ's Brute Force Event Analyzer")
    root.geometry("1000x600")
    root.resizable(False, False)
    style = Style(theme="cyborg")

    main_frame = ttk.Frame(root, padding=10)
    main_frame.pack(fill=tk.BOTH, expand=True)

    label = ttk.Label(main_frame, text="🔍 Brute Force Event Analyzer", font=("Helvetica", 17, "bold"), foreground="green", bootstyle="dark")
    label.pack(pady=5)

    button_frame = ttk.Frame(main_frame, padding=10)
    button_frame.pack(fill="x", padx=10, pady=10)

    btn_open = ttk.Button(button_frame, text="📂 Analyze Events Log Files", command=open_file, width=33, bootstyle="primary-outline")
    btn_open.pack(side="left", padx=7, pady=7)

    btn_live = ttk.Button(button_frame, text="📡  Analyze Live Event Logs", command=analyze_live_log, width=33, bootstyle="primary-outline")
    btn_live.pack(side="left", padx=7, pady=7)

    btn_success = ttk.Button(button_frame, text="✔️ Show Successful Logins", state=tk.DISABLED, width=33, bootstyle="success-outline")
    btn_success.pack(side="left", padx=7, pady=7)

    btn_failed = ttk.Button(button_frame, text="❌ Show Failed Logins", state=tk.DISABLED, width=33, bootstyle="danger-outline")
    btn_failed.pack(side="left", padx=7, pady=7)

    output_text = ScrolledText(main_frame, wrap=tk.WORD, height=15, bg="#121212", fg="white", font=("Courier", 10))
    output_text.pack(fill="both", expand=True, padx=10, pady=10)
    output_text.config(state=tk.DISABLED)

    download_button = ttk.Button(main_frame, text="📥 Download Results", command=download_results, width=28, bootstyle="success-outline")
    download_button.pack(side="left", padx=22, pady=12)

    clear_button = ttk.Button(main_frame, text="🗑️ Clear Output", command=clear_output, width=28, bootstyle="danger-outline")
    clear_button.pack(side="right", padx=22, pady=12)
    root.mainloop()



def open_application_module_4():
    def get_installed_apps():
        uninstall_keys = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        ]

        installed_apps = []
        for key in uninstall_keys:
            try:
                reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key)
                for i in range(winreg.QueryInfoKey(reg_key)[0]):
                    try:
                        subkey_name = winreg.EnumKey(reg_key, i)
                        subkey = winreg.OpenKey(reg_key, subkey_name)
                        app_name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                        try:
                            install_date_str = winreg.QueryValueEx(subkey, "InstallDate")[0]
                            install_date = datetime.strptime(install_date_str, "%Y%m%d").date() if install_date_str else "Unknown"
                        except Exception:
                            install_date = "Unknown"
                        installed_apps.append((app_name, install_date))
                    except Exception:
                        continue
            except Exception:
                continue
        return installed_apps

    def get_uninstalled_apps():
        event_log_type = "Setup"
        uninstalled_apps = []
        try:
            event_log_handle = win32evtlog.OpenEventLog("localhost", event_log_type)
            event_read_flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = True
            while events:
                events = win32evtlog.ReadEventLog(event_log_handle, event_read_flags, 0)
                for event in events:
                    if event.EventID == 1034:
                        try:
                            event_generated_time = event.TimeGenerated.strftime("%d-%m-%Y")
                            app_name = event.StringInserts[0] if event.StringInserts else "Unknown Application"
                            uninstalled_apps.append((app_name, event_generated_time))
                        except Exception:
                            continue
            win32evtlog.CloseEventLog(event_log_handle)
        except Exception:
            pass
        return uninstalled_apps

    def display_applications():
        output_text.config(state=tk.NORMAL)
        output_text.delete(1.0, tk.END)

        apps_installed = get_installed_apps()
        apps_uninstalled = get_uninstalled_apps()

        # Configure text tags
        output_text.tag_configure("header", font=("Courier", 12), foreground="cyan")
        output_text.tag_configure("app", font=("Courier", 11), foreground="white")
        output_text.tag_configure("date", font=("Courier", 11), foreground="green")  # Green color for dates

        output_text.insert(tk.END, f"📌 Installed Applications:\n", "header")
        if apps_installed:
            for app, date in apps_installed:
                output_text.insert(tk.END, f"{app} - Installed on: ", "app")
                output_text.insert(tk.END, f"{date}\n", "date")  # Date in green
        else:
            output_text.insert(tk.END, "No installed applications found.\n", "app")

        output_text.insert(tk.END, f"\n🗑️ Uninstalled Applications:\n", "header")
        if apps_uninstalled:
            for app, date in apps_uninstalled:
                output_text.insert(tk.END, f"{app} - Uninstalled on: ", "app")
                output_text.insert(tk.END, f"{date}\n", "date")  # Date in green
        else:
            output_text.insert(tk.END, "No uninstalled applications found.\n", "app")

        output_text.config(state=tk.DISABLED)


    def clear_output():
        output_text.config(state=tk.NORMAL)
        output_text.delete(1.0, tk.END)
        output_text.config(state=tk.DISABLED)

    def download_results():
        file_path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF Files", "*.pdf")],
            title="Save Results"
        )

        if not file_path:
            return

        try:
            pdf = FPDF()
            pdf.set_auto_page_break(auto=True, margin=15)
            pdf.add_page()
            pdf.set_font("Arial", style="B", size=16)
            pdf.cell(200, 10, "Applications History Report", ln=True, align="C")
            pdf.ln(10)

            pdf.set_font("Arial", style="B", size=12)
            pdf.cell(100, 10, "Installed Applications", border=1, align="C")
            pdf.cell(60, 10, "Date", border=1, align="C")
            pdf.ln()

            for app, date in get_installed_apps():
                pdf.set_font("Arial", size=10)
                pdf.cell(100, 10, app[:40], border=1, align="L")

                # Set green color for date
                pdf.set_text_color(0, 128, 0)
                pdf.cell(60, 10, str(date), border=1, align="C")
                pdf.set_text_color(0, 0, 0)  # Reset text color to black
                pdf.ln()

            pdf.ln(5)
            pdf.set_font("Arial", style="B", size=12)
            pdf.cell(100, 10, "Uninstalled Applications", border=1, align="C")
            pdf.cell(60, 10, "Date", border=1, align="C")
            pdf.ln()

            for app, date in get_uninstalled_apps():
                pdf.set_font("Arial", size=10)
                pdf.cell(100, 10, app[:40], border=1, align="L")

                # Set green color for date
                pdf.set_text_color(0, 128, 0)
                pdf.cell(60, 10, date, border=1, align="C")
                pdf.set_text_color(0, 0, 0)  # Reset text color to black
                pdf.ln()

            pdf.output(file_path)
            messagebox.showinfo("Success", f"Results saved successfully as:\n{file_path}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to save PDF: {e}")

    root = tk.Toplevel()
    root.title("📊 VJ's Applications History Analyzer")
    root.geometry("800x500")
    root.resizable(False, False)
    style = Style(theme="cyborg")

    main_frame = ttk.Frame(root, padding=10)
    main_frame.pack(fill=tk.BOTH, expand=True)

    label = ttk.Label(main_frame, text="📊 Applications History Analyzer", font=("Helvetica", 17, "bold"),foreground="green", bootstyle="dark")
    label.pack(pady=5)

    button_frame = ttk.Frame(main_frame, padding=10)
    button_frame.pack(fill="x", padx=10, pady=10)

    fetch_button = ttk.Button(button_frame, text="🔍 Analyze Applications", command=display_applications, width=28,bootstyle="primary-outline")
    fetch_button.pack(side="left", padx=7, pady=7)

    download_button = ttk.Button(button_frame, text="📥 Download Results", command=download_results, width=28,bootstyle="success-outline")
    download_button.pack(side="left", padx=7, pady=7)

    clear_button = ttk.Button(button_frame, text="🗑️ Clear Output", command=clear_output, width=28,bootstyle="danger-outline")
    clear_button.pack(side="left", padx=7, pady=7)

    output_text = ScrolledText(main_frame, wrap=tk.WORD, height=18, bg="#121212", fg="white", font=("Courier", 10))
    output_text.pack(fill="both", expand=True, padx=10, pady=10)
    output_text.config(state=tk.DISABLED)
    root.mainloop()



def open_application_module_5():
    def file_access_history(directory, selected_date):
        accessed_files = []
        selected_date = datetime.strptime(selected_date, '%Y-%m-%d').date()

        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    access_time = datetime.fromtimestamp(os.path.getatime(file_path)).strftime('%d-%m-%Y %H:%M:%S')
                    access_date = datetime.strptime(access_time, '%d-%m-%Y %H:%M:%S').date()                  
                    if access_date == selected_date:
                        accessed_files.append(file_path)
                except Exception:
                    continue 
        return accessed_files
    class MainFrame(wx.Frame):
        def __init__(self, *args, **kw):
            super(MainFrame, self).__init__(*args, **kw)
            panel = wx.Panel(self)
            panel.SetBackgroundColour(wx.Colour(30, 30, 30)) 
            vbox = wx.BoxSizer(wx.VERTICAL)

            title_label = wx.StaticText(panel, label="📂 Files Access History Analyzer", style=wx.ALIGN_CENTER)
            title_font = wx.Font(17, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_BOLD)
            title_label.SetFont(title_font)
            title_label.SetForegroundColour(wx.Colour(0, 255, 0)) 
            vbox.Add(title_label, flag=wx.ALIGN_CENTER | wx.TOP, border=10)

            hbox_dir = wx.BoxSizer(wx.HORIZONTAL)
            lbl_dir = wx.StaticText(panel, label="Select a Folder or Directory:", style=wx.ALIGN_CENTER)
            lbl_dir.SetForegroundColour(wx.Colour(255, 255, 255))
            self.dir_picker = wx.DirPickerCtrl(panel, message="Select a folder")
            hbox_dir.Add(lbl_dir, flag=wx.RIGHT, border=8)
            hbox_dir.Add(self.dir_picker, proportion=1)
            vbox.Add(hbox_dir, flag=wx.EXPAND | wx.ALL, border=10)

            hbox_date = wx.BoxSizer(wx.HORIZONTAL)
            lbl_date = wx.StaticText(panel, label="Select Date:")
            lbl_date.SetForegroundColour(wx.Colour(255, 255, 255)) 
            self.date_picker = wx.adv.DatePickerCtrl(panel, style=wx.adv.DP_DROPDOWN)
            hbox_date.Add(lbl_date, flag=wx.RIGHT, border=8)
            hbox_date.Add(self.date_picker, proportion=1)
            vbox.Add(hbox_date, flag=wx.EXPAND | wx.ALL, border=10)

            button_box = wx.BoxSizer(wx.HORIZONTAL)
            search_btn = wx.Button(panel, label="🔍 Analyze Files Access History")
            download_btn = wx.Button(panel, label="📥 Download Results")
            button_box.Add(search_btn, flag=wx.RIGHT, border=10)
            button_box.Add(download_btn, flag=wx.RIGHT, border=10)
            vbox.Add(button_box, flag=wx.ALIGN_CENTER | wx.ALL, border=10)

            search_btn.Bind(wx.EVT_BUTTON, self.find_files_and_apps)
            download_btn.Bind(wx.EVT_BUTTON, self.download_results)

            self.result_label = wx.TextCtrl(panel, style=wx.TE_MULTILINE | wx.TE_READONLY | wx.TE_RICH2, size=(400, 300))
            self.result_label.SetBackgroundColour(wx.Colour(50, 50, 50)) 
            self.result_label.SetForegroundColour(wx.Colour(255, 255, 255)) 
            vbox.Add(self.result_label, proportion=1, flag=wx.EXPAND | wx.ALL, border=10)

            panel.SetSizer(vbox)
            self.SetSize((500, 600))

        def insert_colored_text(self, header, data, header_style, data_style, none_style, none_message):
            self.result_label.SetDefaultStyle(header_style)
            self.result_label.AppendText(header)
            if data:
                self.result_label.SetDefaultStyle(data_style)
                self.result_label.AppendText(data + "\n\n")
            else:
                self.result_label.SetDefaultStyle(none_style)
                self.result_label.AppendText(none_message + "\n\n")

        def find_files_and_apps(self, event):
            directory = self.dir_picker.GetPath()
            selected_date = self.date_picker.GetValue().FormatISODate()

            if not selected_date:
                wx.MessageBox("Please select a date.", "Input Error", wx.ICON_WARNING)
                return
            
            self.result_label.Clear()

            header_font = wx.Font(12, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_BOLD)
            header_style = wx.TextAttr(wx.Colour(0, 255, 255))
            header_style.SetFont(header_font) 

            data_font = wx.Font(12, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_BOLD)
            data_style = wx.TextAttr(wx.Colour(255, 255, 255)) 
            data_style.SetFont(data_font)

            none_font = wx.Font(12, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL)
            none_style = wx.TextAttr(wx.Colour(255, 0, 0)) 
            none_style.SetFont(none_font)

            if directory:
                files = file_access_history(directory, selected_date)
                if files:
                    self.insert_colored_text(f"Files accessed on {selected_date}:\n", "\n".join(files), header_style, data_style, none_style, none_message="")
                else:
                    self.insert_colored_text(f"Files accessed on {selected_date}:\n", None, header_style, data_style, none_style, none_message=f"No files accessed on {selected_date}.")
        
        def download_results(self, event):
            with wx.FileDialog(self, "Save Results", wildcard="PDF files (*.pdf)|*.pdf", style=wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT) as fileDialog:
                if fileDialog.ShowModal() == wx.ID_CANCEL:
                    return

                path = fileDialog.GetPath()
                if not path.lower().endswith(".pdf"):
                    path += ".pdf"
                try:
                    pdf = FPDF()
                    pdf.set_auto_page_break(auto=True, margin=15)
                    pdf.add_page()

                    pdf.set_font("Arial", "B", 16) 
                    pdf.cell(0, 10, "Files Access History Report", ln=True, align="C")
                    pdf.ln(10) 

                    pdf.set_font("Arial", size=12)
                    lines = self.result_label.GetValue().split("\n")
                    
                    for line in lines:
                        if line.strip() == "":
                            pdf.ln(5) 
                        else:
                            pdf.multi_cell(0, 7, line)

                    pdf.output(path)
                    wx.MessageBox("Results saved successfully as PDF!", "Success", wx.ICON_INFORMATION)
                except IOError:
                    wx.LogError(f"Cannot save results to file {path}.")

    if __name__ == "__main__":
        app = wx.App(False)
        frame = MainFrame(None, title="📂 VJ's Files Access History Analyzer")
        frame.Show()
        app.MainLoop()



root = tk.Tk()
root.title("VJ's Digital Evidence Analyzer")
root.geometry("850x600")
root.resizable(False, False)
style = Style(theme="cyborg")

main_frame = ttk.Frame(root)
main_frame.pack(fill=tk.BOTH, expand=True)

left_frame = ttk.Frame(main_frame, width=280, bootstyle="dark")
left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
left_frame.pack_propagate(False)

right_frame = ttk.Frame(main_frame, bootstyle="dark")
right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)

label = ttk.Label(left_frame, text="Select an Analyzer to run:", font=("Helvetica", 15, "bold"), bootstyle="inverse-dark")
label.pack(pady=15)

output_text = tk.Text(right_frame, wrap=tk.WORD, height=25, bg="#121212", fg="white", font=("Consolas", 10))
output_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
output_text.config(state=tk.DISABLED)

btn_font = ("Arial", 10, "bold")

btn_app1 = ttk.Button(left_frame, text=" 📶 WiFi Credentials Analyzer", command=open_application_module_1, width=30, bootstyle="primary-outline")
btn_app1.pack(pady=10)

btn_app2 = ttk.Button(left_frame, text=" 📀 System Information Viewer", command=open_application_module_2, width=30, bootstyle="primary-outline")
btn_app2.pack(pady=10)

btn_app3 = ttk.Button(left_frame, text=" 🔍 Brute Force Event Analyzer", command=open_application_module_3, width=30, bootstyle="primary-outline")
btn_app3.pack(pady=10)

btn_app4 = ttk.Button(left_frame, text=" 📊 Applications History Analyzer", command=open_application_module_4, width=30, bootstyle="primary-outline")
btn_app4.pack(pady=10)

btn_app5 = ttk.Button(left_frame, text=" 📂 Files Access History Analyzer", command=open_application_module_5, width=30, bootstyle="primary-outline")
btn_app5.pack(pady=10)
root.mainloop()