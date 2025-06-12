
🖥️ #  Digital Evidence Analyzer Tool

**Digital Evidence Analyzer Tool** is a Python-based forensic utility built to support cybersecurity professionals, forensic investigators, and IT administrators in analyzing critical system data and gathering digital evidence. The tool features a GUI-based, modular design to streamline forensic workflows across five primary analysis domains.

---

## 📌 Key Features

📶 **WiFi Credentials Analyzer**

* Extracts saved SSIDs, passwords, encryption, and authentication details
* Useful for identifying historical wireless network connections

📀 **System Information Viewer**

* Displays system hardware specs and OS configuration
* Lists all connected USB devices for external access tracking

🔍 **Brute Force Analyzer**

* Monitors event logs for multiple failed login attempts
* Detects and reports potential brute force attacks in real time

 📊 **Application History Analyzer**

* Tracks installed/uninstalled applications with dates
* Detects unauthorized software changes

📂 **Files Access History Analyzer**

* Lists files accessed/modified on a specific date in a selected directory
* Helps detect unauthorized or suspicious file access

---

## 🛠️ Tech Stack

| Category         | Details                                                               |
| ---------------- | --------------------------------------------------------------------- |
| Language         | Python 3.10                                                           |
| GUI Frameworks   | Tkinter, ttkbootstrap, wxPython                                       |
| Reporting        | FPDF, PrettyTable                                                     |
| OS Compatibility | Windows 10+                                                           |
| Libraries        | `os`, `platform`, `subprocess`, `win32evtlog`, `wmi`, `tkinter`, etc. |

---

## 🎯 Target Audience

* 🛡️ **Cybersecurity Analysts** – Detect intrusions and collect logs for incident response
* 🕵️ **Digital Forensic Investigators** – Extract digital artifacts for legal investigations
* 🎓 **Students & Educators** – Learn practical digital forensics through real-world tools
* 🖥️ **System Admins** – Audit system activity and monitor for insider threats

---

## ⚙️ Installation & Setup

### ✅ Requirements:

* OS: Windows 10 or higher
* Python: 3.8+
* RAM: 4 GB minimum
* Permissions: Administrator access for logs/registry

### 🔧 Installation:

1. Clone this repository
2. Install required dependencies.
3. Run the tool.

## 🧭 Usage Guide

Once launched, the main GUI offers access to the following modules:

* 📶 **WiFi Credentials Analyzer** – Scan and export saved WiFi credentials
* 🧾 **System Info Viewer** – List system specs and USB device history
* 🧱 **Brute Force Analyzer** – Identify failed logins and detect brute force attempts
* 🧩 **App History Analyzer** – See when apps were installed/uninstalled
* 📁 **File Access Tracker** – Find files accessed on a specific date in a directory

Each module includes options to **download PDF reports** for documentation and evidence handling.

---

## 📈 Output & Reporting

All analysis results can be:

* Viewed on-screen in a styled GUI
* Exported to structured PDF reports for legal or audit use
* Used to support forensic investigations or security audits

---

## 🔒 Use Cases

* 🔐 **Incident Response**
* 👮 **Law Enforcement Forensics**
* 🧑‍💻 **Corporate Security Auditing**
* 🎓 **Cybersecurity Training Labs**

---

## 🆚 Comparison with Existing Tools

| Aspect               | Existing Tools   | DEA Tool               |
| -------------------- | ---------------- | ---------------------- |
| Scope                | Single-purpose   | All-in-one             |
| User Interface       | CLI/Advanced GUI | Beginner-friendly GUI  |
| Report Generation    | Often limited    | 1-click PDF generation |
| Open Source Friendly | Not always       | ✅ Fully Open Source    |

---

## 🚀 Future Enhancements

* 🖥️ Cross-platform (Linux/macOS) support
* 📩 Real-time alert system for brute force detection
* ☁️ Cloud-based log/report storage
* 📱 Mobile companion app for on-the-go access
* 📊 Export to CSV, Excel, JSON formats

---

## 🏁 Conclusion

The **Digital Evidence Analyzer Tool** is a comprehensive, user-friendly forensic application aimed at empowering professionals and learners with robust, real-time forensic capabilities. It simplifies complex analysis tasks and ensures secure, traceable, and legally admissible evidence collection.


