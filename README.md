# Windows Security Hardening Tool

## Overview
The **Windows Security Hardening Tool** is a Python-based GUI application designed to enhance Windows security by allowing users to manage critical system settings easily. The tool integrates PowerShell and Windows Registry modifications to enable or disable security features, apply predefined configurations, and execute custom security scripts. 

It provides real-time status monitoring and supports both built-in security controls and user-defined enhancements. The intuitive interface makes it accessible to both technical and non-technical users, helping to automate system hardening while ensuring a secure Windows environment.

---

## Features

- **Graphical User Interface (GUI):** A user-friendly interface built with Tkinter for easy interaction.
- **Built-in Security Controls:** Enable or disable Windows security features like location tracking, Windows Firewall, remote access, and privacy settings.
- **Custom Script Management:** Upload, edit, and execute user-defined PowerShell scripts for additional security configurations.
- **Real-Time Status Monitoring:** Displays the current security state with visual indicators for enabled/disabled features.
- **Predefined Security Modes:** Apply "Maximum Security" or "Minimum Security" settings with one click.
- **PowerShell Integration:** Executes system-level security commands directly from the application.
- **Admin Privilege Check:** Ensures that security changes are only applied with administrative privileges.

---

## Installation

### Prerequisites
Before installing the Windows Security Hardening Tool, ensure that your system meets the following requirements:

- **Windows OS:** Compatible with Windows 10 and Windows 11.
- **Python 3.x:** Ensure Python is installed (if not running as an executable). You can download it from [python.org](https://python.org).
- **Tkinter:** Included with Python by default.
- **PowerShell:** Built into Windows (required for executing security commands).

### Steps to Install

1. **Download the Repository:**
```bash
git clone https://github.com/your-username/windows-security-hardening-tool.git
cd windows-security-hardening-tool
```

2. **Install Dependencies:**
Open Command Prompt (cmd) as Administrator and run:
```bash
pip install -r requirements.txt
```

3. **Run the Application:**
Execute the following command in Command Prompt (as Administrator):
```bash
python main.py
```
> **Note:** The tool requires admin rights to modify system settings. If prompted, allow the application to run as an administrator.

---

## Usage

### Run as Administrator
Since this is a Windows tool that modifies critical system settings, always run the application as an administrator. This ensures that all changes can be applied successfully.

### Navigating the Interface
The GUI is divided into several key sections:

- **Master Controls:** Quickly apply predefined security configurations such as "Maximum Security" or "Minimum Security" with a single selection.
- **Built-in Controls:** Manage individual Windows security features (e.g., location tracking, firewall settings, remote desktop access) using simple dropdown menus that offer enable/disable options.
- **Custom Controls:** Upload and manage your own PowerShell scripts to extend the tool's capabilities, allowing you to tailor security settings to your specific requirements.
- **Status Monitor:** View real-time indicators showing the current status of each security feature, ensuring you always know which settings are active.

### Applying Security Settings

- **Predefined Modes:** Select a security mode from the Master Controls to instantly apply a set of configurations aimed at maximizing or minimizing system security.
- **Individual Adjustments:** For more granular control, select a feature from the Built-in Controls and choose to enable or disable it via the contextual popup menu.

### Custom Script Management

- **Upload Scripts:** Easily add custom PowerShell scripts by providing a script name and selecting the corresponding enable/disable script files.
- **Edit or Delete Scripts:** Manage your custom controls directly from the interface, allowing you to modify or remove scripts as needed.
- **Real-Time Feedback:** The Status Monitor continuously updates to reflect the current state of each security feature, giving you immediate feedback on any changes made.

---
