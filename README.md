**Overview:**

The Windows Security Hardening Tool is a Python-based GUI application designed to enhance Windows security by allowing users to manage critical system settings easily. The tool integrates PowerShell and Windows Registry modifications to enable or disable security features, apply predefined configurations, and execute custom security scripts.
It provides real-time status monitoring and supports both built-in security controls and user-defined enhancements. The intuitive interface makes it accessible to both technical and non-technical users, helping to automate system hardening while ensuring a secure Windows environment.

**Features**
* Graphical User Interface (GUI): A user-friendly interface built with Tkinter for easy interaction.
* Built-in Security Controls: Enable or disable Windows security features like location tracking, Windows Firewall, remote access, and privacy settings.
* Custom Script Management: Upload, edit, and execute user-defined PowerShell scripts for additional security configurations.
* Real-Time Status Monitoring: Displays the current security state with visual indicators for enabled/disabled features.
* Predefined Security Modes: Apply "Maximum Security" or "Minimum Security" settings with one click.
* PowerShell Integration: Executes system-level security commands directly from the application.
* Admin Privilege Check: Ensures that security changes are only applied with administrative privileges.

**Installation**
*Prerequisites*
Before installing the Windows Security Hardening Tool, ensure that your system meets the following requirements:

Windows OS: Compatible with Windows 10 and Windows 11.
Python 3.x: Ensure Python is installed[if not running exe file]. You can download it from python.org.
Tkinter: Included with Python by default.
PowerShell: Built into Windows (required for executing security commands).

*Steps to Install*
->Download the Repository:
Clone the repository using Git (if installed):
git clone https://github.com/your-username/windows-security-hardening-tool.git  
cd windows-security-hardening-tool  

->Install Dependencies:
Open Command Prompt (cmd) as Administrator and run:
pip install -r requirements.txt  

->Run the Application:
Execute the following command in Command Prompt (as Administrator):
python main.py  
[Grant Administrator Privileges
The tool requires admin rights to modify system settings. If prompted, allow the application to run as an administrator.]

**Usage**
*Run as Administrator*:
Since this is a Windows tool that modifies critical system settings, always run the application as an administrator. This ensures that all changes can be applied successfully.

*Navigating the Interface*:
The GUI is divided into several key sections:

->Master Controls: Quickly apply predefined security configurations such as "Maximum Security" or "Minimum Security" with a single selection.
->Built-in Controls: Manage individual Windows security features (e.g., location tracking, firewall settings, remote desktop access) using simple dropdown menus that offer enable/disable options.
->Custom Controls: Upload and manage your own PowerShell scripts to extend the tool's capabilities, allowing you to tailor security settings to your specific requirements.
->Status Monitor: View real-time indicators showing the current status of each security feature, ensuring you always know which settings are active.

*Applying Security Settings*:

->Predefined Modes: Select a security mode from the Master Controls to instantly apply a set of configurations aimed at maximizing or minimizing system security.
->Individual Adjustments: For more granular control, select a feature from the Built-in Controls and choose to enable or disable it via the contextual popup menu.

*Custom Script Management*:

->Upload Scripts: Easily add custom PowerShell scripts by providing a script name and selecting the corresponding enable/disable script files.
->Edit or Delete Scripts: Manage your custom controls directly from the interface, allowing you to modify or remove scripts as needed.
->Real-Time Feedback: The Status Monitor continuously updates to reflect the current state of each security feature, giving you immediate feedback on any changes made.

**Contributing**
Contributions are welcome! If you'd like to improve the Windows Security Hardening Tool, follow these steps:

*Fork the Repository*

Click the Fork button on GitHub to create your own copy of the project.

*Clone the Repository*
Open Command Prompt (cmd) and run:
git clone https://github.com/your-username/windows-security-hardening-tool.git  
cd windows-security-hardening-tool  

*Create a New Branch*
Before making changes, create a new branch:
git checkout -b feature-branch  

*Make Your Changes*
Modify the code, fix bugs, or add new features.

*Commit Your Changes*
After making changes, commit them with a clear message:
git add .  
git commit -m "Added new security feature"  

*Push to GitHub*
Push your changes to your forked repository:
git push origin feature-branch  

*Submit a Pull Request*
Go to the original repository on GitHub and open a Pull Request (PR) with a description of your changes.


