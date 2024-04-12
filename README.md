# Windows_audit
Windows Audit Script  This PowerShell script performs comprehensive auditing of a Windows system, collecting essential information about hardware, software, network configuration, user accounts, and security settings. It generates detailed logs for analysis and system monitoring.

# Usage
1. Open Powershell in admininstration mode
2. Change directory to where the script is stored
3. Set Execution policy - Set-ExecutionPolicy RemoteSigned
4. .\audit.ps1

# Key Functions and Information Gathered by a Comprehensive Windows Audit Script

    Basic System Information:
        System model, manufacturer, and other hardware details.
        Operating system version, installation date, and other OS-related information.
        Processor details (CPU model, architecture, etc.).

    Hardware Information:
        Memory (RAM) details including capacity, speed, and type.
        Disk drive information such as type, capacity, and interface.
        Network adapter details like name, MAC address, and status.

    Software and Patch Management:
        List of installed software including name, version, and vendor.
        Installed Windows updates and patches (hotfixes).

    Network and Security Information:
        Network configuration details (IP addresses, DNS settings, etc.).
        Firewall settings and status.
        Antivirus status and Windows Defender settings.
        Open ports and listening processes on the system.

    User and Account Information:
        Local user accounts and their properties (name, description, etc.).
        Active Directory user information (if applicable).

    Event Logs and Monitoring:
        Recent system, security, and application event logs.
        Monitoring of system changes and critical events.

    Scheduled Tasks and Services:
        List of scheduled tasks and their configurations.
        Running services on the system with their current status.

    Advanced Security Checks:
        File and folder permissions.
        Registry permissions and settings.
        Checking for unauthorized or suspicious processes.

    System Configuration Checks:
        UAC (User Account Control) settings.
        Startup programs and services.

    Domain and Active Directory Information:
        Details about the domain the system is joined to (if applicable).
        Information about Active Directory users and groups.

    Additional Information:
        Group Policy settings and configurations.
        System startup and boot configurations.
        Advanced system and network configurations.

These functions collectively provide a comprehensive overview of the Windows system's configuration, security posture, hardware specifications, software inventory, and user/account management. Depending on specific audit requirements and use cases, you can tailor the script to include relevant sections and customize the output format for easier analysis and reporting. 

# Output
The output to is stored in
<br>
**C:\AuditLogs**
<br>
![image](https://github.com/Nxirm/Windows_audit-/assets/86094721/fbe01bef-fb81-45be-b432-d352a7574a66)

   
