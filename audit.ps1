# Windows Audit Script

# Output directory for audit logs
$auditDirectory = "C:\AuditLogs"
if (!(Test-Path -Path $auditDirectory)) {
    New-Item -ItemType Directory -Path $auditDirectory | Out-Null
}

# Get basic system information
$systemInfo = Get-CimInstance -ClassName Win32_ComputerSystem
$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
$processorInfo = Get-CimInstance -ClassName Win32_Processor

# Save system information to a text file
$systemInfo | Out-File "$auditDirectory\SystemInfo.txt"
$osInfo | Out-File "$auditDirectory\OSInfo.txt"
$processorInfo | Out-File "$auditDirectory\ProcessorInfo.txt"

# Get installed software information
$software = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
$software | Select-Object DisplayName, Publisher, InstallDate, DisplayVersion | 
    Sort-Object DisplayName | Out-File "$auditDirectory\InstalledSoftware.txt"

# Get network configuration information
$networkInfo = Get-NetIPConfiguration
$networkInfo | Out-File "$auditDirectory\NetworkInfo.txt"

# Get user account information
$userAccounts = Get-LocalUser
$userAccounts | Out-File "$auditDirectory\UserAccounts.txt"

# Get list of running processes
$processes = Get-Process | Select-Object ProcessName, Id, MainWindowTitle
$processes | Out-File "$auditDirectory\RunningProcesses.txt"

# Get memory (RAM) information
$memoryInfo = Get-CimInstance -ClassName Win32_PhysicalMemory
$memoryInfo | Out-File "$auditDirectory\MemoryInfo.txt"

# Get disk drive information
$diskInfo = Get-CimInstance -ClassName Win32_DiskDrive
$diskInfo | Out-File "$auditDirectory\DiskDriveInfo.txt"

# Get network adapter information
$networkAdapterInfo = Get-NetAdapter
$networkAdapterInfo | Out-File "$auditDirectory\NetworkAdapterInfo.txt"

# Get firewall settings
$firewallInfo = Get-NetFirewallProfile
$firewallInfo | Out-File "$auditDirectory\FirewallInfo.txt"

# Check antivirus status (Windows Security)
$antivirusStatus = Get-MpComputerStatus
$antivirusStatus | Out-File "$auditDirectory\AntivirusStatus.txt"

# Check Windows Defender settings
$defenderSettings = Get-MpPreference
$defenderSettings | Out-File "$auditDirectory\WindowsDefenderSettings.txt"

# Get recent system event logs
$systemEventLogs = Get-WinEvent -LogName System -MaxEvents 100
$systemEventLogs | Out-File "$auditDirectory\SystemEventLogs.txt"

# Get recent security event logs
$securityEventLogs = Get-WinEvent -LogName Security -MaxEvents 100
$securityEventLogs | Out-File "$auditDirectory\SecurityEventLogs.txt"

# Get recent application event logs
$applicationEventLogs = Get-WinEvent -LogName Application -MaxEvents 100
$applicationEventLogs | Out-File "$auditDirectory\ApplicationEventLogs.txt"

# Get installed Windows updates
$windowsUpdates = Get-HotFix
$windowsUpdates | Out-File "$auditDirectory\WindowsUpdates.txt"

# Get installed software and their versions
$installedSoftware = Get-WmiObject -Class Win32_Product
$installedSoftware | Select-Object Name, Version, Vendor | Out-File "$auditDirectory\InstalledSoftwareDetailed.txt"

# Get domain information (if applicable)
$domainInfo = Get-WmiObject Win32_NTDomain
$domainInfo | Out-File "$auditDirectory\DomainInfo.txt"

# Get Active Directory user information (if applicable)
$adUsers = Get-ADUser -Filter *
$adUsers | Out-File "$auditDirectory\ADUsers.txt"

# Get group policy settings
$groupPolicies = Get-GPOReport -All -ReportType XML
$groupPolicies | Out-File "$auditDirectory\GroupPolicies.xml"

# Get scheduled tasks
$scheduledTasks = Get-ScheduledTask
$scheduledTasks | Out-File "$auditDirectory\ScheduledTasks.txt"

# Get running services
$services = Get-Service
$services | Out-File "$auditDirectory\RunningServices.txt"

# Check open ports and listening processes
$openPorts = Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' }
$openPorts | Out-File "$auditDirectory\OpenPorts.txt"

# Check file and folder permissions
Get-Acl C:\ | Format-List | Out-File "$auditDirectory\FileFolderPermissions.txt"

# Check registry permissions
Get-Acl HKLM:\SOFTWARE | Format-List | Out-File "$auditDirectory\RegistryPermissions.txt"

# Check UAC settings
$uacSettings = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | Select-Object EnableLUA, ConsentPromptBehaviorAdmin
$uacSettings | Out-File "$auditDirectory\UACSettings.txt"

# Get startup programs
$startupPrograms = Get-CimInstance -Query "SELECT * FROM Win32_StartupCommand"
$startupPrograms | Out-File "$auditDirectory\StartupPrograms.txt"


Write-Host "Audit completed. Logs are saved in: $auditDirectory"
