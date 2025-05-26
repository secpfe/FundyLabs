param (
    [string]$adminPassword,
    [string]$vmName,
    [string]$resourceGroupName
)

Import-Module Az.Compute
Import-Module Az.Accounts

Connect-AzAccount -Identity


$mservscript = @"
# Enable File and Printer sharing
netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes
# Add ssupport to local admins
net localgroup Administrators "ODOMAIN\ssupport" /add

mkdir c:\backup
`$downloadBackupExe = "https://github.com/secpfe/FundyLabs/raw/refs/heads/main/backup.exe"
`$backupExe = "c:\backup\backup.exe"
`$webClient = New-Object System.Net.WebClient
`$webClient.DownloadFile(`$downloadBackupExe, `$backupExe)
`$webClient.Dispose()

Write-Output "Setting Advanced Audit Policies..."

# Logon/Logoff
& auditpol.exe /set /subcategory:"Logon" /success:enable /failure:enable
& auditpol.exe /set /subcategory:"Logoff" /success:disable
& auditpol.exe /set /subcategory:"Special Logon" /success:enable /failure:enable

# Detailed tracking
& auditpol.exe /set /subcategory:"Process Creation" /success:enable /failure:enable

# Privilege use
& auditpol.exe /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable

`$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
`$regValue = "LmCompatibilityLevel"

# Set the desired level
Set-ItemProperty -Path `$regPath -Name `$regValue -Value 1
Write-Output "LAN Manager Authentication Level downgraded to NTLMv1 successfully."

# Create the service using sc.exe
`$command = "sc.exe create BackupSVC binPath= c:\backup\backup.exe obj= odomain\da-batch password= $adminPassword start= auto"
Invoke-Expression `$command


# Define the service account
`$AccountName = "odomain\da-batch"  

# Get the SID of the account
`$accountSID = (New-Object System.Security.Principal.NTAccount(`$AccountName)).Translate([System.Security.Principal.SecurityIdentifier]).Value

# Export the current security policy
`$SecEditFile = "`$env:temp\secpol.cfg"
secedit /export /cfg `$SecEditFile | Out-Null

# Read the exported security policy
`$config = Get-Content `$SecEditFile

# Check if the SID is already listed
if (`$config -match "SeServiceLogonRight\s*=\s*(.*`$accountSID.*)") {
Write-Host "`$AccountName already has 'Log on as a service' rights."
sc start BackupSVC
} else {
# Append the SID to the existing list
`$updatedConfig = `$config -replace "(SeServiceLogonRight\s*=\s*)(.*)", "```$1```$2,*`$accountSID"
Set-Content `$SecEditFile `$updatedConfig

# Apply the updated police
secedit /configure /db secedit.sdb /cfg `$SecEditFile /areas USER_RIGHTS

Write-Host "Granted 'Log on as a service' rights to `$AccountName."
gpupdate /force
sc.exe start backupsvc
}

# Clean up temporary files
Remove-Item `$SecEditFile -Force

`$FileSharePath = "\\10.0.0.4\HealthReports"
`$securePassword = ConvertTo-SecureString "$adminPassword" -AsPlainText -Force
`$Credential = New-Object System.Management.Automation.PSCredential ("odomain\reportAdmin", `$securePassword)

# Directly access the file share with the specified credentials
`$session = New-PSDrive -Name TempShare -PSProvider FileSystem -Root `$FileSharePath -Credential `$Credential
try {
Get-ChildItem -Path "TempShare:\" 
} finally {
Remove-PSDrive -Name TempShare
}

Write-Output "Accessed a folder under reportAdmin account, with downgraded NTLM."

"@

$output = Invoke-AzVMRunCommand -ResourceGroupName $resourceGroupName -VMName $vmName -CommandId "RunPowerShellScript" -ScriptString $mservscript
# View the full output
$output.Value | ForEach-Object { $_.Message }
