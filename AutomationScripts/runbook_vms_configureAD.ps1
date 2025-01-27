param (
    [string]$DCvmName,
    [string]$adminPassword,
    [string]$resourceGroupName
)


Import-Module Az.Compute
Import-Module Az.Accounts

Connect-AzAccount -Identity


$ADConfigureScript = @"
`$pwd = '$adminPassword'

# Import the Active Directory module
Import-Module ActiveDirectory
# Ensure DNS Server module is available
Import-Module DNSServer

# Add a forwarder to Google Public DNS
Add-DnsServerForwarder -IPAddress "8.8.8.8"


# Define global variables
`$OUs = @(
    'Corp',
    'Corp/Servers',
    'Corp/Desktops',
    'Corp/Users',
    'Corp/ServiceAccounts',
    'Corp/Groups',
    'Corp/Admins'
)
`$ServiceAccounts = @('svc-mssql', 'svc-sap', 'svc-riot', 'svc-backup', 'svc-web', 'svc-file', 'svc-email', 'svc-dns', 'svc-print', 'svc-api',
                     'svc-data', 'svc-monitor', 'svc-report', 'svc-backup2', 'svc-web2', 'svc-file2', 'svc-email2', 'svc-dns2', 'svc-print2', 'svc-api2')
`$SecurityGroups = @('Finance', 'Accounting', 'Marketing', 'Sales', 'Support', 'IT', 'Logistics', 'R&D', 'Operations', 'Engineering',
                    'Legal', 'Compliance', 'Procurement', 'Admin', 'Training', 'Quality', 'CustomerService', 'Analytics', 'Risk',
                    'Governance', 'Security', 'Innovation', 'Planning', 'Product')
`$AdditionalGroups = @('ITSupport', 'HR')
`$JobTitles = @('Software Engineer', 'Data Analyst', 'System Administrator', 'Network Engineer', 'Project Manager', 'HR Specialist',
               'Finance Manager', 'Marketing Coordinator', 'Sales Representative', 'Business Analyst', 'Compliance Officer', 'Support Specialist',
               'Quality Assurance Analyst', 'Product Manager', 'Operations Lead', 'Training Coordinator', 'Customer Service Rep', 'Logistics Manager',
               'Security Analyst', 'Procurement Specialist')
`$UserAccounts = @('Alice Johnson', 'Bob Smith', 'Charlie Brown', 'Diana Prince', 'Eve Adams', 'Frank Castle', 'Grace Hopper', 'Hank Pym', 'Ivy Bell', 'Jack Reacher',
                  'Karen Miller', 'Leo Tolstoy', 'Maya Angelou', 'Neil Armstrong', 'Olivia Wilde', 'Paul Atreides', 'Quincy Jones', 'Rose Tyler', 'Sam Wilson', 'Tina Turner',
                  'Uma Thurman', 'Victor Hugo', 'Wendy Darling', 'Xander Harris', 'Yara Greyjoy', 'Support Support')
`$CandiceKevin = @{'Name' = 'Candice Kevin'; 'SamAccountName' = 'candice.kevin'; 'Title' = 'HR Executive'}
`$JonSmith = @{'Name' = 'Jon Smith'; 'SamAccountName' = 'jon'}
`$BatchAccount = @{'Name' = 'DA Batch'; 'SamAccountName' = 'da-batch'}
`$ReportAccount = @{'Name' = 'Report Admin'; 'SamAccountName' = 'reportAdmin'}
`$ComputerAccounts = @('appsrv01', 'appsrv02', 'db001', 'db002', 'sap01', 'sap02', 'web01', 'web02', 'print01', 'print02',
                      'backup01', 'backup02', 'email01', 'email02', 'dns01', 'dns02', 'file01', 'file02', 'app03', 'db003',
                      'web03', 'web04', 'sap03', 'sap04', 'file03')

# Get the domain components dynamically
`$domainDN = (Get-ADDomain).DistinguishedName
`$domainDNS = (Get-ADDomain).DNSRoot

# Create OUs
foreach (`$ou in `$OUs) {
    # Split the OU path to extract the current OU name and parent OU path
    `$parts = `$ou -split '/'
    `$currentOU = `$parts[-1]
    `$parentOU = if (`$parts.Length -gt 1) { "OU=`$(`$parts[-2])" } else { "" } # Handle root-level OUs

    # Construct the full SearchBase path dynamically
    `$searchBase = if (`$parentOU -ne "") { "`$parentOU,`$domainDN" } else { `$domainDN }

    # Check if the OU already exists
    `$existingOU = Get-ADOrganizationalUnit -Filter "Name -eq '`$currentOU'" -SearchBase `$searchBase -ErrorAction SilentlyContinue
    if (-not `$existingOU) {
        # Construct the New-ADOrganizationalUnit path dynamically
        `$ouPath = if (`$parentOU -ne "") { "`$parentOU,`$domainDN" } else { `$domainDN }
        New-ADOrganizationalUnit -Name `$currentOU -Path `$ouPath 
        Write-Host "OU `$ou created"
    }
}



# Create service accounts with SPNs in ServiceAccounts OU
foreach (`$account in `$ServiceAccounts) {
    New-ADUser -Name `$account -SamAccountName `$account -AccountPassword (ConvertTo-SecureString "`$pwd" -AsPlainText -Force) -Enabled `$true -Path "OU=ServiceAccounts,OU=Corp,`$domainDN" 
    Write-Output "User `$account created in ServiceAccounts OU"

    `$serviceType = `$account -replace '^svc-', ''
    `$serverName = "`$serviceType-server01.`$domainDNS"
    Set-ADUser -Identity `$account -ServicePrincipalNames @{Add="`$account/`$serverName"} 
    Write-Output "SPN `$account/`$serverName assigned"
}

# Create global security groups in Groups OU
foreach (`$group in `$SecurityGroups + `$AdditionalGroups) {
    New-ADGroup -Name `$group -GroupScope Global -Path "OU=Groups,OU=Corp,`$domainDN" 
    Write-Output "Group `$group created in Groups OU"
}

# Create user accounts with random job titles in Users OU
foreach (`$user in `$UserAccounts) {
    `$firstName, `$lastName = `$user -split ' '
    `$samAccountName = (`$firstName.Substring(0, 1) + `$lastName).ToLower()
    `$randomTitle = Get-Random -InputObject `$JobTitles
    New-ADUser -Name `$user -SamAccountName `$samAccountName -UserPrincipalName "`$samAccountName@`$domainDNS" -AccountPassword (ConvertTo-SecureString "`$pwd" -AsPlainText -Force) -Enabled `$true -Title `$randomTitle -Path "OU=Users,OU=Corp,`$domainDN" 
    Write-Output "User `$user created with job title `$randomTitle in Users OU"
}

# Create specific accounts in Admins OU
New-ADUser -Name `$CandiceKevin.Name -SamAccountName `$CandiceKevin.SamAccountName -UserPrincipalName "`$(`$CandiceKevin.SamAccountName)@`$domainDNS" -AccountPassword (ConvertTo-SecureString "`$pwd" -AsPlainText -Force) -Enabled `$true -Title `$CandiceKevin.Title -Path "OU=Users,OU=Corp,`$domainDN"
Write-Output "User `$(`$CandiceKevin.Name) created in Admins OU"
Add-ADGroupMember -Identity 'HR' -Members `$CandiceKevin.SamAccountName 
Write-Output "User `$(`$CandiceKevin.Name) added to group HR"

New-ADUser -Name `$JonSmith.Name -SamAccountName `$JonSmith.SamAccountName -UserPrincipalName "`$(`$JonSmith.SamAccountName)@`$domainDNS" -AccountPassword (ConvertTo-SecureString "`$pwd" -AsPlainText -Force) -Enabled `$true -Path "OU=Admins,OU=Corp,`$domainDN" 
Write-Output "User `$(`$JonSmith.Name) created in Admins OU"
Add-ADGroupMember -Identity 'ITSupport' -Members `$JonSmith.SamAccountName 
Write-Output "User `$(`$JonSmith.Name) added to group ITSupport"

New-ADUser -Name `$BatchAccount.Name -SamAccountName `$BatchAccount.SamAccountName -UserPrincipalName "`$(`$BatchAccount.SamAccountName)@`$domainDNS" -AccountPassword (ConvertTo-SecureString "`$pwd" -AsPlainText -Force) -Enabled `$true -Path "OU=Admins,OU=Corp,`$domainDN" 
Write-Output "User `$(`$BatchAccount.Name) created in Admins OU"
Add-ADGroupMember -Identity 'Domain Admins' -Members `$BatchAccount.SamAccountName 
Write-Output "User `$(`$BatchAccount.Name) added to group Domain Admins"

New-ADUser -Name `$ReportAccount.Name -SamAccountName `$ReportAccount.SamAccountName -UserPrincipalName "`$(`$ReportAccount.SamAccountName)@`$domainDNS" -AccountPassword (ConvertTo-SecureString "`$pwd" -AsPlainText -Force) -Enabled `$true -Path "OU=Admins,OU=Corp,`$domainDN" 
Write-Output "User `$(`$ReportAccount.Name) created in Admins OU"
Add-ADGroupMember -Identity 'Server Operators' -Members `$ReportAccount.SamAccountName 
Write-Output "User `$(`$ReportAccount.Name) added to group Server Operators"

# Create computer accounts in Servers OU
foreach (`$computer in `$ComputerAccounts) {
    New-ADComputer -Name `$computer -Path "OU=Servers,OU=Corp,`$domainDN" 
    Write-Output "Computer `$computer created in Servers OU"
}

Write-Output "Active Directory environment setup with OU structure completed successfully."

Write-Output "Enabling LDAP Diagnostics Settings..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" -Name "16 LDAP Interface Events" -Value 2 -Type DWord

Write-Output "LDAP Diagnostics successfully configured."

# Configure Advanced Audit Policies for specific subcategories
# auditpol /get /category:*

Write-Output "Setting Advanced Audit Policies..."

# Logon/Logoff
& auditpol.exe /set /subcategory:"Logon" /success:enable /failure:enable
& auditpol.exe /set /subcategory:"Logoff" /success:disable
& auditpol.exe /set /subcategory:"Special Logon" /success:enable /failure:enable

# Detailed tracking
& auditpol.exe /set /subcategory:"Process Creation" /success:enable /failure:enable

# Privilege use
& auditpol.exe /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable

# Account Logon
& auditpol.exe /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
& auditpol.exe /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
& auditpol.exe /set /subcategory:"Credential Validation" /success:enable
& auditpol.exe /set /subcategory:"Group Membership" /success:enable /failure:enable

# Account Management
& auditpol.exe /set /subcategory:"Computer Account Management" /success:enable
& auditpol.exe /set /subcategory:"Security Group Management" /success:enable
& auditpol.exe /set /subcategory:"User Account Management" /success:enable

# DS Access
& auditpol.exe /set /subcategory:"Directory Service Access" /success:enable /failure:enable

Write-Output "Advanced Audit Policies successfully configured."


# Define the folder path and share name
`$FolderPath = "C:\HealthReports"
`$ShareName = "HealthReports"
`$Description = "Shared folder for health reports"

# Create the folder if it doesn't exist
if (-Not (Test-Path `$FolderPath)) {
    New-Item -ItemType Directory -Path `$FolderPath
    Write-Output "Folder '`$FolderPath' created."
} else {
    Write-Output "Folder '`$FolderPath' already exists."
}

# Set NTFS permissions: Add "Everyone" with read access
`$Acl = Get-Acl `$FolderPath
`$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")
`$Acl.SetAccessRule(`$AccessRule)
Set-Acl -Path `$FolderPath -AclObject `$Acl
Write-Output "NTFS permissions for 'Everyone' set to 'Read'."

# Create the network share
`$ShareParams = @{
    Name        = `$ShareName
    Path        = `$FolderPath
    Description = `$Description
}
New-SmbShare @ShareParams -FullAccess "Administrator" -ReadAccess "Everyone"
Write-Output "Share '`$ShareName' created and shared with 'Everyone' for read access."

"@


# Run object creation script on the DC VM
$output = Invoke-AzVMRunCommand -ResourceGroupName $resourceGroupName -VMName $DCvmName -CommandId "RunPowerShellScript" -ScriptString $ADConfigureScript 

# View the full output of provisioning
$output.Value | ForEach-Object { $_.Message }