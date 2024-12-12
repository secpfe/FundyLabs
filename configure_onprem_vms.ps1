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




# Start DCR onboarding


# Variables
$resourceGroupName = "CyberSOC"
$workspaceName = "CyberSOCWS"
$dcrName = "Minimal-Servers"
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
                        "Security!*[System[(EventID=4769 or EventID=4773)]]",
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


# Deploy Azure Monitor Agent to the VMs
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


#Linux DCR part
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
New-AzDataCollectionRuleAssociation -TargetResourceId $targetLinuxResourceId `
    -DataCollectionRuleId $linuxDataCollectionRuleId `
    -AssociationName $LinuxassociationName

    Write-Output "DCR Association '$LinuxassociationName' created for VM '$web01Name' using Id." 


# Deploy Azure Monitor Agent to the Linux VM
$extension = Set-AzVMExtension -ResourceGroupName $resourceGroupNameOps `
    -VMName $web01Name `
    -Name "AzureMonitorLinuxAgent" `
    -Publisher "Microsoft.Azure.Monitor" `
    -ExtensionType "AzureMonitorLinuxAgent" `
    -TypeHandlerVersion "1.0" `
    -Location $location

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
                  'Uma Thurman', 'Victor Hugo', 'Wendy Darling', 'Xander Harris', 'Yara Greyjoy')
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
$associationName = "$DCvmName-DCR-Association"

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

# replace with additional actions 
Start-Sleep 30

$EnableLDAPAuditScriptString = @"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" -Name "16 LDAP Interface Events" -Value 2 -Type DWord
"@
# Enable LDAP Audit on DC VM
$output = Invoke-AzVMRunCommand -ResourceGroupName $resourceGroupName -VMName $DCvmName -CommandId "RunPowerShellScript" -ScriptString $EnableLDAPAuditScriptString 

# View the full output
$output.Value | ForEach-Object { $_.Message }


# LDAP Simple Bind 
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
sudo apt-get install -y python3-pip
pip3 install ldap3
echo "$PythonScript" > /tmp/temp_script.py
python3 /tmp/temp_script.py
unset DEBIAN_FRONTEND 
"@


Connect-AzAccount -Identity
# Execute the command on the Linux VM
Write-Output "Executing script on the Linux VM..."
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
