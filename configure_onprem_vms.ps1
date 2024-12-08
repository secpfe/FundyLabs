param (
    [string]$adminAccount,
    [string]$adminPassword
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

# Create the Data Collection Rule using the JSON string 
New-AzDataCollectionRule -Name $dcrName -ResourceGroupName $resourceGroupName -JsonString $jsonContent

# Add DCR association to VMs
$vmNames = @("mserv", "win10")
#$vmNames = @("fed01", "wsjoe")

# Retrieve the ImmutableId for the DCR
$dcr = Get-AzDataCollectionRule -ResourceGroupName $resourceGroupName -Name $dcrName
if (!$dcr) {
    Write-Output "DCR '$dcrName' not found in Resource Group '$resourceGroupName'." -ForegroundColor Red
    exit
}

$dataCollectionRuleId = $dcr.Id
$resourceGroupNameOps = "ITOperations"

# Add DCR association to VMs
$vmNames = @("mserv", "win10")
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
$linuxVmName = "linuxVM"


# Retrieve the ImmutableId for the DCR
$linuxDcr = Get-AzDataCollectionRule -ResourceGroupName $resourceGroupName -Name $linuxDcrName
if (!$linuxDcr) {
    Write-Output "DCR '$linuxDcrName' not found in Resource Group '$resourceGroupName'." 
}

$linuxDataCollectionRuleId = $linuxDcr.Id


# Add DCR association to VMs
$linuxVm = Get-AzVM -ResourceGroupName $resourceGroupNameOps -Name $linuxVmName
if (!$linuxVm) {
    Write-Output "VM '$linuxVmName' not found in Resource Group '$resourceGroupNameOps'." 
}

# Build the association
$targetLinuxResourceId = $linuxVm.Id
$LinuxassociationName = "linuxVM-DCR-Association"
# Create DCR association
New-AzDataCollectionRuleAssociation -TargetResourceId $targetLinuxResourceId `
    -DataCollectionRuleId $linuxDataCollectionRuleId `
    -AssociationName $LinuxassociationName

    Write-Output "DCR Association '$LinuxassociationName' created for VM '$linuxVmName' using Id." 


# Deploy Azure Monitor Agent to the Linux VM
$extension = Set-AzVMExtension -ResourceGroupName $resourceGroupNameOps `
    -VMName $linuxVmName `
    -Name "AzureMonitorLinuxAgent" `
    -Publisher "Microsoft.Azure.Monitor" `
    -ExtensionType "AzureMonitorLinuxAgent" `
    -TypeHandlerVersion "1.0" `
    -Location $location

Write-Output "Azure Monitor Agent deployed for VM '$linuxVmName'." 






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
