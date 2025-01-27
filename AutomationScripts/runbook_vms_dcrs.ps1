Import-Module Az.Compute
Import-Module Az.Accounts
Import-Module Az.Monitor

Connect-AzAccount -Identity

$resourceGroupName = "CyberSOC"
$resourceGroupNameOps = "ITOperations"
$workspaceName = "CyberSOCWS"
$dcrName = "Minimal-Servers"
$powershellDcrName = "PowerShellLogs"
$linuxDcrName = "Minimal-Linux"
$DCDcrName = "Additional-DC"
$DCvmName = "DC"
$web01Name = "web01"
$win10name="win10"
$vmNames = @("mserv", "win10", "dc")

# Get the resource group location
$resourceGroup = Get-AzResourceGroup -Name $resourceGroupName
$location = $resourceGroup.Location
$workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $resourceGroupName -Name $workspaceName
# Prepare DCR details
$workspaceResourceId = $workspace.ResourceId
$workspaceId = $workspace.CustomerId

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

$dcJsonContent = @"
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

    New-AzDataCollectionRule -Name $dcrName -ResourceGroupName $resourceGroupName -JsonString $jsonContent
    New-AzDataCollectionRule -Name $powershellDcrName -ResourceGroupName $resourceGroupName -JsonString $powershellDCRJsonContent
    New-AzDataCollectionRule -Name $linuxDcrName -ResourceGroupName $resourceGroupName -JsonString $linuxJsonContent
    New-AzDataCollectionRule -Name $DCDcrName -ResourceGroupName $resourceGroupName -JsonString $dcJsonContent


# DC Association
$DCdcr = Get-AzDataCollectionRule -ResourceGroupName $resourceGroupName -Name $DCDcrName
$dataCollectionRuleId = $DCdcr.Id
$DCvm = Get-AzVM -ResourceGroupName $resourceGroupNameOps -Name $DCvmName
$targetResourceId = $DCvm.Id
$associationName = "$DCvmName-DCR-Association-addt"
New-AzDataCollectionRuleAssociation -TargetResourceId $targetResourceId -DataCollectionRuleId $dataCollectionRuleId -AssociationName $associationName

# Web01 association
$linuxDcr = Get-AzDataCollectionRule -ResourceGroupName $resourceGroupName -Name $linuxDcrName
$linuxDataCollectionRuleId = $linuxDcr.Id
$web01 = Get-AzVM -ResourceGroupName $resourceGroupNameOps -Name $web01Name
$targetLinuxResourceId = $web01.Id
$LinuxassociationName = "web01-DCR-Association"
New-AzDataCollectionRuleAssociation -TargetResourceId $targetLinuxResourceId -DataCollectionRuleId $linuxDataCollectionRuleId -AssociationName $LinuxassociationName

# Win10 powershell DCR association
$powershellDCR = Get-AzDataCollectionRule -ResourceGroupName $resourceGroupName -Name $powershellDcrName
$powershellDataCollectionRuleId = $powershellDCR.Id
$win10 = Get-AzVM -ResourceGroupName $resourceGroupNameOps -Name $win10name
$targetWin10ResourceId = $win10.Id
$Win10PowershellassociationName = "Powershell-win10-DCR-Association"
New-AzDataCollectionRuleAssociation -TargetResourceId $targetWin10ResourceId -DataCollectionRuleId $powershellDataCollectionRuleId -AssociationName $Win10PowershellassociationName

# Server DCR association for multiple VMS
$dcr = Get-AzDataCollectionRule -ResourceGroupName $resourceGroupName -Name $dcrName
$dataCollectionRuleId = $dcr.Id
foreach ($vmName in $vmNames) {
    $vm = Get-AzVM -ResourceGroupName $resourceGroupNameOps -Name $vmName
    $targetResourceId = $vm.Id
    $associationName = "$vmName-DCR-Association"
    New-AzDataCollectionRuleAssociation -TargetResourceId $targetResourceId -DataCollectionRuleId $dataCollectionRuleId -AssociationName $associationName
}