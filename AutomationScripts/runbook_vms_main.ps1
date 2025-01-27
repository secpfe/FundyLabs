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
$DCvmName = "DC"
$resourceGroupName = "CyberSOC"
$resourceGroupNameOps = "ITOperations"
$workspaceName = "CyberSOCWS"
$dcrName = "Minimal-Servers"
$powershellDcrName = "PowerShellLogs"
$linuxDcrName = "Minimal-Linux"
$DCDcrName = "Additional-DC"
$web01Name = "web01"
$mservName = "mserv"
$vmNames = @("mserv", "win10", "dc")
# Get the resource group location
$resourceGroup = Get-AzResourceGroup -Name $resourceGroupName
$location = $resourceGroup.Location
$workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $resourceGroupName -Name $workspaceName
# Prepare DCR details
$workspaceResourceId = $workspace.ResourceId
$workspaceId = $workspace.CustomerId