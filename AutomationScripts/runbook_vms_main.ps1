param (
    [string]$adminAccount,
    [string]$adminPassword,
    [string]$LDAPUserAccount1,
    [string]$LDAPUserAccount2
)

Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Starting Orchestration Runbook..."

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



#######################################
# Step 1. Promote a domain controller
#######################################
Write-Output "Initiating Step 1..."


#param (
#    [string]$adminPassword,
#    [string]$domainName,
#    [string]$DCvmName,
#    [string]$resourceGroupName
#)

$dcJob = Start-AzAutomationRunbook -AutomationAccountName "myOrchestratorAccount" -Name "VMs_PromoteDC" -ResourceGroupName "Orchestrator" -Parameters @{
        $adminPassword = $adminPassword
        domainName     = "odomain.local"
        DCvmName          = $DCvmName
        resourceGroupName = $resourceGroupNameOps
    }

Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Step 1 runbook started!"


#######################################
# Step 1 ends here
#######################################

#######################################################
# Step 2.
# - Setting up Bastion
# - Onboarding web01, win10 and mserv to relevant DCRs
# - Installing AMA for web01, win10, mserv
#######################################################
Write-Output "Initiating Step 2..."

$dcrJob = Start-AzAutomationRunbook -AutomationAccountName "myOrchestratorAccount" -Name "VMs_DCRs" -ResourceGroupName "Orchestrator" 
$amaJob = Start-AzAutomationRunbook -AutomationAccountName "myOrchestratorAccount" -Name "VMs_AMA" -ResourceGroupName "Orchestrator" 
$bastionJob = Start-AzAutomationRunbook -AutomationAccountName "myOrchestratorAccount" -Name "VMs_Bastion" -ResourceGroupName "Orchestrator" 

# Wait for All Jobs to Complete
Wait-AzAutomationJob -AutomationAccountName "myOrchestratorAccount" -JobId $dcrJob.JobId
Wait-AzAutomationJob -AutomationAccountName "myOrchestratorAccount" -JobId $amaJob.JobId
Wait-AzAutomationJob -AutomationAccountName "myOrchestratorAccount" -JobId $bastionJob.JobId

Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - All tasks for Step 2 completed successfully!"

#######################################
# Step 2 ends here
#######################################


########################################################################
# Step 3.
# - Joining win10 and mserv to domain
# Unless machines are successfully joined, the domain is non-operational
# end the script can't proceed
#########################################################################
Write-Output "Initiating Step 3..."

# param (
#     [string]$adminAccount,
#     [string]$adminPassword,
#     [string]$domainName,
#     [string]$DCvmName,
#     [string]$resourceGroupName
# )


$domainJoinJob = Start-AzAutomationRunbook -AutomationAccountName "myOrchestratorAccount" -Name "VMs_domainJoin" -ResourceGroupName "Orchestrator" -Parameters @{
    adminAccount = $adminAccount
    adminPassword = $adminPassword
    domainName     = "odomain.local"
    DCvmName          = $DCvmName
    resourceGroupName = $resourceGroupNameOps
}


Wait-AzAutomationJob -AutomationAccountName "myOrchestratorAccount" -JobId $domainJoinJob.JobId


Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Step 3 tasks completed successfully!"

