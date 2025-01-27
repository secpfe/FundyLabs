param (
    [string]$adminAccount,
    [string]$adminPassword,
    [string]$LDAPUserAccount1,
    [string]$LDAPUserAccount2
)

Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Starting Orchestration Runbook..."

Import-Module Az.Accounts
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



# Function to wait for a job to complete
function Wait-ForAutomationJob {
    param (
        [string]$AutomationAccountName,
        [string]$ResourceGroupName,
        [Guid]$JobId,
        [string]$RunBookName
    )

    while ($true) {
        # Retrieve the job status
        $job = Get-AzAutomationJob -AutomationAccountName $automationAccountName -ResourceGroupName $resourceGroupName -Id $jobId

        Write-Output "Job $RunBookName Status: $($job.Status)"

        if ($job.Status -eq "Completed") {
            Write-Output "Job $RunBookName completed successfully!"
            break
        } elseif ($job.Status -eq "Failed") {
            Write-Output "Job $RunBookName failed. Check logs for details."
            break
        } elseif ($job.Status -eq "Stopped" -or $job.Status -eq "Suspended") {
            Write-Output "Job $RunBookName was stopped or suspended."
            break
        }

        # Wait for a few seconds before checking again
        Start-Sleep -Seconds 30
    }
}

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
        adminPassword = $adminPassword
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
Wait-ForAutomationJob -AutomationAccountName "myOrchestratorAccount" -JobId $dcrJob.JobId -ResourceGroupName "Orchestrator" -RunBookName "DCRs"
Wait-ForAutomationJob -AutomationAccountName "myOrchestratorAccount" -JobId $amaJob.JobId -ResourceGroupName "Orchestrator" -RunBookName "AMA"
Wait-ForAutomationJob -AutomationAccountName "myOrchestratorAccount" -JobId $bastionJob.JobId -ResourceGroupName "Orchestrator" -RunBookName "Bastion"

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
    resourceGroupName = $resourceGroupNameOps
}


Wait-ForAutomationJob -AutomationAccountName "myOrchestratorAccount" -ResourceGroupName "Orchestrator" -JobId $domainJoinJob.JobId -RunBookName "Domain Join"


Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Step 3 tasks completed successfully!"

#######################################
# Step 3 ends here
#######################################


########################################################################
# Step 4.
# - Configuring DNS on DC
# - Creating domain objects
#########################################################################
Write-Output "Initiating Step 4..."


# param (
#     [string]$DCvmName,
#     [string]$adminPassword,
#     [string]$resourceGroupName
# )

$domainConfigureJob = Start-AzAutomationRunbook -AutomationAccountName "myOrchestratorAccount" -Name "VMs_configureAD" -ResourceGroupName "Orchestrator" -Parameters @{
    DCvmName = $DCvmName
    adminPassword = $adminPassword
    resourceGroupName = $resourceGroupNameOps
}

Wait-ForAutomationJob -AutomationAccountName "myOrchestratorAccount" -ResourceGroupName "Orchestrator" -JobId $domainConfigureJob.JobId -RunBookName "AD Configuration"


Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Step 4 tasks completed successfully!"

#######################################
# Step 4 ends here
#######################################


########################################################################
# Step 5.
# - Configure web01 and initiate Win10 profile creation
# - Configuring mserv auditing and downgrading NTLM
# accessing a file share and starting a service
#########################################################################

Write-Output "Initiating Step 5..."

# param (
#     [string]$adminPassword,
#     [string]$vmName,
#     [string]$resourceGroupName
# )
$web01Job = Start-AzAutomationRunbook -AutomationAccountName "myOrchestratorAccount" -Name "VMs_web01_conf" -ResourceGroupName "Orchestrator"  -Parameters @{
    adminPassword = $adminPassword
    vmName = "web01"
    resourceGroupName = $resourceGroupNameOps
}
$mservJob = Start-AzAutomationRunbook -AutomationAccountName "myOrchestratorAccount" -Name "VMs_mserv_conf" -ResourceGroupName "Orchestrator"  -Parameters @{
    adminPassword = $adminPassword
    vmName = "mserv"
    resourceGroupName = $resourceGroupNameOps
}


# Wait for All Jobs to Complete
Wait-ForAutomationJob -AutomationAccountName "myOrchestratorAccount" -JobId $web01Job.JobId -ResourceGroupName "Orchestrator" -RunBookName "Web01 Configuration"
Wait-ForAutomationJob -AutomationAccountName "myOrchestratorAccount" -JobId $mservJob.JobId -ResourceGroupName "Orchestrator" -RunBookName "MServ Configuration"

Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - All tasks for Step 5 completed successfully!"

#######################################
# Step 5 ends here
#######################################

