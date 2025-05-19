param (
    [string]$adminAccount,
    [string]$adminPassword,
    [string]$LDAPUserAccount1,
    [string]$LDAPUserAccount2
)

Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Starting Orchestration Runbook..."
Import-Module Az.Accounts

$maxRetries = 10
$retryDelay = 30
$retryCount = 0
$connected = $false

while (-not $connected -and $retryCount -lt $maxRetries) {
    try {
        $context = (Connect-AzAccount -Identity -ErrorAction Stop).Context

        if ($context -and $context.Subscription -and $context.Subscription.Id) {
            $SubscriptionId = $context.Subscription.Id
            Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Connected to subscription: $SubscriptionId"
            $connected = $true
        } else {
            throw "Subscription context not ready yet"
        }
    } catch {
        Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Failed to connect. Retrying in $retryDelay seconds... ($($_.Exception.Message))"
        Start-Sleep -Seconds $retryDelay
        $retryCount++
    }
}

if (-not $connected) {
    throw "Failed to connect to Azure after $maxRetries attempts. Aborting runbook."
}

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
        $job = Get-AzAutomationJob -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Id $JobId

        Write-Output "Job $RunBookName Status: $($job.Status)"

        if ($job.Status -eq "Completed") {
            Write-Output "Job $RunBookName completed successfully!"
            break
        } elseif ($job.Status -eq "Failed") {
            Write-Output "Job $RunBookName failed. Check logs for details."
            break
        } elseif ($job.Status -eq "Stopped") {
            Write-Output "Job $RunBookName was stopped."
            break
        } elseif ($job.Status -eq "Suspended") {
            Write-Output "Job $RunBookName is suspended. Restarting the job..."
            
            # Restarting the job by creating a new one
            $newJob = Start-AzAutomationRunbook -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Name $RunBookName
            $JobId = $newJob.JobId  
            
            Write-Output "New job for $RunBookName started with JobId: $JobId"
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
#    [string]$location
#)

$dcJob = Start-AzAutomationRunbook -AutomationAccountName "myOrchestratorAccount" -Name "VMs_PromoteDC" -ResourceGroupName "Orchestrator" -Parameters @{
        adminPassword = $adminPassword
        domainName     = "odomain.local"
        DCvmName          = $DCvmName
        resourceGroupName = $resourceGroupNameOps
        location = $location
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
# - Onboarding to AMA
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

$dcAMAJob = Start-AzAutomationRunbook -AutomationAccountName "myOrchestratorAccount" -Name "VMs_onboardDcAMA" -ResourceGroupName "Orchestrator" -Parameters @{
    location = $location
}

Wait-ForAutomationJob -AutomationAccountName "myOrchestratorAccount" -ResourceGroupName "Orchestrator" -JobId $domainConfigureJob.JobId -RunBookName "AD Configuration"
Wait-ForAutomationJob -AutomationAccountName "myOrchestratorAccount" -ResourceGroupName "Orchestrator" -JobId $dcAMAJob.JobId -RunBookName "DC AMA Onboarding"


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
#     [string]$resourceGroupName,
#     [string]$LDAPUserAccount1,
#     [string]$LDAPUserAccount2
# )
$web01Job = Start-AzAutomationRunbook -AutomationAccountName "myOrchestratorAccount" -Name "VMs_web01_conf" -ResourceGroupName "Orchestrator"  -Parameters @{
    adminPassword = $adminPassword
    vmName = "web01"
    resourceGroupName = $resourceGroupNameOps
    LDAPUserAccount1 = $LDAPUserAccount1
    LDAPUserAccount2 = $LDAPUserAccount2
}
# param (
#     [string]$adminPassword,
#     [string]$vmName,
#     [string]$resourceGroupName
# )

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


########################################################################
# Step 6.
# - Logging on candice, downloading rs.exe, running rs.exe
# - Loggin on ssupport
#########################################################################

Write-Output "Initiating Step 6..."

# param (
#     [string]$adminPassword,
#     [string]$resourceGroupName
# )

$win10Job = Start-AzAutomationRunbook -AutomationAccountName "myOrchestratorAccount" -Name "VMs_win10" -ResourceGroupName "Orchestrator"  -Parameters @{
    adminPassword = $adminPassword
    resourceGroupName = $resourceGroupNameOps
}

Wait-ForAutomationJob -AutomationAccountName "myOrchestratorAccount" -JobId $win10Job.JobId -ResourceGroupName "Orchestrator" -RunBookName "Win10 Automation"

Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - All tasks for Step 6 completed successfully!"

#######################################
# Step 6 ends here
#######################################


########################################################################
# Step 7.
# - Secretsdump from mserv using web01
#########################################################################

Write-Output "Initiating Step 7..."

# param (
#     [string]$adminPassword,
#     [string]$vmName,
#     [string]$resourceGroupName
# )
$web01Job = Start-AzAutomationRunbook -AutomationAccountName "myOrchestratorAccount" -Name "VMs_web01_lsa" -ResourceGroupName "Orchestrator"  -Parameters @{
    adminPassword = $adminPassword
    vmName = "web01"
    resourceGroupName = $resourceGroupNameOps
}

# Wait for All Jobs to Complete
Wait-ForAutomationJob -AutomationAccountName "myOrchestratorAccount" -JobId $web01Job.JobId -ResourceGroupName "Orchestrator" -RunBookName "Web01->MSERV LSA Secretsdump attacks"

Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - All tasks for Step 7 completed successfully!"
