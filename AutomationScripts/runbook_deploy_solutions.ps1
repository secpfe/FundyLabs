# Backfill runbook for Microsoft Sentinel Content Hub solutions.
#
# 03.DeploySolutions (LCA) fires the solution deployments with an async ARM PUT and does not wait for
# them to finish, so some can still be Running -- or have Failed -- when the lab chain moves on. This
# runbook re-checks every desired solution and (re)deploys ONLY the ones that did not land:
#   Succeeded            -> skip (already installed)
#   Running / Accepted   -> skip (an LCA deploy is still in flight; let it finish)
#   Failed / Canceled    -> redeploy
#   no deployment at all  -> deploy
#
# It is idempotent: deployments are Incremental and keyed on the same deterministic
# "SentiLab-<contentId>" name 03 uses, so re-running never creates duplicates.
#
# Auth: the myOrchestratorAccount system-assigned managed identity, which 02.AssignPerms grants
# LOD Contributor at subscription scope -- enough to deploy content into the CyberSOC RG. The ACPs
# assigned on leaving Pre-Build work on an allowlist basis (they deny anything whose type is not
# explicitly permitted), and the Content Hub resource types this deploys -- OperationsManagement
# solutions, Insights workbooks, data collection rules, Logic workflows, Web connections -- are on that
# allowlist, so the same operations 03 already runs under those policies apply here too.

param(
    # Minutes to wait for the Content Hub catalog to finish populating before giving up on lookups.
    [int]$CatalogTimeoutMinutes = 5,
    # Minutes to wait for each backfilled deployment to reach a terminal state. 0 = fire-and-forget.
    [int]$DeployTimeoutMinutes = 10
)

$ErrorActionPreference = 'Stop'

$Solutions = @(
    "Windows Security Events", "Microsoft Entra ID", "Azure Activity",
    "Log4j Vulnerability Detection", "Network Session Essentials", "Security Threat Essentials", "Sentinel SOAR Essentials",
    "SOC Handbook", "Threat Intelligence", "UEBA Essentials", "Analytics Health & Audit", "Workspace Usage Report",
    "Azure Key Vault", "Azure Logic Apps", "Common Event Format", "KQL Training", "Insecure Protocols",
    "Microsoft Sentinel Optimization Workbook", "Potential Kerberoasting",
    "Potential Password Spray Attack (Uses Authentication Normalization)", "Service Principal Assigned Privileged Role",
    "Service Principal Authentication Attempt from New Country", "Sign-ins from IPs that attempt sign-ins to disabled accounts (Uses Authentication Normalization)",
    "Use Case Mapper", "User account enabled and disabled within 10 mins", "Workspace audit"
)

# ----------------------------------------------------------------- connect (managed identity)

Write-Output "=== DeploySolutions backfill started ==="
Write-Output "Connecting to Azure with the Automation Account managed identity..."
Disable-AzContextAutosave -Scope Process | Out-Null
# The sliced subscription appears with a delay, so wait for a usable context: Connect-AzAccount can
# hit its 100s HttpClient timeout and return nothing while the sign-in later succeeds.
$connectDeadline = (Get-Date).AddMinutes(6)
do {
    Connect-AzAccount -Identity -ErrorAction SilentlyContinue | Out-Null
    $context = Get-AzContext
    if ($context.Subscription.Id) { break }
    Start-Sleep -Seconds 15
} while ((Get-Date) -lt $connectDeadline)
if (-not $context.Subscription.Id) { throw "Failed to connect to Azure with the Automation Account managed identity." }
Write-Output "Connected successfully. Subscription: $($context.Subscription.Id)"

# ----------------------------------------------------------------- discover RG / workspace

$ResourceGroup = (Get-AzResourceGroup | Where-Object { $_.ResourceGroupName -like '*CyberSOC*' } | Select-Object -First 1).ResourceGroupName
if (-not $ResourceGroup) { throw "CyberSOC resource group not found." }

$workspaceObj = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroup | Select-Object -First 1
if (-not $workspaceObj) { throw "No Log Analytics workspace found in resource group $ResourceGroup" }
$Workspace = $workspaceObj.Name
$Region    = $workspaceObj.Location
Write-Output "Target workspace '$Workspace' ($Region) in resource group '$ResourceGroup'."

# ----------------------------------------------------------------- auth header

$token = Get-AzAccessToken -ResourceUrl "https://management.azure.com/" -TenantId $context.Tenant.Id
$authHeader = @{
    'Content-Type'  = 'application/json'
    'Authorization' = 'Bearer ' + $token.Token
}

$SubscriptionId = $context.Subscription.Id
$serverUrl = "https://management.azure.com"
$baseUri = $serverUrl + "/subscriptions/${SubscriptionId}/resourceGroups/${ResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${Workspace}"

# ----------------------------------------------------------------- helpers

function Get-DeploymentName {
    param([string]$ContentId)
    $name = "SentiLab-" + $ContentId
    if ($name.Length -ge 64) { $name = $name.Substring(0, 64) }
    return $name
}

function Get-DeploymentState {
    # Returns the provisioningState of an existing deployment, or $null if it does not exist.
    param([string]$DeploymentName)
    $url = $serverUrl + "/subscriptions/$SubscriptionId/resourcegroups/$ResourceGroup/providers/Microsoft.Resources/deployments/$DeploymentName" + "?api-version=2021-04-01"
    try {
        $d = Invoke-RestMethod -Method "Get" -Uri $url -Headers $authHeader
        return $d.properties.provisioningState
    } catch {
        return $null
    }
}

function Wait-Deployment {
    param([string]$DeploymentName, [int]$TimeoutMinutes)
    if ($TimeoutMinutes -le 0) { return "NotWaited" }
    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    do {
        $state = Get-DeploymentState -DeploymentName $DeploymentName
        if ($state -in @("Succeeded", "Failed", "Canceled")) { return $state }
        Start-Sleep -Seconds 15
    } while ((Get-Date) -lt $deadline)
    return "TimedOut"
}

# ----------------------------------------------------------------- catalog (retry until populated)

# Right after Sentinel onboarding the Content Hub catalog can still be filling in, so retry until the
# desired display names resolve or the timeout is hit; a partial catalog would silently skip solutions.
$catalogUrl = $baseUri + "/providers/Microsoft.SecurityInsights/contentProductPackages?api-version=2024-03-01"
$catalogDeadline = (Get-Date).AddMinutes($CatalogTimeoutMinutes)
$allSolutions = @()
do {
    try {
        $allSolutions = (Invoke-RestMethod -Method "Get" -Uri $catalogUrl -Headers $authHeader).value
    } catch {
        $allSolutions = @()
    }
    $names = $allSolutions.properties.displayName
    $missingFromCatalog = @($Solutions | Where-Object { $_ -notin $names })
    if ($missingFromCatalog.Count -eq 0) { break }
    Write-Output "Catalog still populating; $($missingFromCatalog.Count) solution(s) not yet listed. Retrying..."
    Start-Sleep -Seconds 15
} while ((Get-Date) -lt $catalogDeadline)

if ($allSolutions.Count -eq 0) { throw "Content Hub catalog returned no packages for workspace '$Workspace'." }

# ----------------------------------------------------------------- backfill

$deployed = @(); $skipped = @(); $failed = @(); $notFound = @()

foreach ($deploySolution in $Solutions) {
    $singleSolution = $allSolutions | Where-Object { $_.properties.displayName -eq $deploySolution } | Select-Object -First 1
    if ($null -eq $singleSolution) {
        Write-Warning "[$deploySolution] not found in catalog; skipping."
        $notFound += $deploySolution
        continue
    }

    $deploymentName = Get-DeploymentName -ContentId $singleSolution.name
    $state = Get-DeploymentState -DeploymentName $deploymentName

    if ($state -eq "Succeeded") {
        Write-Output "[$deploySolution] already deployed (Succeeded); skipping."
        $skipped += $deploySolution
        continue
    }
    if ($state -in @("Running", "Accepted")) {
        Write-Output "[$deploySolution] LCA deployment still in flight ($state); leaving it to finish."
        $skipped += $deploySolution
        continue
    }

    Write-Output "[$deploySolution] deployment state '$([string]$state)'; backfilling..."
    try {
        $solutionURL = $baseUri + "/providers/Microsoft.SecurityInsights/contentProductPackages/$($singleSolution.name)?api-version=2024-03-01"
        $solution = Invoke-RestMethod -Method "Get" -Uri $solutionURL -Headers $authHeader
        $packagedContent = $solution.properties.packagedContent
        # Post-deployment instructions carry invalid characters and are shown nowhere; drop them.
        foreach ($resource in $packagedContent.resources) {
            if ($null -ne $resource.properties.mainTemplate.metadata.postDeployment) {
                $resource.properties.mainTemplate.metadata.postDeployment = $null
            }
        }
        $installBody = @{ "properties" = @{
                "parameters" = @{
                    "workspace"          = @{ "value" = $Workspace }
                    "workspace-location" = @{ "value" = $Region }
                }
                "template" = $packagedContent
                "mode"     = "Incremental"
            }
        }
        $installURL = $serverUrl + "/subscriptions/$SubscriptionId/resourcegroups/$ResourceGroup/providers/Microsoft.Resources/deployments/$deploymentName" + "?api-version=2021-04-01"
        Invoke-RestMethod -Uri $installURL -Method Put -Headers $authHeader -Body ($installBody | ConvertTo-Json -EnumsAsStrings -Depth 50 -EscapeHandling EscapeNonAscii) | Out-Null

        $result = Wait-Deployment -DeploymentName $deploymentName -TimeoutMinutes $DeployTimeoutMinutes
        if ($result -eq "Failed" -or $result -eq "Canceled") {
            Write-Warning "[$deploySolution] backfill deployment ended $result."
            $failed += $deploySolution
        } else {
            Write-Output "[$deploySolution] backfill submitted (final state: $result)."
            $deployed += $deploySolution
        }
    } catch {
        Write-Warning "[$deploySolution] $($_.Exception.Message)"
        $failed += $deploySolution
    }
}

# ----------------------------------------------------------------- summary

Write-Output "=== DeploySolutions backfill summary ==="
Write-Output "Deployed/backfilled : $($deployed.Count)  [$($deployed -join ', ')]"
Write-Output "Skipped (already ok): $($skipped.Count)"
Write-Output "Not in catalog      : $($notFound.Count)  [$($notFound -join ', ')]"
Write-Output "Failed              : $($failed.Count)  [$($failed -join ', ')]"

if ($failed.Count -gt 0) {
    throw "Backfill finished with $($failed.Count) failed solution deployment(s): $($failed -join ', ')"
}
