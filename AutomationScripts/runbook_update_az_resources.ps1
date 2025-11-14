param (
    [string]$workspaceName = "CyberSOCWS"
)

#SETTINGS
$ResourceGroup = "CyberSOC"
$RetentionInDays = 60

$context = (Connect-AzAccount -Identity).context
# Try to get workspace with provided/default name, fallback to discovery if not found
try {
    $workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroup -Name $workspaceName -ErrorAction Stop
    $Workspace = $workspace.Name
} catch {
    # Workspace with provided name not found, discover dynamically
    Write-Output "Workspace '$workspaceName' not found, discovering workspace from resource group..."
    $workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroup | Select-Object -First 1
    if (-not $workspace) {
        throw "No Log Analytics workspace found in resource group $ResourceGroup"
    }
    $Workspace = $workspace.Name
    Write-Output "Discovered workspace: $Workspace"
}
$token = Get-AzAccessToken -ResourceUrl "https://management.azure.com/" -TenantId $context.Tenant.Id
$authHeader = @{
    'Content-Type'  = 'application/json'
    'Authorization' = 'Bearer ' + $token.Token
}

$SubscriptionId = $context.Subscription.Id
$serverUrl = "https://management.azure.com"
$baseUri = $serverUrl + "/subscriptions/${SubscriptionId}/resourceGroups/${ResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${Workspace}?api-version=2023-09-01"

# Get the resource group location
$resourceGroup = Get-AzResourceGroup -Name $ResourceGroup
if (!$resourceGroup) {
        Write-Output "Resource group '$ResourceGroup' not found." -ForegroundColor Red
    exit
}

$location = $resourceGroup.Location

    $argHash = @{
        location = $location 
        properties = @{
            retentionInDays = $RetentionInDays
        }
    }

    try {
        Invoke-RestMethod -Uri $baseUri -Method "Put" -Headers $authHeader -Body ($argHash  | ConvertTo-Json -EnumsAsStrings -Depth 50)
    }
    catch {
        Write-Error "Unable to update the workspace properties with error code: $($_.Exception.Message)" -ErrorAction Stop
    }

    try {
        $webData = Invoke-RestMethod -Method "Get" -Uri $baseUri -Headers $authHeader
                $workspace = [PSCustomObject]@{
                    WorkspaceName = $webdata.name
                    RetentionInDays = $webdata.properties.retentionInDays
            }
    }
    catch {
        Write-Output "Unable to list the workspace properties with error code: $($_.Exception.Message)" 
        Write-Error "Unable to list the workspace properties with error code: $($_.Exception.Message)" -ErrorAction Stop
    }

Write-Output $workspace

#SETTINGS
# $ResourceGroup and $Workspace already set above
$TableNames = @("AzureActivity","SecurityEvent")
$RetentionInDays = 90
$TotalRetentionInDays = 120

# Ensure $Workspace is set - use workspaceName parameter if available, otherwise use discovered value
if (-not $Workspace -and $workspaceName) {
    $Workspace = $workspaceName
    Write-Output "Using workspaceName parameter for tables: $Workspace"
}

Write-Output "Updating tables in workspace: $Workspace"

$tables = [System.Collections.Generic.List[PSObject]]::new()

foreach ($TableName in $TableNames) {
    $serverUrl = "https://management.azure.com"
    # Use same API version as workspace update
    $baseUri = $serverUrl + "/subscriptions/${SubscriptionId}/resourceGroups/${ResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${Workspace}/Tables/${TableName}?api-version=2023-09-01"
    Write-Output "Updating table: $TableName with URI: $baseUri"

    $argHash = @{
        location = $location
        properties = @{
            retentionInDays         = $RetentionInDays
            totalRetentionInDays    = $TotalRetentionInDays
        }
    }

    try {
        Invoke-RestMethod -Uri $baseUri -Method "Put" -Headers $authHeader -Body ($argHash  | ConvertTo-Json -EnumsAsStrings -Depth 50)
        }
    catch {
        Write-Error "Unable to update the table with error code: $($_.Exception.Message)" -ErrorAction Stop
    }

    try {
        $webData = Invoke-RestMethod -Method "Get" -Uri $baseUri -Headers $authHeader
                $table = [PSCustomObject]@{
                    WorkspaceName = $webdata.name
                    RetentionInDays = $webdata.properties.retentionInDays
                    ArchiveRetentionInDays = $webData.properties.archiveRetentionInDays
                    TotalRetentionInDays = $webData.properties.totalRetentionInDays
            }
            $tables.Add($table)
    }
    catch {
        Write-Error "Unable to list the table with error code: $($_.Exception.Message)" -ErrorAction Stop
    }


}

Write-Output $tables


#SETTINGS
$ResourceGroup = "ITOperations"
$Command = "mv /home/site/wwwroot/config.ini /home/site/"
Start-Sleep -Seconds 120

$WebAppName = (Get-AzWebApp -ResourceGroupName $ResourceGroup).Name

$serverUrl = "https://management.azure.com"
$baseUri = $serverUrl + "/subscriptions/${SubscriptionId}/resourceGroups/${ResourceGroup}/providers/Microsoft.Web/sites/${WebAppName}/config/web?api-version=2024-04-01"

$appsetting = @{
    properties = @{
        appCommandLine="$Command"
    }
}

try {
    Invoke-RestMethod -Uri $baseUri -Method "Put" -Headers $authHeader -Body ($appsetting  | ConvertTo-Json -EnumsAsStrings -Depth 50)
    }
catch {
    Write-Output "Unable to update the webapp with error code: $($_.Exception.Message)" 
    Write-Error "Unable to update the webapp with error code: $($_.Exception.Message)" -ErrorAction Stop
}

try {
    $webData = Invoke-RestMethod -Method "Get" -Uri $baseUri -Headers $authHeader
            $webapp = [PSCustomObject]@{
                WebAppName = $webdata.name
                WebAppNameStartupcommand = $webdata.properties.appCommandLine
        }
}
catch {
    Write-Output "Unable to list the webapp properties with error code: $($_.Exception.Message)"
    Write-Error "Unable to list the webapp properties with error code: $($_.Exception.Message)" -ErrorAction Stop
}

return $webapp


