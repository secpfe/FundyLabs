param (
    [string]$workspaceName = "CyberSOCWS"
)

Write-Output "=== Script started ==="
Write-Output "Parameter workspaceName: $workspaceName"

#SETTINGS
$ResourceGroup = (Get-AzResourceGroup | Where-Object { $_.ResourceGroupName -like '*CyberSOC*' } | Select-Object -First 1).ResourceGroupName
if (-not $ResourceGroup) { throw "CyberSOC resource group not found." }
$RetentionInDays = 60

Write-Output "Connecting to Azure..."
$context = (Connect-AzAccount -Identity).context
Write-Output "Connected successfully. Subscription: $($context.Subscription.Id)"

Write-Output "Looking for workspace '$workspaceName' in resource group '$ResourceGroup'..."
# Try to get workspace with provided/default name, fallback to discovery if not found
try {
    $workspaceObj = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroup -Name $workspaceName -ErrorAction Stop
    $Workspace = $workspaceObj.Name
    $location = $workspaceObj.Location  # Save location from workspace object
    Write-Output "Found workspace: $Workspace"
} catch {
    # Workspace with provided name not found, discover dynamically
    Write-Output "Workspace '$workspaceName' not found, discovering workspace from resource group..."
    $workspaceObj = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroup | Select-Object -First 1
    if (-not $workspaceObj) {
        throw "No Log Analytics workspace found in resource group $ResourceGroup"
    }
    $Workspace = $workspaceObj.Name
    $location = $workspaceObj.Location  # Save location from workspace object
    Write-Output "Discovered workspace: $Workspace"
}

Write-Output "Getting access token..."
$token = Get-AzAccessToken -ResourceUrl "https://management.azure.com/" -TenantId $context.Tenant.Id
$authHeader = @{
    'Content-Type'  = 'application/json'
    'Authorization' = 'Bearer ' + $token.Token
}
Write-Output "Access token obtained"

$SubscriptionId = $context.Subscription.Id
$serverUrl = "https://management.azure.com"
$baseUri = $serverUrl + "/subscriptions/${SubscriptionId}/resourceGroups/${ResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${Workspace}?api-version=2023-09-01"

# Get the resource group location
$resourceGroupName = $ResourceGroup  # Save as string first
$resourceGroupObj = Get-AzResourceGroup -Name $resourceGroupName
if (!$resourceGroupObj) {
    Write-Output "Resource group '$resourceGroupName' not found." -ForegroundColor Red
    exit
}

# Ensure $ResourceGroup stays as string
$ResourceGroup = $resourceGroupName

# Location already saved above from workspace object
# If location is still not set, try resource group as fallback
if (!$location) {
    Write-Output "Warning: Workspace location not found, trying resource group location..."
    $location = $resourceGroupObj.Location
}
Write-Output "Using location: $location"

$argHash = @{
    location = $location 
    properties = @{
        retentionInDays = $RetentionInDays
    }
}

try {
    Write-Output "Updating workspace retention to $RetentionInDays days..."
    $updateBody = $argHash | ConvertTo-Json -EnumsAsStrings -Depth 50
    Invoke-RestMethod -Uri $baseUri -Method "Put" -Headers $authHeader -Body $updateBody
    Write-Output "Workspace retention updated successfully"
}
catch {
    Write-Output "ERROR: Failed to update workspace - $($_.Exception.Message)"
    Write-Error "Unable to update the workspace properties with error code: $($_.Exception.Message)" -ErrorAction Stop
}

try {
    $webData = Invoke-RestMethod -Method "Get" -Uri $baseUri -Headers $authHeader
    # Preserve Workspace name as string
    $Workspace = $webData.name
    $workspaceResult = [PSCustomObject]@{
        WorkspaceName = $webData.name
        RetentionInDays = $webData.properties.retentionInDays
    }
}
catch {
    Write-Output "ERROR: Failed to retrieve workspace properties - $($_.Exception.Message)"
    Write-Error "Unable to list the workspace properties with error code: $($_.Exception.Message)" -ErrorAction Stop
}

Write-Output $workspaceResult

#SETTINGS
# $ResourceGroup and $Workspace already set above
$TableNames = @("AzureActivity","SecurityEvent")
$RetentionInDays = 90
$TotalRetentionInDays = 120

Write-Output "=== Starting table retention updates ==="
Write-Output "Updating tables: $($TableNames -join ', ') with RetentionInDays: $RetentionInDays, TotalRetentionInDays: $TotalRetentionInDays"

$argHash = @{}
$argHash.properties = @{
    retentionInDays         = "$RetentionInDays"
    totalRetentionInDays  = "$TotalRetentionInDays"
}

$tables = [System.Collections.Generic.List[PSObject]]::new()

foreach ($TableName in $TableNames) {
    Write-Output "Updating table: $TableName..."
    $serverUrl = "https://management.azure.com"
    $baseUri = $serverUrl + "/subscriptions/${SubscriptionId}/resourceGroups/${ResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${Workspace}/Tables/${TableName}/?api-version=2023-09-01"

    try {
        $updateBody = $argHash | ConvertTo-Json -EnumsAsStrings -Depth 50
        Invoke-RestMethod -Uri $baseUri -Method "Put" -Headers $authHeader -Body $updateBody
        Write-Output "Table $TableName updated successfully"
    }
    catch {
        Write-Output "ERROR: Failed to update table '$TableName' - $($_.Exception.Message)"
        Write-Error "Unable to update the table '$TableName' with error code: $($_.Exception.Message)" -ErrorAction Stop
    }

    try {
        $webData = Invoke-RestMethod -Method "Get" -Uri $baseUri -Headers $authHeader
        $table = [PSCustomObject]@{
            WorkspaceName = $webData.name
            RetentionInDays = $webData.properties.retentionInDays
            ArchiveRetentionInDays = $webData.properties.archiveRetentionInDays
            TotalRetentionInDays = $webData.properties.totalRetentionInDays
        }
        $tables.Add($table)
    }
    catch {
        Write-Output "ERROR: Failed to retrieve table '$TableName' information - $($_.Exception.Message)"
        Write-Error "Unable to list the table '$TableName' with error code: $($_.Exception.Message)" -ErrorAction Stop
    }
}

Write-Output $tables


#SETTINGS
Write-Output "=== Starting webApp configuration update ==="
$ResourceGroup = (Get-AzResourceGroup | Where-Object { $_.ResourceGroupName -like '*ITOperations*' } | Select-Object -First 1).ResourceGroupName
if (-not $ResourceGroup) { throw "ITOperations resource group not found." }
$Command = "mv /home/site/wwwroot/config.ini /home/site/"

Write-Output "Waiting 120 seconds before webApp update..."
Start-Sleep -Seconds 120

Write-Output "Getting webApp from resource group: $ResourceGroup"
$WebAppName = (Get-AzWebApp -ResourceGroupName $ResourceGroup).Name
Write-Output "Found webApp: $WebAppName"

$serverUrl = "https://management.azure.com"
$baseUri = $serverUrl + "/subscriptions/${SubscriptionId}/resourceGroups/${ResourceGroup}/providers/Microsoft.Web/sites/${WebAppName}/config/web?api-version=2024-04-01"

$appsetting = @{
    properties = @{
        appCommandLine="$Command"
    }
}

Write-Output "Updating webApp startup command..."
try {
    Invoke-RestMethod -Uri $baseUri -Method "Put" -Headers $authHeader -Body ($appsetting  | ConvertTo-Json -EnumsAsStrings -Depth 50)
    Write-Output "WebApp startup command updated successfully"
}
catch {
    Write-Output "ERROR: Failed to update webApp - $($_.Exception.Message)"
    Write-Error "Unable to update the webapp with error code: $($_.Exception.Message)" -ErrorAction Stop
}

Write-Output "Retrieving updated webApp configuration..."
try {
    $webData = Invoke-RestMethod -Method "Get" -Uri $baseUri -Headers $authHeader
    $webapp = [PSCustomObject]@{
        WebAppName = $webData.name
        WebAppNameStartupcommand = $webData.properties.appCommandLine
    }
    Write-Output "WebApp configuration retrieved successfully"
    Write-Output "WebApp: $($webapp.WebAppName), Startup Command: $($webapp.WebAppNameStartupcommand)"
}
catch {
    Write-Output "ERROR: Failed to retrieve webApp properties - $($_.Exception.Message)"
    Write-Error "Unable to list the webapp properties with error code: $($_.Exception.Message)" -ErrorAction Stop
}

return $webapp
