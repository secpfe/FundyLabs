# SETTINGS for Log Analytics Workspace and Tables
$ResourceGroup = "CyberSOC"
$Workspace = "CyberSOCWS"
$TableNames = @("AzureActivity", "SecurityEvent")

# Retention settings for the workspace
$WorkspaceRetentionInDays = 60

# Retention settings for tables
$TableRetentionInDays = 90
$TableTotalRetentionInDays = 120

# Get context and access token (used by all script sections)
$context = (Connect-AzAccount -Identity).context
$token = Get-AzAccessToken -ResourceUrl "https://management.azure.com/" -TenantId $context.Tenant.Id
$authHeader = @{
    'Content-Type'  = 'application/json'
    'Authorization' = 'Bearer ' + $token.Token
}
$SubscriptionId = $context.Subscription.Id
$serverUrl = "https://management.azure.com"

# Get the location of the resource group
$resourceGroup = Get-AzResourceGroup -Name $ResourceGroup
if (!$resourceGroup) {
    Write-Output "Resource group '$ResourceGroup' not found." -ForegroundColor Red
    exit
}
$location = $resourceGroup.Location

# Update retention for the workspace
$workspaceBaseUri = "$serverUrl/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$Workspace?api-version=2023-09-01"
$workspaceArgHash = @{
    location = $location 
    properties = @{
        retentionInDays = $WorkspaceRetentionInDays
    }
}

try {
    Invoke-RestMethod -Uri $workspaceBaseUri -Method "Put" -Headers $authHeader -Body ($workspaceArgHash | ConvertTo-Json -EnumsAsStrings -Depth 50)
}
catch {
    Write-Error "Unable to update the workspace properties with error code: $($_.Exception.Message)" -ErrorAction Stop
}

try {
    $webData = Invoke-RestMethod -Method "Get" -Uri $workspaceBaseUri -Headers $authHeader
    $workspace = [PSCustomObject]@{
        WorkspaceName = $webdata.name
        RetentionInDays = $webdata.properties.retentionInDays
    }
    Write-Output "Workspace settings applied: $($workspace | ConvertTo-Json)"
}
catch {
    Write-Error "Unable to list the workspace properties with error code: $($_.Exception.Message)" -ErrorAction Stop
}

# Update retention for each table
$tableArgHash = @{
    properties = @{
        retentionInDays = "$TableRetentionInDays"
        totalRetentionInDays = "$TableTotalRetentionInDays"
    }
}

$tables = [System.Collections.Generic.List[PSObject]]::new()

foreach ($TableName in $TableNames) {
    $tableUri = "$serverUrl/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$Workspace/Tables/$TableName/?api-version=2023-09-01"
    try {
        Invoke-RestMethod -Uri $tableUri -Method "Put" -Headers $authHeader -Body ($tableArgHash | ConvertTo-Json -EnumsAsStrings -Depth 50)
    }
    catch {
        Write-Error "Unable to update the table '$TableName' with error code: $($_.Exception.Message)" -ErrorAction Stop
    }

    try {
        $webData = Invoke-RestMethod -Method "Get" -Uri $tableUri -Headers $authHeader
        $table = [PSCustomObject]@{
            TableName = $webdata.name
            RetentionInDays = $webdata.properties.retentionInDays
            ArchiveRetentionInDays = $webData.properties.archiveRetentionInDays
            TotalRetentionInDays = $webData.properties.totalRetentionInDays
        }
        $tables.Add($table)
        Write-Output "Table '$TableName' settings applied: $($table | ConvertTo-Json)"
    }
    catch {
        Write-Error "Unable to list the table '$TableName' properties with error code: $($_.Exception.Message)" -ErrorAction Stop
    }
}

### Update appCommandLine for a WebApp 

# SETTINGS for WebApp
$WebAppResourceGroup = "ITOperations"
$Command = "mv /home/site/wwwroot/config.ini /home/site/"
Start-Sleep -Seconds 120

# Get the name of the first WebApp in the resource group
$WebAppName = (Get-AzWebApp -ResourceGroupName $WebAppResourceGroup | Select-Object -First 1).Name

$webappBaseUri = "$serverUrl/subscriptions/$SubscriptionId/resourceGroups/$WebAppResourceGroup/providers/Microsoft.Web/sites/$WebAppName/config/web?api-version=2024-04-01"

$appsetting = @{
    properties = @{
        appCommandLine = $Command
    }
}

try {
    Invoke-RestMethod -Uri $webappBaseUri -Method "Put" -Headers $authHeader -Body ($appsetting | ConvertTo-Json -EnumsAsStrings -Depth 50)
}
catch {
    Write-Error "Unable to update the webapp with error code: $($_.Exception.Message)" -ErrorAction Stop
}

try {
    $webData = Invoke-RestMethod -Method "Get" -Uri $webappBaseUri -Headers $authHeader
    $webapp = [PSCustomObject]@{
        WebAppName = $webdata.name
        WebAppStartupCommand = $webdata.properties.appCommandLine
    }
    Write-Output "WebApp settings applied: $($webapp | ConvertTo-Json)"
}
catch {
    Write-Error "Unable to list the webapp properties with error code: $($_.Exception.Message)" -ErrorAction Stop
}

