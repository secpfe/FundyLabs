param (
    [string]$workspaceName = "CyberSOCWS"
)

Write-Output "=== Script started ==="
Write-Output "Parameter workspaceName: $workspaceName"

#SETTINGS
$ResourceGroup = "CyberSOC"
$RetentionInDays = 60

Write-Output "Connecting to Azure..."
$context = (Connect-AzAccount -Identity).context
Write-Output "Connected successfully. Subscription: $($context.Subscription.Id)"

Write-Output "Looking for workspace '$workspaceName' in resource group '$ResourceGroup'..."
# Try to get workspace with provided/default name, fallback to discovery if not found
try {
    $workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroup -Name $workspaceName -ErrorAction Stop
    $Workspace = $workspace.Name
    Write-Output "Found workspace: $Workspace"
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
$resourceGroup = Get-AzResourceGroup -Name $resourceGroupName
if (!$resourceGroup) {
    Write-Output "Resource group '$resourceGroupName' not found." -ForegroundColor Red
    exit
}

# Ensure $ResourceGroup stays as string
$ResourceGroup = $resourceGroupName
$location = $resourceGroup.Location

    $argHash = @{
        location = $location 
        properties = @{
            retentionInDays = $RetentionInDays
        }
    }

    try {
        Write-Output "Updating workspace retention..."
        Invoke-RestMethod -Uri $baseUri -Method "Put" -Headers $authHeader -Body ($argHash  | ConvertTo-Json -EnumsAsStrings -Depth 50)
        Write-Output "Workspace updated successfully"
    }
    catch {
        Write-Error "Unable to update the workspace properties with error code: $($_.Exception.Message)" -ErrorAction Stop
    }

    try {
        $webData = Invoke-RestMethod -Method "Get" -Uri $baseUri -Headers $authHeader
        # Preserve Workspace name as string before overwriting workspace variable
        $Workspace = $webData.name
        $workspace = [PSCustomObject]@{
            WorkspaceName = $webData.name
            RetentionInDays = $webData.properties.retentionInDays
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

Write-Output "=== Starting table retention updates ==="
Write-Output "ResourceGroup: $ResourceGroup"
Write-Output "Workspace: $Workspace"
Write-Output "SubscriptionId: $SubscriptionId"
Write-Output "Location: $location"
Write-Output "Tables to update: $($TableNames -join ', ')"

$argHash = @{}
$argHash.properties = @{
    retentionInDays         = "$RetentionInDays"
    totalRetentionInDays  = "$TotalRetentionInDays"
}

Write-Output "Table retention settings - RetentionInDays: $RetentionInDays, TotalRetentionInDays: $TotalRetentionInDays"
Write-Output "Request body: $($argHash | ConvertTo-Json -EnumsAsStrings -Depth 50)"

$tables = [System.Collections.Generic.List[PSObject]]::new()

foreach ($TableName in $TableNames) {
    Write-Output "--- Processing table: $TableName ---"
    $serverUrl = "https://management.azure.com"
    $baseUri = $serverUrl + "/subscriptions/${SubscriptionId}/resourceGroups/${ResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${Workspace}/Tables/${TableName}/?api-version=2023-09-01"
    
    Write-Output "Table URI: $baseUri"
    Write-Output "Attempting to update table: $TableName"

    try {
        $updateBody = $argHash | ConvertTo-Json -EnumsAsStrings -Depth 50
        Write-Output "PUT request body: $updateBody"
        Write-Output "Sending PUT request to update table..."
        $result = Invoke-RestMethod -Uri $baseUri -Method "Put" -Headers $authHeader -Body $updateBody
        Write-Output "Successfully sent PUT request for table: $TableName"
        Write-Output "PUT response: $($result | ConvertTo-Json -Depth 5)"
        }
    catch {
        $errorDetails = $_.Exception.Message
        Write-Output "ERROR: Failed to update table '$TableName'"
        Write-Output "Error Message: $errorDetails"
        if ($_.Exception.Response) {
            Write-Output "HTTP Status Code: $($_.Exception.Response.StatusCode.value__)"
            try {
                $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                $responseBody = $reader.ReadToEnd()
                Write-Output "Response Body: $responseBody"
            } catch {
                Write-Output "Could not read response body"
            }
        }
        if ($_.ErrorDetails.Message) {
            Write-Output "Error Details: $($_.ErrorDetails.Message)"
        }
        Write-Error "Unable to update the table '$TableName' with error code: $errorDetails" -ErrorAction Stop
    }

    Write-Output "Attempting to retrieve updated table information: $TableName"
    try {
        Write-Output "Sending GET request to retrieve table details..."
        $webData = Invoke-RestMethod -Method "Get" -Uri $baseUri -Headers $authHeader
        Write-Output "Successfully retrieved table information for: $TableName"
        Write-Output "Table Name: $($webData.name)"
        Write-Output "RetentionInDays: $($webData.properties.retentionInDays)"
        Write-Output "TotalRetentionInDays: $($webData.properties.totalRetentionInDays)"
        
        $table = [PSCustomObject]@{
            WorkspaceName = $webdata.name
            RetentionInDays = $webdata.properties.retentionInDays
            ArchiveRetentionInDays = $webData.properties.archiveRetentionInDays
            TotalRetentionInDays = $webData.properties.totalRetentionInDays
        }
        $tables.Add($table)
        Write-Output "Successfully processed table: $TableName"
    }
    catch {
        $errorDetails = $_.Exception.Message
        Write-Output "ERROR: Failed to retrieve table '$TableName' information"
        Write-Output "Error Message: $errorDetails"
        if ($_.Exception.Response) {
            Write-Output "HTTP Status Code: $($_.Exception.Response.StatusCode.value__)"
        }
        Write-Error "Unable to list the table '$TableName' with error code: $errorDetails" -ErrorAction Stop
    }

    Write-Output "--- Finished processing table: $TableName ---"
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