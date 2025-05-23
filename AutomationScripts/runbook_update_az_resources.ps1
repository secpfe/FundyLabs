#SETTINGS
$ResourceGroup = "CyberSOC"
$Workspace = "CyberSOCWS"
$RetentionInDays = 60

$context = (Connect-AzAccount -Identity).context
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
    Write-Output "Resource group '$resourceGroupName' not found." -ForegroundColor Red
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
        Invoke-RestMethod -Uri $baseUri -Method "Put" -Headers $AuthHeader -Body ($argHash  | ConvertTo-Json -EnumsAsStrings -Depth 50)
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
$ResourceGroup = "CyberSOC"
$Workspace = "CyberSOCWS"
$TableNames = @("AzureActivity","SecurityEvent")
$RetentionInDays = 90
$TotalRetentionInDays = 120

$argHash = @{}
$argHash.properties = @{
    retentionInDays         = "$RetentionInDays"
    totalRetentionInDays  = "$TotalRetentionInDays"
}

$tables = [System.Collections.Generic.List[PSObject]]::new()

foreach ($TableName in $TableNames) {
    $serverUrl = "https://management.azure.com"
    $baseUri = $serverUrl + "/subscriptions/${SubscriptionId}/resourceGroups/${ResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${Workspace}/Tables/${TableName}/?api-version=2023-09-01"

    try {
        Invoke-RestMethod -Uri $baseUri -Method "Put" -Headers $AuthHeader -Body ($argHash  | ConvertTo-Json -EnumsAsStrings -Depth 50)
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
    Invoke-RestMethod -Uri $baseUri -Method "Put" -Headers $AuthHeader -Body ($appsetting  | ConvertTo-Json -EnumsAsStrings -Depth 50)
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


