#SETTINGS
$ResourceGroup = "CyberSOC"
$Workspace = "CyberSOCWS"
$RetentionInDays = 60

# $context = (Connect-AzAccount).context
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
        Write-Error "Unable to list the workspace properties with error code: $($_.Exception.Message)" -ErrorAction Stop
    }

return $workspace
