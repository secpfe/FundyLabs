#SETTINGS
$ResourceGroup = "ITOperations"
$WebAppName = "myVulWebApp"
$Command = "mv /home/site/wwwroot/config.ini /home/site/"

$context = (Connect-AzAccount).context
# $context = (Connect-AzAccount -Identity).context
$token = Get-AzAccessToken -ResourceUrl "https://management.azure.com/" -TenantId $context.Tenant.Id
$authHeader = @{
    'Content-Type'  = 'application/json'
    'Authorization' = 'Bearer ' + $token.Token
}
$SubscriptionId = $context.Subscription.Id
$serverUrl = "https://management.azure.com"
$baseUri = $serverUrl + "/subscriptions/${SubscriptionId}/resourceGroups/${ResourceGroup}/providers/Microsoft.Web/sites/${WebAppName}/config/web?api-version=2024-04-01"

#Invoke-RestMethod -Method "Get" -Uri $baseUri -Headers $authHeader

$appsetting = @{
    properties = @{
        appCommandLine="$Command"
    }
}

try {
    Invoke-RestMethod -Uri $baseUri -Method "Put" -Headers $AuthHeader -Body ($appsetting  | ConvertTo-Json -EnumsAsStrings -Depth 50)
    }
catch {
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
    Write-Error "Unable to list the webapp properties with error code: $($_.Exception.Message)" -ErrorAction Stop
}

return $webapp
