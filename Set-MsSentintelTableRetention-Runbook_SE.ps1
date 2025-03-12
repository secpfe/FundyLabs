#SETTINGS
$ResourceGroup = "CyberSOC"
$Workspace = "CyberSOCWS"
$TableNames = @("SecurityEvent")
$RetentionInDays = 90
$TotalRetentionInDays = 180
Start-Sleep -Seconds 120
$context = (Connect-AzAccount -Identity).context
$token = Get-AzAccessToken -ResourceUrl "https://management.azure.com/" -TenantId $context.Tenant.Id
$authHeader = @{
    'Content-Type'  = 'application/json'
    'Authorization' = 'Bearer ' + $token.Token
}
$SubscriptionId = $context.Subscription.Id

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

return $tables
