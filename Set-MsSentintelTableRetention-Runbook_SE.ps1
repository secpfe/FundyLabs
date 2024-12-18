#SETTINGS
$WorkspaceName = "CyberSOCWS"
$TableNames = @("SecurityEvent")
$RetentionInDays = 90
$TotalRetentionInDays = 180

try {
    Connect-AzAccount -Identity
}
catch {
    Write-Error "Failed to get or connect to Azure context: $_" -ErrorAction Stop
}

$workspace = Get-AzResource -Name $WorkspaceName -ResourceType 'Microsoft.OperationalInsights/workspaces'

$tables = [System.Collections.Generic.List[PSObject]]::new()

foreach ($TableName in $TableNames) {
    if ($null -ne $workspace) {
        $apiVersion = '?api-version=2023-09-01'
        $baseUri = '{0}/Tables/{1}' -f $workspace.ResourceId,$TableName
        $tablelistpath = '{0}/{1}' -f $baseUri,$apiVersion
        }
    else {
        Write-Error "Unable to to retrieve log analytics workspace with error code: $($_.Exception.Message)" -ErrorAction Stop
    }

    $argHash = @{}
    $argHash.properties = @{
        retentionInDays         = "$RetentionInDays"
        totalRetentionInDays  = "$TotalRetentionInDays"
    }

    try {
        $result = Invoke-AzRestMethod -Path $tablelistpath -Method PUT -Payload ($argHash | ConvertTo-Json)
        if ($result.StatusCode -ne 200) {
            Write-Error ($result | ConvertFrom-Json)
        }
    }
    catch {
        Write-Error "Unable to update the table with error code: $($_.Exception.Message)" -ErrorAction Stop
    }

    try {
        $webData = Invoke-AzRestMethod -Path $tablelistpath -Method GET 
        if ($webData.StatusCode -eq 200) {
            $webData = ($webData.Content | ConvertFrom-Json)
                $table = [PSCustomObject]@{
                    TableName = $webdata.name
                    RetentionInDays = $webdata.properties.retentionInDays
                    ArchiveRetentionInDays = $webdata.properties.archiveRetentionInDays
                    TotalRetentionInDays = $webdata.properties.totalRetentionInDays
            }
            $tables.Add($table)
        }
        else {
            Write-Error ($webData.Content | ConvertFrom-Json)
        }
    }
    catch {
        Write-Error "Unable to list the table with error code: $($_.Exception.Message)" -ErrorAction Stop
    }
}

return $tables
