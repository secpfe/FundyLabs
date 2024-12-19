# Variables
$ResourceGroup = "CyberSOC"
$Workspace = "CyberSOCWS"
$Region = "westeurope"


$context = (Connect-AzAccount -Identity).context
$token = (Get-AzAccessToken -ResourceUrl "https://management.azure.com/" -TenantId $context.Tenant.Id).Token
$authHeader = @{
    'Content-Type'  = 'application/json'
    'Authorization' = 'Bearer ' + $token.Token
}
$subscriptionId = $context.Subscription.Id



# API URL
$apiUrl = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/dataConnectors/73e01a99-5cd7-4139-a149-9f2736ff2ab5?api-version=2024-03-01"
            

# Request Body
$requestBody = @{
    kind = "MicrosoftCloudAppSecurity"
    properties = @{
        tenantId = $context.Subscription.TenantId
        dataTypes = @{
            alerts = @{
                state = "Disabled"
            }
            discoveryLogs = @{
                state = "Enabled"
            }
        }
    }
} | ConvertTo-Json -Depth 4

# Send API Request
$response = Invoke-RestMethod -Uri $apiUrl -Method Put -Headers @{ Authorization = "Bearer $token" } -ContentType "application/json" -Body $requestBody

if ($response -ne $null) {
    Write-Output "MCAS connector installation initiated successfully."
} else {
    Write-Output "Failed to initiate MCAS connector installation."
}
