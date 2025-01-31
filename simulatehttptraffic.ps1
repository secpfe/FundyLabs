$context = (Connect-AzAccount -Identity).context
$token = Get-AzAccessToken -ResourceUrl "https://management.azure.com/" -TenantId $context.Tenant.Id
$authHeader = @{
    'Content-Type'  = 'application/json'
    'Authorization' = 'Bearer ' + $token.Token
}
$subscriptionId = $context.Subscription.Id

$resourceGroupName = "ITOperations"
$appServiceName = "ASP-CyberSOC-b341"
$apiVersion = "2024-04-01"

$url = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.Web/serverfarms/$appServiceName/sites?api-version=$apiVersion"

$token = (Get-AzAccessToken).Token

$response = Invoke-RestMethod -Uri $url -Method Get -Headers @{ Authorization = "Bearer $token" }

$baseUrl = "https://"+$response.value[0].properties.defaultHostName
$paths = @(
    "/index.php",
    "/",
    "/index.php?page=home",
    "/index.php?page=about",
    "/index.php?page=services",
    "/index.php?page=contact",
    "/?page=home",
    "/?page=about",
    "/?page=services",
    "/?page=contact",
    "/index.php?page=hom",
    "/index.php?page=abouts",
    "/index.php?page=service",
    "/index.php?page=contacts",
    "/?page=hom",
    "/?page=abouts",
    "/?page=service",
    "/?page=contacts",
    "/index.php?page=%252e%252e%252fphp.ini",
    "/index.php?page=%252e%252e%252fsettings.ini"
)

function Get-RandomUrl {
    $randomPath = Get-Random -InputObject $paths
    return "$baseUrl$randomPath"
}

$randomCount = Get-Random -Minimum 1 -Maximum 101

for ($i = 0; $i -lt $randomCount; $i++) {
    $url = Get-RandomUrl
    Invoke-WebRequest -Uri $url -Method GET
    Start-Sleep -Seconds 1
}
