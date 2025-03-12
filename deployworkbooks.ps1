#SETTINGS
$ResourceGroup = "CyberSOC"
$Workspace = "CyberSOCWS"
Start-Sleep -Seconds 120
$context = (Connect-AzAccount -Identity).context
$token = Get-AzAccessToken -ResourceUrl "https://management.azure.com/" -TenantId $context.Tenant.Id
$authHeader = @{
    'Content-Type'  = 'application/json'
    'Authorization' = 'Bearer ' + $token.Token
}
$SubscriptionId = $context.Subscription.Id
$serverUrl = "https://management.azure.com"
$baseUri = $serverUrl + "/subscriptions/${SubscriptionId}/resourceGroups/${ResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${Workspace}"


## RETIREVE ALL SOLUTIONS ($allSolutions)
$packagesUrl = $baseUri + "/providers/Microsoft.SecurityInsights/contentProductPackages?api-version=2023-04-01-preview"
$allSolutions = (Invoke-RestMethod -Method "Get" -Uri $packagesUrl -Headers $authHeader ).value

## RETIREVE ALL WORKBOOKS TEMPLATES ($allTemplates)
$templatesUrl = $baseUri + "/providers/Microsoft.SecurityInsights/contentTemplates?api-version=2023-05-01-preview&%24filter=(properties%2FcontentKind%20eq%20'Workbook')"
$allTemplates = (Invoke-RestMethod -Uri $templatesUrl -Method Get -Headers $authHeader).value

# for each template:
# 1. deploy it
# 2. link it to the relevant solution
foreach ($template in $allTemplates ) {
    # Search for the solution containing the Template
    $solution = $allSolutions.properties | Where-Object -Property "contentId" -Contains $template.properties.packageId
    
    # ========================
    # Create the workbook
    # ========================
    $body = @{
        "location" = "westeurope"
        "kind" = "shared"
        "properties" = @{
            "displayName" = $template.properties.displayName
            "serializedData" = $template.properties.MainTemplate.resources.properties.serializedData
            "category" = "sentinel"
            "description" = $template.properties.MainTemplate.resources.properties.description
            "sourceId" = "/subscriptions/${SubscriptionId}/resourcegroups/${ResourceGroup}/providers/microsoft.operationalinsights/workspaces/${Workspace}"
        }
    }
    $jsonbody = $body | ConvertTo-Json -Depth 1
    
    $workbookName = New-Guid
    $WorkbookUrl = "https://management.azure.com/subscriptions/${SubscriptionId}/resourceGroups/${ResourceGroup}/providers/Microsoft.Insights/workbooks/${workbookName}?api-version=2021-08-01"
    $workbook = (Invoke-RestMethod -Uri $WorkbookUrl -Method Put -Headers $authHeader -Body $jsonbody)

    
    # ========================
    # Link the workbook the the solution 
    # ========================
    $metabody = @{
        "type" = "Microsoft.SecurityInsights/metadata"
        "properties" = @{
            "contentId" = $template.properties.mainTemplate.resources[0].name
            "parentId"  = $workbook.id
            "kind"      = "Workbook"
            "version"   = $template.properties.mainTemplate.resources.properties[1].version
            "source"    = $solution.source
            "author"    = $solution.author
            "support"   = $solution.support
        }
    }
    $metabodyJson = $metabody | ConvertTo-Json -Depth 10

    $SubscriptionId = $context.Subscription.Id
    $serverUrl = "https://management.azure.com"
    $baseUri = $serverUrl + "/subscriptions/${SubscriptionId}/resourceGroups/${ResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${Workspace}"
    $baseMetaURI = $BaseUri + "/providers/Microsoft.SecurityInsights/metadata/${workbookName}?api-version=2024-09-01"
    
    Invoke-RestMethod -Uri $baseMetaURI -Method Put -Headers $authHeader -Body $metabodyJson
    
}
