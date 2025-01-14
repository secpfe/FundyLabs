#SETTINGS
$ResourceGroup = "CyberSOC"
$Workspace = "CyberSOCWS"

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

## RETIREVE ALL ANALYTICS RULE TEMPLATES ($allTemplates)
$templatesUrl = $baseUri + "/providers/Microsoft.SecurityInsights/contentTemplates?api-version=2023-05-01-preview&%24filter=(properties%2FcontentKind%20eq%20'AnalyticsRule')"
$allTemplates = (Invoke-RestMethod -Uri $templatesUrl -Method Get -Headers $authHeader).value

# for each template:
# 1. deploy it
# 2. link it to the relevant solution
foreach ($template in $allTemplates ) {
    # Search for the solution containing the Template
    $solution = $allSolutions.properties | Where-Object -Property "contentId" -Contains $template.properties.packageId
    
    # ========================
    # Create the analytics rule
    # ========================
    
    $BaseAlertUri = $BaseUri + "/providers/Microsoft.SecurityInsights/alertRules/"
    $kind = $template.properties.mainTemplate.resources.kind
    $displayName = $template.properties.mainTemplate.resources.properties[0].displayName

    $eventGroupingSettings = $template.properties.mainTemplate.resources.properties[0].eventGroupingSettings
    if ($null -eq $eventGroupingSettings) {
        $eventGroupingSettings = [ordered]@{aggregationKind = "SingleAlert" }
    }
    $body = ""
    $properties = $template.properties.mainTemplate.resources[0].properties
    $properties.enabled = $true
    
    #Add the field to link this rule with the rule template so that the rule template will show up as used
    #We had to use the "Add-Member" command since this field does not exist in the rule template that we are copying from.
    $properties | Add-Member -NotePropertyName "alertRuleTemplateName" -NotePropertyValue $template.properties.mainTemplate.resources[0].name
    $properties | Add-Member -NotePropertyName "templateVersion" -NotePropertyValue $template.properties.mainTemplate.resources[1].properties.version

    #Depending on the type of alert we are creating, the body has different parameters
    switch ($kind) {
        "MicrosoftSecurityIncidentCreation" {  
            $body = @{
                "kind"       = "MicrosoftSecurityIncidentCreation"
                "properties" = $properties
            }
        }
        "NRT" {
            $body = @{
                "kind"       = "NRT"
                "properties" = $properties
            }
        }
        "Scheduled" {
            $body = @{
                "kind"       = "Scheduled"
                "properties" = $properties
            }
            
        }
        Default { }
    }

    #If we have created the body...
    if ("" -ne $body) {
        #Create the GUId for the alert and create it.
        $guid = (New-Guid).Guid
        #Create the URI we need to create the alert.
        $alertUri = $BaseAlertUri + $guid + "?api-version=2022-12-01-preview"
        try {
            Write-Verbose -Message "Template: $displayName - Creating the rule...."
            $rule = Invoke-RestMethod -Uri $alertUri -Method Put -Headers $AuthHeader -Body ($body | ConvertTo-Json -EnumsAsStrings -Depth 50)
                #This pauses for 1 second so that we don't overload the workspace.
                Start-Sleep -Seconds 1
            
        }
        catch {
            Write-Host -Message "Template: $displayName - ERROR while creating the rule" -ForegroundColor Red
            break
        }
    }


    # ========================
    # Link the analytic rule to the solution 
    # ========================

    $baseMetaURI = $BaseUri + "/providers/Microsoft.SecurityInsights/metadata/analyticsrule-"

    $metabody = @{
        "apiVersion" = "2023-02-01"
        "name"       = "analyticsrule-" + $Rule.name
        "type"       = "Microsoft.OperationalInsights/workspaces/providers/metadata"
        "id"         = $null
        "properties" = @{
            "contentId" = $template.properties.mainTemplate.resources[0].name
            "parentId"  = $rule.id
            "kind"      = "AnalyticsRule"
            "version"   = $template.properties.mainTemplate.resources.properties[1].version
            "source"    = $solution.source
            "author"    = $solution.author
            "support"   = $solution.support
        }
    }
    $metaURI = $baseMetaURI + $rule.name + "?api-version=2023-02-01"
    Invoke-RestMethod -Uri $metaURI -Method Put -Headers $AuthHeader -Body ($metabody | ConvertTo-Json -EnumsAsStrings -Depth 5)
}


# Define the ARM template for PowerShellDownload custom analytics rule
$analyticsRuleTemplate = @"
{
    "`$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
        "workspace": {
            "type": "String"
        }
    },
    "resources": [
        {
            "id": "[concat(resourceId('Microsoft.OperationalInsights/workspaces/providers', parameters('workspace'), 'Microsoft.SecurityInsights'),'/alertRules/7afdc0da-a34c-44fa-8567-5b30fa5901c1')]",
            "name": "[concat(parameters('workspace'),'/Microsoft.SecurityInsights/7afdc0da-a34c-44fa-8567-5b30fa5901c1')]",
            "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
            "kind": "Scheduled",
            "apiVersion": "2023-12-01-preview",
            "properties": {
                "displayName": "PowerShell was used to download executable files or scripts",
                "description": "",
                "severity": "Medium",
                "enabled": true,
                "query": "let PowerShellEvents = SecurityEvent\n | where SystemUserId!='S-1-5-18' \n  | where EventID == 4104 \n| where EventData has_all (\"Invoke-WebRequest\", \"-OutFile\")\n    | where EventData has_any (\".ps1\", \".exe\", \".msi\", \".bat\", \".vbs\", \".dll\", \".zip\", \".jar\")\n    | project TimeGenerated, Computer, SystemUserId, EventData;\nlet LogonEvents = SecurityEvent\n  | where TimeGenerated>ago(1d) \n  | where EventID == 4624\n    | project Computer, TargetUserSid, TargetUserName;\nPowerShellEvents\n| join kind=leftouter LogonEvents on `$left.SystemUserId == `$right.TargetUserSid \n| distinct TimeGenerated, Computer, Account = TargetUserName, EventData",
                "queryFrequency": "PT15M",
                "queryPeriod": "PT15M",
                "triggerOperator": "GreaterThan",
                "triggerThreshold": 0,
                "suppressionDuration": "PT5H",
                "suppressionEnabled": false,
                "startTimeUtc": null,
                "tactics": [
                    "Execution"
                ],
                "techniques": [
                    "T1059"
                ],
                "subTechniques": [
                    "T1059.001"
                ],
                "alertRuleTemplateName": null,
                "incidentConfiguration": {
                    "createIncident": true,
                    "groupingConfiguration": {
                        "enabled": true,
                        "reopenClosedIncident": false,
                        "lookbackDuration": "PT5H",
                        "matchingMethod": "AllEntities",
                        "groupByEntities": [],
                        "groupByAlertDetails": [],
                        "groupByCustomDetails": []
                    }
                },
                "eventGroupingSettings": {
                    "aggregationKind": "SingleAlert"
                },
                "alertDetailsOverride": null,
                "customDetails": null,
                "entityMappings": [
                    {
                        "entityType": "Account",
                        "fieldMappings": [
                            {
                                "identifier": "Name",
                                "columnName": "Account"
                            }
                        ]
                    },
                    {
                        "entityType": "Host",
                        "fieldMappings": [
                            {
                                "identifier": "HostName",
                                "columnName": "Computer"
                            }
                        ]
                    }
                ],
                "sentinelEntitiesMappings": null,
                "templateVersion": null
            }
        }
    ]
}
"@

# Convert the template string to a JSON object
$templateObject = $analyticsRuleTemplate | ConvertFrom-Json

# Prepare the parameters by injecting the workspace name
$deploymentParameters = @{
    "workspace" = @{
        "value" = $Workspace
    }
} | ConvertTo-Json -Depth 10

# Define the deployment body with mode, template, and parameters
$deploymentBody = @{
    "properties" = @{
        "mode" = "Incremental"
        "template" = $templateObject
        "parameters" = ($deploymentParameters | ConvertFrom-Json)
    }
} | ConvertTo-Json -Depth 100

#Write-OutPut $deploymentBody

# Define a unique deployment name
$deploymentName = "DeployPowershellDownloadDetection"

# Construct the deployment URI using subscription and resource group details
$deploymentUri = "$serverUrl/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Resources/deployments/$deploymentName`?api-version=2021-04-01"
#Write-OutPut $deploymentUri

# Execute the deployment with error handling
try {
    Write-Verbose "Deploying PowershellDownload analytics rule..."
    Invoke-RestMethod -Method PUT -Uri $deploymentUri -Headers $authHeader -Body $deploymentBody
    Write-OutPut "✅ PowershellDownload analytics rule deployed successfully." 
}
catch {
    Write-OutPut "❌ Failed to deploy PowershellDownload analytics rule: $_" 
}
