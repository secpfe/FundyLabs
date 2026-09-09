param (
    [string]$location
)


Import-Module Az.Compute
Import-Module Az.Accounts
Connect-AzAccount -Identity

$resourceGroupNameOps = (Get-AzResourceGroup | Where-Object { $_.ResourceGroupName -like '*ITOperations*' } | Select-Object -First 1).ResourceGroupName
if (-not $resourceGroupNameOps) { throw "ITOperations resource group not found." }

Set-AzVMExtension -ResourceGroupName $resourceGroupNameOps -VMName "dc" -Name "AzureMonitorWindowsAgent" -Publisher "Microsoft.Azure.Monitor" -ExtensionType "AzureMonitorWindowsAgent" -TypeHandlerVersion "1.0" -Location $location

Write-Output "Azure Monitor Agent deployed for VM 'DC'." 
