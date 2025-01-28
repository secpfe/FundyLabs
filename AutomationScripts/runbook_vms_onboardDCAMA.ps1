param (
    [string]$location
)


Import-Module Az.Compute
Import-Module Az.Accounts
Connect-AzAccount -Identity

Set-AzVMExtension -ResourceGroupName "ITOperations" -VMName "dc" -Name "AzureMonitorWindowsAgent" -Publisher "Microsoft.Azure.Monitor" -ExtensionType "AzureMonitorWindowsAgent" -TypeHandlerVersion "1.0" -Location $location

Write-Output "Azure Monitor Agent deployed for VM 'DC'." 
