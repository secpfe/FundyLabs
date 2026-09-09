Import-Module Az.Compute
Import-Module Az.Accounts
Import-Module Az.Monitor

Connect-AzAccount -Identity

$resourceGroupName = (Get-AzResourceGroup | Where-Object { $_.ResourceGroupName -like '*CyberSOC*' } | Select-Object -First 1).ResourceGroupName
if (-not $resourceGroupName) { throw "CyberSOC resource group not found." }
$resourceGroupNameOps = (Get-AzResourceGroup | Where-Object { $_.ResourceGroupName -like '*ITOperations*' } | Select-Object -First 1).ResourceGroupName
if (-not $resourceGroupNameOps) { throw "ITOperations resource group not found." }
$web01Name = "web01"
$vmNames = @("mserv", "win10")

# Get the resource group location
$resourceGroup = Get-AzResourceGroup -Name $resourceGroupName
$location = $resourceGroup.Location

# Deploy Azure Monitor Agent to the Linux VM
Set-AzVMExtension -ResourceGroupName $resourceGroupNameOps -VMName $web01Name -Name "AzureMonitorLinuxAgent" -Publisher "Microsoft.Azure.Monitor"     -ExtensionType "AzureMonitorLinuxAgent"  -TypeHandlerVersion "1.0"  -Location $location
Write-Output "Azure Monitor Agent deployed for VM '$web01Name'." 


foreach ($vmName in $vmNames) {
    # Enable the Azure Monitor extension for Windows VMs
    Set-AzVMExtension -ResourceGroupName $resourceGroupNameOps `
        -VMName $vmName `
        -Name "AzureMonitorWindowsAgent" `
        -Publisher "Microsoft.Azure.Monitor" `
        -ExtensionType "AzureMonitorWindowsAgent" `
        -TypeHandlerVersion "1.0" `
        -Location $location

    Write-Output "Azure Monitor Agent deployed for VM '$vmName'." 
}
