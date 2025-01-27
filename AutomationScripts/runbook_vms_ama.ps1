Import-Module Az.Compute
Import-Module Az.Accounts
Import-Module Az.Monitor

Connect-AzAccount -Identity

$vmNames = @("mserv", "win10", "dc")
$resourceGroupName = "CyberSOC"
$resourceGroupNameOps = "ITOperations"
$web01Name = "web01"
$vmNames = @("mserv", "win10", "dc")

# Get the resource group location
$resourceGroup = Get-AzResourceGroup -Name $resourceGroupName
$location = $resourceGroup.Location


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
# Deploy Azure Monitor Agent to the Linux VM
Set-AzVMExtension -ResourceGroupName $resourceGroupNameOps -VMName $web01Name -Name "AzureMonitorLinuxAgent" -Publisher "Microsoft.Azure.Monitor"     -ExtensionType "AzureMonitorLinuxAgent"  -TypeHandlerVersion "1.0"  -Location $location
Write-Output "Azure Monitor Agent deployed for VM '$web01Name'." 
