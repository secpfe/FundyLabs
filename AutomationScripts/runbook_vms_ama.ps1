Write-Output "$(Get-Date -Format o) entry"
Import-Module Az.Accounts
Write-Output "$(Get-Date -Format o) Az.Accounts loaded"
Import-Module Az.Resources
Write-Output "$(Get-Date -Format o) Az.Resources loaded"
Import-Module Az.Compute
Write-Output "$(Get-Date -Format o) Az.Compute loaded"

$null = Connect-AzAccount -Identity -ErrorAction Stop
Write-Output "$(Get-Date -Format o) connected"

# One ARM list call instead of two.
$rgs = Get-AzResourceGroup
$resourceGroupNameOps = ($rgs | Where-Object { $_.ResourceGroupName -like '*ITOperations*' } | Select-Object -First 1).ResourceGroupName
if (-not $resourceGroupNameOps) { throw "ITOperations resource group not found." }
$web01Name = "web01"
$vmNames = @("mserv", "win10")

# Use each VM's own location instead of the CyberSOC RG location.
$web01 = Get-AzVM -ResourceGroupName $resourceGroupNameOps -Name $web01Name
$location = $web01.Location

Write-Output "$(Get-Date -Format o) installing AMA on $web01Name"
Set-AzVMExtension -ResourceGroupName $resourceGroupNameOps -VMName $web01Name `
    -Name "AzureMonitorLinuxAgent" -Publisher "Microsoft.Azure.Monitor" `
    -ExtensionType "AzureMonitorLinuxAgent" -TypeHandlerVersion "1.0" `
    -Location $location -ErrorAction Stop
Write-Output "$(Get-Date -Format o) AMA installed on $web01Name"

foreach ($vmName in $vmNames) {
    Write-Output "$(Get-Date -Format o) installing AMA on $vmName"
    Set-AzVMExtension -ResourceGroupName $resourceGroupNameOps `
        -VMName $vmName `
        -Name "AzureMonitorWindowsAgent" `
        -Publisher "Microsoft.Azure.Monitor" `
        -ExtensionType "AzureMonitorWindowsAgent" `
        -TypeHandlerVersion "1.0" `
        -Location $location `
        -ErrorAction Stop
    Write-Output "$(Get-Date -Format o) AMA installed on $vmName"
}
