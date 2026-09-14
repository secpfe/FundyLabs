param (
    [string]$location
)


Import-Module Az.Compute
Import-Module Az.Accounts
# The sliced subscription appears with a delay, so wait for a usable context: Connect-AzAccount can
# hit its 100s HttpClient timeout and return nothing while the sign-in later succeeds.
$connectDeadline = (Get-Date).AddMinutes(6)
do {
    Connect-AzAccount -Identity -ErrorAction SilentlyContinue | Out-Null
    $context = Get-AzContext
    if ($context.Subscription.Id) { break }
    Start-Sleep -Seconds 15
} while ((Get-Date) -lt $connectDeadline)
if (-not $context.Subscription.Id) { throw "No Azure context after Connect-AzAccount -Identity." }

$resourceGroupNameOps = (Get-AzResourceGroup | Where-Object { $_.ResourceGroupName -like '*ITOperations*' } | Select-Object -First 1).ResourceGroupName
if (-not $resourceGroupNameOps) { throw "ITOperations resource group not found." }

# Use the VM's own location; the passed-in $location is the CyberSOC RG location.
$dc = Get-AzVM -ResourceGroupName $resourceGroupNameOps -Name "dc"
$location = $dc.Location

Set-AzVMExtension -ResourceGroupName $resourceGroupNameOps -VMName "dc" `
    -Name "AzureMonitorWindowsAgent" -Publisher "Microsoft.Azure.Monitor" `
    -ExtensionType "AzureMonitorWindowsAgent" -TypeHandlerVersion "1.0" `
    -Location $location -ErrorAction Stop

Write-Output "Azure Monitor Agent deployed for VM 'DC'." 
