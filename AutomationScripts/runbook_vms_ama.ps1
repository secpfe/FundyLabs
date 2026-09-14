Write-Output "$(Get-Date -Format o) entry"
Import-Module Az.Accounts
Write-Output "$(Get-Date -Format o) Az.Accounts loaded"
Import-Module Az.Resources
Write-Output "$(Get-Date -Format o) Az.Resources loaded"
Import-Module Az.Compute
Write-Output "$(Get-Date -Format o) Az.Compute loaded"

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

# Installed concurrently: each extension takes ~1-2.5 min, and mserv/win10 are rebooting from the
# domain join at this point, which stretches them further.
$targets = @(@{ Vm = $web01Name; Ext = 'AzureMonitorLinuxAgent' })
$targets += $vmNames | ForEach-Object { @{ Vm = $_; Ext = 'AzureMonitorWindowsAgent' } }

$jobs = @()
foreach ($t in $targets) {
    # Keep Write-Output out of the collected expression: `$jobs = foreach (...)` captures every
    # statement's output, so the log lines would land in $jobs instead of the job stream.
    Write-Output "$(Get-Date -Format o) starting AMA install on $($t.Vm)"
    $jobs += Set-AzVMExtension -ResourceGroupName $resourceGroupNameOps -VMName $t.Vm `
        -Name $t.Ext -Publisher "Microsoft.Azure.Monitor" -ExtensionType $t.Ext `
        -TypeHandlerVersion "1.0" -Location $location -AsJob
}

$jobs | Wait-Job | Out-Null

$failed = @()
for ($i = 0; $i -lt $targets.Count; $i++) {
    Write-Output "$(Get-Date -Format o) $($targets[$i].Vm): $($jobs[$i].State)"
    if ($jobs[$i].State -ne 'Completed') { $failed += $targets[$i].Vm }
}
if ($failed) { throw "AMA installation failed on: $($failed -join ', ')" }
