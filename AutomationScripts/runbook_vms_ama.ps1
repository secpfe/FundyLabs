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

# Installed concurrently: each extension takes ~1-2.5 min on its own, and mserv/win10 are rebooting
# from the domain join at this point, which stretches them further. 
$installs = @{}

Write-Output "$(Get-Date -Format o) starting AMA install on $web01Name"
$installs[$web01Name] = Set-AzVMExtension -ResourceGroupName $resourceGroupNameOps -VMName $web01Name `
    -Name "AzureMonitorLinuxAgent" -Publisher "Microsoft.Azure.Monitor" `
    -ExtensionType "AzureMonitorLinuxAgent" -TypeHandlerVersion "1.0" `
    -Location $location -AsJob

foreach ($vmName in $vmNames) {
    Write-Output "$(Get-Date -Format o) starting AMA install on $vmName"
    $installs[$vmName] = Set-AzVMExtension -ResourceGroupName $resourceGroupNameOps `
        -VMName $vmName `
        -Name "AzureMonitorWindowsAgent" `
        -Publisher "Microsoft.Azure.Monitor" `
        -ExtensionType "AzureMonitorWindowsAgent" `
        -TypeHandlerVersion "1.0" `
        -Location $location `
        -AsJob
}

$null = Wait-Job -Job $installs.Values

$failed = New-Object System.Collections.Generic.List[string]
foreach ($vmName in $installs.Keys) {
    $job = $installs[$vmName]
    $null = Receive-Job -Job $job -ErrorAction SilentlyContinue -ErrorVariable jobError
    if ($job.State -ne 'Completed') {
        $reason = if ($jobError) { ($jobError | Select-Object -First 1).ToString() } else { "job state $($job.State)" }
        Write-Output "$(Get-Date -Format o) AMA FAILED on ${vmName}: $reason"
        $failed.Add($vmName) | Out-Null
    } else {
        Write-Output "$(Get-Date -Format o) AMA installed on $vmName"
    }
    Remove-Job -Job $job -Force
}

if ($failed.Count -gt 0) {
    throw "AMA installation failed on: $($failed -join ', ')"
}
