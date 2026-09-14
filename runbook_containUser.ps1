param(
  [Parameter(Mandatory=$true)]
  [string] $userName
)

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

Write-Output "Disabling account for $($userName)"

$script=@"
Import-Module ActiveDirectory
Disable-ADAccount -Identity $userName 
"@

$output = Invoke-AzVMRunCommand -ResourceGroupName $resourceGroupNameOps -VMName "dc" -CommandId "RunPowerShellScript" -ScriptString $script
$output.Value | ForEach-Object { $_.Message }
