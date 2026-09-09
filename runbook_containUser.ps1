param(
  [Parameter(Mandatory=$true)]
  [string] $userName
)

Connect-AzAccount -Identity

$resourceGroupNameOps = (Get-AzResourceGroup | Where-Object { $_.ResourceGroupName -like '*ITOperations*' } | Select-Object -First 1).ResourceGroupName
if (-not $resourceGroupNameOps) { throw "ITOperations resource group not found." }

Write-Output "Disabling account for $($userName)"

$script=@"
Import-Module ActiveDirectory
Disable-ADAccount -Identity $userName 
"@

$output = Invoke-AzVMRunCommand -ResourceGroupName $resourceGroupNameOps -VMName "dc" -CommandId "RunPowerShellScript" -ScriptString $script
$output.Value | ForEach-Object { $_.Message }
