param(
  [Parameter(Mandatory=$true)]
  [string] $userName
)

Connect-AzAccount -Identity

Write-Output "Disabling account for $($userName)"

$script=@"
Import-Module ActiveDirectory
Disable-ADAccount -Identity $userName 
"@

$output = Invoke-AzVMRunCommand -ResourceGroupName ITOperations -VMName "dc" -CommandId "RunPowerShellScript" -ScriptString $script
$output.Value | ForEach-Object { $_.Message }
