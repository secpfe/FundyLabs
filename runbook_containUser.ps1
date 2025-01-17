param(
  [Parameter(Mandatory=$true)]
  [string] $UserUPN
)

Connect-AzAccount -Identity

Write-Output "Disabling account for $($UserUPN)"

$script=@"
Import-Module ActiveDirectory
Disable-ADAccount -Identity $UserUPN 
"@

$output = Invoke-AzVMRunCommand -ResourceGroupName ITOperations -VMName "dc" -CommandId "RunPowerShellScript" -ScriptString $script
$output.Value | ForEach-Object { $_.Message }