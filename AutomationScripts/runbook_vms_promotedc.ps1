param (
    [string]$adminPassword,
    [string]$domainName,
    [string]$DCvmName,
    [string]$resourceGroupName,
    [string]$location
)


Import-Module Az.Compute
Import-Module Az.Accounts
Import-Module Az.Monitor

Connect-AzAccount -Identity

#Set-AzVMExtension -ResourceGroupName "ITOperations" -VMName "dc" -Name "AzureMonitorWindowsAgent" -Publisher "Microsoft.Azure.Monitor" -ExtensionType "AzureMonitorWindowsAgent" -TypeHandlerVersion "1.0" -Location $location
#Write-Output "Azure Monitor Agent deployed for VM 'DC'." 

# PowerShell Script to Run
$dcscript = @"
# Ensure the required Windows feature is installed
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Import the ADDSDeployment module
Import-Module ADDSDeployment

Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses ("127.0.0.1")
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -PropertyType DWord -Value 0xffffffff
w32tm /config /manualpeerlist:"time.windows.com,0x1" /syncfromflags:manual /reliable:YES /update
w32tm /resync

# Define domain configuration
`$domainName = "$domainName"
`$safeModePassword = ConvertTo-SecureString "$adminPassword" -AsPlainText -Force 

# Promote the VM to a Domain Controller
Install-ADDSForest -DomainName `$domainName -SafeModeAdministratorPassword `$safeModePassword -Force
"@

# Invoke Run Command
Invoke-AzVMRunCommand -ResourceGroupName $resourceGroupName -VMName $DCvmName -CommandId "RunPowerShellScript" -ScriptString $dcscript
