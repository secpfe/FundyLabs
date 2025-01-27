param (
    [string]$adminPassword,
    [string]$domainName,
    [string]$DCvmName,
    [string]$resourceGroupName
)


Import-Module Az.Compute
Import-Module Az.Accounts

Connect-AzAccount -Identity


# PowerShell Script to Run
$dcscript = @"
# Ensure the required Windows feature is installed
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Import the ADDSDeployment module
Import-Module ADDSDeployment

# Define domain configuration
`$domainName = "$domainName"
`$safeModePassword = ConvertTo-SecureString "$adminPassword" -AsPlainText -Force 

# Promote the VM to a Domain Controller
Install-ADDSForest -DomainName `$domainName -SafeModeAdministratorPassword `$safeModePassword -Force
"@

# Invoke Run Command
Invoke-AzVMRunCommand -ResourceGroupName $resourceGroupName -VMName $DCvmName -CommandId "RunPowerShellScript" -ScriptString $dcscript
