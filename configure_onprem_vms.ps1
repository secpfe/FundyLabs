Import-Module Az.Compute
Import-Module Az.Account

Connect-AzAccount -Identity


$resourceGroupName = "ITOperations"
$DCvmName = "DC"


# PowerShell Script to Run
$script = @"
# Ensure the required Windows feature is installed
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Import the ADDSDeployment module
Import-Module ADDSDeployment

# Define domain configuration
`$domainName = "odomain.local"
`$safeModePassword = ConvertTo-SecureString "P@ssw0rd123" -AsPlainText -Force # Set a strong password for Directory Services Restore Mode (DSRM)

# Promote the VM to a Domain Controller
Install-ADDSForest -DomainName `$domainName -SafeModeAdministratorPassword `$safeModePassword -Force
"@

# Invoke Run Command
Invoke-AzVMRunCommand -ResourceGroupName $resourceGroupName -VMName $DCvmName -CommandId "RunPowerShellScript" -ScriptString $script



