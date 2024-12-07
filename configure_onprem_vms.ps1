param (
    [string]$adminAccount,
    [string]$adminPassword
)

Import-Module Az.Compute
Import-Module Az.Accounts

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



$resourceGroupName = "ITOperations"
$domainName = "odomain.local"
$domainAdminUser = $adminAccount
$domainAdminPassword = $adminPassword

# List of VM names to join to the domain
$vmNames = @("mserv", "win10")

# PowerShell Script for Domain Join
$domainJoinScript = @"
# Securely store domain admin credentials
`$securePassword = ConvertTo-SecureString '$domainAdminPassword' -AsPlainText -Force
`$credential = New-Object System.Management.Automation.PSCredential('$domainAdminUser', `$securePassword)

# Join the server to the domain
Add-Computer -DomainName '$domainName' -Credential `$credential -Restart -Force
"@

# Function to invoke domain join with retry logic
Function Invoke-DomainJoinWithRetry {
    param(
        [string]$ResourceGroupName,
        [string]$VMName,
        [string]$Script,
        [int]$MaxAttempts = 10,
        [int]$WaitTime = 120  # Wait time in seconds (2 minutes)
    )

    $attempt = 1
    $success = $false

    while ($attempt -le $MaxAttempts -and -not $success) {
        Write-Host "Attempt $attempt to join $VMName to the domain..."

        try {
            $result = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VMName `
                -CommandId "RunPowerShellScript" -ScriptString $Script -ErrorAction Stop

            # Check if there is an error message in StdErr
            $errorMessage = $result.Value[1].Message
            if (![string]::IsNullOrEmpty($errorMessage)) {
                # An error occurred
                Write-Host "Error occurred: $errorMessage"
                if ($attempt -lt $MaxAttempts) {
                    Write-Host "Waiting for 2 minutes before retrying..."
                    Start-Sleep -Seconds $WaitTime
                } else {
                    Write-Host "Maximum attempts reached. Could not join $VMName to the domain."
                }
            } else {
                # No error message, assume success
                Write-Host "$VMName successfully joined to the domain."
                $success = $true
            }
        } catch {
            # Handle any exceptions from Invoke-AzVMRunCommand
            Write-Host "An error occurred while executing the command: $_"
            if ($attempt -lt $MaxAttempts) {
                Write-Host "Waiting for 2 minutes before retrying..."
                Start-Sleep -Seconds $WaitTime
            } else {
                Write-Host "Maximum attempts reached. Could not join $VMName to the domain."
            }
        }

        $attempt++
    }
}

# Invoke Run Command to Join the Domain with retry logic for each VM
foreach ($vmName in $vmNames) {
    Invoke-DomainJoinWithRetry -ResourceGroupName $resourceGroupName -VMName $vmName -Script $domainJoinScript
}
