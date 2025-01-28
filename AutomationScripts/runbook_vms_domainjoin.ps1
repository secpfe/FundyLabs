param (
    [string]$adminAccount,
    [string]$adminPassword,
    [string]$domainName,
    [string]$resourceGroupName
)


Import-Module Az.Compute
Import-Module Az.Accounts

Connect-AzAccount -Identity

$domainAdminUser = $adminAccount
$domainAdminPassword = $adminPassword

# List of VM names to join to the domain
$vmNames = @("mserv", "win10")

# PowerShell Script for Domain Join
$domainJoinScript = @"
# Securely store domain admin credentials
`$securePassword = ConvertTo-SecureString '$domainAdminPassword' -AsPlainText -Force
`$credential = New-Object System.Management.Automation.PSCredential('$domainAdminUser', `$securePassword)

if (`$env:COMPUTERNAME -ieq 'win10') {
# downgrade RDP security
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 0
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name SecurityLayer -Value 0
}

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
        [int]$WaitTime = 30  # Wait time in seconds 
    )

    $attempt = 1
    $success = $false

    while ($attempt -le $MaxAttempts -and -not $success) {
        Write-Output "Attempt $attempt to join $VMName to the domain..."

        try {
            $result = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VMName `
                -CommandId "RunPowerShellScript" -ScriptString $Script -ErrorAction Stop

            # Check if there is an error message in StdErr
            $errorMessage = $result.Value[1].Message
            if (![string]::IsNullOrEmpty($errorMessage)) {
                # An error occurred
                Write-Output "Error occurred: $errorMessage"
                if ($attempt -lt $MaxAttempts) {
                    Write-Output "Waiting $WaitTime seconds before retrying..."
                    Start-Sleep -Seconds $WaitTime
                } else {
                    Write-Output "Maximum attempts reached. Could not join $VMName to the domain."
                }
            } else {
                # No error message, assume success
                Write-Output "$VMName successfully joined to the domain."
                $success = $true
            }
        } catch {
            # Handle any exceptions from Invoke-AzVMRunCommand
            Write-Output "An error occurred while executing the command: $_"
            if ($attempt -lt $MaxAttempts) {
                Write-Output "Waiting $WaitTime seconds before retrying..."
                Start-Sleep -Seconds $WaitTime
            } else {
                Write-Output "Maximum attempts reached. Could not join $VMName to the domain."
            }
        }

        $attempt++
    }
}

# Invoke Run Command to Join the Domain with retry logic for each VM
foreach ($vmName in $vmNames) {
    Invoke-DomainJoinWithRetry -ResourceGroupName $resourceGroupName -VMName $vmName -Script $domainJoinScript
}