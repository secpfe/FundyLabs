# Publishes the Linux azcopy build as a tarball into the same regional 'templates' containers that
# already host the ARM templates, so 01.CopyDCImage's copy container pulls azcopy from inside Azure
# instead of https://aka.ms/downloadazcopy-v10-linux. That aka.ms link redirects to
# release-assets.githubusercontent.com, has no availability guarantee, and on any redirect/proxy hiccup
# a silent 'curl -sSL' writes an HTML error page into azcopy.tar.gz - which then fails as
# "gzip: stdin: not in gzip format" inside the container.
#
# The aka.ms dependency therefore lives HERE, in a human-run publish step, not in the lab runtime.
# The tarball is validated as real gzip before upload, so a bad download can never reach a build.
#
# The blob lands in the 'templates' container on purpose: the read-only container SAS that
# Publish-ArmTemplates.ps1 already generated (the $templateBase map in the LCA scripts) covers it,
# so no second SAS map is needed - 01.CopyDCImage resolves it with $templateBase[$region] -f 'azcopy-linux.tar.gz?'.
#
# Version is pinned by whatever is published: re-run this to bump azcopy. Pass -SourceUrl to pin an
# exact release instead of the 'latest' aka.ms redirect.
#
#   .\Publish-AzCopyPackage.ps1
#   .\Publish-AzCopyPackage.ps1 -Regions swedencentral,westus3
#   .\Publish-AzCopyPackage.ps1 -SourceUrl https://azcopyvnext.azureedge.net/releases/release-10.32.7/azcopy_linux_amd64_10.32.7.tar.gz

[CmdletBinding()]
param(
    [string[]]$Regions = @(
        'southafricanorth', 'swedencentral', 'francecentral', 'switzerlandnorth',
        'westus2', 'eastus2', 'westus3', 'brazilsouth',
        'northeurope', 'canadacentral', 'japaneast'
    ),
    [string]$ResourceGroupName = 'Skillable',
    [string]$Container = 'templates',
    [string]$BlobName = 'azcopy-linux.tar.gz',
    # Omit to pull the current 'latest' build; pass an exact release URL to pin a version.
    [string]$SourceUrl = 'https://aka.ms/downloadazcopy-v10-linux',
    [datetime]$SasExpiry = ([datetime]'2029-12-31T23:59:00Z')
)

$ErrorActionPreference = 'Stop'
Import-Module Az.Accounts
Import-Module Az.Storage

# canadacentral predates the naming convention used by every other region.
$storageAccountOverrides = @{ 'canadacentral' = 'dcvhdcanada' }

function Get-StorageAccountName {
    param([Parameter(Mandatory)][string]$Region)
    if ($storageAccountOverrides.ContainsKey($Region)) { return $storageAccountOverrides[$Region] }
    return "dcvhd" + ($Region -replace '[^a-z0-9]', '').ToLower()
}

$ctxAz = Get-AzContext
if (-not $ctxAz) { throw "Not signed in. Run Connect-AzAccount first." }

$work = Join-Path ([System.IO.Path]::GetTempPath()) ("azcopy-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null

try {
    $tarPath = Join-Path $work $BlobName
    Write-Host "Source       : $SourceUrl"
    Invoke-WebRequest -Uri $SourceUrl -OutFile $tarPath -MaximumRedirection 5 -UseBasicParsing

    # A non-gzip download (HTML error page, truncated body) must never reach a build; verify the gzip
    # magic bytes 1f 8b before publishing, exactly the check the runtime cannot afford to skip.
    $magic = [System.IO.File]::ReadAllBytes($tarPath)[0..1]
    if ($magic[0] -ne 0x1f -or $magic[1] -ne 0x8b) {
        throw "Downloaded file is not gzip (first bytes $('0x{0:X2} 0x{1:X2}' -f $magic[0], $magic[1])). The source likely returned an error page."
    }
    $tarSize = [math]::Round((Get-Item $tarPath).Length / 1MB, 2)

    Write-Host "Subscription : $($ctxAz.Subscription.Name) ($($ctxAz.Subscription.Id))"
    Write-Host "Package      : $BlobName ($tarSize MB, gzip verified)"
    Write-Host "Container    : $Container (private, read-only SAS until $($SasExpiry.ToString('yyyy-MM-dd')))"
    Write-Host ""

    $results = New-Object System.Collections.Generic.List[object]
    $sasByRegion = [ordered]@{}

    foreach ($region in $Regions) {
        $saName = Get-StorageAccountName -Region $region
        Write-Host "=== $region -> $saName"

        $sa = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $saName -ErrorAction SilentlyContinue
        if (-not $sa) {
            Write-Warning "  storage account '$saName' not found in RG '$ResourceGroupName' - skipping"
            $results.Add([PSCustomObject]@{ Region = $region; Account = $saName; Status = 'AccountMissing' }) | Out-Null
            continue
        }

        $key = (Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $saName)[0].Value
        $ctx = New-AzStorageContext -StorageAccountName $saName -StorageAccountKey $key

        if (-not (Get-AzStorageContainer -Name $Container -Context $ctx -ErrorAction SilentlyContinue)) {
            Write-Host "  creating private container '$Container'"
            New-AzStorageContainer -Name $Container -Context $ctx -Permission Off | Out-Null
        }

        Set-AzStorageBlobContent -File $tarPath -Container $Container -Blob $BlobName `
            -Context $ctx -Properties @{ ContentType = 'application/gzip' } -Force | Out-Null
        Write-Host "  uploaded $BlobName"

        $sas = New-AzStorageContainerSASToken -Name $Container -Permission 'r' -ExpiryTime $SasExpiry -Context $ctx
        $sasByRegion[$region] = "https://$saName.blob.core.windows.net/$Container/{0}$sas"

        $results.Add([PSCustomObject]@{ Region = $region; Account = $saName; Status = 'OK' }) | Out-Null
    }

    Write-Host ""
    $results | Format-Table Region, Account, Status -AutoSize | Out-String | Write-Host

    if ($sasByRegion.Count -gt 0) {
        Write-Host "The existing `$templateBase map in the LCA scripts already resolves this blob:"
        Write-Host '    $azcopyUrl = $templateBase[$tplRegionKey] -f ''azcopy-linux.tar.gz?'''
        Write-Host ""
        Write-Host "Refresh the map only if the SAS was regenerated:"
        Write-Host ""
        Write-Host '$templateBase = @{'
        foreach ($region in $sasByRegion.Keys) {
            Write-Host ("    '{0}' = '{1}'" -f $region, $sasByRegion[$region])
        }
        Write-Host '}'
    }
}
finally {
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}
