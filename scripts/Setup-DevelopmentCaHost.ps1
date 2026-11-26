[CmdletBinding()]
param(
    [Parameter()]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string] $StepCaVersion,

    [Parameter()]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string] $WinSwVersion = '2.14.0',

    [Parameter()]
    [Alias('CaDnsName')]
    [string] $CaAddress,

    [Parameter()]
    [string[]] $AllowedDnsNames = @(),

    [Parameter()]
    [string[]] $AllowedIpAddresses = @('192.168.1.86', '192.168.1.163'),

    [Parameter()]
    [ValidatePattern('^\d+(s|m|h)$')]
    [string] $DefaultCertificateDuration = '24h',

    [Parameter()]
    [ValidatePattern('^\d+(s|m|h)$')]
    [string] $MaximumCertificateDuration = '24h',

    [Parameter()]
    [ValidateRange(1, 65535)]
    [int] $Port = 8000,

    [Parameter()]
    [string] $DataRoot = (Join-Path $env:ProgramData 'Smallstep\DevelopmentCA')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this script from an elevated PowerShell session.'
    }
}

function Set-DirectoryAcl {
    param(
        [Parameter(Mandatory)][string] $Path,
        [string] $ServiceAccount,
        [switch] $ServiceModify
    )

    $permissions = @(
        '*S-1-5-18:(OI)(CI)F'
        '*S-1-5-32-544:(OI)(CI)F'
    )
    if ($ServiceAccount) {
        $serviceRights = if ($ServiceModify) { 'M' } else { 'RX' }
        $permissions += "${ServiceAccount}:(OI)(CI)$serviceRights"
    }
    & icacls.exe $Path /inheritance:r /grant:r @permissions | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not set permissions on $Path (icacls exit $LASTEXITCODE)." }
}

function Set-FileReadAcl {
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)][string] $ServiceAccount
    )
    & icacls.exe $Path /inheritance:r /grant:r `
        "${ServiceAccount}:R" '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not set permissions on $Path (icacls exit $LASTEXITCODE)." }
}

function Get-UsbDriveRoot {
    param(
        [string] $ExcludeRoot,
        [string] $Prompt = 'Enter the USB drive letter (for example E:)'
    )

    $drives = @(Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DeviceID })
    if ($ExcludeRoot) {
        $excludedDevice = $ExcludeRoot.TrimEnd('\')
        $drives = @($drives | Where-Object { $_.DeviceID -ine $excludedDevice })
    }
    if ($drives.Count -eq 0) { throw 'No mounted drive volumes were found.' }

    Write-Host 'Mounted drive volumes:'
    $drives | ForEach-Object { Write-Host "  $($_.DeviceID)  $($_.VolumeName)  (drive type $($_.DriveType))" }
    $letter = Read-Host $Prompt
    if ($letter -notmatch '^[A-Za-z]:?$') { throw 'Enter a drive letter such as E or E:.' }
    $root = "{0}:\" -f $letter.TrimEnd(':')
    if (-not ($drives.DeviceID -contains $root.TrimEnd('\'))) {
        throw "$root was not found. No CA files were written."
    }
    Write-Warning 'Windows may report some USB flash drives as fixed disks; confirm that this is the USB drive you intend to keep offline.'
    if ((Read-Host "Type the drive letter $($root.TrimEnd('\')) to confirm") -ne $root.TrimEnd('\')) {
        throw 'USB drive confirmation did not match.'
    }
    return $root
}

function Set-AdminOnlyFileAcl {
    param([Parameter(Mandatory)][string] $Path)
    & icacls.exe $Path /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not restrict temporary secret file permissions on $Path." }
}

function Convert-SecureStringToPlainText {
    param([Parameter(Mandatory)][Security.SecureString] $Value)
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function Read-ConfirmedPassword {
    param([Parameter(Mandatory)][string] $Prompt)
    $first = Read-Host $Prompt -AsSecureString
    $second = Read-Host 'Re-enter the passphrase' -AsSecureString
    $firstText = Convert-SecureStringToPlainText -Value $first
    $secondText = Convert-SecureStringToPlainText -Value $second
    if ($firstText -cne $secondText) {
        $firstText = $null
        $secondText = $null
        throw 'Passphrases did not match.'
    }
    if ($firstText.Length -lt 12) {
        $firstText = $null
        $secondText = $null
        throw 'Use a passphrase of at least 12 characters.'
    }
    $secondText = $null
    return $firstText
}

function Write-PasswordFile {
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)][string] $Password
    )
    [IO.File]::WriteAllText($Path, $Password, [Text.UTF8Encoding]::new($false))
}

function Write-JsonFile {
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)][object] $Value
    )
    $json = $Value | ConvertTo-Json -Depth 100
    [IO.File]::WriteAllText($Path, $json, [Text.UTF8Encoding]::new($false))
}

function Set-CaIssuancePolicy {
    param(
        [Parameter(Mandatory)][object] $Configuration,
        [Parameter(Mandatory)][string[]] $DnsNames,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]] $IpAddresses,
        [Parameter(Mandatory)][string] $DefaultDuration,
        [Parameter(Mandatory)][string] $MaximumDuration
    )

    $before = $Configuration | ConvertTo-Json -Depth 100 -Compress
    if (-not $Configuration.authority) {
        $Configuration | Add-Member -NotePropertyName authority -NotePropertyValue ([pscustomobject]@{})
    }
    if (-not $Configuration.authority.PSObject.Properties['claims'] -or -not $Configuration.authority.claims) {
        $Configuration.authority | Add-Member -NotePropertyName claims -NotePropertyValue ([pscustomobject]@{})
    }
    $Configuration.authority.claims | Add-Member -Force -NotePropertyName defaultTLSCertDuration -NotePropertyValue $DefaultDuration
    $Configuration.authority.claims | Add-Member -Force -NotePropertyName maxTLSCertDuration -NotePropertyValue $MaximumDuration
    $Configuration.authority.claims | Add-Member -Force -NotePropertyName minTLSCertDuration -NotePropertyValue '5m'
    $Configuration.authority | Add-Member -Force -NotePropertyName policy -NotePropertyValue ([pscustomobject]@{
        x509 = [pscustomobject]@{
            allow = [pscustomobject]@{ dns = @($DnsNames); ip = @($IpAddresses) }
        }
    })

    $provisionersProperty = $Configuration.authority.PSObject.Properties['provisioners']
    $provisioners = @()
    if ($provisionersProperty) {
        $provisioners = @($provisionersProperty.Value)
    }
    $hasAcmeProvisioner = @($provisioners | Where-Object { $_.type -eq 'ACME' }).Count -gt 0
    if (-not $hasAcmeProvisioner) {
        $provisioners = @($provisioners) + @([pscustomobject]@{
            type = 'ACME'
            name = 'acme'
        })
        $Configuration.authority | Add-Member -Force -NotePropertyName provisioners -NotePropertyValue $provisioners
    }
    $after = $Configuration | ConvertTo-Json -Depth 100 -Compress
    return ($before -cne $after)
}

function Test-ExistingCaIssuancePolicy {
    param(
        [Parameter(Mandatory)][string] $StepExe,
        [Parameter(Mandatory)][string] $CaPasswordFile,
        [Parameter(Mandatory)][string] $CaUrl,
        [Parameter(Mandatory)][string] $RootCertificate,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]] $AllowedIpAddresses,
        [Parameter(Mandatory)][string] $MaximumDuration
    )
    $provisionerPasswordPath = Join-Path $env:TEMP ("step-test-provisioner-pass-{0}.txt" -f [guid]::NewGuid())
    $allowedCertificatePath = Join-Path $env:TEMP ("step-ca-allowed-{0}.crt" -f [guid]::NewGuid())
    $allowedKeyPath = Join-Path $env:TEMP ("step-ca-allowed-{0}.key" -f [guid]::NewGuid())
    $unauthorizedCertificatePath = Join-Path $env:TEMP ("step-ca-denied-{0}.crt" -f [guid]::NewGuid())
    $unauthorizedKeyPath = Join-Path $env:TEMP ("step-ca-denied-{0}.key" -f [guid]::NewGuid())
    $longLivedCertificatePath = Join-Path $env:TEMP ("step-ca-duration-denied-{0}.crt" -f [guid]::NewGuid())
    $longLivedKeyPath = Join-Path $env:TEMP ("step-ca-duration-denied-{0}.key" -f [guid]::NewGuid())
    $provisionerPassword = Read-Host 'Re-enter the dev-admin passphrase to verify the existing CA policy' -AsSecureString
    $provisionerPasswordText = Convert-SecureStringToPlainText -Value $provisionerPassword
    $provisionerPassword = $null
    try {
        Write-PasswordFile -Path $provisionerPasswordPath -Password $provisionerPasswordText
        $provisionerPasswordText = $null
        Set-AdminOnlyFileAcl -Path $provisionerPasswordPath
        $commonArgs = @('--provisioner', 'dev-admin', '--provisioner-password-file', $provisionerPasswordPath,
            '--password-file', $CaPasswordFile, '--ca-url', $CaUrl, '--root', $RootCertificate)
        & $StepExe ca certificate localhost $allowedCertificatePath $allowedKeyPath @commonArgs --san localhost --not-after=5m
        if ($LASTEXITCODE -ne 0) { throw 'The existing CA did not issue the allowed localhost test certificate.' }
        foreach ($ipAddress in $AllowedIpAddresses) {
            $ipCertificatePath = Join-Path $env:TEMP ("step-ca-allowed-ip-{0}.crt" -f [guid]::NewGuid())
            $ipKeyPath = Join-Path $env:TEMP ("step-ca-allowed-ip-{0}.key" -f [guid]::NewGuid())
            try {
                & $StepExe ca certificate localhost $ipCertificatePath $ipKeyPath @commonArgs --san $ipAddress --not-after=5m
                if ($LASTEXITCODE -ne 0) { throw "The existing CA did not issue a certificate for allowed IP SAN $ipAddress." }
            }
            finally { Remove-Item -LiteralPath $ipCertificatePath, $ipKeyPath -Force -ErrorAction SilentlyContinue }
        }

        & $StepExe ca certificate unauthorized.invalid $unauthorizedCertificatePath $unauthorizedKeyPath @commonArgs --san unauthorized.invalid --not-after=5m 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { throw 'Issuance policy test failed: existing CA issued a certificate for unauthorized.invalid.' }

        $unauthorizedIpCertificatePath = Join-Path $env:TEMP ("step-ca-denied-ip-{0}.crt" -f [guid]::NewGuid())
        $unauthorizedIpKeyPath = Join-Path $env:TEMP ("step-ca-denied-ip-{0}.key" -f [guid]::NewGuid())
        try {
            & $StepExe ca certificate localhost $unauthorizedIpCertificatePath $unauthorizedIpKeyPath @commonArgs --san '192.168.1.99' --not-after=5m 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) { throw 'Issuance policy test failed: existing CA issued a certificate for unauthorized IP SAN 192.168.1.99.' }
        }
        finally { Remove-Item -LiteralPath $unauthorizedIpCertificatePath, $unauthorizedIpKeyPath -Force -ErrorAction SilentlyContinue }

        & $StepExe ca certificate localhost $longLivedCertificatePath $longLivedKeyPath @commonArgs --san localhost "--not-after=$($MaximumDuration)1h" 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { throw 'Duration policy test failed: existing CA issued a certificate beyond the configured maximum.' }
        Write-Host 'Existing CA allowed the approved name and denied the unlisted name and excessive lifetime.'
    }
    finally {
        $provisionerPasswordText = $null
        Remove-Item -LiteralPath $provisionerPasswordPath, $allowedCertificatePath, $allowedKeyPath, `
            $unauthorizedCertificatePath, $unauthorizedKeyPath, $longLivedCertificatePath, $longLivedKeyPath `
            -Force -ErrorAction SilentlyContinue
    }
}

function Copy-DirectoryContents {
    param(
        [Parameter(Mandatory)][string] $Source,
        [Parameter(Mandatory)][string] $Destination
    )
    Get-ChildItem -LiteralPath $Source -Force | Copy-Item -Destination $Destination -Recurse -Force
}

function Get-WinSwBinary {
    param(
        [Parameter(Mandatory)][string] $Version,
        [Parameter(Mandatory)][string] $Destination
    )

    $headers = @{ 'User-Agent' = 'TransactionProcessing-Development-CA-Setup' }
    $releases = Invoke-RestMethod -Uri 'https://api.github.com/repos/winsw/winsw/releases?per_page=100' -Headers $headers
    $release = $releases | Where-Object {
        $_.name -eq "WinSW v$Version" -or $_.tag_name -eq "v.$Version" -or $_.tag_name -eq "v$Version"
    } | Select-Object -First 1
    if (-not $release) { throw "WinSW $Version was not found in the official release list." }
    $tag = $release.tag_name
    $asset = $release.assets | Where-Object { $_.name -eq 'WinSW-x64.exe' } | Select-Object -First 1
    if (-not $asset) { throw "WinSW $tag does not publish the expected x64 executable." }

    $expectedHash = $asset.digest
    if (-not $expectedHash -or $expectedHash -notmatch '^sha256:[0-9a-fA-F]{64}$') {
        throw 'GitHub did not provide a SHA-256 digest for the WinSW release asset; refusing an unverified download.'
    }

    $downloadPath = Join-Path $env:TEMP "WinSW-$Version-x64.exe"
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $downloadPath
    $actualHash = (Get-FileHash -Path $downloadPath -Algorithm SHA256).Hash
    if ($actualHash -ne ($expectedHash -replace '^sha256:', '').ToUpperInvariant()) {
        Remove-Item -LiteralPath $downloadPath -Force
        throw "WinSW SHA-256 check failed for $tag."
    }

    Copy-Item -LiteralPath $downloadPath -Destination $Destination -Force
    Remove-Item -LiteralPath $downloadPath -Force
}

Assert-Administrator

if (-not $StepCaVersion) {
    $StepCaVersion = Read-Host 'Enter the exact Smallstep.step-ca version to install (x.y.z)'
}
if ($StepCaVersion -notmatch '^\d+\.\d+\.\d+$') { throw 'Step CA version must be an exact x.y.z value.' }

if (-not $CaAddress) { $CaAddress = Read-Host 'Enter the CA DNS name or IPv4 address clients will use (without https:// or a port)' }
$caEndpointIp = $null
$caEndpointIsIp = [Net.IPAddress]::TryParse($CaAddress, [ref]$caEndpointIp) -and
    $caEndpointIp.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork
if (-not $caEndpointIsIp -and $CaAddress -notmatch '^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*\.?$') {
    throw 'Enter a DNS hostname or IPv4 address (without https:// or a port).'
}
$caEndpoint = if ($caEndpointIsIp) { $caEndpointIp.ToString() } else { $CaAddress.TrimEnd('.').ToLowerInvariant() }
$caUrl = "https://${caEndpoint}:$Port"
$caTlsNames = @($caEndpoint, 'localhost', $env:COMPUTERNAME) | Select-Object -Unique

$dnsNameSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$baseDnsNames = @('localhost', $env:COMPUTERNAME)
if (-not $caEndpointIsIp) { $baseDnsNames = @($caEndpoint) + $baseDnsNames }
foreach ($dnsName in $baseDnsNames + $AllowedDnsNames) {
    if (-not $dnsName -or $dnsName -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$') {
        throw "AllowedDnsNames must contain exact DNS hostnames without wildcards, URLs, or ports. Invalid value: '$dnsName'."
    }
    [void]$dnsNameSet.Add($dnsName.TrimEnd('.').ToLowerInvariant())
}
$effectiveAllowedDnsNames = @($dnsNameSet | Sort-Object)
$ipAddressSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($ipAddress in $AllowedIpAddresses) {
    $parsedIpAddress = $null
    if (-not $ipAddress -or $ipAddress -notmatch '^(?:\d{1,3}\.){3}\d{1,3}$' -or
        -not [Net.IPAddress]::TryParse($ipAddress, [ref]$parsedIpAddress) -or
        $parsedIpAddress.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
        throw "AllowedIpAddresses must contain valid IPv4 addresses. Invalid value: '$ipAddress'."
    }
    [void]$ipAddressSet.Add($parsedIpAddress.ToString())
}
$effectiveAllowedIpAddresses = @($ipAddressSet | Sort-Object)
function Convert-GoDurationToTimeSpan {
    param([Parameter(Mandatory)][string] $Duration)
    $amount = [int]($Duration -replace '[smh]$', '')
    switch ($Duration.Substring($Duration.Length - 1)) {
        's' { return [TimeSpan]::FromSeconds($amount) }
        'm' { return [TimeSpan]::FromMinutes($amount) }
        'h' { return [TimeSpan]::FromHours($amount) }
    }
}
if ((Convert-GoDurationToTimeSpan $DefaultCertificateDuration) -gt (Convert-GoDurationToTimeSpan $MaximumCertificateDuration)) {
    throw 'DefaultCertificateDuration must not exceed MaximumCertificateDuration.'
}
if ((Convert-GoDurationToTimeSpan $MaximumCertificateDuration) -lt [TimeSpan]::FromMinutes(5)) {
    throw 'MaximumCertificateDuration must be at least 5m, the configured minimum certificate lifetime.'
}

$stepCaRoot = Join-Path $env:ProgramFiles 'Smallstep\step-ca'
$toolDirectory = Join-Path $stepCaRoot $StepCaVersion
$serviceDirectory = Join-Path $stepCaRoot 'service'
$caConfigPath = Join-Path $DataRoot 'config\ca.json'
$rootCertificatePath = Join-Path $DataRoot 'certs\root_ca.crt'
$intermediateCertificatePath = Join-Path $DataRoot 'certs\intermediate_ca.crt'
$intermediateKeyPath = Join-Path $DataRoot 'secrets\intermediate_ca_key'
$passwordFilePath = Join-Path $DataRoot 'secrets\ca-password'
$logsPath = Join-Path $DataRoot 'logs'
$serviceName = 'StepCaDevelopment'
$serviceAccount = "NT SERVICE\$serviceName"
$serviceXmlPath = Join-Path $serviceDirectory 'StepCaDevelopment.xml'
$winswPath = Join-Path $serviceDirectory 'StepCaDevelopment.exe'
$stepExe = Join-Path $toolDirectory 'step.exe'
$stepCaExe = Join-Path $toolDirectory 'step-ca.exe'
$testProvisionerPasswordFile = Join-Path $env:TEMP ("step-test-provisioner-pass-{0}.txt" -f [guid]::NewGuid())

$existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existingService) {
    $serviceDetails = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    if (-not $serviceDetails -or $serviceDetails.PathName.IndexOf($winswPath, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "Service '$serviceName' exists but does not point to this setup's WinSW wrapper. No existing service was changed."
    }
    if ($serviceDetails.StartName -ine $serviceAccount) {
        throw "Existing service '$serviceName' runs as '$($serviceDetails.StartName)', not '$serviceAccount'. Stop and migrate it before rerunning; this script will not silently change the identity of a running CA."
    }
    foreach ($requiredFile in @($stepExe, $stepCaExe, $rootCertificatePath, $intermediateCertificatePath, $intermediateKeyPath, $passwordFilePath, $caConfigPath, $winswPath)) {
        if (-not (Test-Path -LiteralPath $requiredFile)) { throw "Existing CA setup is incomplete: $requiredFile" }
    }
    Set-DirectoryAcl -Path $DataRoot -ServiceAccount $serviceAccount
    Get-ChildItem -LiteralPath $DataRoot -Directory -Recurse | ForEach-Object {
        $isWritableState = $_.FullName -match '\\(db|valuedb|logs)(\\|$)'
        if ($isWritableState) { Set-DirectoryAcl -Path $_.FullName -ServiceAccount $serviceAccount -ServiceModify }
        else { Set-DirectoryAcl -Path $_.FullName -ServiceAccount $serviceAccount }
    }
    Set-FileReadAcl -Path $passwordFilePath -ServiceAccount $serviceAccount

    $existingVersion = (& $stepCaExe version 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0 -or $existingVersion -notmatch [regex]::Escape($StepCaVersion)) {
        throw "The installed CA service uses a different or unverifiable step-ca version. Requested: $StepCaVersion; found: $existingVersion. No CA state was changed."
    }
    Write-Host "Existing step-ca version: $existingVersion"
    Write-Host "Existing step CLI version: $(& $stepExe version)"

    $existingConfig = Get-Content -LiteralPath $caConfigPath -Raw | ConvertFrom-Json
    $policyChanged = Set-CaIssuancePolicy -Configuration $existingConfig -DnsNames $effectiveAllowedDnsNames `
        -IpAddresses $effectiveAllowedIpAddresses `
        -DefaultDuration $DefaultCertificateDuration -MaximumDuration $MaximumCertificateDuration
    $existingTlsNames = @($existingConfig.dnsNames)
    $tlsNamesChanged = (@($existingTlsNames) -join "`n") -cne (@($caTlsNames) -join "`n")
    if ($tlsNamesChanged) { $existingConfig.dnsNames = @($caTlsNames) }
    $configurationChanged = $policyChanged -or $tlsNamesChanged
    if ($configurationChanged) {
        if ($existingService.Status -eq 'Running') {
            & $winswPath stop
            if ($LASTEXITCODE -ne 0) { throw 'Could not stop the existing CA service to apply the configuration.' }
        }
        Write-JsonFile -Path $caConfigPath -Value $existingConfig
    }

    if ($existingService.Status -ne 'Running' -or $configurationChanged) {
        & $winswPath start
        if ($LASTEXITCODE -ne 0) { throw "Could not start existing service; WinSW exit code $LASTEXITCODE." }
    }
    Start-Sleep -Seconds 5
    if ((Get-Service -Name $serviceName).Status -ne 'Running') {
        throw "Existing CA service is not running. Check $logsPath."
    }
    & $stepExe ca health --ca-url "https://localhost:$Port" --root $rootCertificatePath
    if ($LASTEXITCODE -ne 0) { throw "Existing CA health check failed. Check $logsPath." }
    & $stepExe ca health --ca-url $caUrl --root $rootCertificatePath
    if ($LASTEXITCODE -ne 0) { throw "Existing CA health check failed using configured endpoint $caUrl. Check the CA TLS names and $logsPath." }
    Test-ExistingCaIssuancePolicy -StepExe $stepExe -CaPasswordFile $passwordFilePath `
        -CaUrl "https://localhost:$Port" -RootCertificate $rootCertificatePath `
        -AllowedIpAddresses $effectiveAllowedIpAddresses -MaximumDuration $MaximumCertificateDuration

    Write-Host "Existing CA setup is healthy at $caUrl; issuance policy configuration is applied."
    exit 0
}
if (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) {
    throw "Port $Port is already listening. Choose a free port before setting up the CA."
}
if ((Test-Path -LiteralPath $DataRoot) -and -not (Test-Path -LiteralPath $caConfigPath) -and
    @(Get-ChildItem -LiteralPath $DataRoot -Force -ErrorAction SilentlyContinue).Count -gt 0) {
    throw "$DataRoot is not empty but has no CA configuration. Review its contents before rerunning; the script will not overwrite partial setup data."
}

New-Item -ItemType Directory -Path $DataRoot, (Join-Path $DataRoot 'certs'), (Join-Path $DataRoot 'config'), `
    (Join-Path $DataRoot 'secrets'), $logsPath, $toolDirectory, $serviceDirectory -Force | Out-Null
Set-DirectoryAcl -Path $DataRoot
Set-DirectoryAcl -Path (Join-Path $DataRoot 'certs')
Set-DirectoryAcl -Path (Join-Path $DataRoot 'config')
Set-DirectoryAcl -Path (Join-Path $DataRoot 'secrets')
Set-DirectoryAcl -Path $logsPath

$winget = Get-Command winget.exe -ErrorAction SilentlyContinue
if (-not $winget) { throw 'WinGet is required for checksum-verified Smallstep installation. Install App Installer and rerun.' }

Write-Host "Installing Smallstep.step-ca $StepCaVersion with WinGet (the package includes step and step-ca)."
& $winget.Source install --id Smallstep.step-ca --exact --version $StepCaVersion `
    --accept-source-agreements --accept-package-agreements --disable-interactivity
if ($LASTEXITCODE -ne 0) { throw "WinGet failed with exit code $LASTEXITCODE." }

$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$env:Path = @($machinePath, $userPath) -join ';'
$stepCommand = Get-Command step.exe -ErrorAction Stop
$stepCaCommand = Get-Command step-ca.exe -ErrorAction Stop
Copy-Item -LiteralPath $stepCommand.Source -Destination $stepExe -Force
Copy-Item -LiteralPath $stepCaCommand.Source -Destination $stepCaExe -Force

$stepCaVersionOutput = (& $stepCaExe version 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0 -or $stepCaVersionOutput -notmatch [regex]::Escape($StepCaVersion)) {
    throw "Installed step-ca did not report requested version $StepCaVersion. Output: $stepCaVersionOutput"
}
Write-Host "Installed: $stepCaVersionOutput"
Write-Host "step CLI: $(& $stepExe version)"

Get-WinSwBinary -Version $WinSwVersion -Destination $winswPath

$alreadyInitialized = Test-Path -LiteralPath $caConfigPath
if ($alreadyInitialized) {
    foreach ($requiredFile in @($rootCertificatePath, $intermediateCertificatePath, $intermediateKeyPath, $passwordFilePath)) {
        if (-not (Test-Path -LiteralPath $requiredFile)) { throw "Existing CA data is incomplete: $requiredFile" }
    }
    Write-Host "Found existing CA data at $DataRoot; preserving it and skipping initialization."
    $usbRootKeyPath = $null
}
else {
    $usbRoot = Get-UsbDriveRoot -Prompt 'Enter the USB drive letter for the offline root key'
    $usbBackupRoot = Get-UsbDriveRoot -ExcludeRoot $usbRoot -Prompt 'Enter a DIFFERENT USB drive letter for the offline root backup'
    $usbRootDirectory = Join-Path $usbRoot 'Smallstep\DevelopmentRoot'
    $usbBackupDirectory = Join-Path $usbBackupRoot 'Smallstep\DevelopmentRootBackup'
    if (Test-Path -LiteralPath $usbRootDirectory) {
        throw "$usbRootDirectory already exists. Choose an empty USB location; existing key material will not be overwritten."
    }
    if (Test-Path -LiteralPath $usbBackupDirectory) {
        throw "$usbBackupDirectory already exists. Choose an empty location for the verified root backup; existing files will not be overwritten."
    }
    New-Item -ItemType Directory -Path (Join-Path $usbRootDirectory 'certs'), (Join-Path $usbRootDirectory 'secrets') -Force | Out-Null
    $usbRootKeyPath = Join-Path $usbRootDirectory 'secrets\root_ca_key'
    $usbRootCertificatePath = Join-Path $usbRootDirectory 'certs\root_ca.crt'

    $rootPassword = Read-ConfirmedPassword -Prompt 'Set the offline root CA key passphrase (record it safely; the passphrase file will be temporary)'
    $caPassword = Read-ConfirmedPassword -Prompt 'Set the online intermediate CA key passphrase'
    $provisionerPassword = Read-ConfirmedPassword -Prompt 'Set the development provisioner key passphrase (record it safely; its passphrase file will be temporary)'
    $rootPasswordFile = Join-Path $env:TEMP ("step-root-pass-{0}.txt" -f [guid]::NewGuid())
    $provisionerPasswordFile = Join-Path $env:TEMP ("step-provisioner-pass-{0}.txt" -f [guid]::NewGuid())

    try {
        Write-PasswordFile -Path $rootPasswordFile -Password $rootPassword
        Write-PasswordFile -Path $passwordFilePath -Password $caPassword
        Write-PasswordFile -Path $provisionerPasswordFile -Password $provisionerPassword
        Set-AdminOnlyFileAcl -Path $rootPasswordFile
        Set-AdminOnlyFileAcl -Path $provisionerPasswordFile
        $rootPassword = $null
        $caPassword = $null
        $provisionerPassword = $null
        & icacls.exe $passwordFilePath /inheritance:r /grant:r `
            '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Could not restrict permissions on the CA passphrase file.' }

        Write-Host 'For stronger protection, disconnect this host from all networks during the root ceremony.'
        $rootNetworkMode = (Read-Host 'Type OFFLINE after disconnecting, or CONNECTED to continue without disconnecting').Trim().ToUpperInvariant()
        if ($rootNetworkMode -notin @('OFFLINE', 'CONNECTED')) {
            throw 'Enter OFFLINE or CONNECTED to choose how to perform the root ceremony.'
        }
        if ($rootNetworkMode -eq 'CONNECTED') {
            Write-Warning 'Proceeding while connected increases the exposure of the root key while it is in use on this host.'
        }

        $rootArgs = @(
            'certificate', 'create',
            'Transaction Processing Development Root CA',
            $usbRootCertificatePath, $usbRootKeyPath,
            '--profile', 'root-ca',
            '--password-file', $rootPasswordFile
        )
        & $stepExe @rootArgs
        if ($LASTEXITCODE -ne 0) { throw "Root CA creation failed with exit code $LASTEXITCODE." }

        $rootFingerprint = (& $stepExe certificate fingerprint $usbRootCertificatePath 2>&1 | Out-String).Trim()
        if ($LASTEXITCODE -ne 0 -or $rootFingerprint -notmatch '^[0-9a-fA-F]{64}$') {
            throw "Could not calculate the SHA-256 fingerprint for the root certificate. Output: $rootFingerprint"
        }
        Write-Host ''
        Write-Host "Root certificate SHA-256 fingerprint: $rootFingerprint" -ForegroundColor Yellow
        if ((Read-Host 'Record this fingerprint somewhere separate from both USB drives, then type RECORDED') -cne 'RECORDED') {
            throw 'The root fingerprint was not confirmed as recorded out of band.'
        }

        $usbBackupKeyPath = Join-Path $usbBackupDirectory 'secrets\root_ca_key'
        $usbBackupCertificatePath = Join-Path $usbBackupDirectory 'certs\root_ca.crt'
        New-Item -ItemType Directory -Path (Split-Path -Parent $usbBackupKeyPath), (Split-Path -Parent $usbBackupCertificatePath) -Force | Out-Null
        Copy-Item -LiteralPath $usbRootKeyPath -Destination $usbBackupKeyPath
        Copy-Item -LiteralPath $usbRootCertificatePath -Destination $usbBackupCertificatePath
        $sourceKeyHash = (Get-FileHash -LiteralPath $usbRootKeyPath -Algorithm SHA256).Hash
        $backupKeyHash = (Get-FileHash -LiteralPath $usbBackupKeyPath -Algorithm SHA256).Hash
        $sourceCertificateHash = (Get-FileHash -LiteralPath $usbRootCertificatePath -Algorithm SHA256).Hash
        $backupCertificateHash = (Get-FileHash -LiteralPath $usbBackupCertificatePath -Algorithm SHA256).Hash
        $backupFingerprint = (& $stepExe certificate fingerprint $usbBackupCertificatePath 2>&1 | Out-String).Trim()
        if ($sourceKeyHash -ne $backupKeyHash -or $sourceCertificateHash -ne $backupCertificateHash -or
            $backupFingerprint -ne $rootFingerprint) {
            throw 'The root-key backup did not match its source. Do not eject or use either drive; investigate the copy failure.'
        }
        $backupManifestPath = Join-Path $usbBackupDirectory 'backup-manifest.txt'
        [IO.File]::WriteAllLines($backupManifestPath, @(
            "Root certificate fingerprint: $rootFingerprint"
            "Root key SHA-256: $sourceKeyHash"
            "Root certificate SHA-256: $sourceCertificateHash"
            "Network mode during root ceremony: $rootNetworkMode"
            "Backup verified UTC: $([DateTime]::UtcNow.ToString('o'))"
        ), [Text.UTF8Encoding]::new($false))
        Write-Host "Verified root backup: $usbBackupDirectory"

        $previousStepPath = $env:STEPPATH
        try {
            # Keep the root key on removable media; step ca init writes the intermediate key to host storage.
            $env:STEPPATH = $DataRoot
            $initArgs = @(
                'ca', 'init',
                '--root', $usbRootCertificatePath,
                '--key', $usbRootKeyPath,
                '--key-password-file', $rootPasswordFile,
                '--name', 'Transaction Processing Development CA',
                '--dns', $caEndpoint,
                '--dns', 'localhost',
                '--dns', $env:COMPUTERNAME,
                '--address', ":$Port",
                '--with-ca-url', $caUrl,
                '--provisioner', 'dev-admin',
                '--acme',
                '--password-file', $passwordFilePath,
                '--provisioner-password-file', $provisionerPasswordFile
            )
            & $stepExe @initArgs
            if ($LASTEXITCODE -ne 0) { throw "step ca init failed with exit code $LASTEXITCODE." }
        }
        finally {
            if ($null -eq $previousStepPath) { Remove-Item Env:\STEPPATH -ErrorAction SilentlyContinue }
            else { $env:STEPPATH = $previousStepPath }
        }
    }
    finally {
        Remove-Item -LiteralPath $rootPasswordFile, $provisionerPasswordFile -Force -ErrorAction SilentlyContinue
    }

    $usbBackupKeyPath = Join-Path $usbBackupDirectory 'secrets\root_ca_key'
    foreach ($requiredFile in @($usbRootKeyPath, $usbRootCertificatePath, $usbBackupKeyPath, $rootCertificatePath, $intermediateCertificatePath, $intermediateKeyPath, $caConfigPath, $passwordFilePath)) {
        if (-not (Test-Path -LiteralPath $requiredFile)) { throw "Expected CA initialization output is missing: $requiredFile" }
    }

    if (Test-Path -LiteralPath $rootCertificatePath) {
        $hostCertificateHash = (Get-FileHash -LiteralPath $rootCertificatePath -Algorithm SHA256).Hash
        if ($hostCertificateHash -ne $sourceCertificateHash) {
            throw 'step ca init wrote a root certificate that does not match the recorded offline root. Refusing to continue.'
        }
    }
    else {
        Copy-Item -LiteralPath $usbRootCertificatePath -Destination $rootCertificatePath
    }
    $hostRootKeys = @(Get-ChildItem -LiteralPath $DataRoot -Filter 'root_ca_key' -File -Recurse -ErrorAction SilentlyContinue)
    if ($hostRootKeys.Count -gt 0) { throw "The offline root private key was found on the online host under ${DataRoot}: $($hostRootKeys.FullName -join ', '). Remove it before proceeding." }

    $caConfig = Get-Content -LiteralPath $caConfigPath -Raw | ConvertFrom-Json
    $caConfig.root = $rootCertificatePath
    $caConfig.crt = $intermediateCertificatePath
    $caConfig.key = $intermediateKeyPath
    $caConfig.address = ":$Port"
    $caConfig.dnsNames = @($caTlsNames)
    [void](Set-CaIssuancePolicy -Configuration $caConfig -DnsNames $effectiveAllowedDnsNames `
        -IpAddresses $effectiveAllowedIpAddresses `
        -DefaultDuration $DefaultCertificateDuration -MaximumDuration $MaximumCertificateDuration)
    $dbProperty = $caConfig.PSObject.Properties['db']
    if ($dbProperty -and $caConfig.db) {
        $caConfig.db.dataSource = Join-Path $DataRoot 'db'
        if ($caConfig.db.PSObject.Properties['valueDir'] -and $caConfig.db.valueDir) {
            $caConfig.db.valueDir = Join-Path $DataRoot 'valuedb'
        }
    }
    Write-JsonFile -Path $caConfigPath -Value $caConfig
    & icacls.exe $passwordFilePath /inheritance:r /grant:r `
        '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not restrict permissions on the CA passphrase file.' }
}

$caConfig = Get-Content -LiteralPath $caConfigPath -Raw | ConvertFrom-Json
$caConfig.address = ":$Port"
$caConfig.dnsNames = @($caTlsNames | Select-Object -Unique)
[void](Set-CaIssuancePolicy -Configuration $caConfig -DnsNames $effectiveAllowedDnsNames `
    -IpAddresses $effectiveAllowedIpAddresses `
    -DefaultDuration $DefaultCertificateDuration -MaximumDuration $MaximumCertificateDuration)
Write-JsonFile -Path $caConfigPath -Value $caConfig
$defaultsPath = Join-Path $DataRoot 'config\defaults.json'
if (Test-Path -LiteralPath $defaultsPath) {
    $defaults = Get-Content -LiteralPath $defaultsPath -Raw | ConvertFrom-Json
    $defaults.root = $rootCertificatePath
    $defaults.'ca-url' = $caUrl
    Write-JsonFile -Path $defaultsPath -Value $defaults
}

$xml = @"
<service>
  <id>$serviceName</id>
  <name>Smallstep Development CA</name>
  <description>Development certificate authority for Transaction Processing services.</description>
  <executable>$( [Security.SecurityElement]::Escape($stepCaExe) )</executable>
  <arguments>$( [Security.SecurityElement]::Escape('"' + $caConfigPath + '" --password-file "' + $passwordFilePath + '"') )</arguments>
  <workingdirectory>$( [Security.SecurityElement]::Escape($DataRoot) )</workingdirectory>
  <startmode>Automatic</startmode>
  <logpath>$( [Security.SecurityElement]::Escape($logsPath) )</logpath>
  <log mode="roll" />
  <onfailure action="restart" delay="10 sec" />
  <onfailure action="restart" delay="30 sec" />
  <serviceaccount>
    <domain>NT SERVICE</domain>
    <user>$serviceName</user>
    <allowservicelogon>true</allowservicelogon>
  </serviceaccount>
</service>
"@
Set-Content -LiteralPath $serviceXmlPath -Value $xml -Encoding utf8

Write-Host ''
if ($usbRootKeyPath) {
    Write-Host 'Remove/eject both USB drives now. One contains the offline root; the other contains its verified backup.'
    [void](Read-Host 'After ejecting both USB drives, press Enter to install and start the CA service')
    if ((Test-Path -LiteralPath $usbRootKeyPath) -or (Test-Path -LiteralPath $usbBackupKeyPath)) {
        throw 'At least one root-key USB drive is still mounted. Eject both before the CA service starts.'
    }
}

& $winswPath install
if ($LASTEXITCODE -ne 0) { throw "WinSW service installation failed with exit code $LASTEXITCODE." }
# Install creates the virtual service account so Windows can resolve it in filesystem ACLs.
# Reapply ACLs after installation to ensure the CA can read its keys and write only state/log paths.
Set-DirectoryAcl -Path $DataRoot -ServiceAccount $serviceAccount
Get-ChildItem -LiteralPath $DataRoot -Directory -Recurse | ForEach-Object {
    $isWritableState = $_.FullName -match '\\(db|valuedb|logs)(\\|$)'
    if ($isWritableState) { Set-DirectoryAcl -Path $_.FullName -ServiceAccount $serviceAccount -ServiceModify }
    else { Set-DirectoryAcl -Path $_.FullName -ServiceAccount $serviceAccount }
}
Set-FileReadAcl -Path $passwordFilePath -ServiceAccount $serviceAccount
& $winswPath start
if ($LASTEXITCODE -ne 0) { throw "WinSW service start failed with exit code $LASTEXITCODE." }

Start-Sleep -Seconds 5
$service = Get-Service -Name $serviceName
if ($service.Status -ne 'Running') { throw "CA service did not reach Running state; current state is $($service.Status). Check $logsPath." }

& $stepExe ca health --ca-url "https://localhost:$Port" --root $rootCertificatePath
if ($LASTEXITCODE -ne 0) { throw "step ca health failed. Check the WinSW logs under $logsPath." }
& $stepExe ca health --ca-url $caUrl --root $rootCertificatePath
if ($LASTEXITCODE -ne 0) { throw "CA health check failed using configured endpoint $caUrl. Confirm the CA TLS certificate includes this endpoint and check $logsPath." }

$testProvisionerPassword = Read-Host 'Re-enter the dev-admin provisioner passphrase to issue a temporary test certificate' -AsSecureString
$testProvisionerPasswordText = Convert-SecureStringToPlainText -Value $testProvisionerPassword
$testProvisionerPassword = $null
Write-PasswordFile -Path $testProvisionerPasswordFile -Password $testProvisionerPasswordText
$testProvisionerPasswordText = $null
Set-AdminOnlyFileAcl -Path $testProvisionerPasswordFile
$testCertificatePath = Join-Path $env:TEMP ("step-ca-test-{0}.crt" -f [guid]::NewGuid())
$testKeyPath = Join-Path $env:TEMP ("step-ca-test-{0}.key" -f [guid]::NewGuid())
$testBundlePath = Join-Path $env:TEMP ("step-ca-test-{0}-chain.crt" -f [guid]::NewGuid())
try {
    $issueArgs = @(
        'ca', 'certificate', 'localhost', $testCertificatePath, $testKeyPath,
        '--provisioner', 'dev-admin',
        '--provisioner-password-file', $testProvisionerPasswordFile,
        '--password-file', $passwordFilePath,
        '--ca-url', "https://localhost:$Port",
        '--root', $rootCertificatePath,
        '--san', 'localhost',
        '--not-after=5m'
    )
    & $stepExe @issueArgs
    if ($LASTEXITCODE -ne 0) { throw "The test leaf certificate request failed with exit code $LASTEXITCODE." }
    Set-AdminOnlyFileAcl -Path $testCertificatePath
    Set-AdminOnlyFileAcl -Path $testKeyPath
    $bundle = [IO.File]::ReadAllText($testCertificatePath) + [Environment]::NewLine + [IO.File]::ReadAllText($intermediateCertificatePath)
    [IO.File]::WriteAllText($testBundlePath, $bundle, [Text.UTF8Encoding]::new($false))
    Set-AdminOnlyFileAcl -Path $testBundlePath
    & $stepExe certificate verify $testBundlePath --roots $rootCertificatePath --host 'localhost'
    if ($LASTEXITCODE -ne 0) { throw 'The test leaf certificate did not validate to the offline root.' }
    Write-Host 'Test leaf certificate issued and verified to the offline root.'

    foreach ($ipAddress in $effectiveAllowedIpAddresses) {
        $ipCertificatePath = Join-Path $env:TEMP ("step-ca-ip-test-{0}.crt" -f [guid]::NewGuid())
        $ipKeyPath = Join-Path $env:TEMP ("step-ca-ip-test-{0}.key" -f [guid]::NewGuid())
        $ipIssueArgs = @(
            'ca', 'certificate', 'localhost', $ipCertificatePath, $ipKeyPath,
            '--provisioner', 'dev-admin',
            '--provisioner-password-file', $testProvisionerPasswordFile,
            '--password-file', $passwordFilePath,
            '--ca-url', "https://localhost:$Port",
            '--root', $rootCertificatePath,
            '--san', $ipAddress,
            '--not-after=5m'
        )
        & $stepExe @ipIssueArgs 2>&1 | Out-Null
        $ipIssueExitCode = $LASTEXITCODE
        Remove-Item -LiteralPath $ipCertificatePath, $ipKeyPath -Force -ErrorAction SilentlyContinue
        if ($ipIssueExitCode -ne 0) { throw "Issuance policy test failed: CA did not issue for approved IP SAN $ipAddress." }
        Write-Host "Approved IP SAN was accepted: $ipAddress"
    }

    $unauthorizedIpCertificatePath = Join-Path $env:TEMP ("step-ca-denied-ip-{0}.crt" -f [guid]::NewGuid())
    $unauthorizedIpKeyPath = Join-Path $env:TEMP ("step-ca-denied-ip-{0}.key" -f [guid]::NewGuid())
    try {
        $unauthorizedIpArgs = @(
            'ca', 'certificate', 'localhost', $unauthorizedIpCertificatePath, $unauthorizedIpKeyPath,
            '--provisioner', 'dev-admin',
            '--provisioner-password-file', $testProvisionerPasswordFile,
            '--password-file', $passwordFilePath,
            '--ca-url', "https://localhost:$Port",
            '--root', $rootCertificatePath,
            '--san', '192.168.1.99',
            '--not-after=5m'
        )
        & $stepExe @unauthorizedIpArgs 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { throw 'Issuance policy test failed: CA issued a certificate for unauthorized IP SAN 192.168.1.99.' }
    }
    finally { Remove-Item -LiteralPath $unauthorizedIpCertificatePath, $unauthorizedIpKeyPath -Force -ErrorAction SilentlyContinue }

    $unauthorizedCertificatePath = Join-Path $env:TEMP ("step-ca-denied-{0}.crt" -f [guid]::NewGuid())
    $unauthorizedKeyPath = Join-Path $env:TEMP ("step-ca-denied-{0}.key" -f [guid]::NewGuid())
    $unauthorizedArgs = @(
        'ca', 'certificate', 'unauthorized.invalid', $unauthorizedCertificatePath, $unauthorizedKeyPath,
        '--provisioner', 'dev-admin',
        '--provisioner-password-file', $testProvisionerPasswordFile,
        '--password-file', $passwordFilePath,
        '--ca-url', "https://localhost:$Port",
        '--root', $rootCertificatePath,
        '--san', 'unauthorized.invalid',
        '--not-after=5m'
    )
    & $stepExe @unauthorizedArgs 2>&1 | Out-Null
    $unauthorizedExitCode = $LASTEXITCODE
    Remove-Item -LiteralPath $unauthorizedCertificatePath, $unauthorizedKeyPath -Force -ErrorAction SilentlyContinue
    if ($unauthorizedExitCode -eq 0) { throw 'Issuance policy test failed: CA issued a certificate for unauthorized.invalid.' }
    Write-Host 'Unauthorized SAN request was denied by the CA policy.'

    $longLivedCertificatePath = Join-Path $env:TEMP ("step-ca-duration-denied-{0}.crt" -f [guid]::NewGuid())
    $longLivedKeyPath = Join-Path $env:TEMP ("step-ca-duration-denied-{0}.key" -f [guid]::NewGuid())
    $longDurationArgs = @(
        'ca', 'certificate', 'localhost', $longLivedCertificatePath, $longLivedKeyPath,
        '--provisioner', 'dev-admin',
        '--provisioner-password-file', $testProvisionerPasswordFile,
        '--password-file', $passwordFilePath,
        '--ca-url', "https://localhost:$Port",
        '--root', $rootCertificatePath,
        '--san', 'localhost',
        "--not-after=$($MaximumCertificateDuration)1h"
    )
    & $stepExe @longDurationArgs 2>&1 | Out-Null
    $longDurationExitCode = $LASTEXITCODE
    Remove-Item -LiteralPath $longLivedCertificatePath, $longLivedKeyPath -Force -ErrorAction SilentlyContinue
    if ($longDurationExitCode -eq 0) { throw 'Duration policy test failed: CA accepted a certificate at the configured maximum; request a longer duration to validate the limit.' }
    Write-Host 'Certificate duration above the configured maximum was denied.'
}
finally {
    Remove-Item -LiteralPath $testProvisionerPasswordFile, $testCertificatePath, $testKeyPath, $testBundlePath -Force -ErrorAction SilentlyContinue
}

Write-Host ''
Write-Host "Development CA is running at $caUrl"
Write-Host "Root certificate: $rootCertificatePath"
if ($usbRootKeyPath) {
    Write-Host "Offline root-key USB location (keep unplugged): $usbRootKeyPath"
    Write-Host "Verified root backup location (keep unplugged): $usbBackupKeyPath"
    Write-Host "Recorded root SHA-256 fingerprint: $rootFingerprint"
    Write-Host 'Reconnect network access now if required for development clients.'
}
Write-Host 'No Windows Firewall rules were created or changed.'


