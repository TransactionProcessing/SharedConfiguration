[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^\d+\.\d+\.\d+\.\d+$')]
    [string] $CaAddress,

    [Parameter(Mandatory)]
    [ValidatePattern('^\d+\.\d+\.\d+\.\d+$')]
    [string] $ServerIpAddress,

    [Parameter(Mandatory)]
    [ValidatePattern('^[a-fA-F0-9:]{64,95}$')]
    [string] $RootFingerprint,

    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string] $IntermediateCertificatePath,

    [Parameter(Mandatory)]
    [string] $OutputDirectory,

    [Parameter()]
    [ValidateRange(1, 65535)]
    [int] $CaPort = 8000,

    [Parameter()]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string] $StepCliVersion = '0.30.2',

    [Parameter()]
    [ValidateSet('standalone', 'webroot')]
    [string] $AcmeChallengeMode = 'standalone',

    [Parameter()]
    [ValidateSet('pfx', 'pem')]
    [string] $OutputFormat = 'pfx',

    [Parameter()]
    [string] $ServiceIdentity,

    [Parameter()]
    [string] $AcmeWebRoot
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($AcmeChallengeMode -eq 'webroot' -and -not $AcmeWebRoot) {
    throw '-AcmeWebRoot is required when -AcmeChallengeMode is webroot.'
}
if ($AcmeWebRoot -and -not (Test-Path -LiteralPath $AcmeWebRoot -PathType Container)) {
    throw "ACME webroot directory does not exist: $AcmeWebRoot"
}

$temporaryDirectory = Join-Path $env:TEMP ("step-acme-client-{0}" -f [guid]::NewGuid())
New-Item -ItemType Directory -Path $temporaryDirectory | Out-Null
$previousStepPath = $env:STEPPATH
$env:STEPPATH = Join-Path $temporaryDirectory 'step-home'
$archiveName = "step_windows_${StepCliVersion}_amd64.zip"
$releaseTag = "v$StepCliVersion"
$outputFiles = @()
$issuanceSucceeded = $false

try {
    Write-Host "Downloading temporary Step CLI $StepCliVersion..."
    $headers = @{ 'User-Agent' = 'TransactionProcessing-Development-CA-Client' }
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/smallstep/cli/releases/tags/$releaseTag" -Headers $headers
    $archive = $release.assets | Where-Object { $_.name -eq $archiveName } | Select-Object -First 1
    $checksums = $release.assets | Where-Object { $_.name -eq 'checksums.txt' } | Select-Object -First 1
    if (-not $archive -or -not $checksums) { throw "The official Step CLI release $releaseTag is missing expected assets." }

    $archivePath = Join-Path $temporaryDirectory $archiveName
    $checksumsPath = Join-Path $temporaryDirectory 'checksums.txt'
    Invoke-WebRequest -Uri $archive.browser_download_url -OutFile $archivePath -UseBasicParsing
    Invoke-WebRequest -Uri $checksums.browser_download_url -OutFile $checksumsPath -UseBasicParsing
    $checksumPattern = '(?im)^(?<hash>[a-f0-9]{64})\s+\*?' + [regex]::Escape($archiveName) + '\s*$'
    $checksumMatch = [regex]::Match([IO.File]::ReadAllText($checksumsPath), $checksumPattern)
    if (-not $checksumMatch.Success) { throw "No SHA-256 checksum was published for $archiveName." }
    $actualHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash
    if ($actualHash -ne $checksumMatch.Groups['hash'].Value.ToUpperInvariant()) { throw 'Step CLI archive checksum mismatch.' }

    $extractPath = Join-Path $temporaryDirectory 'extracted'
    Expand-Archive -LiteralPath $archivePath -DestinationPath $extractPath
    $stepFiles = @(Get-ChildItem -LiteralPath $extractPath -Filter step.exe -File -Recurse)
    if ($stepFiles.Count -ne 1) { throw "Expected exactly one step.exe in the release; found $($stepFiles.Count)." }
    $stepExe = $stepFiles[0].FullName

    $caUrl = "https://${CaAddress}:$CaPort"
    Write-Host "Bootstrapping trust for $caUrl using the pinned root fingerprint..."
    & $stepExe ca bootstrap --ca-url $caUrl --fingerprint ($RootFingerprint -replace ':', '')
    if ($LASTEXITCODE -ne 0) { throw "CA bootstrap failed with exit code $LASTEXITCODE." }

    $rootCertificatePath = Join-Path $env:STEPPATH 'certs\root_ca.crt'
    if (-not (Test-Path -LiteralPath $rootCertificatePath -PathType Leaf)) {
        throw "Bootstrap did not produce the expected root certificate at $rootCertificatePath."
    }
    & $stepExe certificate verify $IntermediateCertificatePath --roots $rootCertificatePath
    if ($LASTEXITCODE -ne 0) { throw 'The supplied intermediate certificate does not chain to the bootstrapped root.' }
    $destination = [IO.Path]::GetFullPath($OutputDirectory)
    New-Item -ItemType Directory -Path $destination -Force | Out-Null
    $certificatePath = Join-Path $destination 'server.crt'
    $keyPath = Join-Path $destination 'server.key'
    $pfxPath = Join-Path $destination 'server.pfx'
    if ((Test-Path $certificatePath) -or (Test-Path $keyPath) -or (Test-Path $pfxPath)) {
        throw "Refusing to overwrite an existing certificate or key in $destination. Move or back them up first."
    }
    $outputFiles = @($certificatePath, $keyPath, $pfxPath)

    $issueArgs = @('ca', 'certificate', $ServerIpAddress, $certificatePath, $keyPath,
        '--provisioner', 'acme', '--ca-url', $caUrl, '--root', $rootCertificatePath,
        '--san', $ServerIpAddress)
    if ($AcmeChallengeMode -eq 'webroot') { $issueArgs += @('--webroot', $AcmeWebRoot) }
    Write-Host "Requesting an ACME certificate for IP SAN $ServerIpAddress."
    if ($AcmeChallengeMode -eq 'standalone') {
        Write-Host 'Standalone ACME validation needs port 80 available on this server and reachable from the CA host.'
    }
    & $stepExe @issueArgs
    if ($LASTEXITCODE -ne 0) { throw "ACME certificate issuance failed with exit code $LASTEXITCODE." }
    & $stepExe certificate verify $certificatePath --roots $IntermediateCertificatePath --host $ServerIpAddress
    if ($LASTEXITCODE -ne 0) { throw 'The issued server certificate did not verify to the supplied intermediate for the requested IP.' }

    if ($OutputFormat -eq 'pfx') {
        Write-Host 'Create the password-protected PFX when prompted; retain its password in your deployment secret store.'
        & $stepExe certificate p12 --ca $IntermediateCertificatePath $pfxPath $certificatePath $keyPath
        if ($LASTEXITCODE -ne 0) { throw "PFX packaging failed with exit code $LASTEXITCODE." }
        Remove-Item -LiteralPath $keyPath -Force
        $protectedFile = $pfxPath
    }
    else {
        $protectedFile = $keyPath
    }

    $acl = Get-Acl -LiteralPath $protectedFile
    $acl.SetAccessRuleProtection($true, $false)
    $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $currentRule = [System.Security.AccessControl.FileSystemAccessRule]::new($currentIdentity, 'Read,Write', 'Allow')
    $acl.SetAccessRule($currentRule)
    if ($ServiceIdentity) {
        $serviceRule = [System.Security.AccessControl.FileSystemAccessRule]::new($ServiceIdentity, 'Read', 'Allow')
        $acl.AddAccessRule($serviceRule)
    }
    Set-Acl -LiteralPath $protectedFile -AclObject $acl
    if ($OutputFormat -eq 'pfx') {
        Write-Host "Certificate and password-protected PFX created in $destination. Configure the service with the PFX password from your secret store." -ForegroundColor Green
    }
    else {
        Write-Host "Certificate and private key created in $destination. Restrict key access to the service identity before deployment." -ForegroundColor Green
    }
    $issuanceSucceeded = $true
}
finally {
    if (-not $issuanceSucceeded -and $outputFiles.Count -gt 0) {
        Remove-Item -LiteralPath $outputFiles -Force -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force -ErrorAction SilentlyContinue
    if ($null -eq $previousStepPath) { Remove-Item Env:\STEPPATH -ErrorAction SilentlyContinue }
    else { $env:STEPPATH = $previousStepPath }
}
