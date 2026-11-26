[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^\d+\.\d+\.\d+\.\d+$')]
    [string] $CaAddress,

    [Parameter(Mandatory)]
    [string] $RootCertificatePath,

    [Parameter(Mandatory)]
    [string] $IntermediateCertificatePath,

    [Parameter()]
    [ValidatePattern('^\d+\.\d+\.\d+\.\d+$')]
    [string] $TestIpAddress = '192.168.1.86',

    [Parameter()]
    [ValidateRange(1, 65535)]
    [int] $Port = 8000,

    [Parameter()]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string] $StepCliVersion = '0.30.2',

    [Parameter()]
    [string] $StepExePath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-StepCli {
    param(
        [Parameter(Mandatory)][string] $Version,
        [string] $ExplicitPath
    )

    if ($ExplicitPath) {
        if (-not (Test-Path -LiteralPath $ExplicitPath -PathType Leaf)) {
            throw "The supplied step CLI was not found: $ExplicitPath"
        }
        return [pscustomobject]@{
            Path = (Resolve-Path -LiteralPath $ExplicitPath).Path
            TemporaryDirectory = $null
        }
    }

    $temporaryDirectory = Join-Path $env:TEMP ("step-cli-smoke-test-{0}" -f [guid]::NewGuid())
    New-Item -ItemType Directory -Path $temporaryDirectory | Out-Null
    try {
        $archiveName = "step_windows_${Version}_amd64.zip"
        $releaseTag = "v$Version"
        $headers = @{ 'User-Agent' = 'TransactionProcessing-Development-CA-SmokeTest' }
        Write-Host "Fetching Step CLI $Version release metadata..."
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/smallstep/cli/releases/tags/$releaseTag" -Headers $headers
        $archiveAsset = $release.assets | Where-Object { $_.name -eq $archiveName } | Select-Object -First 1
        $checksumAsset = $release.assets | Where-Object { $_.name -eq 'checksums.txt' } | Select-Object -First 1
        if (-not $archiveAsset -or -not $checksumAsset) {
            throw "The official Step CLI $releaseTag release does not contain the expected Windows archive and checksums."
        }

        $archivePath = Join-Path $temporaryDirectory $archiveName
        $checksumsPath = Join-Path $temporaryDirectory 'checksums.txt'
        Write-Host 'Downloading and checking the signed-release checksum...'
        Invoke-WebRequest -Uri $archiveAsset.browser_download_url -OutFile $archivePath -UseBasicParsing
        Invoke-WebRequest -Uri $checksumAsset.browser_download_url -OutFile $checksumsPath -UseBasicParsing

        $checksumPattern = '(?im)^(?<hash>[a-f0-9]{64})\s+\*?' + [regex]::Escape($archiveName) + '\s*$'
        $checksumMatch = [regex]::Match([IO.File]::ReadAllText($checksumsPath), $checksumPattern)
        if (-not $checksumMatch.Success) { throw "No checksum for $archiveName was found in the official release checksums." }
        $expectedHash = $checksumMatch.Groups['hash'].Value.ToUpperInvariant()
        $actualHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash
        if ($actualHash -ne $expectedHash) { throw "Step CLI archive SHA-256 verification failed for $archiveName." }

        $extractDirectory = Join-Path $temporaryDirectory 'extracted'
        Expand-Archive -LiteralPath $archivePath -DestinationPath $extractDirectory -Force
        $stepExecutables = @(Get-ChildItem -LiteralPath $extractDirectory -Filter 'step.exe' -File -Recurse)
        if ($stepExecutables.Count -ne 1) { throw "Expected one step.exe in $archiveName, found $($stepExecutables.Count)." }

        return [pscustomobject]@{
            Path = $stepExecutables[0].FullName
            TemporaryDirectory = $temporaryDirectory
        }
    }
    catch {
        Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force -ErrorAction SilentlyContinue
        throw
    }
}

$caAddressObject = $null
$testIpObject = $null
if (-not [Net.IPAddress]::TryParse($CaAddress, [ref]$caAddressObject) -or
    $caAddressObject.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
    throw "CaAddress must be a valid IPv4 address: $CaAddress"
}
if (-not [Net.IPAddress]::TryParse($TestIpAddress, [ref]$testIpObject) -or
    $testIpObject.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
    throw "TestIpAddress must be a valid IPv4 address: $TestIpAddress"
}

foreach ($requiredPath in @($RootCertificatePath, $IntermediateCertificatePath)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "Required public CA certificate file was not found: $requiredPath"
    }
}

$stepCli = Get-StepCli -Version $StepCliVersion -ExplicitPath $StepExePath
try {
    $stepExe = $stepCli.Path
    Write-Host "Using temporary Step CLI at $stepExe"
    $versionOutput = (& $stepExe version 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0 -or $versionOutput -notmatch [regex]::Escape($StepCliVersion)) {
        throw "The downloaded step CLI did not report version $StepCliVersion. Output: $versionOutput"
    }

    $caUrl = 'https://{0}:{1}' -f $CaAddress, $Port
    Write-Host "Checking remote CA HTTPS health at $caUrl..."
    & $stepExe ca health --ca-url $caUrl --root $RootCertificatePath
    if ($LASTEXITCODE -ne 0) { throw "CA health check failed with exit code $LASTEXITCODE." }

    $testDirectory = Join-Path $env:TEMP ("step-ca-smoke-test-{0}" -f [guid]::NewGuid())
    New-Item -ItemType Directory -Path $testDirectory | Out-Null
    $certificatePath = Join-Path $testDirectory 'dev-system-test.crt'
    $keyPath = Join-Path $testDirectory 'dev-system-test.key'

    try {
        Write-Host "Requesting a five-minute test certificate for IP SAN $TestIpAddress."
        Write-Host 'Enter the dev-admin passphrase when prompted, then a passphrase for the temporary private key.'
        $issueArguments = @(
            'ca', 'certificate', $TestIpAddress, $certificatePath, $keyPath,
            '--provisioner', 'dev-admin',
            '--ca-url', $caUrl,
            '--root', $RootCertificatePath,
            '--san', $TestIpAddress,
            '--not-after=5m'
        )
        & $stepExe @issueArguments
        if ($LASTEXITCODE -ne 0) { throw "Certificate request failed with exit code $LASTEXITCODE." }

        Write-Host 'Verifying the intermediate CA against the root...'
        & $stepExe certificate verify $IntermediateCertificatePath --roots $RootCertificatePath
        if ($LASTEXITCODE -ne 0) { throw 'The intermediate certificate did not verify to the supplied root certificate.' }

        Write-Host "Verifying the issued certificate and IP SAN $TestIpAddress..."
        & $stepExe certificate verify $certificatePath --roots $IntermediateCertificatePath --host $TestIpAddress
        if ($LASTEXITCODE -ne 0) { throw 'The test certificate did not verify to the intermediate for the requested IP.' }

        Write-Host 'PASS: The remote CA is healthy over HTTPS and issued a certificate for the dev IP that chains through the supplied intermediate to the root.' -ForegroundColor Green
    }
    finally {
        Remove-Item -LiteralPath $testDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }
}
finally {
    if ($stepCli.TemporaryDirectory) {
        Remove-Item -LiteralPath $stepCli.TemporaryDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }
}
