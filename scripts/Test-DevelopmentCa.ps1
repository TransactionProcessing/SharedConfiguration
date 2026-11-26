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

function Get-StepCliPath {
    param(
        [Parameter(Mandatory)][string] $Version,
        [string] $ExplicitPath
    )

    if ($ExplicitPath) {
        if (-not (Test-Path -LiteralPath $ExplicitPath -PathType Leaf)) {
            throw "The supplied step CLI was not found: $ExplicitPath"
        }
        return (Resolve-Path -LiteralPath $ExplicitPath).Path
    }

    $relativePath = "step_$Version\bin\step.exe"
    $packagesRootPaths = @(
        (Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Packages'),
        (Join-Path $env:ProgramFiles 'WinGet\Packages')
    )
    foreach ($packagesRoot in $packagesRootPaths) {
        if (-not (Test-Path -LiteralPath $packagesRoot -PathType Container)) { continue }
        $packages = Get-ChildItem -LiteralPath $packagesRoot -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like 'Smallstep.step_*' }
        foreach ($package in $packages) {
            $candidate = Join-Path $package.FullName $relativePath
            if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
        }
    }

    $command = Get-Command 'step.exe' -CommandType Application -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }

    $winget = Get-Command 'winget.exe' -ErrorAction SilentlyContinue
    if (-not $winget) {
        throw "Smallstep step CLI $Version is required. Install it or rerun with -StepExePath pointing to step.exe."
    }

    Write-Host "Installing Smallstep.step $Version with WinGet..."
    & $winget.Source install --id Smallstep.step --exact --version $Version `
        --accept-source-agreements --accept-package-agreements --disable-interactivity
    if ($LASTEXITCODE -ne 0) { throw "WinGet failed to install Smallstep.step $Version (exit $LASTEXITCODE)." }

    foreach ($packagesRoot in $packagesRootPaths) {
        if (-not (Test-Path -LiteralPath $packagesRoot -PathType Container)) { continue }
        $packages = Get-ChildItem -LiteralPath $packagesRoot -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like 'Smallstep.step_*' }
        foreach ($package in $packages) {
            $candidate = Join-Path $package.FullName $relativePath
            if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
        }
    }

    throw "WinGet installed Smallstep.step, but step.exe for version $Version was not found."
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

$stepExe = Get-StepCliPath -Version $StepCliVersion -ExplicitPath $StepExePath
$versionOutput = (& $stepExe version 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0 -or $versionOutput -notmatch [regex]::Escape($StepCliVersion)) {
    throw "The step CLI at '$stepExe' did not report version $StepCliVersion. Output: $versionOutput"
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
