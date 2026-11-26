[CmdletBinding()]
param(
    [Parameter()]
    [ValidatePattern('^\d+\.\d+\.\d+\.\d+$')]
    [string] $CaAddress = '192.168.1.86',

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
    [string] $DataRoot = (Join-Path $env:ProgramData 'Smallstep\DevelopmentCA')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$stepExe = Join-Path (Join-Path $env:ProgramFiles 'Smallstep\step-ca') "$StepCliVersion\step.exe"
$rootCertificate = Join-Path $DataRoot 'certs\root_ca.crt'
$intermediateCertificate = Join-Path $DataRoot 'certs\intermediate_ca.crt'
$caUrl = 'https://{0}:{1}' -f $CaAddress, $Port

foreach ($requiredPath in @($stepExe, $rootCertificate, $intermediateCertificate)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "Required CA test file was not found: $requiredPath"
    }
}

$service = Get-Service -Name 'StepCaDevelopment' -ErrorAction SilentlyContinue
if (-not $service) { throw "Windows service 'StepCaDevelopment' is not installed." }
if ($service.Status -ne 'Running') { throw "CA service is not running; current status is $($service.Status)." }

Write-Host "Checking CA HTTPS health at $caUrl..."
& $stepExe ca health --ca-url $caUrl --root $rootCertificate
if ($LASTEXITCODE -ne 0) { throw "CA health check failed with exit code $LASTEXITCODE." }

$testDirectory = Join-Path $env:TEMP ("step-ca-smoke-test-{0}" -f [guid]::NewGuid())
New-Item -ItemType Directory -Path $testDirectory | Out-Null
$certificatePath = Join-Path $testDirectory 'dev-system-test.crt'
$keyPath = Join-Path $testDirectory 'dev-system-test.key'
$bundlePath = Join-Path $testDirectory 'dev-system-test-chain.crt'

try {
    Write-Host "Requesting a five-minute test certificate for IP SAN $TestIpAddress."
    Write-Host 'Enter the dev-admin passphrase when prompted, then a passphrase for the temporary private key.'
    $issueArguments = @(
        'ca', 'certificate', $TestIpAddress, $certificatePath, $keyPath,
        '--provisioner', 'dev-admin',
        '--ca-url', $caUrl,
        '--root', $rootCertificate,
        '--san', $TestIpAddress,
        '--not-after=5m'
    )
    & $stepExe @issueArguments
    if ($LASTEXITCODE -ne 0) { throw "Certificate request failed with exit code $LASTEXITCODE." }

    $chain = [IO.File]::ReadAllText($certificatePath) + [Environment]::NewLine +
        [IO.File]::ReadAllText($intermediateCertificate)
    [IO.File]::WriteAllText($bundlePath, $chain, [Text.UTF8Encoding]::new($false))

    Write-Host "Verifying the certificate chain and IP SAN $TestIpAddress..."
    & $stepExe certificate verify $bundlePath --roots $rootCertificate --host $TestIpAddress
    if ($LASTEXITCODE -ne 0) { throw 'The test certificate did not verify to the CA root for the requested IP.' }

    Write-Host 'PASS: The CA is healthy over HTTPS and issued a certificate that chains to its root and matches the dev IP.' -ForegroundColor Green
}
finally {
    Remove-Item -LiteralPath $testDirectory -Recurse -Force -ErrorAction SilentlyContinue
}
