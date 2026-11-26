[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string] $RootCertificatePath,

    [Parameter(Mandatory)]
    [ValidatePattern('^([a-fA-F0-9]{64}|[a-fA-F0-9]{2}(:[a-fA-F0-9]{2}){31})$')]
    [string] $ExpectedSha256Fingerprint,

    [Parameter()]
    [string] $ImageName = 'txnprocbase:development'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
    (Resolve-Path -LiteralPath $RootCertificatePath).Path
)
$sha256 = [System.Security.Cryptography.SHA256]::Create()
try {
    $actualFingerprint = ([BitConverter]::ToString($sha256.ComputeHash($certificate.RawData))).Replace('-', '')
}
finally {
    $sha256.Dispose()
    $certificate.Dispose()
}
$expected = $ExpectedSha256Fingerprint -replace ':', ''
if ($actualFingerprint -ine $expected) {
    throw "Root certificate fingerprint mismatch. Expected $expected; received $actualFingerprint. Docker build was not started."
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$dockerArgs = @(
    'build', '--secret', "id=development-ca-root,src=$((Resolve-Path -LiteralPath $RootCertificatePath).Path)",
    '--file', (Join-Path $repoRoot 'Dockerfile'), '--tag', $ImageName, $repoRoot
)
Write-Host "Building $ImageName with the fingerprint-verified public CA root as a BuildKit secret."
& docker @dockerArgs
if ($LASTEXITCODE -ne 0) { throw "Docker build failed with exit code $LASTEXITCODE." }
