[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string] $RootCertificatePath,

    [Parameter(Mandatory)]
    [ValidatePattern('^([a-fA-F0-9]{64}|[a-fA-F0-9]{2}(:[a-fA-F0-9]{2}){31})$')]
    [string] $ExpectedSha256Fingerprint
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
}
$expected = $ExpectedSha256Fingerprint -replace ':', ''
if ($actualFingerprint -ine $expected) {
    throw "Root certificate fingerprint mismatch. Expected $expected; received $actualFingerprint. No certificate was installed."
}
$basicConstraints = $certificate.Extensions |
    Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension] } |
    Select-Object -First 1
if (-not $basicConstraints -or -not $basicConstraints.CertificateAuthority) {
    throw 'The fingerprint matched, but the supplied certificate is not marked as a CA certificate.'
}

$store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
    [System.Security.Cryptography.X509Certificates.StoreName]::Root,
    [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
)
try {
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $alreadyInstalled = @($store.Certificates | Where-Object { $_.Thumbprint -eq $certificate.Thumbprint }).Count -gt 0
    if ($alreadyInstalled) {
        Write-Host "Trusted root is already installed (SHA-256 $actualFingerprint)."
        return
    }

    if ($PSCmdlet.ShouldProcess('LocalMachine\Root', "Install verified root certificate $($certificate.Subject)")) {
        $store.Add($certificate)
        Write-Host "Installed verified root certificate (SHA-256 $actualFingerprint)."
    }
}
finally {
    $store.Close()
    $certificate.Dispose()
}
