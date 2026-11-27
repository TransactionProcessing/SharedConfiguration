[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidateScript({
        $parsedUrl = $null
        [uri]::TryCreate($_, [UriKind]::Absolute, [ref] $parsedUrl) -and
        $parsedUrl.Scheme -eq 'https' -and
        -not $parsedUrl.UserInfo
    })]
    [string] $CaUrl,

    [Parameter(Mandatory)]
    [ValidatePattern('^([a-fA-F0-9]{64}|[a-fA-F0-9]{2}(:[a-fA-F0-9]{2}){31})$')]
    [string] $ExpectedSha256Fingerprint,

    [Parameter()]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string] $StepExePath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($StepExePath) {
    $stepExe = (Resolve-Path -LiteralPath $StepExePath).Path
}
else {
    $stepCommand = Get-Command 'step.exe' -ErrorAction SilentlyContinue
    if (-not $stepCommand) {
        throw 'Smallstep step.exe was not found on PATH. Install the Step CLI or pass -StepExePath.'
    }
    $stepExe = $stepCommand.Source
}

$expected = $ExpectedSha256Fingerprint -replace ':', ''
$temporaryDirectory = Join-Path ([IO.Path]::GetTempPath()) ("development-ca-root-{0}" -f [guid]::NewGuid())
$stepPath = Join-Path $temporaryDirectory 'step-home'
$rootCertificatePath = Join-Path $stepPath 'certs\root_ca.crt'
$previousStepPath = $env:STEPPATH
New-Item -ItemType Directory -Path $temporaryDirectory | Out-Null
$env:STEPPATH = $stepPath

try {
    Write-Host "Downloading and verifying the CA root from $CaUrl..."
    & $stepExe ca bootstrap --ca-url $CaUrl --fingerprint $expected
    if ($LASTEXITCODE -ne 0) {
        throw "CA bootstrap failed with exit code $LASTEXITCODE. No certificate was installed."
    }
    if (-not (Test-Path -LiteralPath $rootCertificatePath -PathType Leaf)) {
        throw 'CA bootstrap did not produce the expected root certificate. No certificate was installed.'
    }

    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rootCertificatePath)
    try {
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        try {
            $actualFingerprint = ([BitConverter]::ToString($sha256.ComputeHash($certificate.RawData))).Replace('-', '')
        }
        finally {
            $sha256.Dispose()
        }
        if ($actualFingerprint -ine $expected) {
            throw "Root certificate fingerprint mismatch. Expected $expected; received $actualFingerprint. No certificate was installed."
        }

        $basicConstraints = $certificate.Extensions |
            Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension] } |
            Select-Object -First 1
        if (-not $basicConstraints -or -not $basicConstraints.CertificateAuthority) {
            throw 'The fingerprint matched, but the downloaded certificate is not marked as a CA certificate.'
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
        }
    }
    finally {
        $certificate.Dispose()
    }
}
finally {
    if ($null -eq $previousStepPath) {
        Remove-Item Env:STEPPATH -ErrorAction SilentlyContinue
    }
    else {
        $env:STEPPATH = $previousStepPath
    }
    Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force -ErrorAction SilentlyContinue
}

