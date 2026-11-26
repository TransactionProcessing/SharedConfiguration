[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ [uri]::IsWellFormedUriString($_, [UriKind]::Absolute) -and ([uri]$_).Scheme -eq 'https' })]
    [string] $Uri,

    [Parameter()]
    [ValidateRange(1, 300)]
    [int] $TimeoutSeconds = 15
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$handler = [System.Net.Http.HttpClientHandler]::new()
$client = [System.Net.Http.HttpClient]::new($handler)
$client.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
$response = $null
try {
    Write-Host "Checking HTTPS with the operating system trust store: $Uri"
    $response = $client.GetAsync($Uri).GetAwaiter().GetResult()
    Write-Host "PASS: TLS certificate validation succeeded; HTTP status $([int]$response.StatusCode) $($response.StatusCode)." -ForegroundColor Green
}
catch [System.Net.Http.HttpRequestException] {
    throw "HTTPS request failed. This commonly means the root is not trusted, the certificate name/IP does not match the URL, or the service is unreachable. $($_.Exception.Message)"
}
finally {
    if ($response) { $response.Dispose() }
    $client.Dispose()
    $handler.Dispose()
}
