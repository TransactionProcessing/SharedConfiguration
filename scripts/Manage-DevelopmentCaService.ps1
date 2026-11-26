[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('TestRecovery', 'Uninstall')]
    [string] $Action,

    [Parameter()]
    [ValidateRange(1, 65535)]
    [int] $Port = 8000,

    [Parameter()]
    [ValidateRange(15, 600)]
    [int] $RecoveryTimeoutSeconds = 120,

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

function Get-ServiceDetails {
    param([Parameter(Mandatory)][string] $Name)

    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $service) { throw "Windows service '$Name' is not installed." }

    $details = Get-CimInstance Win32_Service -Filter "Name='$Name'"
    if (-not $details) { throw "Could not inspect Windows service '$Name'." }

    $serviceDirectory = Join-Path $env:ProgramFiles 'Smallstep\step-ca\service'
    $wrapperPath = Join-Path $serviceDirectory 'StepCaDevelopment.exe'
    $xmlPath = Join-Path $serviceDirectory 'StepCaDevelopment.xml'
    if ($details.PathName.IndexOf($wrapperPath, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "Service '$Name' does not use the expected WinSW wrapper at $wrapperPath."
    }
    if ($details.StartName -ine "NT SERVICE\$Name") {
        throw "Service '$Name' runs as '$($details.StartName)', not its expected virtual service account."
    }
    if (-not (Test-Path -LiteralPath $wrapperPath) -or -not (Test-Path -LiteralPath $xmlPath)) {
        throw 'The WinSW wrapper or its XML configuration is missing.'
    }

    $serviceXml = [xml](Get-Content -LiteralPath $xmlPath -Raw)
    $stepCaExe = $serviceXml.service.executable.Trim()
    if ([IO.Path]::GetFileName($stepCaExe) -ine 'step-ca.exe') {
        throw "The service XML does not point to step-ca.exe: $stepCaExe"
    }
    $stepExe = Join-Path (Split-Path -Parent $stepCaExe) 'step.exe'
    $rootCertificate = Join-Path $DataRoot 'certs\root_ca.crt'

    return [pscustomobject]@{
        Service = $service
        Details = $details
        WrapperPath = $wrapperPath
        StepCaExe = $stepCaExe
        StepExe = $stepExe
        RootCertificate = $rootCertificate
    }
}

function Get-StepCaChildProcess {
    param(
        [Parameter(Mandatory)][int] $WrapperProcessId,
        [Parameter(Mandatory)][string] $ExpectedExecutable,
        [Parameter(Mandatory)][object[]] $Processes
    )

    $pending = [Collections.Generic.Queue[int]]::new()
    $visited = [Collections.Generic.HashSet[int]]::new()
    $pending.Enqueue($WrapperProcessId)
    while ($pending.Count -gt 0) {
        $parentId = $pending.Dequeue()
        if (-not $visited.Add($parentId)) { continue }
        foreach ($candidate in @($Processes | Where-Object { [int]$_.ParentProcessId -eq $parentId })) {
            if ($candidate.ExecutablePath -and
                $candidate.ExecutablePath.Equals($ExpectedExecutable, [StringComparison]::OrdinalIgnoreCase)) {
                return $candidate
            }
            $pending.Enqueue([int]$candidate.ProcessId)
        }
    }
    return $null
}

function Test-CaHealth {
    param([Parameter(Mandatory)][object] $ServiceInfo)

    $healthArgs = @('ca', 'health', '--ca-url', "https://localhost:$Port", '--root', $ServiceInfo.RootCertificate)
    $null = & $ServiceInfo.StepExe @healthArgs 2>&1
    return ($LASTEXITCODE -eq 0)
}

Assert-Administrator
$serviceName = 'StepCaDevelopment'
$serviceInfo = Get-ServiceDetails -Name $serviceName

if ($Action -eq 'Uninstall') {
    Write-Host 'This removes the Windows service registration and preserves CA files, keys, logs, binaries, and configuration.'
    if ((Read-Host "Type UNINSTALL to remove service '$serviceName'") -cne 'UNINSTALL') {
        throw 'Uninstall confirmation did not match. No service changes were made.'
    }

    if ((Get-Service -Name $serviceName).Status -ne 'Stopped') {
        & $serviceInfo.WrapperPath stop
        if ($LASTEXITCODE -ne 0) { throw 'WinSW could not stop the CA service; it was not uninstalled.' }
        $stopDeadline = (Get-Date).AddSeconds(60)
        while ((Get-Service -Name $serviceName).Status -ne 'Stopped' -and (Get-Date) -lt $stopDeadline) {
            Start-Sleep -Seconds 2
        }
        if ((Get-Service -Name $serviceName).Status -ne 'Stopped') {
            throw "CA service did not stop. Review its logs under $(Join-Path $DataRoot 'logs'); no uninstall was attempted."
        }
    }

    & $serviceInfo.WrapperPath uninstall
    if ($LASTEXITCODE -ne 0) { throw "WinSW uninstall failed with exit code $LASTEXITCODE." }
    Start-Sleep -Seconds 2
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        throw 'The service still appears in Windows after WinSW uninstall.'
    }

    Write-Host 'CA service registration removed. CA data and installed files were preserved.'
    Write-Host 'To roll back, rerun Setup-DevelopmentCaHost.ps1 with the same CA version, DNS name, port, and DataRoot.'
    return
}

if ($serviceInfo.Service.Status -ne 'Running') {
    throw "CA service must be running before the recovery test; current status is $($serviceInfo.Service.Status)."
}
if (-not (Test-Path -LiteralPath $serviceInfo.StepCaExe) -or
    -not (Test-Path -LiteralPath $serviceInfo.StepExe) -or
    -not (Test-Path -LiteralPath $serviceInfo.RootCertificate)) {
    throw 'The step-ca binary, step CLI, or CA root certificate is missing; cannot validate service recovery.'
}
if (-not (Test-CaHealth -ServiceInfo $serviceInfo)) {
    throw 'The CA health check failed before the recovery test. Fix the existing issue before testing recovery.'
}

$initialDetails = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
$initialProcesses = @(Get-CimInstance Win32_Process)
$stepCaProcess = Get-StepCaChildProcess -WrapperProcessId ([int]$initialDetails.ProcessId) -ExpectedExecutable $serviceInfo.StepCaExe -Processes $initialProcesses
if (-not $stepCaProcess) {
    throw 'Could not identify step-ca.exe as a child of the CA service wrapper; no process was terminated.'
}

Write-Warning "This test will interrupt CA requests while Windows restarts step-ca.exe. The configured first restart delay is 10 seconds."
Write-Host "Identified step-ca.exe process ID $($stepCaProcess.ProcessId)."
if ((Read-Host 'Type CRASH to terminate only this step-ca.exe process and test service recovery') -cne 'CRASH') {
    throw 'Recovery-test confirmation did not match. No process was terminated.'
}

$failedProcessId = [int]$stepCaProcess.ProcessId
Stop-Process -Id $failedProcessId -Force
$deadline = (Get-Date).AddSeconds($RecoveryTimeoutSeconds)
$recovered = $false
$recoveredProcessId = $null

while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 2
    $serviceInfo = Get-ServiceDetails -Name $serviceName
    $currentDetails = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    if ($serviceInfo.Service.Status -eq 'Running' -and $currentDetails.ProcessId -gt 0) {
        $processes = @(Get-CimInstance Win32_Process)
        $currentStepCa = Get-StepCaChildProcess -WrapperProcessId ([int]$currentDetails.ProcessId) -ExpectedExecutable $serviceInfo.StepCaExe -Processes $processes
        if ($currentStepCa -and [int]$currentStepCa.ProcessId -ne $failedProcessId -and
            (Test-CaHealth -ServiceInfo $serviceInfo)) {
            $recovered = $true
            $recoveredProcessId = [int]$currentStepCa.ProcessId
            break
        }
    }
}

if (-not $recovered) {
    Write-Warning "Automatic recovery was not verified within $RecoveryTimeoutSeconds seconds."
    try {
        & $serviceInfo.WrapperPath restart
        if ($LASTEXITCODE -ne 0) { Write-Warning 'The fallback WinSW restart command failed.' }
    }
    catch { Write-Warning "Could not start the CA service after the failed recovery test: $_" }
    throw "Recovery test failed. Check WinSW and CA logs under $(Join-Path $DataRoot 'logs')."
}

Write-Host "Recovery verified: step-ca.exe restarted as process $recoveredProcessId and the CA health check passed."

