[CmdletBinding()]
param(
    [Parameter()]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string] $StepCaVersion,

    [Parameter()]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string] $WinSwVersion = '2.14.0',

    [Parameter()]
    [string] $CaDnsName,

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
    $drives = @(Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DeviceID })
    if ($drives.Count -eq 0) { throw 'No mounted drive volumes were found.' }

    Write-Host 'Mounted drive volumes:'
    $drives | ForEach-Object { Write-Host "  $($_.DeviceID)  $($_.VolumeName)  (drive type $($_.DriveType))" }
    $letter = Read-Host 'Enter the USB drive letter (for example E:)'
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

if (-not $CaDnsName) { $CaDnsName = Read-Host 'Enter the stable DNS name development services will use for the CA' }
if ($CaDnsName -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$') {
    throw 'Enter a DNS hostname (without https:// or a port).'
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

    if ($existingService.Status -ne 'Running') {
        & $winswPath start
        if ($LASTEXITCODE -ne 0) { throw "Could not start existing service; WinSW exit code $LASTEXITCODE." }
    }
    Start-Sleep -Seconds 5
    if ((Get-Service -Name $serviceName).Status -ne 'Running') {
        throw "Existing CA service is not running. Check $logsPath."
    }
    & $stepExe ca health --ca-url "https://localhost:$Port" --root $rootCertificatePath
    if ($LASTEXITCODE -ne 0) { throw "Existing CA health check failed. Check $logsPath." }

    Write-Host 'CA setup already exists and is healthy; no CA files or service configuration were changed.'
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
    $usbRoot = Get-UsbDriveRoot
    $usbRootDirectory = Join-Path $usbRoot 'Smallstep\DevelopmentRoot'
    $usbStepPath = $usbRootDirectory
    if (Test-Path -LiteralPath $usbRootDirectory) {
        throw "$usbRootDirectory already exists. Choose an empty USB location; existing key material will not be overwritten."
    }
    New-Item -ItemType Directory -Path (Join-Path $usbStepPath 'certs'), (Join-Path $usbStepPath 'secrets'), `
        (Join-Path $usbStepPath 'config') -Force | Out-Null
    $usbRootKeyPath = Join-Path $usbStepPath 'secrets\root_ca_key'
    $usbRootCertificatePath = Join-Path $usbStepPath 'certs\root_ca.crt'

    $rootPassword = Read-ConfirmedPassword -Prompt 'Set the offline root CA key passphrase (record it safely; the passphrase file will be temporary)'
    $caPassword = Read-ConfirmedPassword -Prompt 'Set the online intermediate CA key passphrase'
    $provisionerPassword = Read-ConfirmedPassword -Prompt 'Set the development provisioner key passphrase (record it safely; its passphrase file will be temporary)'
    $rootPasswordFile = Join-Path $env:TEMP ("step-root-pass-{0}.txt" -f [guid]::NewGuid())
    $provisionerPasswordFile = Join-Path $env:TEMP ("step-provisioner-pass-{0}.txt" -f [guid]::NewGuid())

    try {
        Write-PasswordFile -Path $rootPasswordFile -Password $rootPassword
        Write-PasswordFile -Path $passwordFilePath -Password $caPassword
        Write-PasswordFile -Path $provisionerPasswordFile -Password $provisionerPassword
        $rootPassword = $null
        $caPassword = $null
        $provisionerPassword = $null
        & icacls.exe $passwordFilePath /inheritance:r /grant:r `
            '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Could not restrict permissions on the CA passphrase file.' }

        New-Item -ItemType Directory -Path $usbStepPath -Force | Out-Null
        $rootArgs = @(
            'certificate', 'create',
            'Transaction Processing Development Root CA',
            $usbRootCertificatePath, $usbRootKeyPath,
            '--profile', 'root-ca',
            '--password-file', $rootPasswordFile
        )
        & $stepExe @rootArgs
        if ($LASTEXITCODE -ne 0) { throw "Root CA creation failed with exit code $LASTEXITCODE." }

        $previousStepPath = $env:STEPPATH
        try {
            $env:STEPPATH = $usbStepPath
            $initArgs = @(
                'ca', 'init',
                '--root', $usbRootCertificatePath,
                '--key', $usbRootKeyPath,
                '--key-password-file', $rootPasswordFile,
                '--name', 'Transaction Processing Development CA',
                '--dns', $CaDnsName,
                '--dns', 'localhost',
                '--dns', $env:COMPUTERNAME,
                '--address', ":$Port",
                '--with-ca-url', "https://${CaDnsName}:$Port",
                '--provisioner', 'dev-admin',
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

    $usbRootKeyPath = Join-Path $usbStepPath 'secrets\root_ca_key'
    $usbRootCertificatePath = Join-Path $usbStepPath 'certs\root_ca.crt'
    $usbIntermediateCertificatePath = Join-Path $usbStepPath 'certs\intermediate_ca.crt'
    $usbIntermediateKeyPath = Join-Path $usbStepPath 'secrets\intermediate_ca_key'
    $usbConfigPath = Join-Path $usbStepPath 'config\ca.json'
    foreach ($requiredFile in @($usbRootKeyPath, $usbRootCertificatePath, $usbIntermediateCertificatePath, $usbIntermediateKeyPath, $usbConfigPath, $passwordFilePath)) {
        if (-not (Test-Path -LiteralPath $requiredFile)) { throw "Expected CA initialization output is missing: $requiredFile" }
    }

    Copy-DirectoryContents -Source (Join-Path $usbStepPath 'certs') -Destination (Join-Path $DataRoot 'certs')
    Copy-DirectoryContents -Source (Join-Path $usbStepPath 'config') -Destination (Join-Path $DataRoot 'config')
    Get-ChildItem -LiteralPath (Join-Path $usbStepPath 'secrets') -File -Force |
        Where-Object { $_.Name -ne 'root_ca_key' } |
        Copy-Item -Destination (Join-Path $DataRoot 'secrets') -Force
    if (Test-Path -LiteralPath (Join-Path $usbStepPath 'db')) {
        New-Item -ItemType Directory -Path (Join-Path $DataRoot 'db') -Force | Out-Null
        Copy-DirectoryContents -Source (Join-Path $usbStepPath 'db') -Destination (Join-Path $DataRoot 'db')
    }
    if (Test-Path -LiteralPath (Join-Path $usbStepPath 'valuedb')) {
        New-Item -ItemType Directory -Path (Join-Path $DataRoot 'valuedb') -Force | Out-Null
        Copy-DirectoryContents -Source (Join-Path $usbStepPath 'valuedb') -Destination (Join-Path $DataRoot 'valuedb')
    }

    $caConfig = Get-Content -LiteralPath $caConfigPath -Raw | ConvertFrom-Json
    $caConfig.root = $rootCertificatePath
    $caConfig.crt = $intermediateCertificatePath
    $caConfig.key = $intermediateKeyPath
    $caConfig.address = ":$Port"
    $dbProperty = $caConfig.PSObject.Properties['db']
    if ($dbProperty -and $caConfig.db) {
        $caConfig.db.dataSource = Join-Path $DataRoot 'db'
        if ($caConfig.db.PSObject.Properties['valueDir'] -and $caConfig.db.valueDir) {
            $caConfig.db.valueDir = Join-Path $DataRoot 'valuedb'
        }
    }
    Write-JsonFile -Path $caConfigPath -Value $caConfig
    $defaultsPath = Join-Path $DataRoot 'config\defaults.json'
    if (Test-Path -LiteralPath $defaultsPath) {
        $defaults = Get-Content -LiteralPath $defaultsPath -Raw | ConvertFrom-Json
        $defaults.root = $rootCertificatePath
        $defaults.'ca-url' = "https://${CaDnsName}:$Port"
        Write-JsonFile -Path $defaultsPath -Value $defaults
    }

    # The USB is the offline root-key store; remove online signing-key copies from it.
    Get-ChildItem -LiteralPath (Join-Path $usbStepPath 'secrets') -File -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -ne $usbRootKeyPath } |
        Remove-Item -Force

    & icacls.exe $passwordFilePath /inheritance:r /grant:r `
        '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not restrict permissions on the CA passphrase file.' }
}

$caConfig = Get-Content -LiteralPath $caConfigPath -Raw | ConvertFrom-Json
$caConfig.address = ":$Port"
Write-JsonFile -Path $caConfigPath -Value $caConfig

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
    <username>$serviceAccount</username>
    <allowservicelogon>true</allowservicelogon>
  </serviceaccount>
</service>
"@
Set-Content -LiteralPath $serviceXmlPath -Value $xml -Encoding utf8

Write-Host ''
if ($usbRootKeyPath) {
    Write-Host 'Remove/eject the USB drive now. It contains the offline root private key.'
    [void](Read-Host 'After ejecting the USB drive, press Enter to install and start the CA service')
    if (Test-Path -LiteralPath $usbRootKeyPath) {
        throw 'The USB drive is still mounted. Eject it before the CA service starts.'
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

Write-Host ''
Write-Host "Development CA is running at https://${CaDnsName}:$Port"
Write-Host "Root certificate: $rootCertificatePath"
if ($usbRootKeyPath) { Write-Host "Root private key (keep offline): $usbRootKeyPath" }
Write-Host 'No Windows Firewall rules were created or changed.'

