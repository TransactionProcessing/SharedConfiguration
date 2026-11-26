# Development step-ca recovery

This runbook covers backup and restore of the **online development CA state** created by `scripts/Setup-DevelopmentCaHost.ps1`. It does not define key rotation or replace the separate offline root-key backup described in issue #55.

## What must be recoverable

The default data directory is `C:\ProgramData\Smallstep\DevelopmentCA`. It contains the CA configuration, certificates, encrypted intermediate and provisioner keys, and the certificate database. Preserve these together at a consistent point in time.

The file `secrets\ca-password` is a plaintext passphrase file used for unattended service startup. **Never include it in the backup.** Keep the CA key passphrase and the separate `dev-admin` provisioner passphrase in an approved password manager or other protected secret store. The CA key passphrase is needed to recreate `ca-password` during recovery. The provisioner passphrase is needed to use the JWK provisioner after recovery.

The root private key is not part of the online data directory. Keep its two verified copies on the separate offline USB media created during setup. The root certificate in `certs\root_ca.crt` is public and is included in the online-state backup.

## Create an online-state backup

Run these commands in an elevated PowerShell session while the CA service is running. Use a controlled NTFS backup destination separate from the live `DataRoot`; do not store the backup under the live CA directory or on either of the two USBs dedicated to the offline root key. A different volume on the same disk is convenient, but will not protect against failure of that disk.

```powershell
$serviceName = 'StepCaDevelopment'
$dataRoot = Join-Path $env:ProgramData 'Smallstep\DevelopmentCA'
$backupRoot = 'E:\Smallstep\DevelopmentCA-Recovery'
$backupPath = Join-Path $backupRoot (Get-Date -Format 'yyyyMMdd-HHmmss')

$service = Get-Service -Name $serviceName -ErrorAction Stop
if ($service.Status -ne 'Running') { throw 'Start the CA service before creating a consistent backup.' }
New-Item -ItemType Directory -Path $backupPath -Force | Out-Null
Stop-Service -Name $serviceName -ErrorAction Stop
try {
    robocopy.exe $dataRoot $backupPath /E /COPY:DAT /DCOPY:DAT /R:2 /W:2 `
        /XD (Join-Path $dataRoot 'logs') /XF 'ca-password' 'root_ca_key'
    if ($LASTEXITCODE -ge 8) {
        throw "CA data copy failed (robocopy exit $LASTEXITCODE). Do not use this backup."
    }

    & icacls.exe $backupPath /inheritance:r /grant:r `
        '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /T /C | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not restrict backup folder permissions.' }

    $manifestPath = Join-Path $backupPath 'backup-manifest.csv'
    Get-ChildItem -LiteralPath $backupPath -File -Recurse |
        Get-FileHash -Algorithm SHA256 |
        Select-Object Hash, @{ Name = 'RelativePath'; Expression = { $_.Path.Substring($backupPath.Length).TrimStart('\') } } |
        Export-Csv -LiteralPath $manifestPath -NoTypeInformation
}
finally {
    Start-Service -Name $serviceName -ErrorAction Stop
}
```

Robocopy exit codes below 8 indicate the copy completed; still inspect its summary and confirm the manifest exists. The manifest contains paths and hashes, not key contents. Keep the backup and manifest together in the controlled backup location. Protect the encrypted key files and manifest from alteration or loss. The backup excludes logs, the plaintext CA passphrase file, and any file named `root_ca_key`.

Verify a backup before relying on it:

```powershell
$backupPath = 'E:\Smallstep\DevelopmentCA-Recovery\yyyyMMdd-HHmmss'
$manifestPath = Join-Path $backupPath 'backup-manifest.csv'
$entries = @(Import-Csv -LiteralPath $manifestPath)
$files = @(Get-ChildItem -LiteralPath $backupPath -File -Recurse | Where-Object { $_.FullName -ne $manifestPath })
if ($files.Count -ne $entries.Count) { throw 'Backup file count does not match its manifest.' }
foreach ($entry in $entries) {
    $filePath = Join-Path $backupPath $entry.RelativePath
    if (-not (Test-Path -LiteralPath $filePath)) { throw "Backup file is missing: $($entry.RelativePath)" }
    if ((Get-FileHash -LiteralPath $filePath -Algorithm SHA256).Hash -ne $entry.Hash) {
        throw "Backup hash mismatch: $($entry.RelativePath)"
    }
}
```

Do not delete or overwrite an older known-good backup until the new backup has been checked. A recovery exercise should be performed in a separate test location before relying on a backup.

## Restore the online CA

1. Keep both root-key USB devices disconnected. They are not needed to restore the existing intermediate CA.
2. Stop the service with `Stop-Service -Name StepCaDevelopment`. Preserve the damaged data directory under a different name before restoring anything.
3. Verify the backup files against `backup-manifest.csv` in the backup directory. Restore the backup contents to the original `DataRoot`, preserving the `certs`, `config`, `db`, `valuedb`, and `secrets` subdirectories. Do not restore logs, `ca-password`, or a root private key.
4. Recreate `secrets\ca-password` from the CA key passphrase held in the protected secret store. This example prompts securely, writes BOM-free UTF-8, and applies the required ACL; do not put the passphrase in a command line, script, transcript, or log.

   ```powershell
   $passwordPath = Join-Path $env:ProgramData 'Smallstep\DevelopmentCA\secrets\ca-password'
   $securePassword = Read-Host 'Enter the CA key passphrase' -AsSecureString
   $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
   try {
       $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
       [IO.File]::WriteAllText($passwordPath, $plainPassword, [Text.UTF8Encoding]::new($false))
   }
   finally {
       $plainPassword = $null
       [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
       $securePassword = $null
   }
   & icacls.exe $passwordPath /inheritance:r /grant:r `
       'NT SERVICE\StepCaDevelopment:R' '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
   if ($LASTEXITCODE -ne 0) { throw 'Could not restrict the CA passphrase file.' }
   ```

5. Re-run `Setup-DevelopmentCaHost.ps1` with the same step-ca version, DNS name, port, and `DataRoot`. Its existing-data path reapplies the service ACLs, starts the service, and runs the CA health check. Confirm the service is running and health succeeds before returning the CA to use.
6. Issue a short-lived test leaf certificate and verify it against the restored root. The command prompts for the provisioner password and the temporary leaf-key password:

   ```powershell
   $stepExe = Join-Path $env:ProgramFiles 'Smallstep\step-ca\<STEP_CA_VERSION>\step.exe'
   $dataRoot = Join-Path $env:ProgramData 'Smallstep\DevelopmentCA'
   $testRoot = Join-Path $env:TEMP ("step-ca-recovery-{0}" -f [guid]::NewGuid())
   $rootCertificate = Join-Path $dataRoot 'certs\root_ca.crt'
   $intermediateCertificate = Join-Path $dataRoot 'certs\intermediate_ca.crt'
   New-Item -ItemType Directory -Path $testRoot | Out-Null
   $testCertificate = Join-Path $testRoot 'test.crt'
   $testKey = Join-Path $testRoot 'test.key'
   $testBundle = Join-Path $testRoot 'test-chain.crt'

   try {
       & $stepExe ca certificate 'ca-recovery-check' $testCertificate $testKey `
           --provisioner dev-admin --ca-url 'https://localhost:8000' `
           --root $rootCertificate --san localhost --not-after=5m
       if ($LASTEXITCODE -ne 0) { throw 'Test certificate issuance failed.' }

       $bundle = [IO.File]::ReadAllText($testCertificate) + [Environment]::NewLine +
           [IO.File]::ReadAllText($intermediateCertificate)
       [IO.File]::WriteAllText($testBundle, $bundle, [Text.UTF8Encoding]::new($false))
       & $stepExe certificate verify $testBundle --roots $rootCertificate --host localhost
       if ($LASTEXITCODE -ne 0) { throw 'Test certificate did not chain to the restored root.' }
   }
   finally {
       Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
   }
   ```

7. If the restore fails, stop the service and preserve the failed restore for diagnosis. Do not rerun `step ca init` over restored CA state.

The service identity must remain `NT SERVICE\StepCaDevelopment`. The service needs read access to CA config, certificates, encrypted keys, and `ca-password`; it needs modify access to its database and log directories. The setup script reapplies these permissions when run against an existing installation.

## Recovery limits

- This runbook covers restoring from a verified, matching online-state backup. It does not cover intermediate-key or passphrase rotation, root rotation, or issuing a replacement intermediate after loss of the current one.
- If the intermediate key, its passphrase, or both root-key copies are lost, stop and treat the CA as unrecoverable through this procedure. Preserve the data and plan a separately reviewed replacement-CA/rotation procedure.
- Recovery is not complete until the restored service passes the health check and a test leaf certificate chains to the recorded root fingerprint.

