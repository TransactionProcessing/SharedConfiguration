# Development CA client setup

These scripts configure trust and request leaf certificates on client machines. They only use the public root and intermediate certificates; never copy the CA's root or intermediate private keys off the CA host.

## Values to collect from the CA host

Copy these public files from `C:\ProgramData\Smallstep\DevelopmentCA\certs`:

- `root_ca.crt`
- `intermediate_ca.crt`

Obtain the root fingerprint independently from the CA setup record or by running `step certificate fingerprint root_ca.crt` on the CA host. Pass that recorded value to every install/bootstrap script. Do not compute the expected value from the same untrusted copy on the client.

The default CA endpoint in the examples is `192.168.1.175:8000`. Replace it if the CA address changes. The approved server IP SANs currently configured on the CA are development `192.168.1.86` and staging `192.168.1.163`.

## Windows trust and HTTPS check — issue #60

Run PowerShell as Administrator to add the verified public root to the machine-wide Windows root store. The script checks the SHA-256 fingerprint before changing the store and is safe to repeat:

```powershell
.\scripts\Install-DevelopmentCaRoot.ps1 `
  -RootCertificatePath 'C:\temp\root_ca.crt' `
  -ExpectedSha256Fingerprint '<recorded-root-fingerprint>'
```

Check a real service endpoint using the normal operating-system trust behavior. The script does not bypass certificate validation:

```powershell
.\scripts\Test-DevelopmentCaHttps.ps1 -Uri 'https://192.168.1.86:8001/health'
```

Use the actual HTTPS port/path for the service. A service must present a leaf certificate with an IP or DNS SAN matching the URL. Any HTTP status, including 404, proves the TLS handshake completed; certificate, hostname, or connectivity errors fail the check.

## Linux and WSL trust — issue #61

On Ubuntu/Debian (including WSL distributions), install the verified public root:

```bash
sudo ./scripts/Install-DevelopmentCaRoot.sh ./root_ca.crt '<recorded-root-fingerprint>'
./scripts/Test-DevelopmentCaHttps.sh 'https://192.168.1.86:8001/health'
```

The trust store is per Linux distribution. WSL's Windows host trust store does not automatically establish trust inside the Linux distribution. Containers also have their own trust store and need an image rebuild after changes.

## Docker image trust — issue #61

Build the shared runtime image with the verified public root passed as a BuildKit secret. Docker must have BuildKit support enabled:

```powershell
.\scripts\Build-DevelopmentCaDockerImage.ps1 `
  -RootCertificatePath 'C:\temp\root_ca.crt' `
  -ExpectedSha256Fingerprint '<recorded-root-fingerprint>' `
  -ImageName 'txnprocbase:development'
```

The Dockerfile installs only the public root into the image trust store. BuildKit keeps the source file out of the build context and the intermediate build layer. The root will be present in the resulting image's trust store, so treat that image as specific to this development CA. Existing application images must be rebuilt from the updated base and restarted/recreated to use the new trust store.

After building, check TLS from the application container (using an endpoint it can reach):

```sh
docker run --rm --entrypoint /bin/sh txnprocbase:development -c \
  "openssl s_client -connect 192.168.1.86:8001 -verify_ip 192.168.1.86 -verify_return_error </dev/null"
```

An `openssl s_client` exit code of zero and `Verify return code: 0 (ok)` confirm the container trusts the chain and the certificate matches the IP. Use `-verify_hostname` instead of `-verify_ip` when connecting by DNS name.

## Bootstrap and issue a server certificate — issue #62

Run on the Windows server that will host the service. The script downloads a pinned Step CLI release into a temporary folder, checks its published SHA-256 checksum, bootstraps against the expected root fingerprint, then uses the CA's ACME provisioner. The CLI's bootstrap state and downloaded binary are temporary and removed after the run.

For the development server, first make sure inbound TCP port 80 can reach the server from the CA host and that no other process is listening on port 80. Then run PowerShell as the account that will manage the certificate files:

```powershell
.\scripts\Request-DevelopmentServerCertificate.ps1 `
  -CaAddress '192.168.1.175' `
  -ServerIpAddress '192.168.1.86' `
  -RootFingerprint '<recorded-root-fingerprint>' `
  -IntermediateCertificatePath 'C:\temp\intermediate_ca.crt' `
  -OutputDirectory 'C:\ProgramData\TransactionProcessing\Certificates\Development'
```

The default `pfx` output packages the leaf and intermediate certificate into `server.pfx`, prompts for a PFX password, and removes the separate private-key file after packaging. Store the PFX password in the service's secret configuration. Pass `-ServiceIdentity '<Windows service account>'` to grant that identity read access to the generated key file or PFX; the current operator retains read/write access. Use `-OutputFormat pem` for a Linux/container workload; restrict access to `server.key` to the service identity. The script refuses to overwrite existing output files.

The default ACME standalone HTTP-01 challenge starts a temporary listener on TCP port 80 on the target server. If a web server already owns port 80, configure it to serve the ACME challenge webroot and pass `-AcmeChallengeMode webroot -AcmeWebRoot '<webroot>'`. The CA must be able to reach the challenge response from its network. ACME is not a way to avoid the required client reachability.

For staging, repeat the same script on the staging server with `-ServerIpAddress '192.168.1.163'` and a separate output directory. Keep each server's private key on that server; never copy it to the CA host or commit it to Git.

## Scope and follow-up

These scripts establish OS trust, build a trusted development base image, test HTTPS validation, and issue a service leaf certificate. They do not change a service's Kestrel/application configuration, deploy the PFX/key to a service account, or configure automatic renewal/reload. Those changes belong in each service repository and must be completed before the service itself is considered HTTPS-enabled. The service certificates use the CA's current 24-hour default lifetime, so certificate renewal and deployment automation must be planned before relying on them beyond testing.
