# Development CA service recovery and rollback

The service lifecycle helper is separate from the CA setup script. Run PowerShell as Administrator from the repository root.

## Verify crash recovery

Run:

    .\scripts\Manage-DevelopmentCaService.ps1 -Action TestRecovery

The script verifies the CA is healthy, finds the step-ca.exe process beneath the expected WinSW service wrapper, and requires the operator to type CRASH before terminating that child process. It then waits for Windows/WinSW to restart step-ca.exe and verifies the CA health endpoint. The default recovery timeout is 120 seconds; use -RecoveryTimeoutSeconds to adjust it.

This causes a brief interruption to CA requests. Run it when development services can tolerate that interruption. WinSW's configured first failure action restarts the service after 10 seconds. See the [WinSW failure-action documentation](https://github.com/winsw/winsw/blob/v3/docs/xml-config-file.md#onfailure).

## Uninstall and rollback

To remove only the Windows service registration:

    .\scripts\Manage-DevelopmentCaService.ps1 -Action Uninstall

The helper requires the operator to type UNINSTALL, stops the service, and invokes WinSW uninstall. It preserves the CA configuration, online intermediate key, root certificate, logs, WinSW wrapper, and installed Smallstep binaries. It never deletes the CA data directory.

To roll back, rerun scripts/Setup-DevelopmentCaHost.ps1 with the same CA version, CA address (DNS name or IP), port, and DataRoot. The existing CA files are reused to reinstall and start the Windows service. Keep the offline root-key USB devices unplugged and stored safely.

The helper does not remove certificates from Windows trust stores, delete CA data, or modify firewall rules.

