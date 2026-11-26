# Development CA issuance policy

`scripts/Setup-DevelopmentCaHost.ps1` configures the Windows development CA listener and its certificate issuance controls. The CA listens on HTTPS at the configured port (default `8000`). `step-ca` serves HTTPS using the CA URL and the CA server certificate names created during initialization.

## Allowed DNS names

The script writes an authority-wide X.509 DNS allow-list to `ca.json`. By default, the exact allowed names are the CA DNS name, `localhost`, and the Windows computer name. Add service hostnames with `-AllowedDnsNames` when creating or updating the CA, for example:

```powershell
.\scripts\Setup-DevelopmentCaHost.ps1 `
  -CaDnsName 'dev-ca.example.test' `
  -AllowedDnsNames @('orders.dev.example.test', 'payments.dev.example.test')
```

The list does not accept wildcards. Every DNS SAN in an X.509 request must match an allowed name. The script's post-install checks issue a certificate for `localhost` and confirm that an unlisted name is rejected. The configured list replaces any previous authority X.509 policy when the script applies it, so include every development service DNS name that should be issuable.

## Provisioners and certificate lifetimes

The CA keeps the `dev-admin` JWK provisioner and configures an `acme` provisioner for automated issuance. Keep the `dev-admin` key passphrase private to the CA administrator; service automation should use ACME rather than receive the administrator credential. Remote provisioner management is not enabled by this setup.

Certificate lifetime defaults to 24 hours, has a 5 minute minimum, and a 24 hour maximum. Override the default and maximum with `-DefaultCertificateDuration` and `-MaximumCertificateDuration` using Go duration values such as `12h` or `48h`; the default cannot exceed the maximum. The script verifies that a request above the configured maximum is rejected.

ACME issuance also requires the selected ACME challenge to be reachable and configured for the service hostname. The script does not open firewall ports or validate a complete ACME challenge flow.

## Network exposure and administration

The listener uses `:$Port`, which binds on all interfaces. This script deliberately does not create or change Windows Firewall rules, per the deployment decision for this setup. Therefore, the acceptance requirement that port 8000 be inaccessible from unapproved networks is not met by this script alone. Restrict access with an existing network firewall, VLAN, VPN, or equivalent network control before exposing the CA beyond a trusted development network.

The script does not enable Smallstep Remote Management. CA administration therefore remains local to the host and the `dev-admin` signing credential; possession of that credential still permits issuance for names on the allow-list.

## Applying to an existing installation

Rerunning the script with the same CA version applies the allow-list, duration claims, and ACME provisioner to an existing installation. If those settings change, it restarts the CA service and runs the health and issuance-policy checks. The script does not modify firewall configuration.

