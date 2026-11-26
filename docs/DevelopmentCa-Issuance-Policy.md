# Development CA issuance policy

`scripts/Setup-DevelopmentCaHost.ps1` configures the Windows development CA listener and its certificate issuance controls. The CA listens on HTTPS at the configured port (default `8000`). `step-ca` serves HTTPS using the CA URL and the CA server certificate names created during initialization.

## Allowed DNS names

The script writes authority-wide X.509 DNS and IP allow-lists to `ca.json`. By default, DNS names are limited to the CA DNS name (when the CA is addressed by DNS), `localhost`, and the Windows computer name. The IP allow-list includes the development server `192.168.1.86` and staging server `192.168.1.163`.

Use `-CaAddress` to set the CA endpoint to either a DNS name or an IPv4 address. The selected endpoint is included in the CA's HTTPS certificate and in the client URL. `-CaDnsName` remains an accepted alias for existing commands. For example, to have clients connect directly to the development server IP:

```powershell
.\scripts\Setup-DevelopmentCaHost.ps1 `
  -StepCaVersion '0.30.2' `
  -CaAddress '192.168.1.86' `
  -Port 8000
```

When clients will connect by IP address, the issued certificate must contain an IP SAN matching that address. To authorize additional server IPs, use `-AllowedIpAddresses`; to add DNS aliases, use `-AllowedDnsNames`:

```powershell
.\scripts\Setup-DevelopmentCaHost.ps1 `
  -CaAddress 'dev-ca.example.test' `
  -AllowedDnsNames @('orders.dev.example.test', 'payments.dev.example.test') `
  -AllowedIpAddresses @('192.168.1.86', '192.168.1.163')
```

Neither list accepts wildcards. Every DNS or IP SAN in an X.509 request must match its corresponding allow-list. The script's checks issue for `localhost` and the listed IPs, then confirm unlisted DNS and IP identities are rejected. Applying the policy replaces any previous authority X.509 policy, so include every server identity that should be issuable.

## Provisioners and certificate lifetimes

The CA keeps the `dev-admin` JWK provisioner and configures an `acme` provisioner for automated issuance. Keep the `dev-admin` key passphrase private to the CA administrator; service automation should use ACME rather than receive the administrator credential. Remote provisioner management is not enabled by this setup.

Certificate lifetime defaults to 24 hours, has a 5 minute minimum, and a 24 hour maximum. Override the default and maximum with `-DefaultCertificateDuration` and `-MaximumCertificateDuration` using Go duration values such as `12h` or `48h`; the default cannot exceed the maximum. The script verifies that a request above the configured maximum is rejected.

ACME issuance also requires the selected ACME challenge to be reachable and configured for the service hostname. The script does not open firewall ports or validate a complete ACME challenge flow.

## Network exposure and administration

The listener uses `:$Port`, which binds on all interfaces. This script deliberately does not create or change Windows Firewall rules, per the deployment decision for this setup. Therefore, the acceptance requirement that port 8000 be inaccessible from unapproved networks is not met by this script alone. Restrict access with an existing network firewall, VLAN, VPN, or equivalent network control before exposing the CA beyond a trusted development network.

The script does not enable Smallstep Remote Management. CA administration therefore remains local to the host and the `dev-admin` signing credential; possession of that credential still permits issuance for names on the allow-list.

## Applying to an existing installation

Rerunning the script with the same CA version applies the allow-list, duration claims, and ACME provisioner to an existing installation. If those settings change, it restarts the CA service and runs the health and issuance-policy checks. The script does not modify firewall configuration.

