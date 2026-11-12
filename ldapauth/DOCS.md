# Configuration and operation

## Prerequisites

- Home Assistant OS on amd64 or aarch64.
- A reachable Microsoft AD domain controller and DNS resolution from Home Assistant.
- A service account with read-only access to the user search base. Domain administrator privileges are unnecessary.
- An AD security group whose **direct members** may sign in.
- For private PKI: the public root/intermediate CA certificate that issued the domain controller certificate.

## Configure the app

Set the following options in the app's **Configuration** tab. Save and restart the app after changing options.

| Option | Example / behavior |
| --- | --- |
| `ldap_server` | `ldaps://dc.example.com:636`; use a DNS name matching the domain controller certificate. A bare hostname or hostname with port is also accepted. |
| `bind_user` | `ha-bind@example.com`, or a full service-account DN. |
| `bind_password` | Password for the read-only lookup account. |
| `user_base_dn` | `OU=Users,DC=example,DC=com`. Searches the subtree. |
| `groups_base_dn` | `OU=Groups,DC=example,DC=com`; parent DN shared by the access groups. |
| `user_group` | `HA-Users`; the group's CN. Required for every user, including administrators. |
| `admin_group` | Optional group CN, e.g. `HA-Admins`. Empty disables administrator assignment. |
| `enable_ldaps` | Default `true` for new installations. Forces TLS; port 389 becomes 636. Existing explicit settings are retained. An `ldaps://` URL always uses TLS. |
| `ldaps_verify` | Default `true`. Validates the certificate chain and server hostname. |
| `ldaps_ca_pem` | Optional public CA PEM bundle, as an alternative to upload. Literal `\n` line breaks are accepted. |
| `debug_logging` | Default `false`. Application diagnostics; LDAP protocol logging stays disabled. |

Use **Open Web UI → Test directory connection** to verify the service-account bind and TLS connection. This does not check a particular user's password or group membership.

## Upload the AD CA certificate

1. Export the issuing **root CA** and, when needed, intermediate CA certificates from your PKI. Use Base-64/PEM or binary DER.
2. Open the app through **Open Web UI**, or enable **Show in sidebar**.
3. Choose or drop a `.pem`, `.cer`, `.crt` or `.der` file, then select **Upload certificate**.
4. Check the displayed subject, issuer, expiry and SHA-256 fingerprint against your CA's published values.
5. Test the directory connection.

Files must be smaller than 128 KiB. PEM bundles can contain multiple CA certificates. The app rejects private keys, malformed files, expired/not-yet-valid certificates and certificates without the CA basic constraint. Upload the **issuing CA**, not the domain controller's leaf certificate. PFX/PKCS#12 is not supported.

Uploads are atomically saved with private permissions to `/data/certificates/ad-ca.pem`, included in app backups, and used on the next directory connection. Existing connections may finish using their previous trust snapshot. No app restart is needed.

Trust source priority:

1. Certificate uploaded through Ingress.
2. `ldaps_ca_pem` from Configuration.
3. `/homeassistant/certs/ldap-cert.pem` (the existing Home Assistant `/config/certs/ldap-cert.pem` file).
4. `/ssl/ldap-cert.pem`.
5. System CA trust store.

An invalid custom certificate fails closed; it does not silently fall back. **Remove uploaded certificate** removes only the uploaded bundle and returns to the next available source. Certificate trust has no effect on plain LDAP or when server verification is disabled.

## Configure Home Assistant sign-in

1. From the Ingress panel, download **auth-wrapper.py**. This copy includes the app's internal hostname and a private API key. Save it inside the Home Assistant configuration folder as `/config/auth-wrapper.py`, readable only by the account running Core (for example, `chmod 600 /config/auth-wrapper.py`). The file need not be executable.
2. Merge the following into your existing `configuration.yaml`. Keep a single `homeassistant:` section and retain your other authentication providers as needed:

```yaml
homeassistant:
  auth_providers:
    - type: command_line
      name: Active Directory
      command: python3
      args:
        - /config/auth-wrapper.py
      meta: true
    - type: homeassistant
```

3. Check your Home Assistant configuration, restart Core, and test AD sign-in in a private browser window while retaining your local administrator session.

The script uses Python's standard library; Core does not need curl, jq or any extra packages. Credentials arrive through the `username` and `password` environment variables. The script sends them only to the app's internal authentication endpoint and returns a nonzero exit status on errors. It explicitly outputs `group = system-users` for regular users and `group = system-admin` for configured administrator-group members.

The generated script contains a secret. Do not commit it, publish it, or place it in `/config/www`, a shared folder or another public location. The key persists across app restarts and upgrades. Reinstalling the app with its data removed creates a new key; download a fresh script afterward. To rotate a compromised key, stop the app, remove `/data/auth_token` through trusted container administration, restart the app and replace the downloaded script.

## Users and roles

- Users may sign in with `sAMAccountName` or `userPrincipalName`.
- Only a single unambiguous directory match is accepted. A successful user bind and direct membership of the required group are both necessary.
- An administrator must belong to **both** the required access group and the configured administrator group.
- Home Assistant creates a separate command-line-provider account. A similarly named local account is not automatically merged.
- Home Assistant applies the returned name and group when the account is first created. Subsequent AD group changes do **not** change the existing Home Assistant role. Review existing accounts manually under **Settings → People → Users**.
- Every new sign-in checks AD access, but existing Home Assistant sessions and refresh tokens remain managed by Home Assistant. Removing someone from an AD group does not immediately revoke existing sessions; revoke their Home Assistant sessions or disable their account when required.
- Nested groups, primary-group membership and groups in different parent DNs are not supported.
- The command-line provider uses its supplied username as identity. Signing in using different aliases, casing or a UPN instead of a short name can create separate Home Assistant accounts. Use one consistent login format.

See the [official command-line authentication documentation](https://www.home-assistant.io/docs/authentication/providers/#command-line) for metadata and role behavior.

## Network and security

- Port **8099** serves only the Ingress panel. It accepts the actual Supervisor TCP peer `172.30.32.2` and never trusts `X-Forwarded-For` for access control.
- Port **8000** serves only `/auth` and a restricted `/health`. It is reachable on the internal app network and requires the generated bearer key for authentication requests.
- Neither port is published to the host. Host networking and additional container privileges are not requested.
- The panel is administrator-only in Home Assistant. Certificate mutations also require a per-process CSRF token.
- Four bounded LDAP workers keep directory I/O off the HTTP event loop. TCP connect/receive and directory searches have explicit timeouts. Authentication is limited to 10 requests per submitted username and 120 requests overall per minute, per app process.
- Submitted passwords are never persisted or logged. The service-account password remains in Supervisor-managed private options and backups. The downloaded wrapper stores the API key, not the bind password.
- LDAP referrals are disabled to prevent forwarding credentials to other servers. Use verified LDAPS; plain LDAP sends bind credentials without encryption.
- AppArmor allows application reads and private data writes, together with the S6 runtime, read-only certificate files and network operations. Keep Protection mode enabled.
- The broad Home Assistant configuration mount is read-only and exists for legacy CA-file compatibility; the AppArmor profile grants access only to its legacy certificate path.

The expected [security rating](https://contributors.home-assistant.io/apps/reference/security-rating/) is 7/8 before installation and 8/8 when AppArmor loads. Confirm the installed rating and profile enforcement on your HAOS host.

## Upgrading from 2.x

1. Back up the app and Home Assistant configuration. Keep the local provider and an active local administrator session.
2. Upgrade to 3.0. Existing options are retained. Support now follows the current HAOS architectures: amd64 and aarch64.
3. Open the new Ingress panel and test the service-account connection. Existing `/config/certs/ldap-cert.pem` is still supported through the read-only `/homeassistant` mount.
4. Download the new `auth-wrapper.py` and update `configuration.yaml` as above. The old shell wrapper and localhost endpoint stop working because host networking and anonymous `/auth` access have been removed.
5. Restart Core and verify regular-user and administrator logins separately.
6. Review **all existing command-line users' roles**. The old wrapper emitted unsupported metadata and could leave Home Assistant's default administrator group in effect. Correct roles manually; the new script only controls newly created users.

There is now one authoritative `config.yaml`. The old duplicate `config.json` has been removed; defaults live in `options`, while saved values remain owned by Supervisor.

## Troubleshooting

| Symptom | Action |
| --- | --- |
| Setup needed | Fill out the service account, password, user base, group base and required group; save and restart. |
| Directory connection fails | Check DNS, domain-controller port/firewall, service-account password, hostname match and CA validity. |
| Certificate rejected | Export a valid issuing CA as PEM or DER, with the CA basic constraint. Remove all private-key material. |
| Connection test works, login fails | Check direct access-group membership, the user search base, password, account expiry/lockout and a unique username. |
| HTTP 401 from `/auth` | Replace the wrapper with a fresh download, or check the user's credentials and group membership. |
| HTTP 429 | Wait one minute; review repeated login attempts. Limits reset on restart. |
| HTTP 503 | The directory is unavailable or all four workers are occupied; check directory health. |
| Panel says Forbidden | Open the UI through Home Assistant Ingress. Direct LAN access is intentionally unavailable. |
| App fails before starting | Read app logs and HAOS AppArmor audit denials. Validate the profile on your host; do not disable Protection mode as a workaround. |
| Wrapper cannot reach the app | Download it from this installation. Verify Core can resolve the internal app hostname and that the app is running. |

The watchdog checks HTTP service health independently of AD availability, so an AD outage does not cause a restart loop. Enable **Watchdog** in Home Assistant to use automatic health restarts. S6 restarts the service if its process exits.

## Release validation

Automated tests use simulated LDAP responses, a local TLS endpoint and generated test certificates. A real HAOS installation is still needed to verify container startup, AppArmor audit output, Ingress, the displayed security score, internal Core DNS and real AD sign-in on both supported architectures. No claim of live HAOS/AD certification is made by this repository.

Support: [GitHub issues](https://github.com/janlon6260/home-assistant-active-directory-auth/issues). Remove secrets and personal directory information before sharing logs. Licensed under [Apache-2.0](https://github.com/janlon6260/home-assistant-active-directory-auth/blob/main/LICENSE).
