# Active Directory Authentication for Home Assistant

Sign in to Home Assistant with Microsoft Active Directory. Control access with AD groups, validate LDAPS using your own certificate authority, and manage certificates directly inside Home Assistant.

- Production aiohttp server supervised by S6, with graceful shutdown and a watchdog.
- Home Assistant Ingress panel, available in English and Norwegian, with light and dark themes.
- Upload public CA certificates as PEM bundles or DER files; no restart required.
- Required access group and an optional administrator group.
- Custom AppArmor profile, isolated container networking and no published host ports.
- A downloadable authentication script with a private, persistent API key.

## Install

Requires Home Assistant OS on **amd64** or **aarch64**.

[![Install Active Directory Authentication in Home Assistant](https://my.home-assistant.io/badges/supervisor_app.svg)](https://my.home-assistant.io/redirect/supervisor_app/?app=62996225_ldapauth&repository_url=https%3A%2F%2Fgithub.com%2Fjanlon6260%2Fhome-assistant-active-directory-auth)

The button opens this app in your own Home Assistant. Confirm adding the repository if prompted, then select **Install**. You can also [add the repository directly](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2Fjanlon6260%2Fhome-assistant-active-directory-auth), or follow the manual steps below.

1. Open **Settings → Apps → App store → ⋮ → Repositories**.
2. Add `https://github.com/janlon6260/home-assistant-active-directory-auth`.
3. Install **Active Directory Authentication**.
4. Complete the **Configuration** tab and start the app.
5. Select **Open Web UI** to upload your AD CA certificate and download your configured authentication script.
6. Follow the panel's sign-in setup steps, or see the [complete documentation](ldapauth/DOCS.md).

**Marketplace:** Home Assistant's Marketplace distributes community integrations, cards, themes and templates. This project runs as a Home Assistant OS app and is installed through **Apps**, rather than Marketplace. See the [Home Assistant repository documentation](https://contributors.home-assistant.io/marketplace/reference/repository-structure/).

## Upgrading from 2.x

Version 3.0 changes the network and authentication setup. **Download and install the new script before relying on AD sign-in.** The old `http://127.0.0.1:8000/auth` wrapper no longer works. Keep the local Home Assistant authentication provider and your current administrator session available during migration. See [migration instructions](ldapauth/DOCS.md#upgrading-from-2x).

## Security rating

The configuration is expected to score **7/8 before installation** and **8/8 once its custom AppArmor profile is loaded**: base 5, Ingress +2, custom AppArmor +1. The installed score depends on the host successfully loading AppArmor. This is a configuration-based expectation, not a Home Assistant certification. See the [official scoring rules](https://contributors.home-assistant.io/apps/reference/security-rating/).

## Development

Create `.venv` with the first command and activate it using the command for your shell before running the remaining commands:

```sh
python -m venv .venv
python -m pip install -r requirements-dev.txt
python -m ruff check .
python -m ruff format --check .
python -m pytest --cov=ldapauth --cov-report=term-missing
python -m pip_audit -r ldapauth/requirements.txt
npm ci
npm run format:check
python -m playwright install chromium
python -m scripts.browser_smoke
```

Tests cover HTTP authorization, Ingress isolation, certificate handling, LDAP access decisions, TLS handshakes and the Home Assistant authentication wrapper. They use synthetic certificates and simulated directory accounts; a real AD/HAOS installation must also be verified before release. GitHub Actions runs the automated checks and builds both supported container architectures without publishing them.

See [validation results and remaining host checks](VALIDATION.md).

Report bugs through [GitHub issues](https://github.com/janlon6260/home-assistant-active-directory-auth/issues). Do not include passwords, downloaded authentication scripts, API keys or directory exports.

<<<<<<< HEAD
Licensed under [Apache-2.0](LICENSE).
=======
| Config field name  | Description                                                                                                           |
| ------------------ | --------------------------------------------------------------------------------------------------------------------- |
| **ldap_server**    | Full LDAP or LDAPS URI to your domain controller (e.g. `ldap://dc1.example.org:389` or `ldaps://dc1.example.org:636`) |
| **bind_user**      | A privileged AD user with permission to search for users and groups (e.g. `ha-bind@example.com`)                |
| **bind_password**  | Password for the bind user                                                                                            |
| **user_base_dn**   | Distinguished Name of the OU containing user accounts                                                                 |
| **groups_base_dn** | Distinguished Name of the OU containing security groups                                                               |
| **user_group**     | Users must be a member of this group to log in                                                                        |
| **admin_group**    | Optional. Users in this group will be marked as admin                                                                 |
| **enable_ldaps**   | Enables secure LDAPS connection (port 636)                                                                            |
| **ldaps_verify**   | Validates the certificate presented by the domain controller                                                          |
| **ldaps_ca_pem**   | Optional text field for pasting PEM certificate if not using `/config/certs/ldap-cert.pem`                            |
| **debug_logging**  | Enables verbose debug output for troubleshooting                                                                      |
>>>>>>> 84ff87661257a50a6147736f22ecdd92426dff54

Editable icon and logo sources live in `branding/`. Regenerate the PNG assets with `python -m scripts.render_branding` (add `--chrome` to use a locally installed Chrome).
