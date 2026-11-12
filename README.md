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

[![Open the Home Assistant app store](https://my.home-assistant.io/badges/supervisor_store.svg)](https://my.home-assistant.io/redirect/supervisor_store/)

The button opens the app store in your own Home Assistant. Add this repository using the steps below, then install the app. Opening the store does not add a repository or install an app automatically.

1. Open **Settings → Apps → App store → ⋮ → Repositories**.
2. If the repository below is not already listed, select **Add**, paste its URL and confirm.
3. Return to the app store, search for **Active Directory Authentication**, open it and select **Install**.
4. Complete the **Configuration** tab and start the app.
5. Select **Open Web UI** to upload your AD CA certificate and download your configured authentication script.
6. Follow the panel's sign-in setup steps, or see the [complete documentation](ldapauth/DOCS.md).

Repository URL:

```text
https://github.com/janlon6260/home-assistant-active-directory-auth
```

If you used an add-repository link and only the app store opened, use steps 1–3 above. Home Assistant skips the confirmation when the repository is already present; an automatic-dialog failure has also been [reported upstream](https://github.com/home-assistant/my.home-assistant.io/issues/698).

**Marketplace:** Home Assistant's Marketplace distributes community integrations, cards, themes and templates. This project runs as a Home Assistant OS app and is installed through **Apps**, rather than Marketplace. See the [Home Assistant repository documentation](https://contributors.home-assistant.io/marketplace/reference/repository-structure/).

## Upgrading from 2.x

Version 3.0 changes the network and authentication setup. **Download and install the new script before relying on AD sign-in.** The old `http://127.0.0.1:8000/auth` wrapper no longer works. Keep the local Home Assistant authentication provider and your current administrator session available during migration. See [migration instructions](ldapauth/DOCS.md#upgrading-from-2x).

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

Licensed under [Apache-2.0](LICENSE).

## Configuration reference

| Config field name  | Description                                                                                                           |
| ------------------ | --------------------------------------------------------------------------------------------------------------------- |
| **ldap_server**    | Full LDAP or LDAPS URI to your domain controller (e.g. `ldap://dc1.example.org:389` or `ldaps://dc1.example.org:636`) |
| **bind_user**      | Read-only AD account used to search for users and groups (e.g. `ha-bind@example.com`)                |
| **bind_password**  | Password for the bind user                                                                                            |
| **user_base_dn**   | Distinguished Name of the OU containing user accounts                                                                 |
| **groups_base_dn** | Parent DN used with short group names; optional when all configured groups use full DNs                               |
| **user_group**     | Required access group, specified as a short name or a full DN                                                         |
| **admin_group**    | Optional group name or full DN; members receive the administrator role when their Home Assistant account is created   |
| **enable_ldaps**   | Enables secure LDAPS connection (port 636)                                                                            |
| **ldaps_verify**   | Validates the certificate presented by the domain controller                                                          |
| **ldaps_ca_pem**   | Optional text field for pasting PEM certificate if not using `/config/certs/ldap-cert.pem`                            |
| **debug_logging**  | Enables verbose debug output for troubleshooting                                                                      |

Editable icon and logo sources live in `branding/`. Regenerate the PNG assets with `python -m scripts.render_branding` (add `--chrome` to use a locally installed Chrome).
