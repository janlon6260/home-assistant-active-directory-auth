# Changelog

## 3.0.3

- Added an Ingress diagnostics view with manual refresh, a bounded in-memory log buffer and authentication request counts, independent of Home Assistant's live log stream.
- Restrict diagnostics to Ingress, redact configured secrets and omit raw exception details.
- Clarified that the downloaded authentication script must be copied from the user's computer into Home Assistant's configuration folder; added troubleshooting for Core's missing-file error.
- Record unexpected authentication failures as HTTP 500 with a safe message.
- Added regression and browser checks for diagnostics, access isolation, request counts and log handling.

## 3.0.2

- Fixed the Home Assistant authentication examples to use `/usr/local/bin/python3`, because the command-line provider does not inherit the normal executable search path.
- Added safe script errors on stderr for missing configuration, connection failures, rejected requests and invalid responses.
- Added application debug traces for the authentication pipeline and directory connection tests, with explicit startup logging to stdout.
- Added tests that run the wrapper with a minimal provider environment and verify safe debug output.
- Fixed ShellCheck SC1008 by selecting Bash explicitly in CI; split validation steps and preserve both Python matrix results when one fails.

## 3.0.1

- Fixed rejected sign-ins when an access or administrator group is specified using its full distinguished name.
- Accept short group names and full DNs; a shared group base is only required for short names.
- Compare group DNs consistently across letter casing and separator whitespace, while retaining direct-membership checks.
- Added safe authentication failure reasons to app logs and a separate warning for outdated script API keys.
- Updated English/Norwegian option descriptions and added LDAP client regression tests for group matching.

## 3.0.0

### Breaking changes

- Replace the old shell authentication wrapper with the configured Python script downloaded through Ingress. Host port 8000 and anonymous authentication requests have been removed.
- Supported HAOS architectures are now amd64 and aarch64.
- Review existing Home Assistant command-line user roles: previous unsupported metadata could result in administrator access. The new wrapper explicitly assigns standard users and optional administrators on account creation.

### Added

- Production aiohttp server with S6 supervision, graceful shutdown and health watchdog.
- Ingress administration panel in English and Norwegian with responsive light/dark presentation.
- Validated public CA certificate upload, expiry/fingerprint display, atomic private storage and live reload for subsequent binds.
- A custom AppArmor profile, isolated networking, CSRF protection and persistent API-key authentication.
- Bounded LDAP workers, connection/search timeouts, authentication rate limits and reliable connection cleanup.
- Automated tests, linting, dependency auditing and container-build CI.
- Complete in-app documentation, configuration translations and migration guidance using current Apps and Marketplace terminology.

### Fixed

- Consolidated conflicting configuration files into one `config.yaml` with proper defaults.
- Corrected Home Assistant provider configuration, metadata and administrator-role behavior.
- Escaped usernames and group RDNs, disabled referrals and rejected ambiguous directory matches.
- Removed unnecessary writable shared-folder access and public diagnostics.
- Resolved merge conflicts in app metadata and container packaging that prevented Supervisor from discovering the app.

## 2.0.1
Fix:
- Fixed installation failure on recent Home Assistant OS and Supervisor versions.
- Removed dependency on the deprecated BUILD_FROM build argument.
- Explicitly defined the Home Assistant base image in the Dockerfile to ensure compatibility with the updated Supervisor build system.

## 2.0.0
- Added LDAPS support

## 1.0.3
- Moved `options` to `config.json` to preserve user configuration during updates
- Minor improvements to metadata

## 1.0.0
- Initial release with Active Directory authentication via LDAP
