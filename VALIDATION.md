# Validation — 12 November 2026

Local checks for version 3.0.0, run on Windows before any commit or push:

| Check | Result |
| --- | --- |
| Python 3.13.1 test suite | 95 passed, 1 skipped |
| Python 3.14.8 test suite | 95 passed, 1 skipped |
| Python statement coverage | 94% overall; certificate and settings modules 100% |
| Real TLS handshakes | Trusted CA and matching hostname accepted; untrusted CA and mismatched hostname rejected |
| HTTP and authentication | API-key enforcement, Ingress TCP-peer isolation, CSRF, input/body limits, roles, rate limits and worker availability passed |
| Production application lifecycle | Both listeners start; health endpoint responds; worker pool closes on shutdown |
| Browser workflow, Chrome 157 | Ingress URL prefix, connection test, certificate upload, script download, removal/cancel, language switching, light/dark presentation and mobile layout passed |
| Browser errors | No JavaScript exceptions or failed HTTP responses during the tested workflow |
| Python dependency audit | No known vulnerabilities in the resolved production dependencies or the updated local test environment |
| npm dependency audit | No known vulnerabilities |
| Alpine/Python 3.14 dependencies | Binary wheels resolved for both musllinux ARM64 and AMD64 |
| Ruff, Prettier, JavaScript syntax, Bash syntax | Passed |
| Git whitespace checks | Passed |
| Published configuration failure | Reproduced YAML parsing failure from merge-conflict markers; corrected local metadata passes packaging checks |
| Merge-conflict protection | Checks app files, repository metadata, README and CI definitions; detected all three affected files before the fix and passes afterward |
| PNG branding | Icon 128 × 128; logo 440 × 100; generated from editable SVG sources |

The skipped test checks POSIX mode `0600`, which Windows cannot enforce. The Linux CI job runs it. ldap3 emits two upstream pyasn1 deprecation warnings; these did not cause failures.

Browser screenshots are written locally to the ignored `test-results/` directory. Test certificates, private keys, dependency caches and virtual environments are also ignored by Git.

## Remaining host validation

This machine has no Docker runtime or installed WSL distribution. The following checks therefore **have not been run locally**:

- Linux container builds and S6 startup on amd64/aarch64.
- AppArmor parser validation, profile loading, enforcement and audit output.
- The actual Home Assistant security score, Ingress session authorization and Core-to-app hostname resolution.
- Authentication against a real Active Directory domain, including regular-user and administrator account creation.

GitHub Actions is configured to lint, test Python 3.13/3.14, audit dependencies, parse AppArmor, run ShellCheck, exercise the browser workflow, build both container architectures and verify container startup/health. These workflows have not been executed remotely during this task.

## Upgrade review

Before using 3.0.0 for AD sign-in, install the configured Python wrapper downloaded from Ingress and update the Home Assistant provider configuration. Review existing users' roles manually: the previous wrapper emitted unsupported role metadata. See [migration instructions](ldapauth/DOCS.md#upgrading-from-2x).
