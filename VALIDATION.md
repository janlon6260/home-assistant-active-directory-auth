# Validation — 13 November 2026

Local checks for version 3.0.3, run on Windows. Dependency audits and Alpine binary-availability checks were last run on 12 November 2026; dependency versions have not changed.

| Check | Result |
| --- | --- |
| Python 3.13.1 test suite | 124 passed, 1 skipped |
| Python 3.14.8 test suite | 124 passed, 1 skipped |
| Python statement coverage | 94% overall; certificate and settings modules 100% |
| Real TLS handshakes | Trusted CA and matching hostname accepted; untrusted CA and mismatched hostname rejected |
| HTTP and authentication | API-key enforcement, Ingress TCP-peer isolation, CSRF, input/body limits, roles, rate limits and worker availability passed |
| AD group matching | Reproduced rejected sign-in for a full group DN in 3.0.0; 3.0.1 accepts CN/full DN, casing and separator whitespace and retains required membership and password checks |
| LDAP client regression | ldap3 mock directory exercises lookup, short-name/UPN sign-in and user binds for CN/full-DN access groups |
| Authentication diagnostics | App logs distinguish missing group membership and other denial reasons without exposing submitted credentials |
| Ingress log snapshots | Finite non-cached response; bounded buffer, configured-secret redaction, exception-detail exclusion, received-request counts and last completed HTTP status passed |
| Diagnostics isolation | Direct access and spoofed forwarding headers denied; diagnostics unavailable on the authentication listener |
| Minimal provider environment | Downloaded wrapper succeeds with only provider credentials and no inherited PATH (plus SYSTEMROOT on Windows); configuration examples use Core's absolute Python path |
| Wrapper failure diagnostics | HTTP and connection failures produce stderr diagnostics without echoing submitted credentials, API keys or raw server exceptions |
| Debug option | Incoming HTTP authentication, lookup bind, user search, group matching and user bind emit safe application traces when enabled |
| ShellCheck 0.11.0 | Reproduced SC1008 using the old command; the corrected `--shell=bash` invocation passes |
| Production application lifecycle | Both listeners start; health endpoint responds; worker pool closes on shutdown |
| Browser workflow, Chrome 157 | Ingress URL prefix, diagnostics refresh after an authentication request, connection test, certificate upload, script download, removal/cancel, language switching, light/dark presentation and mobile layout passed |
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

The user's Core output confirms the current sign-in blocker: `/usr/local/bin/python3` starts but cannot open `/config/auth-wrapper.py` because the file is missing. The authentication script must be installed in Core's configuration folder before any request can reach the app. Real AD sign-in has not been verified after correcting that installation.

The native Home Assistant Log tab timeout reported by the user has not been reproduced or verified fixed. SSH output confirms that the 3.0.2 service starts and produces log entries. Version 3.0.3 provides an independent finite log snapshot in Ingress; this alternative passed local HTTP and browser checks but still needs host verification. An [upstream report](https://github.com/home-assistant/supervisor/issues/6844#issuecomment-5170851317) confirmed desktop web protection buffering the native log stream; that cause has not been established in this user's environment.

## Existing CI evidence

Reviewed [run 43326510019](https://github.com/janlon6260/home-assistant-active-directory-auth/actions/runs/43326510019) for commit `ffb8089`:

- Both amd64 and arm64 container builds and startup/health checks passed.
- Browser checks passed.
- Both Python test suites and dependency audits passed.
- The Python 3.13 validation job passed AppArmor syntax validation, then failed on ShellCheck SC1008. The corresponding Python 3.14 job was cancelled during its final validation step.

Version 3.0.2 fixes the ShellCheck invocation, separates validator steps, and disables fail-fast for the Python matrix. This revised workflow has not been run remotely by the assistant.

## Upgrade review

Before using 3.0.0 for AD sign-in, install the configured Python wrapper downloaded from Ingress and update the Home Assistant provider configuration. Review existing users' roles manually: the previous wrapper emitted unsupported role metadata. See [migration instructions](ldapauth/DOCS.md#upgrading-from-2x).
