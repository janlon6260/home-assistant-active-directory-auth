# Changelog

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
