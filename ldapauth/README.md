# Active Directory Authentication

Use your Microsoft Active Directory account to sign in to Home Assistant.

Require membership in an AD access group, optionally grant administrator access to a separate group, and verify your domain controller with LDAPS. Manage trusted CA certificates and test the directory connection from a Home Assistant Ingress panel, in English or Norwegian.

The app uses a production aiohttp server supervised by S6, an AppArmor profile and isolated networking. No host ports are opened.

After installation, complete **Configuration**, start the app and select **Open Web UI**. The panel guides you through certificate upload and Home Assistant authentication setup. The **Documentation** tab includes all options, migration instructions and limitations.

**Upgrading from 2.x:** Replace your old authentication wrapper with the script downloaded from the new panel. Version 3.0 no longer serves unauthenticated requests on host port 8000. Keep a local administrator account available while upgrading.
