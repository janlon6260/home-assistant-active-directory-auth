# Active Directory authentication add-on for Home Assistant

Tested and verified working on Home Assistant OS 2025.5.3 :white_check_mark:

This Home Assistant add-on enables authentication against a Microsoft Active Directory (AD) domain using LDAP.  
It integrates with the Home Assistant `command_line` authentication provider and supports:

- Lookup and verification of AD users via LDAP bind
- Group-based access control
- Optional administrator assignment based on AD group membership (see limitations)
- Seamless integration with existing Home Assistant local users

## Features

- Authenticate users against Active Directory using LDAP over TCP (port 389)
- Match authenticated AD users with existing Home Assistant users (by `username`)
- Automatically creates user account in Home Assistant if none exists
- Optional promotion to admin based on group membership (if supported)
- Supports full names (`displayName` or `cn`) and email from AD

## Installation

1. Open Home Assistant UI
2. Navigate to **Settings → Add-ons → Add-on Store**
3. Click the ⋮ menu in the top-right corner → **Repositories**
4. Add the following repository: https://github.com/janlon6260/home-assistant-active-directory-auth
5. Install the **Active Directory authentication Add-on**

## Configuration

### 1. Home Assistant `configuration.yaml`

Add the `command_line` auth provider to your Home Assistant configuration:

```yaml
homeassistant:
  auth_providers:
    - type: command_line
      name: "Local users"
      command: /config/auth-wrapper.sh
      meta: true

    - type: homeassistant
      name: "Microsoft Active Directory"
      meta: true
```

The command should point to the provided auth-wrapper.sh script, which handles communication with the internal LDAP Flask server (running on port 8000).

### 2. Add-on Configuration UI

When configuring the add-on in the UI, you must provide the following:

| Field              | Description                                                                 |
|--------------------|-----------------------------------------------------------------------------|
| **LDAP-server**     | Full LDAP URI to your domain controller (e.g. `ldap://dc1.example.org:389`) |
| **Bind user**       | A privileged AD user with permission to search for users and groups         |
| **Bind password**   | Password for the bind user                                                  |
| **User base DN**    | Distinguished Name of the OU containing user accounts                       |
| **Group base DN**   | Distinguished Name of the OU containing security groups                     |
| **Allowed AD group**| Users must be a member of this group to log in                              |
| **Admin AD group**  | Optional. Users in this group will be marked as admin (if supported)  

### 3. File: auth-wrapper.sh (placed in the /config folder)
This Bash script is responsible for calling the local Flask server and outputting metadata in the format Home Assistant expects:

```bash
#!/bin/bash

response=$(curl -s -f -X POST \
  --data-urlencode "username=$username" \
  --data-urlencode "password=$password" \
  http://IP-OF-HA:8000/auth)

if [ $? -ne 0 ]; then
  exit 1
fi

USERNAME=$(echo "$response" | jq -r .username)
NAME=$(echo "$response" | jq -r .name)
EMAIL=$(echo "$response" | jq -r .email)
IS_ADMIN=$(echo "$response" | jq -r .is_admin)

[ "$USERNAME" != "null" ] && echo "username = $USERNAME"
[ "$NAME" != "null" ] && echo "name = $NAME"
[ "$EMAIL" != "null" ] && echo "email = $EMAIL"
echo "is_active = true"
if [ "$IS_ADMIN" == "true" ]; then
  echo "is_admin = true"
fi
```

### Notes

- A user will only be allowed to log in if they are a member of the **AD group name set in the config**. 
- Username matching is not available at the moment. Even if a user with the same name exists locally, a new user will be created upon successful authentication
- The administrator flag (`is_admin`) is passed to Home Assistant, but **does not override** local user roles.
- **Administrator privileges are automatically granted when an AD user logs in**. These privileges must be manually revoked from within Home Assistant after the user has been created.

### Security

- Passwords are **never stored**; they are passed directly to Active Directory over **HTTP (localhost only)**.
- The add-on should **only be used in trusted networks**, as communication between HA, the add-on and DC is unencrypted.
- The bind user should have **minimal permissions** — only read access to users and groups.

### Troubleshooting

- Check the **add-on log output** under:  
  `Settings → Add-ons → Active Directory authentication`
- You can test the `/auth` endpoint manually with:

  ```bash
  curl -X POST http://IP-OF-HA:8000/auth \
       -d "username=yourusername" \
       -d "password=yourpassword"

