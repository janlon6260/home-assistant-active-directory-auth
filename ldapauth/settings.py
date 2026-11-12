from dataclasses import dataclass, field
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Settings:
    ldap_server: str = "ldaps://dc.example.com:636"
    bind_user: str = ""
    bind_password: str = field(default="", repr=False)
    user_base_dn: str = ""
    groups_base_dn: str = ""
    user_group: str = ""
    admin_group: str = ""
    enable_ldaps: bool = True
    ldaps_verify: bool = True
    ldaps_ca_pem: str = field(default="", repr=False)
    debug_logging: bool = False

    @classmethod
    def from_options(cls, options: dict) -> "Settings":
        values = {key: value for key, value in options.items() if key in cls.__dataclass_fields__}

        values.setdefault("enable_ldaps", False)
        for key, value in values.items():
            expected = bool if key in {"enable_ldaps", "ldaps_verify", "debug_logging"} else str
            if not isinstance(value, expected):
                raise ValueError(f"Invalid option type: {key}")
        settings = cls(**values)
        settings.endpoint()
        return settings

    def endpoint(self) -> tuple[str, int, bool]:
        raw = self.ldap_server.strip()
        parsed = urlsplit(raw if "://" in raw else f"//{raw}")
        if parsed.scheme not in {"", "ldap", "ldaps"} or not parsed.hostname:
            raise ValueError("ldap_server must be an LDAP/LDAPS URL or hostname")
        if parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
            raise ValueError("ldap_server must not contain credentials, paths or query parameters")
        secure = parsed.scheme == "ldaps" or self.enable_ldaps
        port = parsed.port if parsed.port is not None else (636 if secure else 389)
        if secure and port == 389:
            port = 636
        if not 1 <= port <= 65535:
            raise ValueError("Invalid LDAP port")
        return parsed.hostname, port, secure

    @property
    def configured(self) -> bool:
        return all(
            value.strip()
            for value in (
                self.bind_user,
                self.bind_password,
                self.user_base_dn,
                self.groups_base_dn,
                self.user_group,
            )
        )
