import logging
import ssl
from dataclasses import dataclass

from ldap3 import NONE, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars

from .certificates import CertificateStore
from .groups import normalize_dn, resolve_group_dn
from .settings import Settings

LDAP_TIMEOUT = 5
LOGGER = logging.getLogger(__name__)


class AuthenticationFailed(Exception):
    def __init__(self, reason: str = "invalid_credentials"):
        allowed = {
            "invalid_credentials",
            "not_configured",
            "user_not_found",
            "ambiguous_user",
            "required_group_missing",
        }
        self.reason = reason if reason in allowed else "invalid_credentials"
        super().__init__(self.reason)


class DirectoryUnavailable(Exception):
    pass


@dataclass(frozen=True)
class Identity:
    username: str
    name: str
    email: str
    is_admin: bool

    def as_dict(self) -> dict:
        return {
            "username": self.username,
            "name": self.name,
            "email": self.email,
            "is_active": True,
            "is_admin": self.is_admin,
        }


def clean_metadata(value: str) -> str:

    return " ".join(str(value).split())[:256]


class Directory:
    def __init__(self, settings: Settings, certificates: CertificateStore):
        self.settings = settings
        self.certificates = certificates

    def _server(self) -> Server:
        host, port, secure = self.settings.endpoint()
        LOGGER.debug(
            "Preparing directory connection (TLS=%s, verify=%s)", secure, self.settings.ldaps_verify
        )
        tls = None
        if secure:
            ca = self.certificates.trust() if self.settings.ldaps_verify else None
            tls = Tls(
                validate=ssl.CERT_REQUIRED if self.settings.ldaps_verify else ssl.CERT_NONE,
                version=ssl.PROTOCOL_TLS_CLIENT,
                ca_certs_data=ca.decode("ascii") if ca else None,
                sni=host,
            )
        return Server(
            host, port=port, use_ssl=secure, tls=tls, get_info=NONE, connect_timeout=LDAP_TIMEOUT
        )

    def _connection(self, server: Server, user: str, password: str) -> Connection:
        return Connection(
            server,
            user=user,
            password=password,
            receive_timeout=LDAP_TIMEOUT,
            auto_referrals=False,
            raise_exceptions=False,
        )

    def authenticate(self, username: str, password: str) -> Identity:
        LOGGER.debug("LDAP authentication started")
        if not username or not password:
            raise AuthenticationFailed
        if not self.settings.configured:
            raise AuthenticationFailed("not_configured")
        lookup = user = None
        try:
            server = self._server()
            lookup = self._connection(server, self.settings.bind_user, self.settings.bind_password)
            LOGGER.debug("Directory lookup bind started")
            if not lookup.bind():
                LOGGER.debug(
                    "Directory lookup bind rejected (LDAP result=%s)", lookup.result.get("result")
                )
                raise DirectoryUnavailable
            LOGGER.debug("Directory lookup bind succeeded")
            safe = escape_filter_chars(username)
            query = (
                "(&(objectCategory=person)(objectClass=user)"
                f"(|(sAMAccountName={safe})(userPrincipalName={safe})))"
            )
            lookup.search(
                self.settings.user_base_dn,
                query,
                search_scope=SUBTREE,
                size_limit=2,
                time_limit=LDAP_TIMEOUT,
                attributes=["sAMAccountName", "displayName", "cn", "mail", "memberOf"],
            )
            LOGGER.debug(
                "User search completed (entries=%d, LDAP result=%s)",
                len(lookup.entries),
                lookup.result.get("result"),
            )
            if lookup.result.get("result") != 0:
                raise DirectoryUnavailable
            if not lookup.entries:
                raise AuthenticationFailed("user_not_found")
            if len(lookup.entries) != 1:
                raise AuthenticationFailed("ambiguous_user")
            entry = lookup.entries[0]
            attributes = {
                key.lower(): value for key, value in entry.entry_attributes_as_dict.items()
            }

            def first(key: str, default: str = "") -> str:
                values = attributes.get(key.lower(), [])
                return str(values[0]) if values else default

            groups = {normalize_dn(str(group)) for group in attributes.get("memberof", [])}
            required = self._group_dn(self.settings.user_group)
            LOGGER.debug("Required group membership matched: %s", required in groups)
            if required not in groups:
                raise AuthenticationFailed("required_group_missing")
            user = self._connection(server, entry.entry_dn, password)
            LOGGER.debug("User credential bind started")
            if not user.bind():
                LOGGER.debug(
                    "User credential bind rejected (LDAP result=%s)", user.result.get("result")
                )
                if user.result.get("result") == 49:
                    raise AuthenticationFailed
                raise DirectoryUnavailable
            LOGGER.debug("User credential bind succeeded")
            return Identity(
                first("sAMAccountName", username).casefold(),
                clean_metadata(first("displayName", first("cn", username))),
                clean_metadata(first("mail")),
                bool(
                    self.settings.admin_group
                    and self._group_dn(self.settings.admin_group) in groups
                ),
            )
        except (LDAPException, OSError, ValueError) as error:
            LOGGER.debug("Directory operation failed (%s)", type(error).__name__)
            raise DirectoryUnavailable from error
        finally:
            for connection in (user, lookup):
                if connection is not None:
                    try:
                        connection.unbind()
                    except (LDAPException, OSError):
                        pass

    def _group_dn(self, group: str) -> str:
        return resolve_group_dn(group, self.settings.groups_base_dn)

    def check(self) -> None:
        LOGGER.debug("Directory service-account connection test started")
        connection = None
        try:
            if not self.settings.configured:
                raise DirectoryUnavailable
            connection = self._connection(
                self._server(), self.settings.bind_user, self.settings.bind_password
            )
            if not connection.bind():
                LOGGER.debug(
                    "Service-account connection test rejected (LDAP result=%s)",
                    connection.result.get("result"),
                )
                raise DirectoryUnavailable
            LOGGER.debug("Service-account connection test succeeded")
        except (LDAPException, OSError, ValueError) as error:
            LOGGER.debug("Directory connection test failed (%s)", type(error).__name__)
            raise DirectoryUnavailable from error
        finally:
            if connection is not None:
                try:
                    connection.unbind()
                except (LDAPException, OSError):
                    pass
