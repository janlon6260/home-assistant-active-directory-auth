import ssl
from dataclasses import dataclass

from ldap3 import NONE, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import escape_rdn

from .certificates import CertificateStore
from .settings import Settings

LDAP_TIMEOUT = 5


class AuthenticationFailed(Exception):
    pass


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
        if not username or not password or not self.settings.configured:
            raise AuthenticationFailed
        lookup = user = None
        try:
            server = self._server()
            lookup = self._connection(server, self.settings.bind_user, self.settings.bind_password)
            if not lookup.bind():
                raise DirectoryUnavailable
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
            if lookup.result.get("result") != 0:
                raise DirectoryUnavailable
            if len(lookup.entries) != 1:
                raise AuthenticationFailed
            entry = lookup.entries[0]
            attributes = {
                key.lower(): value for key, value in entry.entry_attributes_as_dict.items()
            }

            def first(key: str, default: str = "") -> str:
                values = attributes.get(key.lower(), [])
                return str(values[0]) if values else default

            groups = {str(group).casefold() for group in attributes.get("memberof", [])}
            required = self._group_dn(self.settings.user_group)
            if required not in groups:
                raise AuthenticationFailed
            user = self._connection(server, entry.entry_dn, password)
            if not user.bind():
                if user.result.get("result") == 49:
                    raise AuthenticationFailed
                raise DirectoryUnavailable
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
            raise DirectoryUnavailable from error
        finally:
            for connection in (user, lookup):
                if connection is not None:
                    try:
                        connection.unbind()
                    except (LDAPException, OSError):
                        pass

    def _group_dn(self, group: str) -> str:
        return f"CN={escape_rdn(group)},{self.settings.groups_base_dn}".casefold()

    def check(self) -> None:
        connection = None
        try:
            if not self.settings.configured:
                raise DirectoryUnavailable
            connection = self._connection(
                self._server(), self.settings.bind_user, self.settings.bind_password
            )
            if not connection.bind():
                raise DirectoryUnavailable
        except (LDAPException, OSError, ValueError) as error:
            raise DirectoryUnavailable from error
        finally:
            if connection is not None:
                try:
                    connection.unbind()
                except (LDAPException, OSError):
                    pass
