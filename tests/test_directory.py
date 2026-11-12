import ssl
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from ldap3 import MOCK_SYNC, Connection
from ldap3.core.exceptions import LDAPSocketOpenError

from ldapauth.certificates import CertificateStore
from ldapauth.directory import AuthenticationFailed, Directory, DirectoryUnavailable


@pytest.fixture
def directory(settings, tmp_path):
    return Directory(settings, CertificateStore(tmp_path))


@pytest.fixture
def connections(directory, monkeypatch):
    entry = SimpleNamespace(
        entry_dn="CN=Alice,OU=Users,DC=example,DC=com",
        entry_attributes_as_dict={
            "sAMAccountName": ["Alice"],
            "displayName": ["Alice Example"],
            "mail": ["alice@example.com"],
            "memberOf": ["CN=HA-Users,OU=Groups,DC=example,DC=com"],
        },
    )
    lookup = Mock(entries=[entry], result={"result": 0})
    lookup.bind.return_value = True
    user = Mock(result={"result": 0})
    user.bind.return_value = True
    factory = Mock(side_effect=[lookup, user])
    monkeypatch.setattr(directory, "_connection", factory)
    return SimpleNamespace(lookup=lookup, user=user, entry=entry, factory=factory)


def test_standard_user(directory, connections):
    identity = directory.authenticate("Alice", "secret")
    assert identity.username == "alice"
    assert identity.name == "Alice Example"
    assert identity.is_admin is False
    connections.user.unbind.assert_called_once()
    connections.lookup.unbind.assert_called_once()
    assert connections.factory.call_args_list[1].args[1:] == (connections.entry.entry_dn, "secret")


def test_full_access_group_dn_is_used_without_appending_base(directory, connections):
    directory.settings = replace(
        directory.settings, user_group="CN=HA-Users,OU=Groups,DC=example,DC=com"
    )
    assert directory.authenticate("alice", "secret").is_admin is False


def test_full_group_dns_work_without_a_shared_base(directory, connections):
    directory.settings = replace(
        directory.settings,
        groups_base_dn="",
        user_group="CN=HA-Users,OU=Groups,DC=example,DC=com",
        admin_group="CN=HA-Admins,OU=Privileged Groups,DC=example,DC=com",
    )
    connections.entry.entry_attributes_as_dict["memberOf"].append(
        "CN=HA-Admins,OU=Privileged Groups,DC=example,DC=com"
    )
    assert directory.settings.configured
    assert directory.authenticate("alice", "secret").is_admin is True


def test_full_group_dn_does_not_bypass_membership(directory, connections):
    directory.settings = replace(
        directory.settings, user_group="CN=HA-Other,OU=Groups,DC=example,DC=com"
    )
    with pytest.raises(AuthenticationFailed):
        directory.authenticate("alice", "secret")
    connections.user.bind.assert_not_called()


@pytest.mark.parametrize(
    "group",
    [
        "HA-Users",
        "CN=HA-Users,OU=Groups,DC=example,DC=com",
        "cn=ha-users, OU=Groups, DC=example, DC=com",
    ],
)
def test_ldap_client_authenticates_cn_and_full_dn(settings, tmp_path, monkeypatch, group):
    service_dn = "CN=Lookup,OU=Service Accounts,DC=example,DC=com"
    user_dn = "CN=Alice,OU=Users,DC=example,DC=com"
    settings = replace(
        settings,
        ldap_server="ldap://dc.example.test",
        enable_ldaps=False,
        bind_user=service_dn,
        user_group=group,
        admin_group="",
    )
    directory = Directory(settings, CertificateStore(tmp_path))

    def connection_factory(server, user, password):
        connection = Connection(server, user=user, password=password, client_strategy=MOCK_SYNC)
        connection.strategy.add_entry(
            service_dn,
            {
                "objectClass": ["person", "user"],
                "userPassword": "lookup-secret",
            },
        )
        connection.strategy.add_entry(
            user_dn,
            {
                "objectClass": ["person", "user"],
                "objectCategory": "person",
                "sAMAccountName": "Alice",
                "userPrincipalName": "alice@example.com",
                "displayName": "Alice Example",
                "mail": "alice@example.com",
                "memberOf": ["CN=HA-Users,OU=Groups,DC=example,DC=com"],
                "userPassword": "user-secret",
            },
        )
        return connection

    monkeypatch.setattr(directory, "_connection", connection_factory)
    for username in ("alice", "alice@example.com"):
        identity = directory.authenticate(username, "user-secret")
        assert identity.username == "alice"
        assert identity.name == "Alice Example"
        assert identity.is_admin is False
    with pytest.raises(AuthenticationFailed, match="invalid_credentials"):
        directory.authenticate("alice", "incorrect")


def test_administrator_requires_both_groups(directory, connections):
    connections.entry.entry_attributes_as_dict["memberOf"].append(
        "CN=HA-ADMINS,OU=Groups,DC=example,DC=com"
    )
    assert directory.authenticate("alice", "secret").is_admin is True


def test_admin_alone_has_no_access(directory, connections):
    connections.entry.entry_attributes_as_dict["memberOf"] = [
        "CN=HA-Admins,OU=Groups,DC=example,DC=com"
    ]
    with pytest.raises(AuthenticationFailed):
        directory.authenticate("alice", "secret")
    connections.lookup.unbind.assert_called_once()
    connections.user.bind.assert_not_called()


@pytest.mark.parametrize("entries", [[], ["duplicate", "duplicate"]])
def test_unique_user_required(directory, connections, entries):
    connections.lookup.entries = entries
    with pytest.raises(AuthenticationFailed):
        directory.authenticate("alice", "secret")
    connections.lookup.unbind.assert_called_once()


def test_invalid_password(directory, connections):
    connections.user.bind.return_value = False
    connections.user.result = {"result": 49}
    with pytest.raises(AuthenticationFailed):
        directory.authenticate("alice", "incorrect")
    connections.user.unbind.assert_called_once()
    connections.lookup.unbind.assert_called_once()


@pytest.mark.parametrize("stage", ["lookup_bind", "search", "user_bind", "socket"])
def test_directory_failures_close_connections(directory, connections, stage):
    if stage == "lookup_bind":
        connections.lookup.bind.return_value = False
    elif stage == "search":
        connections.lookup.result = {"result": 4}
    elif stage == "user_bind":
        connections.user.bind.return_value = False
        connections.user.result = {"result": 52}
    else:
        connections.lookup.search.side_effect = LDAPSocketOpenError("secret internal message")
    with pytest.raises(DirectoryUnavailable):
        directory.authenticate("alice", "secret")
    connections.lookup.unbind.assert_called_once()


def test_escape_username_group_and_metadata(directory, connections):
    directory.settings = replace(directory.settings, user_group="HA,Users")
    connections.entry.entry_attributes_as_dict["memberOf"] = [
        r"CN=HA\,Users,OU=Groups,DC=example,DC=com"
    ]
    connections.entry.entry_attributes_as_dict["displayName"] = ["Alice\ngroup = system-admin"]
    identity = directory.authenticate("*)(objectClass=*)", "secret")
    query = connections.lookup.search.call_args.args[1]
    assert r"\2a\29\28objectClass=\2a\29" in query
    assert "\n" not in identity.name
    assert identity.is_admin is False


def test_missing_password_never_binds(directory, connections):
    with pytest.raises(AuthenticationFailed):
        directory.authenticate("alice", "")
    connections.factory.assert_not_called()


def test_server_tls_and_referral_policy(directory, ca):
    directory.certificates.upload(ca.pem)
    server = directory._server()
    assert server.ssl is True
    assert server.tls.validate == ssl.CERT_REQUIRED
    assert server.tls.sni == "dc.example.com"
    assert server.tls.ca_certs_data == ca.pem.decode()
    connection = directory._connection(server, "u", "p")
    assert connection.auto_referrals is False
    assert connection.receive_timeout == 5
    directory.settings = replace(directory.settings, ldaps_verify=False)
    assert directory._server().tls.validate == ssl.CERT_NONE
    directory.settings = replace(directory.settings, ldap_server="ldap://dc", enable_ldaps=False)
    assert directory._server().ssl is False


def test_check_bind_success_and_failure(directory, connections):
    directory.check()
    connections.lookup.unbind.assert_called_once()
    connections.user.bind.return_value = False
    with pytest.raises(DirectoryUnavailable):
        directory.check()
    connections.user.unbind.assert_called_once()


def test_missing_admin_group_and_display_name(directory, connections):
    directory.settings = replace(directory.settings, admin_group="")
    connections.entry.entry_attributes_as_dict.pop("displayName")
    assert directory.authenticate("alice", "secret").is_admin is False
