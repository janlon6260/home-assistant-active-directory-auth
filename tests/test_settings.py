from dataclasses import replace

import pytest

from ldapauth.settings import Settings


@pytest.mark.parametrize(
    "value,enabled,expected",
    [
        ("ldap://dc.example.com", False, ("dc.example.com", 389, False)),
        ("ldaps://dc.example.com", False, ("dc.example.com", 636, True)),
        ("dc.example.com", True, ("dc.example.com", 636, True)),
        ("dc.example.com:1389", False, ("dc.example.com", 1389, False)),
        ("ldap://dc.example.com:389", True, ("dc.example.com", 636, True)),
        ("ldaps://[::1]:1636", False, ("::1", 1636, True)),
    ],
)
def test_endpoint(value, enabled, expected):
    assert Settings(ldap_server=value, enable_ldaps=enabled).endpoint() == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "https://example.com",
        "ldaps://user:secret@dc",
        "ldaps://dc/path",
        "ldaps://dc?q=x",
        "ldaps://dc#x",
        "ldap://dc:0",
        "ldap://dc:99999",
        "ldap://dc:abc",
    ],
)
def test_bad_endpoint(value):
    with pytest.raises(ValueError):
        Settings.from_options({"ldap_server": value})


def test_secret_hidden_and_configuration(settings):
    assert settings.configured
    assert "lookup-secret" not in repr(settings)
    assert not replace(settings, user_group="").configured
    assert not replace(settings, bind_password="").configured


def test_short_group_names_require_a_group_base(settings):
    assert not replace(settings, groups_base_dn="").configured
    assert not replace(
        settings, groups_base_dn="", user_group="CN=HA-Users,OU=Groups,DC=example,DC=com"
    ).configured


def test_full_group_names_do_not_require_a_group_base(settings):
    assert replace(
        settings,
        groups_base_dn="",
        admin_group="",
        user_group="CN=HA-Users,OU=Groups,DC=example,DC=com",
    ).configured


def test_old_options_keep_plain_ldap():
    settings = Settings.from_options({"ldap_server": "ldap://dc", "unknown_option": "ignored"})
    assert settings.endpoint() == ("dc", 389, False)


@pytest.mark.parametrize(
    "options", [{"enable_ldaps": "false"}, {"bind_password": None}, {"debug_logging": 1}]
)
def test_option_types(options):
    with pytest.raises(ValueError, match="Invalid option type"):
        Settings.from_options(options)
