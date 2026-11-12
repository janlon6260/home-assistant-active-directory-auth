from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from ldapauth.directory import Identity
from ldapauth.server import Runtime
from ldapauth.settings import Settings


@pytest.fixture(scope="session")
def ca_factory():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def make(*, ca=True, days=365, start_days=-1, constraints=True, name="Test AD CA"):
        now = datetime.now(UTC)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now + timedelta(days=start_days))
            .not_valid_after(now + timedelta(days=days))
        )
        if constraints:
            builder = builder.add_extension(x509.BasicConstraints(ca=ca, path_length=None), True)
        certificate = builder.sign(key, hashes.SHA256())
        return SimpleNamespace(
            key=key,
            certificate=certificate,
            pem=certificate.public_bytes(serialization.Encoding.PEM),
            der=certificate.public_bytes(serialization.Encoding.DER),
        )

    return make


@pytest.fixture
def ca(ca_factory):
    return ca_factory()


@pytest.fixture
def settings():
    return Settings(
        ldap_server="ldaps://dc.example.com:636",
        bind_user="lookup@example.com",
        bind_password="lookup-secret",
        user_base_dn="OU=Users,DC=example,DC=com",
        groups_base_dn="OU=Groups,DC=example,DC=com",
        user_group="HA-Users",
        admin_group="HA-Admins",
    )


@pytest.fixture
def runtime(settings, tmp_path):
    directory = Mock()
    directory.authenticate.return_value = Identity(
        "alice", "Alice Example", "alice@example.com", False
    )
    directory.check.return_value = None
    instance = Runtime(settings, tmp_path, directory=directory, legacy_paths=())
    yield instance
    instance.pool.shutdown(wait=True, cancel_futures=True)


@pytest.fixture
async def auth_client(aiohttp_client, runtime):
    from ldapauth.server import create_auth_app

    return await aiohttp_client(create_auth_app(runtime))


@pytest.fixture
async def ingress_client(aiohttp_client, runtime, monkeypatch):
    from ldapauth import server

    monkeypatch.setattr(server, "peer_address", lambda request: server.SUPERVISOR_IP)
    return await aiohttp_client(server.create_ingress_app(runtime))
