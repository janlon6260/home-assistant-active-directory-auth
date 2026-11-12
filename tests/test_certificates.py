import os
from unittest.mock import patch

import pytest

from ldapauth.certificates import MAX_CERTIFICATE_BYTES, CertificateStore, validate_certificate


def test_pem_and_der_normalization(ca):
    pem, details = validate_certificate(ca.der)
    assert pem == ca.pem
    assert details[0]["subject"] == "CN=Test AD CA"
    assert len(details[0]["sha256"].split(":")) == 32
    assert validate_certificate(ca.pem)[0] == ca.pem


def test_bundle(ca, ca_factory):
    other = ca_factory(name="Intermediate")
    pem, details = validate_certificate(ca.pem + other.pem)
    assert len(details) == 2
    assert pem == ca.pem + other.pem


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"garbage",
        b"x" * (MAX_CERTIFICATE_BYTES + 1),
        b"-----BEGIN PRIVATE KEY-----\nsecret",
        b"-----BEGIN CERTIFICATE-----bad-----END CERTIFICATE-----",
    ],
)
def test_invalid_content(data):
    with pytest.raises(ValueError):
        validate_certificate(data)


@pytest.mark.parametrize(
    "options",
    [{"ca": False}, {"constraints": False}, {"days": -1, "start_days": -365}, {"start_days": 1}],
)
def test_unusable_ca(ca_factory, options):
    with pytest.raises(ValueError):
        validate_certificate(ca_factory(**options).pem)


def test_trailing_garbage_or_private_key(ca):
    for data in (ca.pem + b"garbage", ca.pem + b"-----BEGIN RSA PRIVATE KEY-----"):
        with pytest.raises(ValueError):
            validate_certificate(data)


def test_priority_reload_and_removal(tmp_path, ca, ca_factory):
    legacy = tmp_path / "legacy.pem"
    legacy.write_bytes(ca.pem)
    pasted = ca_factory(name="Pasted CA")
    store = CertificateStore(tmp_path, pasted.pem.decode(), (legacy,))
    assert store.status()["source"] == "configuration"
    assert store.trust() == pasted.pem
    store.upload(ca.der)
    assert store.status()["source"] == "uploaded"
    assert store.trust() == ca.pem
    assert store.remove()["source"] == "configuration"
    assert store.trust() == pasted.pem
    store = CertificateStore(tmp_path, legacy_paths=(legacy,))
    assert store.status()["source"] == "file"
    legacy.unlink()
    assert store.status()["source"] == "system"
    assert store.trust() is None


def test_invalid_ca_fails_closed(tmp_path, ca):
    store = CertificateStore(tmp_path, ca.pem.decode())
    store.uploaded.parent.mkdir()
    store.uploaded.write_bytes(b"broken")
    assert store.status()["valid"] is False
    with pytest.raises(ValueError):
        store.trust()


def test_failed_upload_preserves_previous_bundle(tmp_path, ca):
    store = CertificateStore(tmp_path)
    store.upload(ca.pem)
    with pytest.raises(ValueError):
        store.upload(b"bad")
    assert store.trust() == ca.pem
    with patch("ldapauth.certificates.os.replace", side_effect=OSError("disk failure")):
        with pytest.raises(OSError):
            store.upload(ca.pem)
    assert store.trust() == ca.pem
    assert not list(store.uploaded.parent.glob(".upload-*"))


@pytest.mark.skipif(os.name == "nt", reason="POSIX ownership modes are enforced in the container")
def test_private_file_permissions(tmp_path, ca):
    store = CertificateStore(tmp_path)
    store.upload(ca.pem)
    assert store.uploaded.stat().st_mode & 0o777 == 0o600


def test_escaped_pem_and_oversized_legacy_file(tmp_path, ca):
    store = CertificateStore(tmp_path, ca.pem.decode().replace("\n", "\\n"))
    assert store.trust() == ca.pem
    legacy = tmp_path / "oversized.pem"
    legacy.write_bytes(b"x" * (MAX_CERTIFICATE_BYTES + 1))
    store = CertificateStore(tmp_path, legacy_paths=(legacy,))
    assert store.status()["valid"] is False
