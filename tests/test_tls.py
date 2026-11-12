import socket
import ssl
import threading
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from ldap3.core.exceptions import LDAPCertificateError

from ldapauth.certificates import CertificateStore
from ldapauth.directory import Directory


@pytest.fixture
def tls_endpoint(tmp_path, ca):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca.certificate.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .sign(ca.key, hashes.SHA256())
    )
    certificate_file, key_file = tmp_path / "server.pem", tmp_path / "server.key"
    certificate_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate_file, key_file)
    names = []
    context.set_servername_callback(lambda sock, name, ctx: names.append(name))
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(5)

    def serve():
        try:
            client, _ = listener.accept()
            with client:
                client.settimeout(5)
                try:
                    with context.wrap_socket(client, server_side=True) as tls:
                        tls.recv(1)
                except (ssl.SSLError, OSError):
                    pass
        except OSError:
            pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    yield SimpleNamespace(port=listener.getsockname()[1], names=names)
    listener.close()
    thread.join(timeout=6)
    assert not thread.is_alive()


@pytest.mark.parametrize(
    "trusted,hostname,success",
    [(True, "localhost", True), (True, "wrong.example.com", False), (False, "localhost", False)],
)
def test_actual_tls_trust_and_hostname(
    settings, tmp_path, ca, tls_endpoint, trusted, hostname, success
):
    store = CertificateStore(tmp_path)
    if trusted:
        store.upload(ca.pem)
    directory = Directory(
        replace(settings, ldap_server=f"ldaps://{hostname}:{tls_endpoint.port}"), store
    )
    server = directory._server()
    raw_socket = socket.create_connection(("127.0.0.1", tls_endpoint.port), timeout=5)
    connection = SimpleNamespace(server=server, socket=raw_socket)
    try:
        if success:
            server.tls.wrap_socket(connection, do_handshake=True)
            assert connection.socket.version() in {"TLSv1.2", "TLSv1.3"}
            assert tls_endpoint.names == [hostname]
        else:
            with pytest.raises((ssl.SSLError, LDAPCertificateError)):
                server.tls.wrap_socket(connection, do_handshake=True)
    finally:
        connection.socket.close()
