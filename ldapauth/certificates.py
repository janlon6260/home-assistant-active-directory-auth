import os
import re
import tempfile
import threading
from datetime import UTC, datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

MAX_CERTIFICATE_BYTES = 128 * 1024
PEM_BLOCK = re.compile(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL)


def validate_certificate(data: bytes) -> tuple[bytes, list[dict]]:
    if not data or len(data) > MAX_CERTIFICATE_BYTES:
        raise ValueError("Choose a certificate file smaller than 128 KiB.")
    if b"PRIVATE KEY" in data:
        raise ValueError("Private keys must never be uploaded. Choose a public CA certificate.")
    try:
        if b"-----BEGIN" in data:
            blocks = PEM_BLOCK.findall(data)
            if not blocks or PEM_BLOCK.sub(b"", data).strip():
                raise ValueError("The file must contain only PEM certificates.")
            certificates = [x509.load_pem_x509_certificate(block) for block in blocks]
        else:
            certificates = [x509.load_der_x509_certificate(data)]
    except ValueError as error:
        raise ValueError("The file is not a valid PEM or DER certificate bundle.") from error
    now = datetime.now(UTC)
    metadata = []
    for cert in certificates:
        try:
            if not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                raise ValueError(
                    "Upload the issuing root/intermediate CA, not the server certificate."
                )
        except x509.ExtensionNotFound as error:
            raise ValueError("The certificate must have the CA basic constraint.") from error
        if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
            raise ValueError("The CA certificate is expired or not yet valid.")
        metadata.append(
            {
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "expires": cert.not_valid_after_utc.isoformat(),
                "sha256": cert.fingerprint(hashes.SHA256()).hex(":"),
            }
        )
    pem = b"".join(cert.public_bytes(serialization.Encoding.PEM) for cert in certificates)
    return pem, metadata


def private_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=".upload-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as target:
            target.write(data)
            target.flush()
            os.fsync(target.fileno())
        os.chmod(name, 0o600)
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


class CertificateStore:
    def __init__(self, data_dir: Path, pasted_pem: str = "", legacy_paths: tuple[Path, ...] = ()):
        self.uploaded = data_dir / "certificates" / "ad-ca.pem"
        self.pasted = pasted_pem.replace("\\n", "\n").strip().encode()
        self.legacy_paths = legacy_paths
        self.lock = threading.RLock()

    def _active(self) -> tuple[str, bytes | None]:
        if self.uploaded.exists():
            return "uploaded", self.uploaded.read_bytes()
        if self.pasted:
            return "configuration", self.pasted
        for path in self.legacy_paths:
            if path.is_file():
                if path.stat().st_size > MAX_CERTIFICATE_BYTES:
                    raise ValueError("The CA certificate file exceeds 128 KiB.")
                return "file", path.read_bytes()
        return "system", None

    def trust(self) -> bytes | None:
        with self.lock:
            _, data = self._active()
            return validate_certificate(data)[0] if data is not None else None

    def status(self) -> dict:
        with self.lock:
            try:
                source, data = self._active()
                certificates = validate_certificate(data)[1] if data is not None else []
                return {
                    "source": source,
                    "valid": True,
                    "certificates": certificates,
                    "uploaded": self.uploaded.exists(),
                }
            except (OSError, ValueError) as error:
                return {
                    "source": "invalid",
                    "valid": False,
                    "error": str(error),
                    "certificates": [],
                    "uploaded": self.uploaded.exists(),
                }

    def upload(self, data: bytes) -> dict:
        pem, _ = validate_certificate(data)
        with self.lock:
            private_write(self.uploaded, pem)
            return self.status()

    def remove(self) -> dict:
        with self.lock:
            self.uploaded.unlink(missing_ok=True)
            return self.status()
