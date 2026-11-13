import logging
from collections import deque


class Diagnostics(logging.Handler):
    def __init__(self, secrets: tuple[str, ...] = ()):
        super().__init__()
        self.lines: deque[str] = deque(maxlen=100)
        self.secrets = tuple(value for value in secrets if value)
        self.auth_requests = 0
        self.last_status: int | None = None
        self.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))

    def emit(self, record: logging.LogRecord) -> None:
        if record.name != "ldapauth" and not record.name.startswith("ldapauth."):
            return
        try:
            message = f"{self.formatter.formatTime(record)} {record.levelname} {record.name}: "
            message += record.getMessage()
        except Exception:
            return
        for secret in self.secrets:
            message = message.replace(secret, "[redacted]")
        self.lines.append(message[:1024])

    def snapshot(self) -> dict:
        self.acquire()
        try:
            return {
                "auth_requests": self.auth_requests,
                "last_status": self.last_status,
                "logs": list(self.lines),
            }
        finally:
            self.release()
