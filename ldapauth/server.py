import asyncio
import hashlib
import hmac
import json
import logging
import secrets
import socket
import sys
import time
from collections import OrderedDict, deque
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from aiohttp import web

from . import __version__
from .certificates import MAX_CERTIFICATE_BYTES, CertificateStore, private_write
from .directory import AuthenticationFailed, Directory, DirectoryUnavailable
from .settings import Settings

LOGGER = logging.getLogger(__name__)
SUPERVISOR_IP = "172.30.32.2"
STATIC = Path(__file__).parent / "static"
RUNTIME = web.AppKey("runtime", object)


def peer_address(request: web.Request) -> str:
    peer = request.transport.get_extra_info("peername") if request.transport else None
    return str(peer[0]) if peer else ""


class RateLimit:
    def __init__(self):
        self.users: OrderedDict[str, deque] = OrderedDict()
        self.global_attempts: deque = deque()

    def allow(self, username: str) -> bool:
        now = time.monotonic()
        key = hashlib.sha256(username.casefold().encode()).hexdigest()
        attempts = self.users.setdefault(key, deque())
        self.users.move_to_end(key)
        if len(self.users) > 2048:
            self.users.popitem(last=False)
        for window in (attempts, self.global_attempts):
            while window and window[0] <= now - 60:
                window.popleft()
        if len(attempts) >= 10 or len(self.global_attempts) >= 120:
            return False
        attempts.append(now)
        self.global_attempts.append(now)
        return True


class Runtime:
    def __init__(
        self,
        settings: Settings,
        data_dir: Path,
        directory=None,
        legacy_paths: tuple[Path, ...] = (
            Path("/homeassistant/certs/ldap-cert.pem"),
            Path("/ssl/ldap-cert.pem"),
        ),
    ):
        self.settings = settings
        self.certificates = CertificateStore(data_dir, settings.ldaps_ca_pem, legacy_paths)
        self.directory = directory or Directory(settings, self.certificates)
        token_file = data_dir / "auth_token"
        if not token_file.exists():
            private_write(token_file, secrets.token_urlsafe(48).encode())
        self.auth_token = token_file.read_text().strip()
        if (
            not 32 <= len(self.auth_token) <= 128
            or not self.auth_token.isascii()
            or not all(char.isalnum() or char in "-_" for char in self.auth_token)
        ):
            raise ValueError("Invalid stored authentication token")
        self.csrf_token = secrets.token_urlsafe(32)
        self.rate_limit = RateLimit()
        self.pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="ldap")
        self.slots = asyncio.Semaphore(4)

    async def call_directory(self, function, *args):
        if self.slots.locked():
            raise web.HTTPServiceUnavailable(text="Directory workers are busy. Try again shortly.")
        async with self.slots:
            future = asyncio.get_running_loop().run_in_executor(self.pool, function, *args)
            try:
                return await asyncio.shield(future)
            except asyncio.CancelledError:
                await future
                raise


@web.middleware
async def security_headers(request, handler):
    try:
        response = await handler(request)
    except web.HTTPException as error:
        response = error
    response.headers.update(
        {
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'self'",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        }
    )
    if isinstance(response, web.HTTPException):
        raise response
    return response


@web.middleware
async def ingress_only(request, handler):
    if peer_address(request) != SUPERVISOR_IP:
        raise web.HTTPForbidden(text="Open this application through Home Assistant Ingress.")
    if request.method not in {"GET", "HEAD"}:
        supplied = request.headers.get("X-CSRF-Token", "").encode("utf-8")
        if not hmac.compare_digest(supplied, request.app[RUNTIME].csrf_token.encode("ascii")):
            raise web.HTTPForbidden(text="Refresh the page and try again.")
    return await handler(request)


async def health(request):
    if peer_address(request) not in {SUPERVISOR_IP, "127.0.0.1", "::1"}:
        raise web.HTTPForbidden()
    return web.json_response({"status": "ok", "version": __version__})


async def authenticate(request):
    LOGGER.debug("Authentication request received on the internal endpoint")
    runtime = request.app[RUNTIME]
    supplied = request.headers.get("Authorization", "").encode("utf-8")
    if not hmac.compare_digest(supplied, ("Bearer " + runtime.auth_token).encode("ascii")):
        LOGGER.warning("Authentication script rejected: invalid API key; download a fresh wrapper")
        raise web.HTTPUnauthorized(text="Authentication failed.")
    try:
        if request.content_type == "application/json":
            data = await request.json()
        elif request.content_type == "application/x-www-form-urlencoded":
            data = await request.post()
        else:
            raise web.HTTPUnsupportedMediaType()
    except (ValueError, UnicodeError) as error:
        raise web.HTTPBadRequest(text="Invalid request body.") from error
    if not hasattr(data, "get"):
        raise web.HTTPBadRequest(text="Expected an object.")
    username, password = data.get("username"), data.get("password")
    if (
        not isinstance(username, str)
        or not isinstance(password, str)
        or not username.strip()
        or not password
        or len(username) > 256
        or len(password) > 4096
        or any(ord(c) < 32 for c in username)
        or "\x00" in password
    ):
        raise web.HTTPUnauthorized(text="Authentication failed.")
    try:
        username.encode("utf-8")
        password.encode("utf-8")
    except UnicodeError as error:
        raise web.HTTPUnauthorized(text="Authentication failed.") from error
    if not runtime.rate_limit.allow(username.strip()):
        raise web.HTTPTooManyRequests(text="Try again shortly.", headers={"Retry-After": "60"})
    try:
        identity = await runtime.call_directory(
            runtime.directory.authenticate, username.strip(), password
        )
    except AuthenticationFailed as error:
        LOGGER.info("Directory authentication denied: %s", error.reason)
        raise web.HTTPUnauthorized(text="Authentication failed.") from error
    except DirectoryUnavailable as error:
        LOGGER.warning(
            "Directory authentication unavailable; check configuration, TLS and connectivity"
        )
        raise web.HTTPServiceUnavailable(text="Directory unavailable.") from error
    LOGGER.info("Directory authentication succeeded")
    return web.json_response(identity.as_dict())


async def index(request):
    return web.Response(
        text=(STATIC / "index.html").read_text(encoding="utf-8"), content_type="text/html"
    )


async def asset(request):
    filename = request.match_info["filename"]
    if filename not in {"app.js", "style.css"}:
        raise web.HTTPNotFound()
    return web.Response(
        body=(STATIC / filename).read_bytes(),
        content_type="text/javascript" if filename.endswith(".js") else "text/css",
    )


async def status(request):
    runtime = request.app[RUNTIME]
    settings = runtime.settings
    host, port, secure = settings.endpoint()
    return web.json_response(
        {
            "version": __version__,
            "configured": settings.configured,
            "server": {"host": host, "port": port, "tls": secure, "verify": settings.ldaps_verify},
            "groups": {"users": settings.user_group, "admins": settings.admin_group},
            "certificate": runtime.certificates.status(),
            "csrf_token": runtime.csrf_token,
        }
    )


async def upload_certificate(request):
    if request.content_type != "application/octet-stream":
        raise web.HTTPUnsupportedMediaType(
            text="Upload the certificate as application/octet-stream."
        )
    try:
        result = request.app[RUNTIME].certificates.upload(await request.read())
    except ValueError as error:
        raise web.HTTPBadRequest(text=str(error)) from error
    except OSError as error:
        LOGGER.error("Could not save CA certificate")
        raise web.HTTPInternalServerError(
            text="Could not save the certificate. Check app storage."
        ) from error
    LOGGER.info("CA trust bundle updated through Ingress")
    return web.json_response(result)


async def delete_certificate(request):
    try:
        result = request.app[RUNTIME].certificates.remove()
    except OSError as error:
        raise web.HTTPInternalServerError(
            text="Could not remove the uploaded certificate."
        ) from error
    LOGGER.info("Uploaded CA trust bundle removed through Ingress")
    return web.json_response(result)


async def check_directory(request):
    LOGGER.debug("Directory connection test requested through Ingress")
    runtime = request.app[RUNTIME]
    if not runtime.rate_limit.allow("__connection_check__"):
        raise web.HTTPTooManyRequests(text="Try again shortly.")
    try:
        await runtime.call_directory(runtime.directory.check)
    except DirectoryUnavailable as error:
        LOGGER.warning(
            "Directory connection test failed; check configuration, TLS and connectivity"
        )
        raise web.HTTPBadGateway(
            text="Connection failed. Check the server, bind credentials and CA certificate."
        ) from error
    LOGGER.info("Directory connection test succeeded")
    return web.json_response({"ok": True})


async def download_wrapper(request):
    runtime = request.app[RUNTIME]
    hostname = socket.gethostname().replace("_", "-")
    source = (Path(__file__).parent / "auth-wrapper.py").read_text(encoding="utf-8")
    source = source.replace('"__AUTH_ENDPOINT__"', json.dumps(f"http://{hostname}:8000/auth"))
    source = source.replace('"__AUTH_TOKEN__"', json.dumps(runtime.auth_token))
    return web.Response(
        text=source,
        content_type="text/x-python",
        headers={
            "Content-Disposition": 'attachment; filename="auth-wrapper.py"',
        },
    )


def create_ingress_app(runtime: Runtime) -> web.Application:
    app = web.Application(
        middlewares=[security_headers, ingress_only], client_max_size=MAX_CERTIFICATE_BYTES
    )
    app[RUNTIME] = runtime
    app.add_routes(
        [
            web.get("/", index),
            web.get("/static/{filename}", asset),
            web.get("/api/status", status),
            web.post("/api/certificate", upload_certificate),
            web.delete("/api/certificate", delete_certificate),
            web.post("/api/check", check_directory),
            web.get("/auth-wrapper.py", download_wrapper),
        ]
    )
    return app


def create_auth_app(runtime: Runtime) -> web.Application:
    app = web.Application(middlewares=[security_headers], client_max_size=16 * 1024)
    app[RUNTIME] = runtime
    app.add_routes([web.post("/auth", authenticate), web.get("/health", health)])
    return app


def production_app(data_dir: Path = Path("/data"), *, ingress_port: int = 8099) -> web.Application:
    settings = Settings.from_options(
        json.loads((data_dir / "options.json").read_text(encoding="utf-8"))
    )
    logging.getLogger("ldapauth").setLevel(
        logging.DEBUG if settings.debug_logging else logging.INFO
    )
    logging.getLogger("ldap3").setLevel(logging.WARNING)
    LOGGER.info("Application logging configured (debug=%s)", settings.debug_logging)
    runtime = Runtime(settings, data_dir)
    app = create_auth_app(runtime)

    async def ingress_lifecycle(_app):
        runner = web.AppRunner(
            create_ingress_app(runtime), access_log=None, shutdown_timeout=20, keepalive_timeout=30
        )
        try:
            await runner.setup()
            await web.TCPSite(runner, "0.0.0.0", ingress_port).start()
            LOGGER.info(
                "Active Directory %s started: Ingress 8099, internal authentication 8000",
                __version__,
            )
            if not settings.configured:
                LOGGER.warning("Complete the app configuration before enabling AD sign-in")
            if not settings.endpoint()[2] or not settings.ldaps_verify:
                LOGGER.warning(
                    "LDAP transport is not verified TLS; enable LDAPS and certificate verification"
                )
            yield
        finally:
            await runner.cleanup()
            await asyncio.to_thread(runtime.pool.shutdown, wait=True, cancel_futures=True)

    app.cleanup_ctx.append(ingress_lifecycle)
    return app


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stdout,
        force=True,
    )
    web.run_app(
        production_app(),
        host="0.0.0.0",
        port=8000,
        access_log=None,
        print=None,
        shutdown_timeout=20,
        keepalive_timeout=30,
    )
