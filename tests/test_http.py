import asyncio
from unittest.mock import Mock

import pytest

from ldapauth import server
from ldapauth.certificates import MAX_CERTIFICATE_BYTES
from ldapauth.directory import AuthenticationFailed, DirectoryUnavailable
from ldapauth.server import RateLimit, Runtime, create_ingress_app


def headers(runtime):
    return {"Authorization": "Bearer " + runtime.auth_token}


async def test_auth_requires_key(auth_client, runtime):
    response = await auth_client.post("/auth", json={"username": "alice", "password": "secret"})
    assert response.status == 401
    runtime.directory.authenticate.assert_not_called()
    assert response.headers["Cache-Control"] == "no-store"


async def test_non_ascii_key_is_rejected(auth_client):
    response = await auth_client.post(
        "/auth",
        headers={"Authorization": "Bearer æøå"},
        json={"username": "alice", "password": "secret"},
    )
    assert response.status == 401


async def test_invalid_unicode_credentials_are_denied(auth_client, runtime):
    response = await auth_client.post(
        "/auth", headers=headers(runtime), json={"username": "bad\ud800", "password": "secret"}
    )
    assert response.status == 401
    runtime.directory.authenticate.assert_not_called()


async def test_production_startup_and_shutdown(aiohttp_client, settings, tmp_path):
    import json
    from dataclasses import asdict

    (tmp_path / "options.json").write_text(json.dumps(asdict(settings)), encoding="utf-8")
    app = server.production_app(tmp_path, ingress_port=0)
    client = await aiohttp_client(app)
    response = await client.get("/health")
    assert response.status == 200
    assert (await client.get("/api/status")).status == 404
    runtime = app[server.RUNTIME]
    assert len(runtime.auth_token) >= 32
    await client.close()

    with pytest.raises(RuntimeError, match="shutdown"):
        runtime.pool.submit(lambda: None)


async def test_debug_option_produces_safe_application_traces(
    aiohttp_client, settings, tmp_path, caplog, monkeypatch
):
    import json
    import logging
    from dataclasses import asdict, replace

    logger = logging.getLogger("ldapauth")
    monkeypatch.setattr(logger, "level", logger.level)
    settings = replace(settings, debug_logging=True)
    (tmp_path / "options.json").write_text(json.dumps(asdict(settings)), encoding="utf-8")
    with caplog.at_level(logging.DEBUG):
        app = server.production_app(tmp_path, ingress_port=0)
        runtime = app[server.RUNTIME]
        runtime.directory = Mock()
        runtime.directory.authenticate.side_effect = AuthenticationFailed("required_group_missing")
        client = await aiohttp_client(app)
        response = await client.post(
            "/auth", headers=headers(runtime), json={"username": "alice", "password": "user-secret"}
        )
        await client.close()
    assert response.status == 401
    assert "Application logging configured (debug=True)" in caplog.text
    assert "Authentication request received on the internal endpoint" in caplog.text
    assert "required_group_missing" in caplog.text
    assert "alice" not in caplog.text
    assert "user-secret" not in caplog.text
    assert runtime.auth_token not in caplog.text


async def test_auth_success_json_and_form(auth_client, runtime):
    for arguments in (
        {"json": {"username": "Alice", "password": "secret"}},
        {"data": {"username": "Alice", "password": "secret"}},
    ):
        response = await auth_client.post("/auth", headers=headers(runtime), **arguments)
        assert response.status == 200
        identity = await response.json()
        assert identity["is_admin"] is False
        assert identity["is_active"] is True


@pytest.mark.parametrize(
    "payload,status",
    [
        ({}, 401),
        ({"username": "alice", "password": ""}, 401),
        ({"username": "alice\nfoo", "password": "secret"}, 401),
        ({"username": "alice", "password": 123}, 401),
        ({"username": "alice", "password": "a\x00b"}, 401),
        ([], 400),
        ({"username": "a" * 257, "password": "secret"}, 401),
    ],
)
async def test_invalid_auth_body(auth_client, runtime, payload, status):
    response = await auth_client.post("/auth", headers=headers(runtime), json=payload)
    assert response.status == status
    runtime.directory.authenticate.assert_not_called()


async def test_malformed_unsupported_and_oversized_auth(auth_client, runtime):
    response = await auth_client.post("/auth", headers=headers(runtime), data=b"bad")
    assert response.status == 415
    response = await auth_client.post(
        "/auth", headers={**headers(runtime), "Content-Type": "application/json"}, data=b"{"
    )
    assert response.status == 400
    response = await auth_client.post(
        "/auth", headers=headers(runtime), json={"username": "alice", "password": "x" * 17000}
    )
    assert response.status == 413


@pytest.mark.parametrize("error,status", [(AuthenticationFailed, 401), (DirectoryUnavailable, 503)])
async def test_auth_denied_without_secret_leak(auth_client, runtime, caplog, error, status):
    runtime.directory.authenticate.side_effect = error("password=super-secret")
    response = await auth_client.post(
        "/auth", headers=headers(runtime), json={"username": "alice", "password": "secret"}
    )
    assert response.status == status
    assert "super-secret" not in await response.text()
    assert "super-secret" not in caplog.text
    assert "alice" not in caplog.text


async def test_group_denial_reason_is_logged_without_exposing_details(auth_client, runtime, caplog):
    runtime.directory.authenticate.side_effect = AuthenticationFailed("required_group_missing")
    with caplog.at_level("INFO", logger="ldapauth.server"):
        response = await auth_client.post(
            "/auth", headers=headers(runtime), json={"username": "alice", "password": "secret"}
        )
    assert response.status == 401
    assert "required_group_missing" in caplog.text
    assert "required_group_missing" not in await response.text()
    assert "alice" not in caplog.text
    assert "secret" not in caplog.text


async def test_auth_rate_limit(auth_client, runtime):
    for _ in range(10):
        response = await auth_client.post(
            "/auth", headers=headers(runtime), json={"username": "alice", "password": "secret"}
        )
        assert response.status == 200
    response = await auth_client.post(
        "/auth", headers=headers(runtime), json={"username": "ALICE", "password": "secret"}
    )
    assert response.status == 429
    assert response.headers["Retry-After"] == "60"


def test_rate_limit_global_expiry_and_memory_bound(monkeypatch):
    now = 100.0
    monkeypatch.setattr(server.time, "monotonic", lambda: now)
    limit = RateLimit()
    for number in range(120):
        assert limit.allow(f"user{number}")
    assert not limit.allow("another")
    now += 61
    assert limit.allow("another")
    for number in range(3000):
        limit.allow(str(number))
    assert len(limit.users) <= 2048


async def test_busy_workers_return_503(auth_client, runtime):
    for _ in range(4):
        await runtime.slots.acquire()
    try:
        response = await auth_client.post(
            "/auth", headers=headers(runtime), json={"username": "alice", "password": "secret"}
        )
        assert response.status == 503
        runtime.directory.authenticate.assert_not_called()
    finally:
        for _ in range(4):
            runtime.slots.release()


async def test_health_independent_of_directory(auth_client, runtime):
    runtime.directory.check.side_effect = DirectoryUnavailable
    response = await auth_client.get("/health")
    assert response.status == 200
    assert (await response.json())["status"] == "ok"
    for path in ("/", "/api/status", "/diagnose", "/auth-wrapper.py"):
        assert (await auth_client.get(path)).status == 404


async def test_direct_ingress_and_spoofed_headers_denied(aiohttp_client, runtime):
    client = await aiohttp_client(create_ingress_app(runtime))
    for path in ("/", "/api/status", "/auth-wrapper.py", "/static/app.js"):
        response = await client.get(
            path, headers={"X-Forwarded-For": server.SUPERVISOR_IP, "X-Remote-User-Id": "owner"}
        )
        assert response.status == 403


async def test_ingress_status_and_assets(ingress_client, runtime):
    response = await ingress_client.get("/api/status")
    assert response.status == 200
    body = await response.text()
    assert runtime.auth_token not in body
    assert runtime.settings.bind_password not in body
    assert runtime.settings.bind_user not in body
    assert (await response.json())["csrf_token"] == runtime.csrf_token
    for path in ("/", "/static/style.css", "/static/app.js"):
        response = await ingress_client.get(path)
        assert response.status == 200
        assert "frame-ancestors 'self'" in response.headers["Content-Security-Policy"]
    assert (await ingress_client.get("/static/unknown")).status == 404
    assert (await ingress_client.post("/auth")).status == 403


async def test_certificate_mutations_require_csrf(ingress_client, runtime, ca):
    response = await ingress_client.post(
        "/api/certificate", data=ca.pem, headers={"Content-Type": "application/octet-stream"}
    )
    assert response.status == 403
    assert not runtime.certificates.uploaded.exists()
    assert (await ingress_client.delete("/api/certificate")).status == 403


async def test_upload_delete_and_request_limits(ingress_client, runtime, ca):
    csrf = {"X-CSRF-Token": runtime.csrf_token, "Content-Type": "application/octet-stream"}
    response = await ingress_client.post("/api/certificate", data=ca.der, headers=csrf)
    assert response.status == 200
    assert (await response.json())["source"] == "uploaded"
    assert runtime.certificates.trust() == ca.pem
    response = await ingress_client.post("/api/certificate", data=b"bad", headers=csrf)
    assert response.status == 400
    assert runtime.certificates.trust() == ca.pem
    response = await ingress_client.post(
        "/api/certificate", data=b"x" * (MAX_CERTIFICATE_BYTES + 1), headers=csrf
    )
    assert response.status == 413
    response = await ingress_client.delete("/api/certificate", headers=csrf)
    assert response.status == 200
    assert (await response.json())["source"] == "system"


async def test_check_success_failure_and_csrf(ingress_client, runtime):
    assert (await ingress_client.post("/api/check")).status == 403
    csrf = {"X-CSRF-Token": runtime.csrf_token}
    assert (await ingress_client.post("/api/check", headers=csrf)).status == 200
    runtime.directory.check.side_effect = DirectoryUnavailable("secret")
    response = await ingress_client.post("/api/check", headers=csrf)
    assert response.status == 502
    assert "secret" not in await response.text()


async def test_wrapper_download(ingress_client, runtime, monkeypatch):
    monkeypatch.setattr(server.socket, "gethostname", lambda: "local_ldapauth")
    response = await ingress_client.get("/auth-wrapper.py")
    source = await response.text()
    assert '"http://local-ldapauth:8000/auth"' in source
    assert runtime.auth_token in source
    assert "__AUTH_" not in source
    assert response.headers["Cache-Control"] == "no-store"
    compile(source, "auth-wrapper.py", "exec")


def test_api_key_persists_and_short_key_rejected(settings, tmp_path):
    first = Runtime(settings, tmp_path, directory=Mock())
    second = Runtime(settings, tmp_path, directory=Mock())
    try:
        assert first.auth_token == second.auth_token
        assert first.csrf_token != second.csrf_token
    finally:
        first.pool.shutdown()
        second.pool.shutdown()
    (tmp_path / "auth_token").write_text("bad")
    with pytest.raises(ValueError, match="Invalid stored authentication token"):
        Runtime(settings, tmp_path)


async def test_event_loop_remains_responsive(auth_client, runtime):
    import threading

    started, release = threading.Event(), threading.Event()
    identity = runtime.directory.authenticate.return_value

    def slow(*args):
        started.set()
        release.wait(timeout=3)
        return identity

    runtime.directory.authenticate.side_effect = slow
    task = asyncio.create_task(
        auth_client.post(
            "/auth", headers=headers(runtime), json={"username": "alice", "password": "secret"}
        )
    )
    try:
        await asyncio.to_thread(started.wait, 2)
        response = await asyncio.wait_for(auth_client.get("/health"), timeout=1)
        assert response.status == 200
    finally:
        release.set()
    assert (await task).status == 200
