import logging
import sys

import pytest

from ldapauth.diagnostics import Diagnostics
from ldapauth.directory import AuthenticationFailed, DirectoryUnavailable


def record(message, *, name="ldapauth.server", exc_info=None):
    return logging.LogRecord(name, logging.INFO, __file__, 0, message, (), exc_info)


def test_log_snapshot_is_bounded_and_redacts_configured_secrets():
    diagnostics = Diagnostics(("api-token", "bind-password"))
    diagnostics.handle(record("External service noise", name="external"))
    assert diagnostics.snapshot()["logs"] == []
    for number in range(101):
        diagnostics.handle(record(f"Message {number}: api-token bind-password " + "x" * 2000))
    snapshot = diagnostics.snapshot()
    assert len(snapshot["logs"]) == 100
    assert "Message 1:" in snapshot["logs"][0]
    assert "Message 100:" in snapshot["logs"][-1]
    assert all(len(line) <= 1024 for line in snapshot["logs"])
    assert "api-token" not in str(snapshot)
    assert "bind-password" not in str(snapshot)
    assert "[redacted]" in snapshot["logs"][-1]
    snapshot["logs"].clear()
    assert len(diagnostics.snapshot()["logs"]) == 100


def test_snapshot_excludes_exception_details_and_handles_invalid_records():
    diagnostics = Diagnostics()
    try:
        raise ValueError("Sensitive exception detail")
    except ValueError:
        diagnostics.handle(record("Directory failed", exc_info=sys.exc_info()))
    broken = record("Bad format %s %s")
    broken.args = ("one",)
    diagnostics.handle(broken)
    logs = diagnostics.snapshot()["logs"]
    assert len(logs) == 1
    assert "Directory failed" in logs[0]
    assert "Sensitive exception detail" not in logs[0]


async def test_initial_ingress_snapshot_is_finite_and_not_cached(ingress_client):
    response = await ingress_client.get("/api/diagnostics")
    assert response.status == 200
    assert response.content_length is not None
    assert response.headers["Cache-Control"] == "no-store"
    assert await response.json() == {"auth_requests": 0, "last_status": None, "logs": []}


@pytest.mark.parametrize(
    "error,status",
    [(None, 200), (AuthenticationFailed(), 401), (DirectoryUnavailable(), 503)],
)
async def test_snapshot_tracks_completed_authentication(
    auth_client, ingress_client, runtime, error, status
):
    runtime.directory.authenticate.side_effect = error
    for _ in range(2):
        response = await auth_client.post(
            "/auth",
            headers={"Authorization": "Bearer " + runtime.auth_token},
            json={"username": "alice", "password": "submitted-secret"},
        )
        assert response.status == status
    response = await ingress_client.get("/api/diagnostics")
    snapshot = await response.json()
    assert snapshot["auth_requests"] == 2
    assert snapshot["last_status"] == status
    assert "submitted-secret" not in str(snapshot)
    assert runtime.auth_token not in str(snapshot)


async def test_snapshot_counts_rejected_api_keys(auth_client, ingress_client, runtime):
    assert (await auth_client.post("/auth")).status == 401
    snapshot = await (await ingress_client.get("/api/diagnostics")).json()
    assert snapshot["auth_requests"] == 1
    assert snapshot["last_status"] == 401
    runtime.directory.authenticate.assert_not_called()


async def test_unexpected_authentication_error_is_safe_and_counted(
    auth_client, ingress_client, runtime, caplog
):
    runtime.directory.authenticate.side_effect = RuntimeError("secret-exception-detail")
    response = await auth_client.post(
        "/auth",
        headers={"Authorization": "Bearer " + runtime.auth_token},
        json={"username": "alice", "password": "submitted-secret"},
    )
    assert response.status == 500
    assert "secret-exception-detail" not in await response.text()
    assert "secret-exception-detail" not in caplog.text
    assert "submitted-secret" not in caplog.text
    snapshot = await (await ingress_client.get("/api/diagnostics")).json()
    assert snapshot["auth_requests"] == 1
    assert snapshot["last_status"] == 500
