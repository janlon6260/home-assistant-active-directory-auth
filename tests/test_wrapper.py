import asyncio
import importlib.util
import os
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

from ldapauth.directory import AuthenticationFailed, Identity

SOURCE = Path(__file__).parents[1] / "ldapauth" / "auth-wrapper.py"


@pytest.fixture
def wrapper():
    spec = importlib.util.spec_from_file_location("auth_wrapper", SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_wrapper_missing_credentials_fails_without_request(wrapper, monkeypatch, capsys):
    monkeypatch.delenv("username", raising=False)
    monkeypatch.delenv("password", raising=False)
    assert wrapper.main() == 1
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize(
    "identity",
    [
        {},
        {"is_active": True, "is_admin": "false", "name": "A"},
        {"is_active": False, "is_admin": False, "name": "A"},
        [],
    ],
)
def test_wrapper_malformed_response_fails_closed(wrapper, monkeypatch, identity, capsys):
    import json

    monkeypatch.setenv("username", "alice")
    monkeypatch.setenv("password", "secret")
    response = Mock(status=200)
    response.read.return_value = json.dumps(identity).encode()
    context = Mock()
    context.__enter__ = Mock(return_value=response)
    context.__exit__ = Mock(return_value=False)
    opener = Mock()
    opener.open.return_value = context
    monkeypatch.setattr(wrapper, "ENDPOINT", "http://example.test/auth")
    monkeypatch.setattr(wrapper, "build_opener", lambda *args: opener)
    assert wrapper.main() == 1
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("admin", [False, True])
@pytest.mark.parametrize("inherit_environment", [False, True])
async def test_wrapper_real_http_subprocess(
    auth_client, runtime, tmp_path, admin, inherit_environment
):
    import json

    runtime.directory.authenticate.return_value = Identity(
        "alice", "Alice\ngroup = system-admin", "alice@example.com", admin
    )
    source = SOURCE.read_text().replace(
        '"__AUTH_ENDPOINT__"', json.dumps(str(auth_client.make_url("/auth")))
    )
    source = source.replace('"__AUTH_TOKEN__"', json.dumps(runtime.auth_token))
    script = tmp_path / "wrapper.py"
    script.write_text(source)
    environment = {
        **(os.environ if inherit_environment else {}),
        "username": "alice",
        "password": "user-secret",
    }
    if inherit_environment:
        environment["HTTP_PROXY"] = "http://127.0.0.1:1"
    if os.name == "nt":
        environment["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        str(script),
        env=environment,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    output, errors = await asyncio.wait_for(process.communicate(), timeout=10)
    assert process.returncode == 0
    lines = output.decode().splitlines()
    assert len(lines) == 2
    assert lines[-1] == ("group = system-admin" if admin else "group = system-users")
    assert b"user-secret" not in output + errors
    assert runtime.auth_token.encode() not in output + errors
    runtime.directory.authenticate.assert_called_once_with("alice", "user-secret")


async def test_wrapper_denial_produces_no_metadata(auth_client, runtime, tmp_path):
    import json

    runtime.directory.authenticate.side_effect = AuthenticationFailed
    source = SOURCE.read_text().replace(
        '"__AUTH_ENDPOINT__"', json.dumps(str(auth_client.make_url("/auth")))
    )
    source = source.replace('"__AUTH_TOKEN__"', json.dumps(runtime.auth_token))
    script = tmp_path / "wrapper.py"
    script.write_text(source)
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        str(script),
        env={**os.environ, "username": "alice", "password": "bad"},
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    output, errors = await asyncio.wait_for(process.communicate(), timeout=10)
    assert process.returncode == 1
    assert output == b""
    assert b"HTTP 401" in errors
    assert runtime.auth_token.encode() not in errors


def test_wrapper_template_reports_unconfigured_script(wrapper, monkeypatch, capsys):
    monkeypatch.setenv("username", "alice")
    monkeypatch.setenv("password", "user-secret")
    assert wrapper.main() == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Unconfigured script" in captured.err
    assert "alice" not in captured.err
    assert "user-secret" not in captured.err


@pytest.mark.parametrize("status", [401, 404, 429, 503, 500])
def test_wrapper_http_errors_are_safe_and_visible(wrapper, monkeypatch, capsys, status):
    from urllib.error import HTTPError

    monkeypatch.setenv("username", "alice")
    monkeypatch.setenv("password", "user-secret")
    monkeypatch.setattr(wrapper, "ENDPOINT", "http://example.test/auth")
    opener = Mock()
    opener.open.side_effect = HTTPError(
        wrapper.ENDPOINT, status, "user-secret private-api-key", {}, None
    )
    monkeypatch.setattr(wrapper, "build_opener", lambda *args: opener)
    assert wrapper.main() == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "AD authentication:" in captured.err
    assert "user-secret" not in captured.err
    assert "private-api-key" not in captured.err
    assert "alice" not in captured.err


def test_wrapper_connection_error_does_not_disclose_exception(wrapper, monkeypatch, capsys):
    from urllib.error import URLError

    monkeypatch.setenv("username", "alice")
    monkeypatch.setenv("password", "user-secret")
    monkeypatch.setattr(wrapper, "ENDPOINT", "http://example.test/auth")
    opener = Mock()
    opener.open.side_effect = URLError("user-secret private-api-key")
    monkeypatch.setattr(wrapper, "build_opener", lambda *args: opener)
    assert wrapper.main() == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Cannot reach the app" in captured.err
    assert "user-secret" not in captured.err
    assert "private-api-key" not in captured.err


def test_wrapper_redirect_is_disabled(wrapper):
    assert (
        wrapper.NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://example.com/")
        is None
    )
