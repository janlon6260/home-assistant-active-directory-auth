#!/usr/bin/env python3

import json
import os
import sys
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

ENDPOINT = "__AUTH_ENDPOINT__"
AUTH_TOKEN = "__AUTH_TOKEN__"


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, new_url):
        return None


def fail(message: str) -> int:
    print(f"AD authentication: {message}", file=sys.stderr, flush=True)
    return 1


def main() -> int:
    username, password = os.environ.get("username", ""), os.environ.get("password", "")
    if not username or not password:
        return fail("Missing credentials from the command-line provider.")
    if ENDPOINT.startswith("__"):
        return fail("Unconfigured script. Download auth-wrapper.py from the app's web interface.")
    try:
        payload = json.dumps({"username": username, "password": password}).encode()
        request = Request(
            ENDPOINT,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer " + AUTH_TOKEN,
            },
            method="POST",
        )
        with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=25) as response:
            body = response.read(8193)
            if response.status != 200 or len(body) > 8192:
                return fail("Invalid response from the authentication service.")
            identity = json.loads(body)
        if (
            not isinstance(identity, dict)
            or identity.get("is_active") is not True
            or type(identity.get("is_admin")) is not bool
            or not isinstance(identity.get("name"), str)
        ):
            return fail("Invalid user metadata from the authentication service.")
        name = " ".join(identity["name"].split())[:256]
        print(f"name = {name}")
        print("group = system-admin" if identity["is_admin"] else "group = system-users")
        return 0
    except HTTPError as error:
        messages = {
            401: "Request rejected (HTTP 401). Check the app log and the script's API key.",
            404: "Authentication endpoint not found (HTTP 404). Download a fresh script.",
            429: "Too many authentication attempts (HTTP 429). Wait one minute and try again.",
            503: "Directory unavailable or busy (HTTP 503). Check the app log.",
        }
        return fail(messages.get(error.code, "Authentication service returned an HTTP error."))
    except (URLError, OSError, TimeoutError):
        return fail("Cannot reach the app. Check that it is running and download a fresh script.")
    except ValueError:
        return fail("Invalid endpoint or service response. Download a fresh script.")


if __name__ == "__main__":
    sys.exit(main())
