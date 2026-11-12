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


def main() -> int:
    username, password = os.environ.get("username", ""), os.environ.get("password", "")
    if not username or not password:
        return 1
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
    try:
        with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=25) as response:
            body = response.read(8193)
            if response.status != 200 or len(body) > 8192:
                return 1
            identity = json.loads(body)
        if (
            not isinstance(identity, dict)
            or identity.get("is_active") is not True
            or type(identity.get("is_admin")) is not bool
            or not isinstance(identity.get("name"), str)
        ):
            return 1
        name = " ".join(identity["name"].split())[:256]
        print(f"name = {name}")
        print("group = system-admin" if identity["is_admin"] else "group = system-users")
        return 0
    except (HTTPError, URLError, OSError, ValueError, TimeoutError):
        return 1


if __name__ == "__main__":
    sys.exit(main())
