#!/usr/bin/env python3
import os
import json
import ssl
import logging
from urllib.parse import urlparse
from flask import Flask, request, abort, jsonify
from ldap3 import Server, Connection, ALL, Tls
from ldap3.utils.conv import escape_filter_chars
import subprocess

CONFIG_PATH = "/data/options.json"

with open(CONFIG_PATH) as f:
    config = json.load(f)

LDAP_SERVER_RAW = config["ldap_server"]
LDAP_LOOKUP_USER = config["bind_user"]
LDAP_LOOKUP_PASSWORD = config["bind_password"]
LDAP_USER_BASE_DN = config["user_base_dn"]
LDAP_GROUPS_BASE_DN = config["groups_base_dn"]
LDAP_USER_GROUP_DN = f"CN={config['user_group']},{LDAP_GROUPS_BASE_DN}"
LDAP_ADMIN_GROUP_DN = f"CN={config['admin_group']},{LDAP_GROUPS_BASE_DN}"

ENABLE_LDAPS = bool(config.get("enable_ldaps", False))
LDAPS_VERIFY = bool(config.get("ldaps_verify", True))
LDAPS_CA_PEM = (config.get("ldaps_ca_pem") or "").strip()
if "\\n" in LDAPS_CA_PEM:
    LDAPS_CA_PEM = LDAPS_CA_PEM.replace("\\n", "\n")
DEBUG_LOGGING = bool(config.get("debug_logging", False))
LDAP_TIMEOUT = 3

logging.basicConfig(
    level=logging.DEBUG if DEBUG_LOGGING else logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    force=True,
)
logger = logging.getLogger(__name__)

EMBEDDED_CA_FILE = "/data/ldaps_ca.pem"
if LDAPS_CA_PEM:
    try:
        with open(EMBEDDED_CA_FILE, "w", encoding="utf-8") as f:
            f.write(LDAPS_CA_PEM.strip() + "\n")
        if os.path.exists(EMBEDDED_CA_FILE):
            logger.info(f"CA-fil skrevet: {EMBEDDED_CA_FILE} ({os.path.getsize(EMBEDDED_CA_FILE)} bytes)")
        else:
            logger.error("Feil: klarte ikke å skrive CA-fil")
    except Exception as e:
        logger.error(f"Feil ved skriving av CA-fil: {e}")

SEARCH_FILTER_TPL = (
    f"(&(objectClass=person)"
    f"(|(sAMAccountName={{}})(userPrincipalName={{}})))"
)

app = Flask(__name__)

def _parse_ldap_server(url_or_host: str):
    parsed = urlparse(url_or_host)
    if parsed.scheme in ("ldap", "ldaps"):
        host = parsed.hostname
        port = parsed.port or (636 if parsed.scheme == "ldaps" else 389)
        use_ssl = parsed.scheme == "ldaps"
    else:
        host = url_or_host
        use_ssl = ENABLE_LDAPS
        port = 636 if use_ssl else 389
    if ENABLE_LDAPS:
        use_ssl = True
        if port == 389 or port is None:
            port = 636
    logger.debug(f"Kobler til {host}:{port} (SSL={use_ssl})")
    return host, port, use_ssl

def _make_server():
    host, port, use_ssl = _parse_ldap_server(LDAP_SERVER_RAW)
    tls = None
    if use_ssl:
        validate_mode = ssl.CERT_REQUIRED if LDAPS_VERIFY else ssl.CERT_NONE
        ca_file = EMBEDDED_CA_FILE if LDAPS_VERIFY and LDAPS_CA_PEM else None
        tls = Tls(
            ca_certs_file=ca_file,
            validate=validate_mode,
            version=ssl.PROTOCOL_TLS_CLIENT,
        )
    return Server(host=host, port=port, use_ssl=use_ssl, get_info=ALL, tls=tls)

def ldap_auth(username, password):
    safe = escape_filter_chars(username)
    search_filter = SEARCH_FILTER_TPL.format(safe, safe)

    server = _make_server()
    conn = Connection(
        server,
        user=LDAP_LOOKUP_USER,
        password=LDAP_LOOKUP_PASSWORD,
        receive_timeout=LDAP_TIMEOUT,
        auto_bind=True,
    )

    if not conn.search(
        LDAP_USER_BASE_DN,
        search_filter,
        attributes=["sAMAccountName", "displayName", "cn", "mail", "memberOf"],
    ):
        logger.warning(f"Bruker ikke funnet: {username}")
        raise Exception("User not found")

    entry = conn.entries[0]
    user_dn = entry.entry_dn
    if not conn.rebind(user=user_dn, password=password):
        logger.warning(f"Ugyldige legitimasjonsdata for {username}")
        raise Exception("Invalid credentials")

    groups = [str(g).lower() for g in entry.memberOf] if entry.memberOf else []
    if LDAP_USER_GROUP_DN.lower() not in groups:
        logger.warning(f"Bruker {username} mangler nødvendig gruppe")
        raise Exception("Not in required user group")

    is_admin = LDAP_ADMIN_GROUP_DN.lower() in groups
    logger.info(f"Autentisert {username} (admin={is_admin})")

    display = entry.displayName.value if entry.displayName else username
    email = entry.mail.value if entry.mail else ""
    return username, display, email, is_admin

@app.route("/auth", methods=["POST"])
def auth():
    u = request.form.get("username")
    p = request.form.get("password")
    if not u or not p:
        abort(401)
    try:
        username, name, email, is_admin = ldap_auth(u, p)
    except Exception as e:
        logger.error(f"Autentisering feilet for {u}: {e}")
        abort(401)
    return jsonify(
        {
            "username": username,
            "name": name,
            "email": email,
            "is_active": True,
            "is_admin": is_admin,
        }
    ), 200

@app.route("/diagnose", methods=["GET"])
def diagnose():
    result = {}
    result["exists"] = os.path.exists(EMBEDDED_CA_FILE)
    if result["exists"]:
        try:
            result["size_bytes"] = os.path.getsize(EMBEDDED_CA_FILE)
            out = subprocess.check_output(
                ["openssl", "x509", "-in", EMBEDDED_CA_FILE, "-noout", "-subject", "-issuer"],
                stderr=subprocess.STDOUT,
                text=True,
            )
            result["openssl_output"] = out.strip()
        except subprocess.CalledProcessError as e:
            result["openssl_output"] = e.output.strip()
        except Exception as e:
            result["error"] = str(e)
    else:
        result["error"] = "CA file not found"
    return jsonify(result), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False, use_reloader=False)
