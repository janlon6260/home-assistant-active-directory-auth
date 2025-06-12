#!/usr/bin/env python3
import os, json
from flask import Flask, request, abort, jsonify
from ldap3 import Server, Connection, ALL
from ldap3.utils.conv import escape_filter_chars

CONFIG_PATH = "/data/options.json"
with open(CONFIG_PATH) as f:
    config = json.load(f)

LDAP_SERVER = config["ldap_server"]
LDAP_LOOKUP_USER = config["bind_user"]
LDAP_LOOKUP_PASSWORD = config["bind_password"]
LDAP_TIMEOUT = 3
LDAP_USER_BASE_DN = config["user_base_dn"]
LDAP_GROUPS_BASE_DN = config["groups_base_dn"]
LDAP_USER_GROUP_DN = f"CN={config['user_group']},{LDAP_GROUPS_BASE_DN}"
LDAP_ADMIN_GROUP_DN = f"CN={config['admin_group']},{LDAP_GROUPS_BASE_DN}"

SEARCH_FILTER_TPL = (
    f"(&(objectClass=person)"
    f"(|(sAMAccountName={{}})(userPrincipalName={{}})))"
)

app = Flask(__name__)

def ldap_auth(username, password):
    safe = escape_filter_chars(username)
    search_filter = SEARCH_FILTER_TPL.format(safe, safe)

    server = Server(LDAP_SERVER, get_info=ALL)
    conn = Connection(server, user=LDAP_LOOKUP_USER, password=LDAP_LOOKUP_PASSWORD,
                      receive_timeout=LDAP_TIMEOUT, auto_bind=True)

    if not conn.search(LDAP_USER_BASE_DN, search_filter, attributes=[
        'sAMAccountName', 'displayName', 'cn', 'mail', 'memberOf'
    ]):
        raise Exception("User not found")

    entry = conn.entries[0]
    user_dn = entry.entry_dn
    samaccount = entry.sAMAccountName.value if entry.sAMAccountName else username
    display = entry.displayName.value if entry.displayName else (
        entry.cn.value if entry.cn else samaccount
    )
    email = entry.mail.value if entry.mail else ""
    groups = [str(g).lower() for g in entry.memberOf] if entry.memberOf else []

    if not conn.rebind(user=user_dn, password=password):
        raise Exception("Invalid credentials")

    if LDAP_USER_GROUP_DN.lower() not in groups:
        raise Exception("Not in required user group")

    is_admin = LDAP_ADMIN_GROUP_DN.lower() in groups
    return samaccount, display, email, is_admin

@app.route('/auth', methods=['POST'])
def auth():
    u = request.form.get('username')
    p = request.form.get('password')
    if not u or not p:
        abort(401)
    try:
        username, name, email, is_admin = ldap_auth(u, p)
    except:
        abort(401)
    return jsonify({
        "username": username,
        "name": name,
        "email": email,
        "is_active": True,
        "is_admin": is_admin
    }), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False, use_reloader=False)
