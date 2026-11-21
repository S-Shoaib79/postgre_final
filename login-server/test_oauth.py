"""
End-to-end test of the OAuth login server, the AM (or am_stub.py) and the am_keys endpoint.
PostgreSQL, the AM and login_server.py must be running (start.ps1).

    python test_oauth.py [--server http://127.0.0.1:7000] [--tenant ACME]
                         [--username alice.sharma] [--password Alice-pass-1]

The test signs the user in and out (its login_status and keys change). With am_stub.py the
first password a user signs in with is the one the stub keeps, so use the same one every time.
"""
import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
CFG = json.load(open(os.path.join(HERE, "config.json"), encoding="utf-8"))
results = []


def call(method, url, form=None, json_body=None, headers=None):
    data, hdrs = None, dict(headers or {})
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
    if json_body is not None:
        data = json.dumps(json_body).encode()
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=40) as r:
            status, raw = r.status, r.read()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
    try:
        return status, json.loads(raw or b"{}")
    except ValueError:
        return status, {"raw": raw.decode(errors="replace")[:200]}


def check(name, ok, detail=""):
    results.append(bool(ok))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({detail})" if detail and not ok else ""))
    return ok


def db(sql):
    r = subprocess.run([CFG.get("psql", r"D:\postgres-dev\install\bin\psql.exe"), "-X", "-q", "-A", "-t",
                        "-U", CFG.get("db_user", "postgres"), "-d", CFG.get("db_name", "erms"), "-c", sql],
                       capture_output=True, text=True, timeout=30)
    return r.stdout.strip()


def keys_state(username):
    """'<login_status>|<rows>|<rows with a key>'"""
    return db(f"SELECT u.login_status || '|' || count(k.*) || '|' || count(k.asset_key) "
              f"FROM user_accounts u LEFT JOIN user_asset_map k USING (user_id) "
              f"WHERE u.username = '{username}' GROUP BY u.login_status")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", default=f"http://127.0.0.1:{CFG.get('port', 7000)}")
    ap.add_argument("--tenant", default="ACME")
    ap.add_argument("--username", default="alice.sharma")
    ap.add_argument("--password", default="Alice-pass-1")
    ap.add_argument("--keys-endpoint", default="http://127.0.0.1:7001/api/am/keys")
    a = ap.parse_args()
    S = a.server.rstrip("/")
    print(f"OAuth test against {S} as {a.tenant}/{a.username}\n")

    print("1. Metadata")
    st, md = call("GET", S + "/.well-known/oauth-authorization-server")
    check("discovery document", st == 200 and md.get("token_endpoint") == S + "/oauth/token", f"{st} {md}")

    print("2. Password grant")
    st, tok = call("POST", S + "/oauth/token", form={"grant_type": "password", "client_id": "erms_web",
                   "tenant": a.tenant, "username": a.username, "password": a.password})
    if not check("tokens issued", st == 200 and tok.get("access_token") and tok.get("refresh_token"),
                 f"{st} {tok}"):
        print("\nCannot continue without tokens (is the AM running? right password?).")
        return 1
    access, refresh, login_id = tok["access_token"], tok["refresh_token"], tok.get("login_id", "")
    row = db(f"SELECT count(*) FROM oauth_tokens WHERE token_id = '{login_id}' AND revoked_at IS NULL "
             f"AND access_hash <> '{access}' AND refresh_hash IS NOT NULL")
    check("session stored in oauth_tokens (hashes only)", row == "1", row)
    st, e = call("POST", S + "/oauth/token", form={"grant_type": "password", "tenant": a.tenant,
                 "username": a.username, "password": a.password + "-wrong"})
    check("wrong password refused (400 invalid_grant)", st == 400 and e.get("error") == "invalid_grant", f"{st} {e}")
    st, e = call("POST", S + "/oauth/token", form={"grant_type": "password", "client_id": "nobody",
                 "tenant": a.tenant, "username": a.username, "password": a.password})
    check("unknown client refused (401 invalid_client)", st == 401 and e.get("error") == "invalid_client", f"{st} {e}")
    st, e = call("POST", S + "/oauth/token", form={"grant_type": "client_credentials"})
    check("unsupported grant refused", st == 400 and e.get("error") == "unsupported_grant_type", f"{st} {e}")

    print("3. Keys pushed by the AM with this loginId")
    state = ""
    for _ in range(30):
        state = keys_state(a.username)
        ls, rows, with_key = (state.split("|") + ["", "", ""])[:3]
        if ls == "1" and rows not in ("", "0") and rows == with_key:
            break
        time.sleep(0.5)
    check("login_status = 1 and every user_asset_map row has a key", ls == "1" and rows == with_key
          and rows not in ("", "0"), f"login_status|rows|with key = {state}")

    print("4. Introspect / userinfo")
    st, i = call("POST", S + "/oauth/introspect", form={"token": access})
    check("access token active", st == 200 and i.get("active") and i.get("username") == a.username, f"{st} {i}")
    st, i = call("POST", S + "/oauth/introspect", form={"token": refresh, "token_type_hint": "refresh_token"})
    check("refresh token active", st == 200 and i.get("active") and i.get("token_type") == "refresh_token", f"{i}")
    st, i = call("POST", S + "/oauth/introspect", form={"token": "made-up"})
    check("unknown token inactive", st == 200 and i == {"active": False}, f"{i}")
    st, u = call("GET", S + "/oauth/userinfo", headers={"Authorization": "Bearer " + access})
    check("userinfo", st == 200 and u.get("preferred_username") == a.username, f"{st} {u}")
    st, u = call("GET", S + "/oauth/userinfo", headers={"Authorization": "Bearer made-up"})
    check("userinfo refuses a bad token (401)", st == 401, f"{st}")

    print("5. Refresh (rotation)")
    st, t2 = call("POST", S + "/oauth/token", form={"grant_type": "refresh_token", "refresh_token": refresh})
    check("new token pair", st == 200 and t2.get("access_token") not in (None, access)
          and t2.get("login_id") == login_id, f"{st} {t2}")
    access2, refresh2 = t2.get("access_token", ""), t2.get("refresh_token", "")
    st, e = call("POST", S + "/oauth/token", form={"grant_type": "refresh_token", "refresh_token": refresh})
    check("old refresh token refused", st == 400 and e.get("error") == "invalid_grant", f"{st} {e}")
    st, i = call("POST", S + "/oauth/introspect", form={"token": access})
    check("old access token inactive", i.get("active") is False, f"{i}")
    st, u = call("GET", S + "/oauth/userinfo", headers={"Authorization": "Bearer " + access2})
    check("new access token works", st == 200, f"{st} {u}")

    print("6. am_keys refuses keys for a loginId that is not a live session (needs the new am_keys.dll)")
    secret = CFG.get("push_secret", "")
    bogus = {"loginId": "not-a-session", "username": a.username,
             "assets": [{"name": "A01", "value": "A" * 43 + "="}]}
    st, e = call("POST", a.keys_endpoint, json_body=bogus, headers={"X-AM-Secret": secret})
    check("push with an unknown loginId refused (409 NOT_SIGNED_IN)", st == 409 and e.get("code") == "NOT_SIGNED_IN",
          f"{st} {e}" + ("  <- the old am_keys.dll is still loaded" if st == 200 else ""))
    st, e = call("POST", a.keys_endpoint, json_body={k: v for k, v in bogus.items() if k != "loginId"},
                 headers={"X-AM-Secret": secret})
    check("push without loginId refused (400 MISSING_LOGIN_ID)", st == 400 and e.get("code") == "MISSING_LOGIN_ID",
          f"{st} {e}")

    print("7. Revoke")
    st, _ = call("POST", S + "/oauth/revoke", form={"token": refresh2, "token_type_hint": "refresh_token"})
    check("revoke answers 200", st == 200, f"{st}")
    st, i = call("POST", S + "/oauth/introspect", form={"token": access2})
    check("access token of the revoked session inactive", i.get("active") is False, f"{i}")
    state = keys_state(a.username)
    ls, rows, with_key = (state.split("|") + ["", "", ""])[:3]
    check("login_status = 0 and the keys are removed", ls == "0" and with_key == "0", f"login_status|rows|with key = {state}")
    st, _ = call("POST", S + "/oauth/revoke", form={"token": "made-up"})
    check("revoking an unknown token still answers 200 (RFC 7009)", st == 200, f"{st}")

    passed = sum(results)
    print(f"\n{passed}/{len(results)} passed")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
