"""TEST ONLY: stands in for the AM's new login endpoint until the Java service has it.

    python am_stub.py --secret <push_secret> [--port 8097] [--keys-endpoint http://127.0.0.1:7001/api/am/keys]

  POST /api/v1/auth/login   X-Api-Key: <tenant key>   {"username", "password", "requestId"}
    - the first login of a username (per tenant) stores its password; later logins must match it
    - answers the login app with OK or FAILURE only, never keys:
          200 {"result": "OK"}        401 {"result": "FAILURE", "message": ...}
    - after an OK it sends the keys straight to PostgreSQL's keys endpoint (am_keys), X-AM-Secret:
          {"loginId", "username", "assets": [{"name": "A01".."A04", "value": <32-byte key, base64>}]}
      The key of each type is derived from the API key, so it is the same for the whole tenant.
"""
import argparse
import base64
import hashlib
import json
import secrets
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TYPES = ["A01", "A02", "A03", "A04"]
passwords = {}  # (sha256 of api key, tenant id, username) -> password hash
lock = threading.Lock()


def pw_hash(password):
    return hashlib.sha256(password.encode()).hexdigest()


def send_keys(args, api_key, login_id, username):
    time.sleep(1)
    assets = [{"name": t, "value": base64.b64encode(hashlib.sha256(f"{api_key}|{t}".encode()).digest()).decode()}
              for t in TYPES]
    body = json.dumps({"loginId": login_id, "username": username, "assets": assets}).encode()
    req = urllib.request.Request(args.keys_endpoint, data=body, method="POST",
                                 headers={"Content-Type": "application/json", "X-AM-Secret": args.secret})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            status, answer = r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        status, answer = e.code, e.read().decode()
    except (urllib.error.URLError, OSError) as e:
        status, answer = 0, str(e)
    print(f"  keys for '{username}' -> PostgreSQL keys endpoint: {status} {answer.strip()[:300]}", flush=True)


class Handler(BaseHTTPRequestHandler):
    def reply(self, status, doc):
        raw = json.dumps(doc).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def failure(self, status, message):
        return self.reply(status, {"result": "FAILURE", "message": message})

    def do_POST(self):
        if self.path != "/api/v1/auth/login":
            return self.failure(404, "No such endpoint.")
        api_key = self.headers.get("X-Api-Key", "")
        if not api_key:
            return self.failure(401, "X-Api-Key is required.")
        try:
            doc = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        except ValueError:
            return self.failure(400, "Not JSON.")
        # Same request as the jar: the tenant is the API key's, requestId is the loginId
        tenant_id, username, password = doc.get("tenantId") or "-", doc.get("username"), doc.get("password")
        login_id = doc.get("requestId") or doc.get("loginId") or ""
        if not (username and password):
            return self.failure(400, "username and password are required.")
        who = (hashlib.sha256(api_key.encode()).hexdigest(), str(tenant_id), username)
        with lock:
            stored = passwords.get(who)
            if stored is None:
                passwords[who] = pw_hash(password)
                note = "password stored (first login)"
            elif not secrets.compare_digest(stored, pw_hash(password)):
                print(f"  login '{username}' (tenant {tenant_id}): wrong password -> FAILURE", flush=True)
                return self.failure(401, "Wrong username or password.")
            else:
                note = "password matches"
        print(f"  login '{username}' (tenant {tenant_id}): {note} -> OK; sending keys to the keys endpoint",
              flush=True)
        threading.Thread(target=send_keys, args=(ARGS, api_key, login_id, username), daemon=True).start()
        self.reply(200, {"result": "OK"})

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8097)
    ap.add_argument("--keys-endpoint", default="http://127.0.0.1:7001/api/am/keys")
    ap.add_argument("--secret", required=True)
    ARGS = ap.parse_args()
    print(f"AM stub on http://127.0.0.1:{ARGS.port}/api/v1/auth/login  (answers OK / FAILURE; "
          f"keys go to {ARGS.keys_endpoint})", flush=True)
    ThreadingHTTPServer(("127.0.0.1", ARGS.port), Handler).serve_forever()
