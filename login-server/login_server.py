"""
ERMS login app and OAuth 2.0 server for the ERMS database. It never receives or stores keys.

    python login_server.py            start (settings in config.json next to this file)

Sign-in (browser form at /, or POST /oauth/token grant_type=password for programs)
  1. The user gives tenant (org_code), username and password.
  2. The app finds the user in user_accounts, makes a new session id (token_id), takes the
     tenant's API key from PostgreSQL's own am_client.conf (api_key.<TenantID>) and sends
         POST {am_url}{am_login_path}   X-Api-Key: <tenant key>
         {"username": ..., "password": ..., "requestId": <token_id = loginId>}
     The AM answers OK or FAILURE only:  200  /  401 (no keys in the answer)
  3. OK: in one transaction the session goes into oauth_tokens (only SHA-256 hashes of the
     tokens are stored) and  UPDATE user_accounts SET login_status = 1  (the hook makes the
     user_asset_map rows). FAILURE: the sign-in is refused.
  4. The AM sends the keys straight to PostgreSQL's keys endpoint (the am_keys background
     worker, http://127.0.0.1:7001/api/am/keys) with the same loginId. PostgreSQL stores them
     only if that loginId is a live session of that user.
  5. When the user's last live session ends (revoke, sign-out or expiry), login_status = 0
     and the hook removes the keys (oauth_end_sessions in merged/05_oauth.sql).

OAuth endpoints (tokens are opaque; sessions live in PostgreSQL, so they survive a restart)
  POST /oauth/token        RFC 6749  grant_type=password (tenant, username, password)
                                     grant_type=refresh_token (refresh_token); rotates both tokens
  POST /oauth/introspect   RFC 7662  token [, token_type_hint]  -> {"active": ...}
  POST /oauth/revoke       RFC 7009  token [, token_type_hint]  -> ends the whole session
  GET  /oauth/userinfo               Authorization: Bearer <access token>
  GET  /.well-known/oauth-authorization-server   RFC 8414 metadata (also at openid-configuration)
Bodies may be form-encoded (standard) or JSON. client_id goes in the body or HTTP Basic auth;
it must be one of config.json "clients" (public clients: no secret). Default: erms_web.

Only the Python standard library is used; the database is reached through psql.exe.
The server listens on 127.0.0.1 only.
"""
import base64
import hashlib
import html
import json
import os
import secrets
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(HERE, "config.json")

DEFAULTS = {
    "port": 7000,
    "am_url": "",                         # empty = the url in am_client.conf
    "am_login_path": "/api/v1/auth/login",
    "am_timeout_seconds": 5,
    "am_client_conf": r"D:\postgres-dev\data\am_client.conf",
    "token_lifetime_seconds": 3600,       # access token
    "refresh_token_lifetime_seconds": 28800,
    "clients": ["erms_web"],
    "scopes": ["read", "write"],
    "sweep_seconds": 30,
    "psql": r"D:\postgres-dev\install\bin\psql.exe",
    "db_host": "localhost",
    "db_port": 5432,
    "db_name": "erms",
    "db_user": "postgres",
    "db_password": "",
}


def load_config():
    cfg = dict(DEFAULTS)
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, encoding="utf-8") as f:
            cfg.update(json.load(f))
    else:
        print("  (no config.json: using defaults; copy config.example.json to config.json)")
    if os.environ.get("ERMS_LOGIN_PORT"):
        cfg["port"] = int(os.environ["ERMS_LOGIN_PORT"])
    cfg["token_lifetime_seconds"] = max(60, int(cfg["token_lifetime_seconds"]))
    cfg["refresh_token_lifetime_seconds"] = max(cfg["token_lifetime_seconds"],
                                                 int(cfg["refresh_token_lifetime_seconds"]))
    return cfg


CFG = load_config()
ISSUER = f"http://127.0.0.1:{CFG['port']}"
lock = threading.Lock()
events = []


def log(msg):
    line = f"{time.strftime('%H:%M:%S')}  {msg}"
    print("  " + line, flush=True)
    with lock:
        events.insert(0, line)
        del events[50:]


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


# ---------------------------------------------------------------- PostgreSQL (through psql)
class DbError(Exception):
    pass


def psql(sql, **variables):
    """Runs SQL with psql variables (:'name' is a safely quoted literal). Returns the JSON of the
    last line that starts with '{', or None."""
    cmd = [CFG["psql"], "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1",
           "-h", CFG["db_host"], "-p", str(CFG["db_port"]), "-U", CFG["db_user"], "-d", CFG["db_name"]]
    for k, v in variables.items():
        cmd += ["-v", f"{k}={v}"]
    env = dict(os.environ)
    if CFG["db_password"]:
        env["PGPASSWORD"] = CFG["db_password"]
    try:
        r = subprocess.run(cmd, input=sql, capture_output=True, text=True, timeout=30, env=env)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise DbError(f"cannot run psql: {e}")
    if r.returncode != 0:
        lines = (r.stderr or "psql failed").strip().splitlines()
        raise DbError(next((l.strip() for l in lines if "error" in l.lower()), lines[-1].strip()))
    for line in reversed(r.stdout.splitlines()):
        if line.startswith("{"):
            return json.loads(line)
    return None


def db_find_user(org_code, username):
    return psql("""
SELECT json_build_object('tenant_id', t.tenant_id, 'org_code', t.org_code, 'user_id', u.user_id,
                         'username', u.username, 'user_status', u.status, 'tenant_status', t.status)
FROM user_accounts u JOIN tenants t ON t.tenant_id = u.tenant_id
WHERE upper(t.org_code) = upper(:'org') AND u.username = :'uname';
""", org=org_code, uname=username)


# A session as JSON; used with  oauth_tokens t JOIN user_accounts u JOIN tenants tn
SESSION_JSON = """json_build_object('token_id', t.token_id, 'user_id', u.user_id,
  'tenant_id', u.tenant_id, 'org_code', tn.org_code, 'username', u.username,
  'client_id', t.client_id, 'scope', t.scope,
  'exp', extract(epoch FROM t.access_expires_at)::bigint,
  'session_exp', extract(epoch FROM t.session_expires_at)::bigint,
  'iat', extract(epoch FROM coalesce(t.refreshed_at, t.created_at))::bigint)"""

# A live session: not revoked, account and tenant active, still signed in
LIVE = """t.revoked_at IS NULL AND u.status = 'ACTIVE' AND tn.status = 'ACTIVE'
  AND u.login_status = 1"""


def db_create_session(user, token_id, access, refresh, client_id, scope):
    """The session row and login_status = 1, in one transaction."""
    session_life = CFG["refresh_token_lifetime_seconds"] if refresh else CFG["token_lifetime_seconds"]
    psql(f"""
BEGIN;
INSERT INTO oauth_tokens (token_id, access_hash, refresh_hash, tenant_id, user_id, client_id, scope,
                          access_expires_at, session_expires_at)
VALUES (:'tid', :'ah', NULLIF(:'rh', ''), {int(user['tenant_id'])}, {int(user['user_id'])},
        :'cid', :'scope',
        now() + make_interval(secs => {int(CFG['token_lifetime_seconds'])}),
        now() + make_interval(secs => {int(session_life)}));
UPDATE user_accounts SET login_status = 1 WHERE user_id = {int(user['user_id'])};
COMMIT;
""", tid=token_id, ah=token_hash(access), rh=token_hash(refresh) if refresh else "",
         cid=client_id, scope=scope)


def db_session_by_access(token):
    if not token:
        return None
    return psql(f"""
SELECT {SESSION_JSON}
FROM oauth_tokens t JOIN user_accounts u ON u.user_id = t.user_id JOIN tenants tn ON tn.tenant_id = u.tenant_id
WHERE t.access_hash = :'h' AND t.access_expires_at > now() AND {LIVE};
""", h=token_hash(token))


def db_session_by_refresh(token):
    if not token:
        return None
    return psql(f"""
SELECT {SESSION_JSON}
FROM oauth_tokens t JOIN user_accounts u ON u.user_id = t.user_id JOIN tenants tn ON tn.tenant_id = u.tenant_id
WHERE t.refresh_hash = :'h' AND t.session_expires_at > now() AND {LIVE};
""", h=token_hash(token))


def db_rotate(old_refresh, client_id, access, refresh):
    """Swaps a live refresh token for a new pair (the old pair stops working). The row lock
    makes a second use of the same refresh token find nothing. Returns the session or None."""
    return psql(f"""
WITH upd AS (
  UPDATE oauth_tokens t
     SET access_hash = :'ah', refresh_hash = :'rh', refreshed_at = now(),
         access_expires_at = now() + make_interval(secs => {int(CFG['token_lifetime_seconds'])}),
         session_expires_at = now() + make_interval(secs => {int(CFG['refresh_token_lifetime_seconds'])})
    FROM user_accounts u, tenants tn
   WHERE t.refresh_hash = :'old' AND t.session_expires_at > now() AND t.client_id = :'cid'
     AND u.user_id = t.user_id AND tn.tenant_id = u.tenant_id AND {LIVE}
  RETURNING t.*)
SELECT {SESSION_JSON}
FROM upd t JOIN user_accounts u ON u.user_id = t.user_id JOIN tenants tn ON tn.tenant_id = u.tenant_id;
""", old=token_hash(old_refresh), cid=client_id, ah=token_hash(access), rh=token_hash(refresh))


def db_end_by_token(token, reason):
    """Ends the session an access or refresh token belongs to (live or not). Returns how many
    users were signed out (0 if the user has another live session or the token is unknown)."""
    doc = psql("""
SELECT json_build_object('signed_out', oauth_end_sessions(
  ARRAY(SELECT token_id FROM oauth_tokens WHERE access_hash = :'h' OR refresh_hash = :'h'), :'reason'));
""", h=token_hash(token), reason=reason)
    return (doc or {}).get("signed_out", 0)


def db_sweep():
    return (psql("SELECT json_build_object('n', oauth_sweep());") or {}).get("n", 0)


def db_keys(user_id):
    """The user's rows, with a fingerprint instead of the key."""
    return psql(f"""
SELECT json_build_object('login_status', (SELECT login_status FROM user_accounts WHERE user_id = {int(user_id)}),
  'keys', (SELECT coalesce(json_agg(json_build_object(
      'type_id', type_id, 'has_key', asset_key IS NOT NULL,
      'fingerprint', CASE WHEN asset_key IS NULL THEN NULL
                     ELSE left(encode(sha256(decode(asset_key, 'base64')), 'hex'), 12) END)
    ORDER BY type_id), '[]') FROM user_asset_map WHERE user_id = {int(user_id)}));
""")


def sweeper():
    """Ends expired sessions; a user whose last session expired is signed out."""
    while True:
        time.sleep(CFG["sweep_seconds"])
        try:
            n = db_sweep()
            if n:
                log(f"expired sessions ended: {n} user(s) signed out (login_status = 0, keys removed)")
        except DbError as e:
            log(f"session sweep failed: {e}")


# ---------------------------------------------------------------- the AM
def am_settings():
    """url and API keys from PostgreSQL's am_client.conf (key = value lines)."""
    conf = {}
    try:
        with open(CFG["am_client_conf"], encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, _, v = line.partition("=")
                    conf[k.strip()] = v.strip()
    except OSError:
        pass
    return conf


def api_key_for(tenant_id):
    conf = am_settings()
    return conf.get(f"api_key.{tenant_id}") or conf.get("api_key") or ""


def am_url():
    return (CFG["am_url"] or am_settings().get("url", "")).rstrip("/")


def call_am_login(user, password, login_id):
    """Asks the AM to check the password. Returns (ok, message, unreachable). The AM answers OK
    or FAILURE; nothing else in its answer is used. Never logs the password."""
    url, key = am_url(), api_key_for(user["tenant_id"])
    if not url:
        return False, "AM address not set (am_url in config.json or url in am_client.conf).", True
    if not key:
        return False, f"No API key for tenant {user['tenant_id']} in am_client.conf.", True
    # The jar's format: the tenant is the API key's (a tenantId is refused), and requestId
    # comes back with the keys delivery, so it is our loginId.
    body = json.dumps({"username": user["username"], "password": password,
                       "requestId": login_id}).encode()
    req = urllib.request.Request(url + CFG["am_login_path"], data=body, method="POST",
                                 headers={"X-Api-Key": key, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=CFG["am_timeout_seconds"]) as r:
            status, raw = r.status, r.read()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        log(f"AM login call for '{user['username']}' failed: cannot reach {url} ({e})")
        return False, f"Cannot reach the AM at {url}.", True
    try:
        doc = json.loads(raw or b"{}")
    except ValueError:
        doc = {}
    result = str(doc.get("result", "")).upper() if isinstance(doc, dict) else ""
    ok = status in (200, 201, 202) and result in ("OK", "")
    log(f"AM POST {CFG['am_login_path']} for '{user['username']}' (tenant {user['tenant_id']}) "
        f"-> {status} {'OK' if ok else 'FAILURE'}")
    if ok:
        return True, "OK", False
    if status in (200, 201, 202, 401, 404):
        return False, "Wrong tenant, username or password.", False
    if status == 403:
        return False, "This account is blocked in the AM.", False
    if status == 429:
        return False, "Too many failed sign-ins: wait a few minutes and try again.", False
    if status == 502:
        return False, "Sign-in is unavailable: the AM could not deliver the keys to PostgreSQL (am_keys).", True
    return False, f"AM answered {status}.", True


# ---------------------------------------------------------------- sign-in
class OAuthError(Exception):
    def __init__(self, status, error, description):
        super().__init__(description)
        self.status, self.error, self.description = status, error, description


def sign_in(org, username, password, client_id, scope, with_refresh):
    """Checks the user with the AM and opens a session. Returns (session, access, refresh)."""
    if not (org and username and password):
        raise OAuthError(400, "invalid_request", "tenant, username and password are required.")
    try:
        user = db_find_user(org, username)
    except DbError as e:
        log(f"database error at sign-in: {e}")
        raise OAuthError(503, "server_error", f"Database not reachable: {e}")
    if not user:
        log(f"sign-in refused: no user '{username}' in tenant '{org}'")
        raise OAuthError(400, "invalid_grant", "Wrong tenant, username or password.")
    if user["user_status"] != "ACTIVE" or user["tenant_status"] != "ACTIVE":
        log(f"sign-in refused: '{username}' is {user['user_status']}, tenant {user['tenant_status']}")
        raise OAuthError(400, "invalid_grant", "This account or its tenant is not active.")

    token_id = secrets.token_urlsafe(24)   # public: the loginId the AM sends back with the keys
    access = secrets.token_urlsafe(32)
    refresh = secrets.token_urlsafe(32) if with_refresh else None
    # The session is committed BEFORE the AM call: the jar delivers the keys to am_keys
    # before it answers the login, and am_keys stores them only for a live session.
    # The tokens are not given out until the AM says OK; on any failure the session ends.
    try:
        db_create_session(user, token_id, access, refresh, client_id, scope)
    except DbError as e:
        log(f"database error at sign-in: {e}")
        raise OAuthError(503, "server_error", f"Database error: {e}")
    ok, msg, unreachable = call_am_login(user, password, token_id)
    if not ok:
        try:
            psql("SELECT oauth_end_sessions(ARRAY[:'tid'], 'login_failed');", tid=token_id)
        except DbError as e:
            log(f"database error ending the failed sign-in {token_id[:6]}...: {e}")
        raise OAuthError(503 if unreachable else 400,
                         "server_error" if unreachable else "invalid_grant", msg)
    log(f"'{username}' (tenant {user['org_code']}) signed in, session {token_id[:6]}... "
        f"(client {client_id}, login_status = 1)")
    return {**user, "token_id": token_id}, access, refresh


def check_scope(requested, allowed):
    """Space-separated scope; empty = all allowed. Returns the scope string in a fixed order."""
    want = (requested or "").split() or list(allowed)
    if not set(want) <= set(allowed):
        raise OAuthError(400, "invalid_scope", f"Allowed scopes: {' '.join(allowed)}.")
    return " ".join(s for s in allowed if s in want)


# ---------------------------------------------------------------- web
def page(title, body):
    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{html.escape(title)}</title>
<style>
body{{font:15px/1.5 system-ui,sans-serif;max-width:820px;margin:28px auto;padding:0 16px}}
table{{border-collapse:collapse;width:100%}} td,th{{text-align:left;padding:6px 8px;border-bottom:1px solid #ddd}}
pre{{background:#f1f2f4;padding:10px;border-radius:6px;white-space:pre-wrap;word-break:break-all}}
.ok{{color:#127a3a}} .bad{{color:#b42318}} .muted{{color:#666}}
button{{background:#2f5bea;color:#fff;border:0;border-radius:6px;padding:8px 16px;font:inherit;cursor:pointer}}
input{{font:inherit;padding:6px 8px;margin:4px 0 10px;width:240px}}
</style></head><body><h1>{html.escape(title)}</h1>{body}</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def send(self, status, body, ctype="text/html; charset=utf-8", headers=None):
        raw = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Pragma", "no-cache")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def send_json(self, status, doc, headers=None):
        self.send(status, json.dumps(doc, indent=2), "application/json", headers)

    def send_oauth_error(self, e):
        headers = {"WWW-Authenticate": 'Basic realm="erms"'} if e.error == "invalid_client" else None
        self.send_json(e.status, {"error": e.error, "error_description": e.description}, headers)

    def params(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        if self.headers.get("Content-Type", "").startswith("application/json"):
            try:
                doc = json.loads(raw or b"{}")
            except ValueError:
                return {}
            return {k: "" if v is None else str(v) for k, v in doc.items()} if isinstance(doc, dict) else {}
        return {k: v[0] for k, v in urllib.parse.parse_qs(raw.decode()).items()}

    def client_id(self, p):
        """client_id from HTTP Basic auth or the body; must be a known (public) client."""
        cid = ""
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Basic "):
            try:
                cid = urllib.parse.unquote(base64.b64decode(auth[6:]).decode().partition(":")[0])
            except (ValueError, UnicodeDecodeError):
                raise OAuthError(401, "invalid_client", "Malformed Basic authorization.")
        cid = cid or p.get("client_id", "").strip() or "erms_web"
        if cid not in CFG["clients"]:
            raise OAuthError(401, "invalid_client", f"Unknown client_id '{cid}'.")
        return cid

    def session(self):
        """The live session of the Bearer token or the browser cookie: (token, session or None)."""
        token = ""
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:].strip()
        if not token:
            for part in (self.headers.get("Cookie") or "").split(";"):
                k, _, v = part.strip().partition("=")
                if k == "sid":
                    token = v
        try:
            return token, db_session_by_access(token)
        except DbError as e:
            log(f"database error reading the session: {e}")
            return token, None

    # ---- routing
    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/":
            return self.home()
        if path == "/api/me":
            return self.api_me()
        if path == "/oauth/userinfo":
            return self.userinfo()
        if path in ("/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"):
            return self.metadata()
        if path in ("/oauth/token", "/oauth/introspect", "/oauth/revoke", "/login", "/logout"):
            return self.send_json(405, {"error": "invalid_request", "error_description": "Use POST."},
                                  {"Allow": "POST"})
        self.send_json(404, {"message": "No such endpoint.", "code": "NO_SUCH_ENDPOINT"})

    def do_POST(self):
        routes = {"/login": self.browser_login,
                  "/logout": lambda: self.logout(browser=True),
                  "/api/logout": lambda: self.logout(browser=False),
                  "/oauth/token": self.token,
                  "/oauth/introspect": self.introspect,
                  "/oauth/revoke": self.revoke,
                  "/oauth/userinfo": self.userinfo}
        route = routes.get(urllib.parse.urlparse(self.path).path)
        if route:
            return route()
        self.send_json(404, {"message": "No such endpoint.", "code": "NO_SUCH_ENDPOINT"})

    # ---- OAuth endpoints
    def token(self):
        p = self.params()
        try:
            cid = self.client_id(p)
            grant = p.get("grant_type", "").strip() or "password"   # no grant_type: the old callers
            if grant == "password":
                scope = check_scope(p.get("scope"), CFG["scopes"])
                s, access, refresh = sign_in(p.get("tenant", "").strip(), p.get("username", "").strip(),
                                             p.get("password", ""), cid, scope, with_refresh=True)
            elif grant == "refresh_token":
                old = p.get("refresh_token", "").strip()
                if not old:
                    raise OAuthError(400, "invalid_request", "refresh_token is required.")
                access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
                try:
                    current = db_session_by_refresh(old)
                    if current and p.get("scope"):
                        check_scope(p.get("scope"), current["scope"].split())   # may only narrow
                    s = db_rotate(old, cid, access, refresh) if current else None
                except DbError as e:
                    raise OAuthError(503, "server_error", f"Database error: {e}")
                if not s:
                    raise OAuthError(400, "invalid_grant", "The refresh token is not valid (expired, revoked, "
                                                           "already used, or issued to another client).")
                scope = s["scope"]
                log(f"'{s['username']}' refreshed session {s['token_id'][:6]}...")
            else:
                raise OAuthError(400, "unsupported_grant_type", "Use grant_type=password or refresh_token.")
        except OAuthError as e:
            return self.send_oauth_error(e)
        self.send_json(200, {"access_token": access, "token_type": "Bearer",
                             "expires_in": CFG["token_lifetime_seconds"],
                             "refresh_token": refresh,
                             "refresh_expires_in": CFG["refresh_token_lifetime_seconds"],
                             "scope": scope, "login_id": s["token_id"]})

    def introspect(self):
        p = self.params()
        token, hint = p.get("token", "").strip(), p.get("token_type_hint", "")
        if not token:
            return self.send_oauth_error(OAuthError(400, "invalid_request", "token is required."))
        lookups = [("access_token", db_session_by_access), ("refresh_token", db_session_by_refresh)]
        if hint == "refresh_token":
            lookups.reverse()
        s = kind = None
        try:
            for kind, lookup in lookups:
                s = lookup(token)
                if s:
                    break
        except DbError as e:
            return self.send_oauth_error(OAuthError(503, "server_error", f"Database error: {e}"))
        if not s:
            return self.send_json(200, {"active": False})
        self.send_json(200, {"active": True,
                             "token_type": "Bearer" if kind == "access_token" else "refresh_token",
                             "scope": s["scope"], "client_id": s["client_id"], "username": s["username"],
                             "sub": str(s["user_id"]), "tenant_id": s["tenant_id"], "org_code": s["org_code"],
                             "exp": s["exp"] if kind == "access_token" else s["session_exp"],
                             "iat": s["iat"], "iss": ISSUER, "login_id": s["token_id"]})

    def revoke(self):
        """RFC 7009: answers 200 even for an unknown token. Ends the whole session."""
        p = self.params()
        token = p.get("token", "").strip()
        if not token:
            return self.send_oauth_error(OAuthError(400, "invalid_request", "token is required."))
        try:
            n = db_end_by_token(token, "revoked")
        except DbError as e:
            return self.send_oauth_error(OAuthError(503, "server_error", f"Database error: {e}"))
        log("token revoked" + ("; user signed out (login_status = 0, keys removed)" if n else ""))
        self.send_json(200, {})

    def userinfo(self):
        token, s = self.session()
        if not s:
            challenge = 'Bearer error="invalid_token"' if token else 'Bearer realm="erms"'
            return self.send(401, json.dumps({"error": "invalid_token"}), "application/json",
                             {"WWW-Authenticate": challenge})
        try:
            rows = db_keys(s["user_id"]) or {}
        except DbError as e:
            return self.send_json(503, {"error": "server_error", "error_description": f"Database error: {e}"})
        self.send_json(200, {"sub": str(s["user_id"]), "preferred_username": s["username"],
                             "tenant_id": s["tenant_id"], "org_code": s["org_code"], "scope": s["scope"],
                             "login_status": rows.get("login_status"),
                             "keys": [{"type_id": k["type_id"], "has_key": k["has_key"]}
                                      for k in rows.get("keys") or []]})

    def metadata(self):
        self.send_json(200, {
            "issuer": ISSUER,
            "token_endpoint": ISSUER + "/oauth/token",
            "introspection_endpoint": ISSUER + "/oauth/introspect",
            "revocation_endpoint": ISSUER + "/oauth/revoke",
            "userinfo_endpoint": ISSUER + "/oauth/userinfo",
            "grant_types_supported": ["password", "refresh_token"],
            "response_types_supported": [],
            "scopes_supported": CFG["scopes"],
            "token_endpoint_auth_methods_supported": ["none"],
            "introspection_endpoint_auth_methods_supported": ["none"],
            "revocation_endpoint_auth_methods_supported": ["none"],
        })

    # ---- browser sign in / out
    def browser_login(self):
        p = self.params()
        try:
            _, access, _ = sign_in(p.get("tenant", "").strip(), p.get("username", "").strip(),
                                   p.get("password", ""), "erms_web", " ".join(CFG["scopes"]),
                                   with_refresh=False)
        except OAuthError as e:
            return self.home(f'<p class="bad">{html.escape(e.description)}</p>',
                             401 if e.error in ("invalid_grant", "invalid_request") else e.status)
        self.send(303, "", headers={"Location": "/", "Set-Cookie":
                                    f"sid={access}; HttpOnly; SameSite=Lax; Path=/; "
                                    f"Max-Age={CFG['token_lifetime_seconds']}"})

    def logout(self, browser):
        token, s = self.session()
        if s:
            try:
                n = db_end_by_token(token, "signed_out")
                log(f"'{s['username']}' signed out of session {s['token_id'][:6]}..."
                    + (" (login_status = 0, keys removed)" if n else " (another session is still live)"))
            except DbError as e:
                log(f"database error at sign-out: {e}")
        if browser:
            return self.send(303, "", headers={"Location": "/", "Set-Cookie": "sid=; Max-Age=0; Path=/"})
        self.send_json(200, {"message": "Signed out."})

    # ---- pages
    def home(self, notice="", status=200):
        _, s = self.session()
        recent = "<br>".join(html.escape(e) for e in events[:15]) or "(nothing yet)"
        if s:
            left = max(0, s["exp"] - int(time.time()))
            body = f"""{notice}<p>Signed in as <b>{html.escape(s['username'])}</b>, tenant
<b>{html.escape(s['org_code'])}</b> ({s['tenant_id']}) · user_id {s['user_id']}</p>
<p class="muted">Session {html.escape(s['token_id'][:6])}... (the loginId the AM sends the keys with)
· expires in {left // 60} min</p>
<form method="post" action="/logout"><button>Sign out</button></form>
<h3>user_asset_map</h3><div id="keys" class="muted">loading...</div>
<p class="muted">Read from PostgreSQL. Keys are never shown, only a SHA-256 fingerprint. Refreshes every 2 seconds.</p>
<script>
async function load(){{
  const r = await fetch('/api/me'); const d = await r.json(); const el = document.getElementById('keys');
  if (!r.ok) {{ el.textContent = d.message || d.error || r.status; return; }}
  if (!d.keys.length) {{ el.textContent = 'No rows yet.'; return; }}
  el.innerHTML = '<table><tr><th>type_id</th><th>asset_key</th></tr>' + d.keys.map(k =>
    '<tr><td>'+k.type_id+'</td><td>'+(k.has_key ? '<span class=ok>set</span> sha256 '+k.fingerprint
    : '<span class=bad>empty (waiting for the AM)</span>')+'</td></tr>').join('') + '</table>';
}}
load(); setInterval(load, 2000);
</script>"""
        else:
            body = f"""{notice}<form method="post" action="/login">
<label>Tenant (org code)<br><input name="tenant" placeholder="ACME" autofocus></label><br>
<label>Username<br><input name="username"></label><br>
<label>Password<br><input name="password" type="password"></label><br>
<button>Sign in</button></form>"""
        body += f"""<h3>Recent activity</h3><pre>{recent}</pre>
<p class="muted">AM: {html.escape(am_url() or 'not set')}{html.escape(CFG['am_login_path'])} ·
database {html.escape(CFG['db_name'])} ·
<a href="/.well-known/oauth-authorization-server">OAuth metadata</a></p>"""
        self.send(status, page("ERMS login", body))

    def api_me(self):
        _, s = self.session()
        if not s:
            return self.send(401, json.dumps({"error": "invalid_token"}), "application/json",
                             {"WWW-Authenticate": 'Bearer error="invalid_token"'})
        try:
            rows = db_keys(s["user_id"]) or {}
        except DbError as e:
            return self.send_json(503, {"message": f"Database error: {e}", "code": "DB_ERROR"})
        self.send_json(200, {"username": s["username"], "tenant": s["org_code"], "tenant_id": s["tenant_id"],
                             "user_id": s["user_id"], "login_status": rows.get("login_status"),
                             "keys": rows.get("keys") or []})

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    print(f"ERMS login + OAuth 2.0 on {ISSUER}   (Ctrl+C to stop)")
    print(f"  AM: {am_url() or 'NOT SET'}{CFG['am_login_path']}   database: {CFG['db_name']}", flush=True)
    try:
        ready = (psql("SELECT json_build_object('ok', to_regclass('oauth_tokens') IS NOT NULL "
                      "AND to_regproc('oauth_sweep') IS NOT NULL);") or {}).get("ok")
    except DbError as e:
        ready = None
        print(f"  database not reachable yet: {e}")
    if ready is False:
        print(r"  oauth_tokens is missing: run  psql -U postgres -d erms -f D:\postgres-dev\merged\05_oauth.sql")
        raise SystemExit(1)
    threading.Thread(target=sweeper, daemon=True).start()
    try:
        ThreadingHTTPServer(("127.0.0.1", CFG["port"]), Handler).serve_forever()
    except KeyboardInterrupt:
        print("Stopped.")
