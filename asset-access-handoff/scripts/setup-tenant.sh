#!/usr/bin/env bash
# One-time setup of a local Asset Access Service: loads the role/asset map (if not loaded yet)
# and creates a tenant with its first admin. Needs curl. The service must be running.
#
#   ADMIN_PASSWORD='the-platform-admin-password' TENANT_ADMIN_PASSWORD='manager-password-123' \
#     ./scripts/setup-tenant.sh
#
# Optional settings (environment variables, defaults shown):
#   BASE_URL=http://localhost:8080  ADMIN_USER=admin  MAP_FILE=samples/role-asset-map.json
#   TENANT_SLUG=acme  TENANT_NAME="Acme Corp"  TENANT_ADMIN=manager
#
# The map can be loaded only once per database. To start again, see sql/reset_database.sql.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
BASE_URL="${BASE_URL:-http://localhost:8080}"
ADMIN_USER="${ADMIN_USER:-admin}"
MAP_FILE="${MAP_FILE:-$here/../samples/role-asset-map.json}"
TENANT_SLUG="${TENANT_SLUG:-acme}"
TENANT_NAME="${TENANT_NAME:-Acme Corp}"
TENANT_ADMIN="${TENANT_ADMIN:-manager}"
: "${ADMIN_PASSWORD:?Set ADMIN_PASSWORD to the platform admin password}"
: "${TENANT_ADMIN_PASSWORD:?Set TENANT_ADMIN_PASSWORD to the new tenant admin password}"

# json_field NAME: prints the first string value of "NAME" in the JSON on stdin.
json_field() { { grep -o "\"$1\" *: *\"[^\"]*\"" | sed -n '1s/.*: *"\(.*\)"/\1/p'; } || true; }
# json_escape TEXT: escapes backslashes and double quotes for a JSON string.
json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

# api METHOD PATH [BODY] [TOKEN]: sets $status and $body.
api() {
  local args=(-sS -o /tmp/asset-access-body.$$ -w '%{http_code}' -X "$1" "$BASE_URL$2")
  [ -n "${3:-}" ] && args+=(-H 'Content-Type: application/json; charset=utf-8' --data-binary "$3")
  [ -n "${4:-}" ] && args+=(-H "Authorization: Bearer $4")
  if ! status="$(curl "${args[@]}")"; then
    echo "Cannot reach $BASE_URL. Is the service running?" >&2; exit 1
  fi
  body="$(cat /tmp/asset-access-body.$$)"; rm -f /tmp/asset-access-body.$$
}
fail() { echo "$1: $(printf '%s' "$body" | json_field message) ($(printf '%s' "$body" | json_field code))" >&2; exit 1; }

echo "1. Logging in as platform admin '$ADMIN_USER'..."
api POST /api/admin/auth/token "{\"username\":\"$(json_escape "$ADMIN_USER")\",\"password\":\"$(json_escape "$ADMIN_PASSWORD")\"}"
[ "$status" = 200 ] || fail "Login failed"
token="$(printf '%s' "$body" | json_field accessToken)"
echo "   $(printf '%s' "$body" | json_field message)"
trap 'api POST /api/admin/auth/logout "" "$token" || true' EXIT

echo "2. Checking the role/asset map..."
api GET /api/admin/role-asset-map "" "$token"
[ "$status" = 200 ] || fail "Reading the map failed"
if printf '%s' "$body" | grep -q '"data" *: *{ *}'; then
  echo "   Not loaded yet. Loading $MAP_FILE ..."
  api POST /api/admin/role-asset-map "$(cat "$MAP_FILE")" "$token"
  [ "$status" = 201 ] || fail "Loading the map failed"
else
  echo "   Already loaded. Skipping."
fi
echo "   $(printf '%s' "$body" | json_field message)"

echo "3. Creating tenant '$TENANT_SLUG' with admin '$TENANT_ADMIN'..."
api POST /api/admin/tenants "{\"slug\":\"$(json_escape "$TENANT_SLUG")\",\"name\":\"$(json_escape "$TENANT_NAME")\",\"admin\":{\"username\":\"$(json_escape "$TENANT_ADMIN")\",\"password\":\"$(json_escape "$TENANT_ADMIN_PASSWORD")\"}}" "$token"
if [ "$status" = 201 ]; then
  echo "   $(printf '%s' "$body" | json_field message)"
elif printf '%s' "$body" | grep -q '"TENANT_EXISTS"'; then
  echo "   $(printf '%s' "$body" | json_field message) Keeping the existing tenant."
else
  fail "Creating the tenant failed"
fi

cat <<EOF

Done. Next, create an API key for the client app:
  1. Open $BASE_URL/login
  2. Tenant: $TENANT_SLUG   Username: $TENANT_ADMIN   Password: (the tenant admin password)
  3. Open 'API keys', create a key, and copy it (it is shown only once).
  4. Test it:  API_KEY='ak_...' ./scripts/smoke-test.sh
EOF
