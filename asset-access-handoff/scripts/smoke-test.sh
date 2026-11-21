#!/usr/bin/env bash
# Checks that an API key works end to end: lists the roles, registers a test user with the
# first role, logs the user in (which delivers the user's assets to the receiver), then
# disables the test user. Needs curl, and a receiver at app.asset-delivery.url: for a test,
# run scripts/test-receiver.py in another terminal first.
#
#   API_KEY='ak_0123456789abcdef.xxxxxxxx' ./scripts/smoke-test.sh
#
# Users cannot be deleted, so each run leaves one disabled user named smoke-<random>.
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
: "${API_KEY:?Set API_KEY to the tenant API key (ak_...)}"

json_field() { { grep -o "\"$1\" *: *\"[^\"]*\"" | sed -n '1s/.*: *"\(.*\)"/\1/p'; } || true; }

# api METHOD PATH EXPECTED_STATUS [BODY]: prints the service's message, or fails.
api() {
  local args=(-sS -o /tmp/asset-access-body.$$ -w '%{http_code}' -X "$1" "$BASE_URL$2" -H "X-Api-Key: $API_KEY")
  [ -n "${4:-}" ] && args+=(-H 'Content-Type: application/json; charset=utf-8' --data-binary "$4")
  if ! status="$(curl "${args[@]}")"; then
    echo "Cannot reach $BASE_URL. Is the service running?" >&2; exit 1
  fi
  body="$(cat /tmp/asset-access-body.$$)"; rm -f /tmp/asset-access-body.$$
  if [ "$status" != "$3" ]; then
    echo "$1 $2 failed: $(printf '%s' "$body" | json_field message) ($(printf '%s' "$body" | json_field code))" >&2
    exit 1
  fi
  echo "   $(printf '%s' "$body" | json_field message)"
}

username="smoke-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"

echo "1. GET /api/v1/roles"
api GET /api/v1/roles 200
role="$(printf '%s' "$body" | json_field name)"

echo "2. POST /api/v1/users  ($username, role '$role')"
api POST /api/v1/users 201 "{\"username\":\"$username\",\"password\":\"smoke-test-password\",\"role\":\"$role\"}"

echo "3. POST /api/v1/auth/login  ($username)"
login_body="{\"username\":\"$username\",\"password\":\"smoke-test-password\",\"requestId\":\"smoke-test\"}"
if ! status="$(curl -sS -o /tmp/asset-access-body.$$ -w '%{http_code}' -X POST "$BASE_URL/api/v1/auth/login" \
      -H "X-Api-Key: $API_KEY" -H 'Content-Type: application/json; charset=utf-8' --data-binary "$login_body")"; then
  echo "Cannot reach $BASE_URL. Is the service running?" >&2; exit 1
fi
body="$(cat /tmp/asset-access-body.$$)"; rm -f /tmp/asset-access-body.$$
if [ "$status" = 502 ]; then
  echo "   The password was accepted, but the assets could not be delivered:" >&2
  echo "   $(printf '%s' "$body" | json_field message)" >&2
  echo "   Check app.asset-delivery.url and .secret in config/application.yml, and that the" >&2
  echo "   receiver is running (scripts/test-receiver.py for a test)." >&2
  exit 1
elif [ "$status" != 200 ]; then
  echo "POST /api/v1/auth/login failed: $(printf '%s' "$body" | json_field message) ($(printf '%s' "$body" | json_field code))" >&2
  exit 1
fi
echo "   $(printf '%s' "$body" | json_field message) The receiver has the user's assets."

echo "4. PUT /api/v1/users/$username/enabled  (false)"
api PUT "/api/v1/users/$username/enabled" 200 '{"enabled":false}'

echo
echo "Smoke test passed: the API key, user registration, login and asset delivery all work."
