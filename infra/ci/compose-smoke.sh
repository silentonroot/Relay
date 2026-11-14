#!/usr/bin/env bash
#
# Builds the images, starts infra/compose.yaml with throwaway secrets, checks that the stack
# behaves as documented, and removes everything again.
#
#   infra/ci/compose-smoke.sh            build, start, check, remove
#   AAB_SMOKE_KEEP=1 infra/ci/...        leave the stack running for inspection
#
# Used by continuous integration and runnable on any machine with Docker and Compose. Every
# secret here is generated for this run and deleted with it; nothing is real.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
port="${AAB_DASHBOARD_PORT:-8080}"
base="http://127.0.0.1:${port}"
work="$(mktemp -d "${TMPDIR:-/tmp}/aab-smoke.XXXXXX")"
export AAB_HOST_SECRETS_DIR="${work}/secrets"
export AAB_DASHBOARD_PORT="${port}"
export COMPOSE_PROJECT_NAME="${AAB_SMOKE_PROJECT:-aab-smoke}"

compose() { docker compose -f "${repo}/infra/compose.yaml" "$@"; }
say() { printf '== %s\n' "$*"; }
fail() {
  printf 'FAILED: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  status=$?
  if [ "${status}" -ne 0 ]; then
    say "service state and logs (the run failed)"
    compose ps -a || true
    compose logs --no-color --tail 80 || true
  fi
  if [ "${AAB_SMOKE_KEEP:-0}" != "1" ]; then
    compose down --volumes --remove-orphans >/dev/null 2>&1 || true
    rm -rf "${work}"
  else
    say "left running; secrets directory: ${work}"
  fi
  exit "${status}"
}
trap cleanup EXIT

# --- throwaway secrets -------------------------------------------------------------------
umask 077
mkdir -p "${AAB_HOST_SECRETS_DIR}"
db_password="$(openssl rand -hex 24)"
printf '%s' "${db_password}" >"${AAB_HOST_SECRETS_DIR}/postgres_password"
printf 'DATABASE_URL=postgres://aab:%s@postgres:5432/aab\n' "${db_password}" \
  >"${AAB_HOST_SECRETS_DIR}/broker-api.env"
openssl rand -base64 18 >"${work}/owner_password"
# The containers run as other users and read these through bind mounts.
chmod 755 "${work}" "${AAB_HOST_SECRETS_DIR}"
chmod 644 "${AAB_HOST_SECRETS_DIR}/postgres_password" "${AAB_HOST_SECRETS_DIR}/broker-api.env"
unset db_password

# --- build and start ---------------------------------------------------------------------
say "build and start"
compose up --build --detach --wait

status_of() { curl --silent --max-time 10 --output /dev/null --write-out '%{http_code}' "$@"; }

# --- checks ------------------------------------------------------------------------------
say "health through nginx"
health="$(curl --silent --max-time 10 "${base}/v1/health")"
case "${health}" in
  *'"status":"ok"'*'"database":"ok"'*) ;;
  *) fail "unexpected health response: ${health}" ;;
esac

say "dashboard and security headers"
[ "$(status_of "${base}/")" = "200" ] || fail "dashboard index did not return 200"
headers="$(curl --silent --max-time 10 --dump-header - --output /dev/null "${base}/")"
for header in content-security-policy x-frame-options x-content-type-options referrer-policy; do
  printf '%s' "${headers}" | grep --quiet --ignore-case "^${header}:" ||
    fail "missing response header: ${header}"
done

say "unexpected Host is refused"
[ "$(status_of --header 'Host: unexpected.example' "${base}/")" = "421" ] ||
  fail "a request with an unexpected Host was not refused with 421"

say "API requires a session"
[ "$(status_of "${base}/v1/connections")" = "401" ] || fail "unauthenticated request was not 401"

say "migrations"
tables="$(compose exec -T postgres psql --username=aab --dbname=aab --tuples-only --no-align \
  --command "select count(*) from information_schema.tables where table_schema = 'public'")"
[ "${tables}" -ge 14 ] || fail "expected at least 14 tables after migration, found ${tables}"

say "API container hardening"
compose exec -T broker-api sh -c '
  [ "$(id -u)" != "0" ] || { echo "runs as root"; exit 1; }
  ! touch /app/.write-test 2>/dev/null || { echo "root filesystem is writable"; exit 1; }
  ! env | grep -q "^AAB_KEK_DIR=" || { echo "a key directory is configured"; exit 1; }
' || fail "API container hardening check failed"
compose exec -T broker-api node -e "
  fetch('https://example.com', { signal: AbortSignal.timeout(4000) }).then(
    () => { console.error('the API container reached the internet'); process.exit(1); },
    () => process.exit(0),
  );" || fail "the API container has outbound network access"

say "owner bootstrap, login and a denied operation"
compose exec -T broker-api npm run --silent create-owner -- --email owner@example.test \
  <"${work}/owner_password" >/dev/null
python3 - "${base}" "${work}/owner_password" <<'PY'
import http.cookiejar, json, sys, urllib.error, urllib.request

base, password_file = sys.argv[1], sys.argv[2]
password = open(password_file).read().strip()
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def call(method, path, body=None, csrf=None):
    headers = {}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["content-type"] = "application/json"
    if csrf:
        headers["x-csrf-token"] = csrf
    request = urllib.request.Request(base + path, data=data, method=method, headers=headers)
    try:
        with opener.open(request, timeout=60) as response:
            return response.status, json.loads(response.read() or b"null")
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read() or b"null")


def expect(label, actual, wanted):
    if actual != wanted:
        sys.exit(f"FAILED: {label}: expected {wanted!r}, got {actual!r}")


status, session = call("POST", "/v1/auth/login", {"email": "owner@example.test", "password": password})
expect("login", status, 200)
csrf = session["csrfToken"]
cookie = next(c for c in jar if c.name == "aab_session")
expect("session cookie is HttpOnly", cookie.has_nonstandard_attr("HttpOnly"), True)

status, application = call("POST", "/v1/applications/register", {
    "adapterId": "northstar", "adapterVersion": "0.1.0", "name": "Northstar",
    "allowedOrigins": ["http://localhost:4100"], "authModes": ["browser_session"]}, csrf)
expect("register application", status, 201)
status, connection = call("POST", "/v1/connections",
                          {"applicationId": application["id"], "displayName": "Smoke (synthetic)"}, csrf)
expect("create connection", status, 201)
status, agent = call("POST", "/v1/agents", {"name": "Smoke agent", "clientIdentity": "compose-smoke"}, csrf)
expect("create agent", status, 201)

execute = {"agentId": agent["id"], "connectionId": connection["id"], "operation": "orders.list",
           "arguments": {}, "idempotencyKey": "compose-smoke-0001"}
status, body = call("POST", "/v1/operations/execute", execute, csrf)
expect("ungranted execute status", status, 403)
expect("ungranted execute code", body["error"]["code"], "denied")
status, body = call("POST", "/v1/operations/execute", execute)
expect("execute without CSRF token", (status, body["error"]["code"]), (403, "csrf_failed"))
status, events = call("GET", "/v1/audit-events?limit=50")
expect("audit list", status, 200)
types = {event["eventType"] for event in events["items"]}
for wanted in ("auth.login_succeeded", "application.registered", "connection.created",
               "agent.created", "policy.evaluated"):
    if wanted not in types:
        sys.exit(f"FAILED: audit event {wanted} is missing")
PY
jobs="$(compose exec -T postgres psql --username=aab --dbname=aab --tuples-only --no-align \
  --command 'select count(*) from execution_jobs')"
[ "${jobs}" = "0" ] || fail "a denied operation created ${jobs} job row(s)"

say "published ports"
published="$(docker ps --filter "label=com.docker.compose.project=${COMPOSE_PROJECT_NAME}" \
  --format '{{.Ports}}' | tr ',' '\n' | grep -- '->' || true)"
[ "$(printf '%s\n' "${published}" | grep -c .)" = "1" ] || fail "expected exactly one published port"
case "${published}" in
  *"127.0.0.1:${port}->"*) ;;
  *) fail "the published port is not bound to loopback: ${published}" ;;
esac

say "all checks passed"
