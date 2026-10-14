#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
#
# The local demo of the v0.1.0 preview (docs/quickstart.md): the server, a
# gateway, the GitHub simulator (REST, and the GitHub MCP server's tools) and
# the sandbox images, all on this machine and all SIMULATED. DEVELOPMENT ONLY:
# every address is loopback and every secret is generated for this checkout.
#
#   tools/scripts/demo.sh up       start everything (safe to run again)
#   tools/scripts/demo.sh down     stop the processes (data, secrets and the database stay)
#   tools/scripts/demo.sh status   show each process and the server's readiness
#   tools/scripts/demo.sh age      DEVELOPMENT ONLY: backdate the demo org so approvals count (quickstart step 8)
#   tools/scripts/demo.sh link-github EMAIL LOGIN   DEVELOPMENT ONLY: link a demo person to a GitHub login (quickstart step 9)
#
# Run it through `task demo:up`, `task demo:down` and `task demo:status`.
# Works in Git Bash on Windows, and on Linux and macOS. State lives under
# .demo/ (git-ignored): logs, pid files, configuration and the files the
# quickstart reads. Needs Go, Docker (28 or later), openssl and curl.
set -euo pipefail

cd "$(dirname "$0")/../.."
ROOT=$(pwd)
DEMO=.demo
SECRETS=deploy/dev/secrets
EXE=""
case "$(uname -s)" in MINGW* | MSYS* | CYGWIN*) EXE=".exe" ;; esac

API=http://localhost:8080  # "localhost", not 127.0.0.1: security keys (WebAuthn) need a host name
GATEWAY=http://localhost:8090
GITHUB_SIM=127.0.0.1:9092
GITHUB_MCP=127.0.0.1:9093
PROCS="github-sim server gateway"

if command -v task > /dev/null 2>&1; then
  TASK=(task)
else
  TASK=(go tool -modfile=tools/pins/task/go.mod task)
fi

say() { printf '%s\n' "$*"; }
die() { printf 'demo: %s\n' "$*" >&2; exit 1; }
bin() { printf 'bin/%s%s' "$1" "$EXE"; }

alive() { # alive PIDFILE
  [ -f "$1" ] && kill -0 "$(cat "$1")" 2> /dev/null
}

stop_pid() { # stop_pid PID: kill, then insist (Windows needs taskkill for native processes that ignore SIGTERM)
  local pid=$1 i
  kill "$pid" 2> /dev/null || true
  for i in 1 2 3 4 5 6 7 8 9 10; do
    kill -0 "$pid" 2> /dev/null || return 0
    sleep 0.3
  done
  if [ -n "$EXE" ] && [ -r "/proc/$pid/winpid" ]; then
    taskkill //F //PID "$(cat "/proc/$pid/winpid")" > /dev/null 2>&1 || true
  else
    kill -9 "$pid" 2> /dev/null || true
  fi
}

start_proc() { # start_proc NAME COMMAND...: a background process with a log and a pid file
  local name=$1
  shift
  if alive "$DEMO/pids/$name.pid"; then
    say "  $name: already running (pid $(cat "$DEMO/pids/$name.pid"))"
    return 0
  fi
  nohup "$@" > "$DEMO/logs/$name.log" 2>&1 &
  echo $! > "$DEMO/pids/$name.pid"
  say "  $name: started (pid $!, log $DEMO/logs/$name.log)"
}

wait_for() { # wait_for DESCRIPTION SECONDS COMMAND...
  local what=$1 secs=$2 i
  shift 2
  for ((i = 0; i < secs; i++)); do
    "$@" > /dev/null 2>&1 && return 0
    sleep 1
  done
  die "$what did not come up within ${secs}s (see $DEMO/logs/)"
}

rand_pw() { openssl rand -hex 24; }

write_compose_env() {
  local f=deploy/compose/.env
  [ -f "$f" ] && return 0
  say "  writing $f (local-only passwords)"
  (
    umask 077
    {
      echo "PC_PG_PASSWORD=$(rand_pw)"
      echo "PC_PG_TEST_PASSWORD=$(rand_pw)"
      echo "KC_ADMIN_PASSWORD=$(rand_pw)"
    } > "$f"
  )
}

write_secrets() { # the files of BUILD_GUIDE §4, created only when absent
  mkdir -p "$SECRETS"
  local r
  for r in pc_app pc_migrator pc_audit_ro pc_retention; do
    [ -f "$SECRETS/$r.pw" ] || (umask 077 && rand_pw > "$SECRETS/$r.pw")
  done
  # shellcheck disable=SC1091
  (set -a && . deploy/compose/.env && printf 'postgres://pc_owner:%s@127.0.0.1:5432/pantherclaw?sslmode=disable' "$PC_PG_PASSWORD") > "$SECRETS/admin.url.new"
  if [ ! -f "$SECRETS/admin.url" ]; then mv "$SECRETS/admin.url.new" "$SECRETS/admin.url"; else rm -f "$SECRETS/admin.url.new"; fi
  [ -f "$SECRETS/keycloak.secret" ] || printf 'pantherclaw-dev-only-client-secret' > "$SECRETS/keycloak.secret"
  [ -f "$DEMO/github-signin.secret" ] || (umask 077 && rand_pw > "$DEMO/github-signin.secret")
}

write_configs() {
  mkdir -p "$DEMO/gateway"
  # The server: loopback only (the dev package key and `dev seed` insist on it),
  # people sign in through the Keycloak development realm.
  cat > "$DEMO/server.json" << 'JSON'
{
  "role": "all",
  "log": { "level": "info" },
  "http": { "addr": "127.0.0.1:8080" },
  "database": {
    "host": "127.0.0.1",
    "port": 5432,
    "name": "pantherclaw",
    "sslmode": "disable",
    "app_user": "pc_app",
    "app_password_file": "deploy/dev/secrets/pc_app.pw",
    "migrator_user": "pc_migrator",
    "migrator_password_file": "deploy/dev/secrets/pc_migrator.pw",
    "retention_user": "pc_retention",
    "retention_password_file": "deploy/dev/secrets/pc_retention.pw"
  },
  "kek_files": ["deploy/dev/secrets/kek"],
  "worker_concurrency": 4,
  "authority": {
    "grant_max_per_action": "100",
    "grant_currency": "USD",
    "budget_name": "dev-refunds",
    "permit_ttl": "5s",
    "stale_dispatch_after": "30s",
    "budget_lock_timeout": "100ms"
  },
  "gateway_api": {
    "addr": "127.0.0.1:8443",
    "hostnames": ["127.0.0.1", "localhost"],
    "url": "https://127.0.0.1:8443"
  },
  "auth": {
    "public_url": "http://localhost:8080",
    "api_key_env": "dev",
    "oidc_providers": [
      {
        "name": "keycloak",
        "issuer": "http://127.0.0.1:8180/realms/pantherclaw",
        "client_id": "pantherclaw",
        "client_secret_file": "deploy/dev/secrets/keycloak.secret",
        "allow_insecure_loopback": true
      }
    ]
  },
  "github": { "client_id": "Iv23liSimulated", "client_secret_file": ".demo/github-signin.secret", "web_url": "http://127.0.0.1:9092", "api_url": "http://127.0.0.1:9092" },
  "webauthn": { "rp_name": "PantherClaw demo" },
  "notifications": { "concurrency": 5 },
  "dev": { "package_key_file": "deploy/dev/secrets/package-dev.pub.json" }
}
JSON
  # The gateway: its identity, broker key and approver keys stay under .demo/.
  cat > "$DEMO/gateway.json" << 'JSON'
{
  "log": { "level": "info" },
  "listen": "127.0.0.1:8090",
  "public_url": "http://localhost:8090",
  "control": {
    "api_url": "http://127.0.0.1:8080",
    "identity_dir": ".demo/gateway/identity",
    "timeout": "2s"
  },
  "broker": { "key_file": ".demo/gateway/broker.json", "kek_files": ["deploy/dev/secrets/kek"] },
  "egress": { "allowed_prefixes": ["127.0.0.1/32"] },
  "approvals": { "approver_keys_file": ".demo/approver-keys.json" }
}
JSON
}

up() {
  command -v docker > /dev/null || die "Docker is not installed"
  command -v openssl > /dev/null || die "openssl is not installed"
  command -v curl > /dev/null || die "curl is not installed"
  mkdir -p "$DEMO/logs" "$DEMO/pids"

  say "1/7 database and identity provider"
  write_compose_env
  "${TASK[@]}" up PROFILE=core > "$DEMO/logs/compose.log" 2>&1 || { cat "$DEMO/logs/compose.log" >&2; die "task up PROFILE=core failed"; }
  "${TASK[@]}" up PROFILE=identity >> "$DEMO/logs/compose.log" 2>&1 || { cat "$DEMO/logs/compose.log" >&2; die "task up PROFILE=identity failed"; }
  wait_for "PostgreSQL" 60 docker compose -f deploy/compose/compose.yaml exec -T postgres pg_isready -U pc_owner -d pantherclaw
  wait_for "Keycloak" 180 curl -fsS -o /dev/null http://127.0.0.1:8180/realms/pantherclaw/.well-known/openid-configuration

  say "2/7 build"
  go build -trimpath -o bin/ ./cmd/pantherclaw-server ./cmd/pantherclaw-gateway ./cmd/pantherclaw-sim ./cmd/pclaw

  say "3/7 secrets, configuration, database"
  write_secrets
  write_configs
  local server
  server=$(bin pantherclaw-server)
  if [ ! -f "$DEMO/db.done" ]; then
    "$server" db bootstrap --admin-url-file "$SECRETS/admin.url" \
      --app-password-file "$SECRETS/pc_app.pw" --migrator-password-file "$SECRETS/pc_migrator.pw" \
      --audit-password-file "$SECRETS/pc_audit_ro.pw" --retention-password-file "$SECRETS/pc_retention.pw" > "$DEMO/logs/bootstrap.log" 2>&1 ||
      { cat "$DEMO/logs/bootstrap.log" >&2; die "db bootstrap failed"; }
  fi
  [ -f "$SECRETS/kek" ] || "$server" keys gen-kek --out "$SECRETS/kek" > /dev/null
  "$server" migrate up --config "$DEMO/server.json" > "$DEMO/logs/migrate.log" 2>&1 || { cat "$DEMO/logs/migrate.log" >&2; die "migrate up failed"; }
  touch "$DEMO/db.done"
  [ -f "$DEMO/gateway/broker.json" ] || "$(bin pantherclaw-gateway)" broker-key generate --out "$DEMO/gateway/broker.json" --kek-file "$SECRETS/kek" > /dev/null

  say "4/7 the GitHub simulator (REST on $GITHUB_SIM, MCP on $GITHUB_MCP)"
  [ -f "$DEMO/github-mcp.token" ] || (umask 077 && printf 'ghp_%s' "$(openssl rand -hex 18)" > "$DEMO/github-mcp.token")
  start_proc github-sim "$(bin pantherclaw-sim)" github --addr "$GITHUB_SIM" --app-key "$DEMO/github-app.pem" --account acme --repos payments \
    --mcp-addr "$GITHUB_MCP" --mcp-token-file "$DEMO/github-mcp.token"
  wait_for "the GitHub simulator" 30 curl -fsS "http://$GITHUB_SIM/repos/acme/payments" -H "Authorization: Bearer $(cat "$DEMO/github-mcp.token")"

  say "5/7 the demo org: seed (a gateway, a workload with a grant, the GitHub connection)"
  if [ ! -f "$DEMO/seed.done" ]; then
    rm -f "$DEMO/gateway-enroll.json" "$DEMO/workload.json" "$DEMO/facts.key" "$DEMO/approver-keys.json"
    "$server" dev seed --config "$DEMO/server.json" --org-name acme --gateway-out "$DEMO/gateway-enroll.json" \
      --workload-out "$DEMO/workload.json" --facts-key-out "$DEMO/facts.key" --shell --github-url "http://$GITHUB_SIM" \
      > "$DEMO/seed.out" 2>&1 || { cat "$DEMO/seed.out" >&2; die "dev seed failed"; }
    touch "$DEMO/seed.done"
  fi

  say "6/7 sandbox images"
  "${TASK[@]}" sandbox:images > "$DEMO/images.out" 2>&1 || { cat "$DEMO/images.out" >&2; die "task sandbox:images failed"; }
  local edge probe
  edge=$(sed -n 's/^edge  //p' "$DEMO/images.out" | tail -1)
  probe=$(sed -n 's/^probe //p' "$DEMO/images.out" | tail -1)
  [ -n "$edge" ] && [ -n "$probe" ] || die "could not read the image ids from $DEMO/images.out"
  write_env "$edge" "$probe"

  say "7/7 server and gateway"
  start_proc server "$server" serve --config "$DEMO/server.json"
  wait_for "the server's /readyz" 60 curl -fsS "$API/readyz"
  start_proc gateway "$(bin pantherclaw-gateway)" serve --config "$DEMO/gateway.json" --enroll-file "$DEMO/gateway-enroll.json"
  wait_for "the gateway" 60 curl -sS -o /dev/null "$GATEWAY/"
  next_steps
}

# write_env writes the file the quickstart sources: the pclaw settings and the
# ids `dev seed` printed.
write_env() {
  local org agent grant github gwid
  org=$(sed -n 's/^seeded org \([0-9a-f-]\{36\}\).*/\1/p' "$DEMO/seed.out" | head -1)
  agent=$(sed -n 's#.*/agent/\([0-9a-f-]\{36\}\)/inst/.*#\1#p' "$DEMO/seed.out" | head -1)
  grant=$(sed -n 's/.* with grant \([0-9a-f-]\{36\}\).*/\1/p' "$DEMO/seed.out" | head -1)
  github=$(sed -n 's/^seeded github connection \([0-9a-f-]\{36\}\).*/\1/p' "$DEMO/seed.out" | head -1)
  gwid=$(sed -n 's/^seeded gateway \([0-9a-f-]\{36\}\).*/\1/p' "$DEMO/seed.out" | head -1)
  cat > "$DEMO/env.sh" << EOS
# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
# Source this file: . .demo/env.sh   (written by tools/scripts/demo.sh up)
export PATH="$ROOT/bin:\$PATH"
export PANTHERCLAW_CONFIG_DIR="$ROOT/$DEMO/pclaw"
export PANTHERCLAW_SANDBOX_EDGE_IMAGE="$1"
export PANTHERCLAW_SANDBOX_PROBE_IMAGE="$2"
export DEMO_SERVER="$API"
export DEMO_GATEWAY="$GATEWAY"
export DEMO_ORG="$org"
export DEMO_GATEWAY_ID="$gwid"
export DEMO_AGENT="$agent"
export DEMO_GRANT="$grant"
export DEMO_GITHUB="$github"
EOS
}

next_steps() {
  cat << EOF

The demo is up (all SIMULATED, all on this machine).
  server   $API      (log $DEMO/logs/server.log)
  gateway  $GATEWAY  (log $DEMO/logs/gateway.log)
  GitHub   http://$GITHUB_SIM, MCP http://$GITHUB_MCP

Next, in each terminal you use:  . $DEMO/env.sh
Then follow docs/quickstart.md from step 2 ("pclaw login").
Stop with: task demo:down
EOF
}

down() {
  local p f
  for p in gateway server github-sim; do
    f="$DEMO/pids/$p.pid"
    if alive "$f"; then
      stop_pid "$(cat "$f")"
      say "  $p: stopped"
    else
      say "  $p: not running"
    fi
    rm -f "$f"
  done
  say "The database, Keycloak and $SECRETS stay. 'task down PROFILE=core' stops the containers."
}

# demo_sql runs SQL (on stdin) against the demo database, as its owner. It
# refuses unless the database is on this machine and the configuration is the
# one `demo.sh up` wrote: these shortcuts are raw SQL, for the local demo only.
demo_sql() {
  [ -f "$DEMO/env.sh" ] && [ -f "$DEMO/server.json" ] && [ -f "$DEMO/seed.done" ] || die "run 'task demo:up' first"
  # shellcheck disable=SC1091
  . "$DEMO/env.sh"
  [ -n "${DEMO_ORG:-}" ] || die "run 'task demo:up' first"
  grep -q '"host": "127.0.0.1"' "$DEMO/server.json" || die "the demo configuration does not use a local database; refusing"
  case "$(cat "$SECRETS/admin.url" 2> /dev/null)" in
    postgres://*@127.0.0.1:* | postgres://*@localhost:*) ;;
    *) die "the database URL in $SECRETS/admin.url is not local; refusing" ;;
  esac
  docker compose -f deploy/compose/compose.yaml exec -T postgres psql -v ON_ERROR_STOP=1 -q -U pc_owner -d pantherclaw "$@"
}

# age backdates the demo org's people, role bindings and security keys by 30
# days. Approvals count only from accounts, roles and keys of a minimum age
# (G0 M5 part 2, decision 5), which a real org may lengthen but never shorten.
# This simulates a week-old org so that a fresh demo can be approved within
# minutes. DEVELOPMENT ONLY: it edits the demo org's rows directly, as the
# end-to-end tests do.
age() {
  demo_sql << SQL
UPDATE pc.users SET created_at = now() - interval '30 days' WHERE org_id = '$DEMO_ORG';
UPDATE pc.role_bindings SET created_at = now() - interval '30 days' WHERE org_id = '$DEMO_ORG';
UPDATE pc.webauthn_credentials SET created_at = now() - interval '30 days' WHERE org_id = '$DEMO_ORG';
SQL
  say "  people, roles and security keys of the demo org are now 30 days old"
}

# github_account_id mirrors the GitHub simulator's id for a login
# (internal/sim/github AccountID): n = 1000; n = n*31 + byte; n mod 1e9 + 1.
github_account_id() {
  local login=$1 n=1000 i c
  for ((i = 0; i < ${#login}; i++)); do
    printf -v c '%d' "'${login:i:1}"
    n=$((n * 31 + c)) # wraps like uint64; fixed up below
  done
  local m=$((n % 1000000000))
  if ((n < 0)); then m=$(((m + 1000000000 + 709551616) % 1000000000)); fi # 2^64 mod 1e9: n wrapped past 2^63
  echo $((m + 1))
}

# link_github links a person of the demo org to a GitHub login, as `pclaw github
# link` would after the person signed in to GitHub. The simulator's command
# line has no sign-in App, so the demo links the reviewer directly.
link_github() {
  local who=${1:-} login=${2:-} gid
  [ -n "$who" ] && [ -n "$login" ] || die "usage: demo.sh link-github <person email or subject> <github login>"
  [[ $who =~ ^[A-Za-z0-9._@+-]+$ ]] || die "the person must be an email or a subject (letters, digits and . _ @ + -)"
  [[ $login =~ ^[A-Za-z0-9-]+$ ]] || die "the GitHub login must be letters, digits and -"
  gid=$(github_account_id "$login")
  demo_sql << SQL
INSERT INTO pc.github_identities (org_id, id, user_id, github_login, github_user_id, linked_by, verified_at)
  SELECT '$DEMO_ORG', gen_random_uuid(), u.id, '$login', $gid, 'demo', now()
  FROM pc.users u WHERE u.org_id = '$DEMO_ORG' AND (u.email = '$who' OR u.subject = '$who') LIMIT 1;
INSERT INTO pc.github_identity_history (org_id, github_user_id, user_id)
  SELECT '$DEMO_ORG', $gid, u.id FROM pc.users u WHERE u.org_id = '$DEMO_ORG' AND (u.email = '$who' OR u.subject = '$who') LIMIT 1
  ON CONFLICT DO NOTHING;
SQL
  say "  linked $who to GitHub login $login (id $gid) in the demo org, if that person exists"
}

status() {
  local p f rc=0
  for p in $PROCS; do
    f="$DEMO/pids/$p.pid"
    if alive "$f"; then say "  $p: running (pid $(cat "$f"))"; else say "  $p: not running"; rc=1; fi
  done
  if curl -fsS "$API/readyz" > /dev/null 2>&1; then say "  server /readyz: ready"; else say "  server /readyz: not ready"; rc=1; fi
  return $rc
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  status) status ;;
  age) age ;;
  link-github) shift; link_github "$@" ;;
  *) die "usage: demo.sh up|down|status|age|link-github" ;;
esac
