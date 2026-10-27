#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
#
# perf-m13-inner.sh runs inside the PostgreSQL container's network
# namespace (started by perf-m13.sh); /perf holds the binaries and the
# results. Not meant to be run by hand.
set -euo pipefail
cd /perf
echo "== machine"
echo "cpus $(nproc)"; grep MemTotal /proc/meminfo; uname -r
admin="postgres://postgres:${PGPASSWORD}@127.0.0.1:5432/postgres?sslmode=disable"

for round in $(seq 1 "$ROUNDS"); do
	echo "== round $round: BenchmarkRefund ($BENCHTIME)"
	# The test reads ../../../../packages, as from its package directory.
	mkdir -p /repo/internal/authority/adapters/pgauthority
	(cd /repo/internal/authority/adapters/pgauthority && PC_TEST_REQUIRE_DB=1 PC_TEST_PG_ADMIN_URL="$admin" \
		/perf/pgauthority.test -test.run '^$' -test.bench BenchmarkRefund -test.benchtime "$BENCHTIME" -test.count 1 2>&1) |
		grep -v '^{' || true
done

echo "== stack setup"
s=/tmp/s
mkdir -p "$s/gateway"
for r in pc_app pc_migrator pc_audit_ro pc_retention; do
	head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n' >"$s/$r.pw"
done
printf 'postgres://postgres:%s@127.0.0.1:5432/pantherclaw?sslmode=disable' "$PGPASSWORD" >"$s/admin.url"
chmod 600 "$s"/*
cat >"$s/server.json" <<JSON
{"role":"all","log":{"level":"warn"},"http":{"addr":"127.0.0.1:8080"},
 "database":{"host":"127.0.0.1","port":5432,"name":"pantherclaw","sslmode":"disable",
  "app_user":"pc_app","app_password_file":"$s/pc_app.pw",
  "migrator_user":"pc_migrator","migrator_password_file":"$s/pc_migrator.pw",
  "retention_user":"pc_retention","retention_password_file":"$s/pc_retention.pw"},
 "kek_files":["$s/kek"],"worker_concurrency":4,
 "authority":{"grant_max_per_action":"100","grant_currency":"USD","budget_name":"perf-refunds","permit_ttl":"5s",
  "stale_dispatch_after":"30s","budget_lock_timeout":"100ms"},
 "gateway_api":{"addr":"127.0.0.1:8443","hostnames":["127.0.0.1"],"url":"https://127.0.0.1:8443"},
 "auth":{"public_url":"http://127.0.0.1:8080","api_key_env":"dev","oidc_providers":[]},
 "limits":{"api":{"per_org_per_minute":1000000,"per_credential_per_minute":1000000}},
 "admin":{"addr":"127.0.0.1:6060"}}
JSON
cat >"$s/gateway.json" <<JSON
{"log":{"level":"warn"},"listen":"127.0.0.1:8090","public_url":"http://127.0.0.1:8090",
 "control":{"api_url":"http://127.0.0.1:8080","identity_dir":"$s/gateway","timeout":"2s"},
 "egress":{"allowed_prefixes":["127.0.0.1/32"]}}
JSON
./pantherclaw-server db bootstrap --admin-url-file "$s/admin.url" --app-password-file "$s/pc_app.pw" \
	--migrator-password-file "$s/pc_migrator.pw" --audit-password-file "$s/pc_audit_ro.pw" --retention-password-file "$s/pc_retention.pw"
./pantherclaw-server keys gen-kek --out "$s/kek"
./pantherclaw-server migrate up --config "$s/server.json"
./pantherclaw-server dev seed --config "$s/server.json" --org-name perf --budget-limit 100000000.00 \
	--gateway-out "$s/gateway-enroll.json" --target-url http://127.0.0.1:9090 \
	--workload-out "$s/workload.json" --facts-key-out "$s/facts.key"
./pantherclaw-server serve --config "$s/server.json" >/tmp/server.log 2>&1 &
./pantherclaw-sim payments --addr 127.0.0.1:9090 >/tmp/sim.log 2>&1 &
wait_port() { for _ in $(seq 1 120); do (echo >"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0; sleep 0.5; done; echo "port $1 never opened" >&2; return 1; }
wait_port 8080
./pantherclaw-gateway serve --config "$s/gateway.json" --enroll-file "$s/gateway-enroll.json" >/tmp/gateway.log 2>&1 &
gw=$!
wait_port 8090
sleep 3

# profile RATE saves a 15 s CPU profile of the server, taken 10 s into the
# load, from the loopback admin listener (HR-382), as /perf/out/cpu-rRATE.http
# (the raw HTTP response; perf-m13.sh strips the headers).
profile() {
	sleep 10
	exec 3<>/dev/tcp/127.0.0.1/6060
	printf 'GET /debug/pprof/profile?seconds=15 HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n' >&3
	cat <&3 >"/perf/out/cpu-r$1.http"
	exec 3<&-
}

for round in $(seq 1 "$ROUNDS"); do
	for r in $RATES; do
		echo "== round $round: load at $r rps for $DURATION"
		if [ "${PROFILE:-0}" = 1 ] && [ "$round" = 1 ]; then profile "$r" & fi
		./pantherclaw-sim load --workload-file "$s/workload.json" --facts-key-file "$s/facts.key" --unique \
			--rate "$r" --duration "$DURATION" --warmup 5s --out "/perf/out/load-r$r-$round.json" || echo "load at $r failed"
		echo "gateway rss_kb $(awk '/VmRSS/ {print $2}' "/proc/$gw/status") hwm_kb $(awk '/VmHWM/ {print $2}' "/proc/$gw/status")"
		sleep 5
	done
done
echo "== errors"
grep -c '"level":"ERROR"' /tmp/server.log /tmp/gateway.log || true
grep '"level":"ERROR"' /tmp/server.log /tmp/gateway.log | cut -c1-300 | sort | uniq -c | sort -rn | head -10 || true
