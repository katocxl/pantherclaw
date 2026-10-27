#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
#
# perf-m13.sh: the M13 performance measurement (G0 M13 F7; PN-011.1,
# PN-011.2; docs/perf/M13.md), with fixed conditions so that runs compare.
#
# It builds static Linux binaries of this tree (server, gateway, simulator)
# and the pgauthority integration test binary, starts a private
# PostgreSQL 17 container (the compose file's pinned image), and runs
# everything inside that container's network namespace, so PostgreSQL is
# on loopback ("co-located") and Docker Desktop's port forwarding is not
# measured. Then:
#
#   1. BenchmarkRefund (Authorize, BeginDispatch and RecordExecution on
#      PostgreSQL, closed loop) with 1 and 8 workers, -benchtime 1000x;
#   2. the whole stack (server, gateway over mTLS, payments simulator) under
#      `pantherclaw-sim load --unique` (open loop) at each rate in RATES,
#      with the gateway's resident memory after each run.
#
# Results go to bin/perf/out/ (git-ignored). The container is removed at
# the end. Nothing here needs an account or the network beyond Docker.
#
# Environment: RATES (default "10 50 100"), DURATION (default 30s),
# BENCHTIME (default 1000x), ROUNDS (default 1), PROFILE=1 (a 15 s server CPU
# profile during the first round of each rate), NAME (the container, default
# pc-perf-m13; two trees measured side by side need two names), KEEP=1
# keeps the container.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
out=bin/perf
name=${NAME:-pc-perf-m13}
image=$(sed -n 's/^ *image: \(postgres:17-bookworm@sha256:[0-9a-f]*\)$/\1/p' deploy/compose/compose.yaml | head -n1)
if [ -z "$image" ]; then
	echo "perf-m13: no pinned postgres image in deploy/compose/compose.yaml" >&2
	exit 1
fi
command -v docker >/dev/null || { echo "perf-m13: docker is required" >&2; exit 1; }

echo "perf-m13: building static Linux binaries into $out"
mkdir -p "$out/out"
CGO_ENABLED=0 GOOS=linux GOARCH="${GOARCH:-amd64}" go build -trimpath -o "$out/" ./cmd/pantherclaw-server ./cmd/pantherclaw-gateway ./cmd/pantherclaw-sim
CGO_ENABLED=0 GOOS=linux GOARCH="${GOARCH:-amd64}" go test -c -tags integration -trimpath -o "$out/pgauthority.test" ./internal/authority/adapters/pgauthority/
cp tools/scripts/perf-m13-inner.sh "$out/inner.sh"

pw=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
docker rm -f "$name" >/dev/null 2>&1 || true
cleanup() { if [ "${KEEP:-0}" != 1 ]; then docker rm -f "$name" >/dev/null 2>&1 || true; fi; }
trap cleanup EXIT
echo "perf-m13: starting $name ($image)"
docker run -d --name "$name" -e POSTGRES_PASSWORD="$pw" -e POSTGRES_DB=pantherclaw --shm-size 256m \
	"$image" -c max_connections=200 -c shared_buffers=256MB >/dev/null
for _ in $(seq 1 60); do
	if docker exec "$name" pg_isready -U postgres -d pantherclaw >/dev/null 2>&1; then break; fi
	sleep 1
done

# Windows paths for the bind mounts under Git Bash. The benchmark reads
# the repository's packages directory.
mount=$(cd "$out" && (pwd -W 2>/dev/null || pwd))
pkgs=$(cd packages && (pwd -W 2>/dev/null || pwd))
MSYS_NO_PATHCONV=1 docker run --rm --network "container:$name" -v "$mount:/perf" -v "$pkgs:/repo/packages:ro" \
	-e PGPASSWORD="$pw" -e RATES="${RATES:-10 50 100}" -e DURATION="${DURATION:-30s}" \
	-e BENCHTIME="${BENCHTIME:-1000x}" -e ROUNDS="${ROUNDS:-1}" -e PROFILE="${PROFILE:-0}" \
	--entrypoint bash "$image" /perf/inner.sh 2>&1 | tee "$out/out/perf-m13.log"
echo "perf-m13: results in $out/out (perf-m13.log, load-*.json)"
# PROFILE=1: strip the HTTP headers of the server CPU profiles, for
# `go tool pprof -top bin/perf/pantherclaw-server bin/perf/out/cpu-rRATE.pprof`.
for raw in "$out"/out/cpu-r*.http; do
	[ -e "$raw" ] || continue
	# The profile is gzip data: it starts at the first 1f 8b after the headers.
	at=$(head -c 4096 "$raw" | od -An -v -tx1 | tr -s ' \n' '\n' | grep -v '^$' |
		awk 'prev == "1f" && $0 == "8b" { print NR - 2; exit } { prev = $0 }')
	if [ -n "$at" ]; then tail -c +$((at + 1)) "$raw" >"${raw%.http}.pprof"; fi
done
