#!/bin/sh
# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
#
# Failover profile, a standby (G0 M19 D202, D213): a base backup of
# $UPSTREAM with -R (primary_conninfo, standby.signal), through the slot
# $SLOT when set, then a hot standby named $NAME (its application_name,
# which the upstream's synchronous_standby_names names). Once promoted
# (SELECT pg_promote()), it waits for $SYNC_NAMES with
# synchronous_commit=remote_apply, as a primary verified sync would; a
# standby of a standby follows the promotion to the new timeline.
set -eu
until pg_isready -q -h "$UPSTREAM" -U postgres; do sleep 1; done
mkdir -p "$PGDATA"
chown postgres:postgres "$PGDATA"
chmod 700 "$PGDATA"
slot=""
if [ -n "${SLOT:-}" ]; then slot="-S $SLOT"; fi
# shellcheck disable=SC2086 # $slot is empty or two words
PGPASSWORD="$PC_PG_TEST_PASSWORD" gosu postgres pg_basebackup -D "$PGDATA" -R -X stream $slot \
  -d "host=$UPSTREAM user=replicator application_name=$NAME"
# A backup of a standby carries that standby's slot; without $SLOT, use none.
if [ -z "${SLOT:-}" ]; then sed -i "/^primary_slot_name/d" "$PGDATA/postgresql.auto.conf"; fi
exec gosu postgres postgres -c max_connections=300 -c hot_standby=on -c synchronous_commit=remote_apply \
  -c "synchronous_standby_names=${SYNC_NAMES:-}"
