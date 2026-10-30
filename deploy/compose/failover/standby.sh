#!/bin/sh
# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
#
# Failover profile, standby (G0 M19 D202): a base backup of the primary
# with -R (primary_conninfo, standby.signal) through the slot "standby",
# then a hot standby that the primary waits for (synchronous_standby_names
# names it by its application_name). Promote it with SELECT pg_promote().
set -eu
until pg_isready -q -h pg-primary -U postgres; do sleep 1; done
mkdir -p "$PGDATA"
chown postgres:postgres "$PGDATA"
chmod 700 "$PGDATA"
PGPASSWORD="$PC_PG_TEST_PASSWORD" gosu postgres pg_basebackup -D "$PGDATA" -R -X stream -S standby \
  -d "host=pg-primary user=replicator application_name=standby"
exec gosu postgres postgres -c max_connections=300 -c hot_standby=on
