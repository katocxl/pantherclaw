#!/bin/sh
# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
#
# Failover profile, primary (G0 M19 D202): a replication role, a physical
# slot for the standby, the standby named synchronous, and a pg_hba entry
# that lets it stream with a SCRAM password. Runs once, from
# docker-entrypoint-initdb.d.
set -eu
psql -v ON_ERROR_STOP=1 -U postgres -v pw="$PC_PG_TEST_PASSWORD" <<'SQL'
CREATE ROLE replicator WITH REPLICATION LOGIN PASSWORD :'pw';
SELECT pg_create_physical_replication_slot('standby');
-- Set here, not on the command line: the entrypoint's temporary server
-- would otherwise wait on every commit for a standby that is not there yet.
ALTER SYSTEM SET synchronous_standby_names = 'FIRST 1 (standby)';
SQL
echo "host replication replicator all scram-sha-256" >>"$PGDATA/pg_hba.conf"
