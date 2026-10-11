-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Coverage invalidation events and the reassess lister (G0 M9 track A
-- slice A5; HR-211, F441, F453, T-085). Every change that must drop
-- ENFORCED at once is recorded in the same transaction as the change, by
-- triggers, so no code path can forget one:
--
--   - a connection that moves to another gateway ('gateway'), or any other
--     change to a connection but its name, limits and bookkeeping
--     ('connection'): the row is compared as a whole, so columns added
--     later, such as 00090's agent_hosts, are covered without a change
--     here;
--   - a connection's default route mode, or one route's mode
--     ('route_mode');
--   - a sealed credential sealed, superseded or revoked ('credential');
--   - a package's pinned version ('package_version'), for every connection
--     of the package;
--   - a gateway's state ('gateway'), for every connection it serves, but
--     not a certificate renewal: the binding is the gateway;
--   - an agent instance admitted outside a sandbox ('instance'), for every
--     connection the agent has closure evidence or a snapshot for. Its
--     sandbox_session_id comes with 00090 and is read through to_jsonb, so
--     until then every admitted instance counts as outside a sandbox.
--
-- The sandbox records image and configuration changes itself
-- (sandbox_image, sandbox_config). The reassess job lists orgs through the
-- audited cross-org lister (purpose coverage_reassess): orgs with pending
-- invalidations, with transactions the route inventory has not read, or
-- with a current ENFORCED snapshot past its expiry.
--
-- PostgreSQL 17 has no uuidv7(): pc.coverage_uuid_v7() builds one from the
-- clock and gen_random_uuid() (RFC 9562 layout: 48-bit milliseconds,
-- version 7, the variant gen_random_uuid() set).

-- +goose Up
-- +goose StatementBegin
CREATE FUNCTION pc.coverage_uuid_v7() RETURNS uuid
LANGUAGE sql VOLATILE
SET search_path = pc, pg_temp
AS $$
    SELECT encode(set_bit(set_bit(overlay(uuid_send(gen_random_uuid())
        PLACING substring(int8send(floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint) FROM 3)
        FROM 1 FOR 6), 52, 1), 53, 1), 'hex')::uuid
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION pc.coverage_connection_changed() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
DECLARE
    -- What never changes what a connection lets an agent reach, and the two
    -- columns with kinds of their own.
    quiet constant text[] := ARRAY['name', 'max_response_bytes', 'timeout_ms', 'quarantine_reason', 'revision',
                                   'created_by', 'created_at', 'updated_by', 'updated_at', 'gateway_id', 'default_mode'];
BEGIN
    IF NEW.gateway_id IS DISTINCT FROM OLD.gateway_id THEN
        INSERT INTO pc.coverage_invalidations (org_id, id, kind, connection_id, subject_id, detail)
        VALUES (NEW.org_id, pc.coverage_uuid_v7(), 'gateway', NEW.id, NEW.gateway_id, 'connection moved to another gateway');
    END IF;
    IF NEW.default_mode IS DISTINCT FROM OLD.default_mode THEN
        INSERT INTO pc.coverage_invalidations (org_id, id, kind, connection_id, subject_id, detail)
        VALUES (NEW.org_id, pc.coverage_uuid_v7(), 'route_mode', NEW.id, NEW.id, 'default mode ' || NEW.default_mode);
    END IF;
    IF (to_jsonb(NEW) - quiet) IS DISTINCT FROM (to_jsonb(OLD) - quiet) THEN
        INSERT INTO pc.coverage_invalidations (org_id, id, kind, connection_id, subject_id, detail)
        VALUES (NEW.org_id, pc.coverage_uuid_v7(), 'connection', NEW.id, NEW.id, 'connection changed');
    END IF;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER connections_coverage AFTER UPDATE ON pc.connections
    FOR EACH ROW EXECUTE FUNCTION pc.coverage_connection_changed();

-- +goose StatementBegin
CREATE FUNCTION pc.coverage_route_mode_changed() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' OR NEW.mode IS DISTINCT FROM OLD.mode THEN
        INSERT INTO pc.coverage_invalidations (org_id, id, kind, connection_id, detail)
        VALUES (NEW.org_id, pc.coverage_uuid_v7(), 'route_mode', NEW.connection_id, 'route ' || NEW.route || ' ' || NEW.mode);
    END IF;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER connection_routes_coverage AFTER INSERT OR UPDATE OF mode ON pc.connection_routes
    FOR EACH ROW EXECUTE FUNCTION pc.coverage_route_mode_changed();

-- +goose StatementBegin
CREATE FUNCTION pc.coverage_credential_changed() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' OR NEW.state IS DISTINCT FROM OLD.state THEN
        INSERT INTO pc.coverage_invalidations (org_id, id, kind, connection_id, subject_id, detail)
        VALUES (NEW.org_id, pc.coverage_uuid_v7(), 'credential', NEW.connection_id, NEW.id, 'credential ' || lower(NEW.state));
    END IF;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER credentials_coverage AFTER INSERT OR UPDATE OF state ON pc.credentials
    FOR EACH ROW EXECUTE FUNCTION pc.coverage_credential_changed();

-- +goose StatementBegin
CREATE FUNCTION pc.coverage_package_pinned() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' OR NEW.version_id IS DISTINCT FROM OLD.version_id THEN
        INSERT INTO pc.coverage_invalidations (org_id, id, kind, connection_id, subject_id, detail)
        SELECT c.org_id, pc.coverage_uuid_v7(), 'package_version', c.id, NEW.version_id, 'package ' || NEW.version
        FROM pc.connections c
        JOIN pc.tool_packages p ON p.org_id = c.org_id AND p.name = c.package
        WHERE c.org_id = NEW.org_id AND p.id = NEW.package_id AND c.state <> 'RETIRED';
    END IF;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER package_pins_coverage AFTER INSERT OR UPDATE OF version_id ON pc.package_pins
    FOR EACH ROW EXECUTE FUNCTION pc.coverage_package_pinned();

-- +goose StatementBegin
CREATE FUNCTION pc.coverage_gateway_changed() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF NEW.state IS DISTINCT FROM OLD.state THEN
        INSERT INTO pc.coverage_invalidations (org_id, id, kind, connection_id, subject_id, detail)
        SELECT c.org_id, pc.coverage_uuid_v7(), 'gateway', c.id, NEW.id, 'gateway ' || lower(NEW.state)
        FROM pc.connections c
        WHERE c.org_id = NEW.org_id AND c.gateway_id = NEW.id AND c.state <> 'RETIRED';
    END IF;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER gateways_coverage AFTER UPDATE OF state ON pc.gateways
    FOR EACH ROW EXECUTE FUNCTION pc.coverage_gateway_changed();

-- +goose StatementBegin
CREATE FUNCTION pc.coverage_instance_admitted() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF NEW.state = 'ADMITTED' AND (TG_OP = 'INSERT' OR OLD.state IS DISTINCT FROM 'ADMITTED')
       AND to_jsonb(NEW) ->> 'sandbox_session_id' IS NULL THEN
        INSERT INTO pc.coverage_invalidations (org_id, id, kind, connection_id, agent_id, subject_id, detail)
        SELECT NEW.org_id, pc.coverage_uuid_v7(), 'instance', s.connection_id, NEW.agent_id, NEW.id,
               'instance admitted outside a sandbox'
        FROM (SELECT c.connection_id FROM pc.coverage_closures c WHERE c.org_id = NEW.org_id AND c.agent_id = NEW.agent_id
              UNION
              SELECT n.connection_id FROM pc.coverage_snapshots n WHERE n.org_id = NEW.org_id AND n.agent_id = NEW.agent_id) s;
    END IF;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER agent_instances_coverage AFTER INSERT OR UPDATE OF state ON pc.agent_instances
    FOR EACH ROW EXECUTE FUNCTION pc.coverage_instance_admitted();

GRANT EXECUTE ON FUNCTION pc.coverage_uuid_v7() TO pc_app;

-- Current ENFORCED snapshots past their expiry, for the lister.
CREATE INDEX coverage_snapshots_enforced ON pc.coverage_snapshots (org_id, expires_at) WHERE state = 'ENFORCED';

GRANT SELECT (org_id, reassessed_at) ON pc.coverage_invalidations TO pc_lister;
GRANT SELECT (org_id, transactions_after) ON pc.coverage_inventory TO pc_lister;
GRANT SELECT (org_id, id, created_at) ON pc.transactions TO pc_lister;
GRANT SELECT (org_id, id, agent_id, connection_id, operation, state, expires_at) ON pc.coverage_snapshots TO pc_lister;

-- The lister below replaces the whole function, starting from 00072's.
-- Refuse to run if the current one has purposes it does not carry (a
-- migration merged before this one added them), rather than drop them:
-- add them below and to this list first.
-- +goose StatementBegin
DO $$
DECLARE
    found text[];
BEGIN
    SELECT array_agg(m[1] ORDER BY m[1]) INTO found
    FROM regexp_matches(
        (SELECT prosrc FROM pg_proc WHERE oid = 'pc.cross_org_list(text, integer)'::regprocedure),
        'WHEN ''([a-z_]+)'' THEN', 'g') AS m;
    IF found IS DISTINCT FROM ARRAY['budget_settle', 'checkpoints_due', 'integrity_due', 'ledger_unchained', 'orgs',
                                    'permits_sweep', 'retention_due', 'verifications_due'] THEN
        RAISE EXCEPTION '00087_coverage_invalidation: pc.cross_org_list has purposes %; carry the new ones into this migration', found;
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pc.cross_org_list(p_purpose text, p_max_rows integer)
RETURNS TABLE (org_id uuid, id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF p_max_rows IS NULL OR p_max_rows < 1 OR p_max_rows > 10000 THEN
        RAISE EXCEPTION 'cross_org_list: max_rows must be between 1 and 10000';
    END IF;
    INSERT INTO pc.cross_org_list_audit (purpose, max_rows, caller)
    VALUES (left(p_purpose, 64), p_max_rows, session_user);
    CASE p_purpose
        WHEN 'orgs' THEN
            RETURN QUERY SELECT o.id, o.id FROM pc.orgs o WHERE o.state = 'ACTIVE' ORDER BY o.id LIMIT p_max_rows;
        WHEN 'ledger_unchained' THEN
            RETURN QUERY
                SELECT DISTINCT e.org_id, e.org_id
                FROM pc.ledger_entries e
                LEFT JOIN pc.ledger_heads h ON h.org_id = e.org_id
                WHERE e.xid >= coalesce(h.xid_watermark, '0'::xid8)
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'permits_sweep' THEN
            RETURN QUERY
                SELECT DISTINCT p.org_id, p.org_id
                FROM pc.permits p
                WHERE (p.state = 'ISSUED' AND p.expires_at < now())
                   OR (p.state = 'DISPATCHING' AND p.dispatching_at < now() - interval '30 seconds')
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'verifications_due' THEN
            RETURN QUERY
                SELECT DISTINCT v.org_id, v.org_id
                FROM pc.verifications v
                WHERE (v.state IN ('PENDING', 'LEASED') AND v.deadline_at <= now())
                   OR (v.state = 'LEASED' AND v.lease_expires_at <= now())
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'checkpoints_due' THEN
            -- Orgs whose chain grew past their latest checkpoint and whose
            -- checkpointing has not stopped.
            RETURN QUERY
                SELECT h.org_id, h.org_id
                FROM pc.ledger_heads h
                WHERE h.seq > coalesce((SELECT max(c.tree_size) FROM pc.checkpoints c WHERE c.org_id = h.org_id), 0)
                  AND NOT EXISTS (SELECT 1 FROM pc.evidence_integrity i WHERE i.org_id = h.org_id AND i.state = 'FAILED')
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'integrity_due' THEN
            -- Orgs with a checkpoint whose chain was not re-verified in the
            -- last day.
            RETURN QUERY
                SELECT h.org_id, h.org_id
                FROM pc.ledger_heads h
                WHERE EXISTS (SELECT 1 FROM pc.checkpoints c WHERE c.org_id = h.org_id)
                  AND NOT EXISTS (SELECT 1 FROM pc.evidence_integrity i WHERE i.org_id = h.org_id
                                  AND (i.state = 'FAILED' OR i.verified_at > now() - interval '1 day'))
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'budget_settle' THEN
            RETURN QUERY
                SELECT DISTINCT r.org_id, r.org_id
                FROM pc.reservations r
                WHERE r.pending
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'retention_due' THEN
            -- Active orgs whose retention job has not run successfully in
            -- the last day (HR-198).
            RETURN QUERY
                SELECT o.id, o.id
                FROM pc.orgs o
                WHERE o.state = 'ACTIVE'
                  AND NOT EXISTS (SELECT 1 FROM pc.retention_status s WHERE s.org_id = o.id
                                  AND s.last_run_at > now() - interval '1 day')
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'coverage_reassess' THEN
            -- Active orgs with pending coverage invalidations, with
            -- transactions the route inventory has not read (a minute
            -- behind the clock), or with a current ENFORCED snapshot past
            -- its expiry (HR-211).
            RETURN QUERY
                SELECT o.id, o.id
                FROM pc.orgs o
                WHERE o.state = 'ACTIVE'
                  AND (EXISTS (SELECT 1 FROM pc.coverage_invalidations i WHERE i.org_id = o.id AND i.reassessed_at IS NULL)
                       OR EXISTS (SELECT 1 FROM pc.transactions t
                                  WHERE t.org_id = o.id AND t.created_at < now() - interval '1 minute'
                                    AND t.id > coalesce((SELECT w.transactions_after FROM pc.coverage_inventory w
                                                         WHERE w.org_id = o.id), '00000000-0000-0000-0000-000000000000'))
                       OR EXISTS (SELECT 1 FROM pc.coverage_snapshots s
                                  WHERE s.org_id = o.id AND s.state = 'ENFORCED' AND s.expires_at <= now()
                                    AND NOT EXISTS (SELECT 1 FROM pc.coverage_snapshots n
                                                    WHERE n.org_id = s.org_id AND n.agent_id = s.agent_id
                                                      AND n.connection_id = s.connection_id
                                                      AND n.operation = s.operation AND n.id > s.id)))
                ORDER BY 1
                LIMIT p_max_rows;
        ELSE
            RAISE EXCEPTION 'cross_org_list: unknown purpose';
    END CASE;
END;
$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pc.cross_org_list(p_purpose text, p_max_rows integer)
RETURNS TABLE (org_id uuid, id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF p_max_rows IS NULL OR p_max_rows < 1 OR p_max_rows > 10000 THEN
        RAISE EXCEPTION 'cross_org_list: max_rows must be between 1 and 10000';
    END IF;
    INSERT INTO pc.cross_org_list_audit (purpose, max_rows, caller)
    VALUES (left(p_purpose, 64), p_max_rows, session_user);
    CASE p_purpose
        WHEN 'orgs' THEN
            RETURN QUERY SELECT o.id, o.id FROM pc.orgs o WHERE o.state = 'ACTIVE' ORDER BY o.id LIMIT p_max_rows;
        WHEN 'ledger_unchained' THEN
            RETURN QUERY
                SELECT DISTINCT e.org_id, e.org_id
                FROM pc.ledger_entries e
                LEFT JOIN pc.ledger_heads h ON h.org_id = e.org_id
                WHERE e.xid >= coalesce(h.xid_watermark, '0'::xid8)
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'permits_sweep' THEN
            RETURN QUERY
                SELECT DISTINCT p.org_id, p.org_id
                FROM pc.permits p
                WHERE (p.state = 'ISSUED' AND p.expires_at < now())
                   OR (p.state = 'DISPATCHING' AND p.dispatching_at < now() - interval '30 seconds')
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'verifications_due' THEN
            RETURN QUERY
                SELECT DISTINCT v.org_id, v.org_id
                FROM pc.verifications v
                WHERE (v.state IN ('PENDING', 'LEASED') AND v.deadline_at <= now())
                   OR (v.state = 'LEASED' AND v.lease_expires_at <= now())
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'checkpoints_due' THEN
            -- Orgs whose chain grew past their latest checkpoint and whose
            -- checkpointing has not stopped.
            RETURN QUERY
                SELECT h.org_id, h.org_id
                FROM pc.ledger_heads h
                WHERE h.seq > coalesce((SELECT max(c.tree_size) FROM pc.checkpoints c WHERE c.org_id = h.org_id), 0)
                  AND NOT EXISTS (SELECT 1 FROM pc.evidence_integrity i WHERE i.org_id = h.org_id AND i.state = 'FAILED')
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'integrity_due' THEN
            -- Orgs with a checkpoint whose chain was not re-verified in the
            -- last day.
            RETURN QUERY
                SELECT h.org_id, h.org_id
                FROM pc.ledger_heads h
                WHERE EXISTS (SELECT 1 FROM pc.checkpoints c WHERE c.org_id = h.org_id)
                  AND NOT EXISTS (SELECT 1 FROM pc.evidence_integrity i WHERE i.org_id = h.org_id
                                  AND (i.state = 'FAILED' OR i.verified_at > now() - interval '1 day'))
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'budget_settle' THEN
            RETURN QUERY
                SELECT DISTINCT r.org_id, r.org_id
                FROM pc.reservations r
                WHERE r.pending
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'retention_due' THEN
            -- Active orgs whose retention job has not run successfully in
            -- the last day (HR-198).
            RETURN QUERY
                SELECT o.id, o.id
                FROM pc.orgs o
                WHERE o.state = 'ACTIVE'
                  AND NOT EXISTS (SELECT 1 FROM pc.retention_status s WHERE s.org_id = o.id
                                  AND s.last_run_at > now() - interval '1 day')
                ORDER BY 1
                LIMIT p_max_rows;
        ELSE
            RAISE EXCEPTION 'cross_org_list: unknown purpose';
    END CASE;
END;
$$;
-- +goose StatementEnd
REVOKE SELECT (org_id, id, agent_id, connection_id, operation, state, expires_at) ON pc.coverage_snapshots FROM pc_lister;
REVOKE SELECT (org_id, id, created_at) ON pc.transactions FROM pc_lister;
REVOKE SELECT (org_id, transactions_after) ON pc.coverage_inventory FROM pc_lister;
REVOKE SELECT (org_id, reassessed_at) ON pc.coverage_invalidations FROM pc_lister;
DROP INDEX pc.coverage_snapshots_enforced;
DROP TRIGGER agent_instances_coverage ON pc.agent_instances;
DROP TRIGGER gateways_coverage ON pc.gateways;
DROP TRIGGER package_pins_coverage ON pc.package_pins;
DROP TRIGGER credentials_coverage ON pc.credentials;
DROP TRIGGER connection_routes_coverage ON pc.connection_routes;
DROP TRIGGER connections_coverage ON pc.connections;
DROP FUNCTION pc.coverage_instance_admitted();
DROP FUNCTION pc.coverage_gateway_changed();
DROP FUNCTION pc.coverage_package_pinned();
DROP FUNCTION pc.coverage_credential_changed();
DROP FUNCTION pc.coverage_route_mode_changed();
DROP FUNCTION pc.coverage_connection_changed();
DROP FUNCTION pc.coverage_uuid_v7();
