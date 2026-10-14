-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Connector runtime (G0 M9 track C slice C2; HR-084, HR-216, HR-218). A
-- customer-hosted gateway reports each run of a connector's container:
-- the connection and spec revision it runs, the container, the engine and
-- runtime, its state and, when it failed, why (an error class, never a
-- message). The gateway names each run; the server takes the org and the
-- gateway from its certificate alone and accepts a run only of a connector
-- connection that gateway serves. A run moves only forward (STARTING,
-- RUNNING, then STOPPED or FAILED), and its times are the database's.

-- +goose Up
CREATE TABLE pc.connector_instances (
    org_id           uuid        NOT NULL REFERENCES pc.orgs (id),
    -- The gateway's id for this run of the connector.
    id               uuid        NOT NULL,
    connection_id    uuid        NOT NULL,
    spec_revision    integer     NOT NULL CHECK (spec_revision > 0),
    gateway_id       uuid        NOT NULL,
    container_name   text        NOT NULL CHECK (container_name ~ '^pc-[a-z0-9][a-z0-9-]{0,40}$'),
    state            text        NOT NULL CHECK (state IN ('STARTING', 'RUNNING', 'STOPPED', 'FAILED')),
    engine_version   text        NOT NULL CHECK (engine_version ~ '^[0-9A-Za-z.+_-]{1,64}$'),
    api_version      text        NOT NULL CHECK (api_version ~ '^[0-9]{1,3}\.[0-9]{1,3}$'),
    runtime          text        NOT NULL CHECK (runtime IN ('runc', 'runsc')),
    last_error_class text        CHECK (last_error_class IS NULL OR last_error_class ~ '^[a-z0-9_]{1,64}$'),
    started_at       timestamptz NOT NULL DEFAULT now(),
    stopped_at       timestamptz,
    updated_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, gateway_id) REFERENCES pc.gateways (org_id, id),
    FOREIGN KEY (org_id, connection_id, spec_revision) REFERENCES pc.connector_specs (org_id, connection_id, revision),
    CONSTRAINT connector_instances_stopped CHECK ((state IN ('STOPPED', 'FAILED')) = (stopped_at IS NOT NULL))
);
CREATE INDEX connector_instances_connection ON pc.connector_instances (org_id, connection_id, id DESC);

-- A run moves only forward, only its state and error class change, and
-- its times are the database's.
-- +goose StatementBegin
CREATE FUNCTION pc.connector_instance_forward() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND (OLD.state IN ('STOPPED', 'FAILED') OR (OLD.state = 'RUNNING' AND NEW.state = 'STARTING')) THEN
        RAISE EXCEPTION 'connector run % moves only forward', OLD.id USING ERRCODE = 'check_violation';
    END IF;
    NEW.updated_at := now();
    IF TG_OP = 'INSERT' THEN
        NEW.started_at := now();
    END IF;
    IF NEW.state IN ('STOPPED', 'FAILED') THEN
        NEW.stopped_at := now();
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER connector_instances_forward BEFORE INSERT OR UPDATE ON pc.connector_instances
    FOR EACH ROW EXECUTE FUNCTION pc.connector_instance_forward();

ALTER TABLE pc.connector_instances ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.connector_instances FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.connector_instances
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

GRANT SELECT ON pc.connector_instances TO pc_app, pc_audit_ro;
GRANT INSERT (org_id, id, connection_id, spec_revision, gateway_id, container_name, state, engine_version, api_version, runtime,
    last_error_class) ON pc.connector_instances TO pc_app;
GRANT UPDATE (state, last_error_class) ON pc.connector_instances TO pc_app;

-- +goose Down
DROP TABLE pc.connector_instances;
DROP FUNCTION pc.connector_instance_forward();
