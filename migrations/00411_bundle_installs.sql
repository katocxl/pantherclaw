-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Publisher bundle installs (G0 M37 D1082; FD8, FQ37-2; HR-796..798). An
-- install verifies a pc-bundle/1 file against the org's ACTIVE publisher
-- pins and hands each item to its kind's existing DRAFT path: nothing is
-- activated, published or enabled. bundle_items records what each item
-- became (a package draft to review and org-sign, a DRAFT custom rule, a
-- DRAFT automation, or a template), so a revocation finds it (D1083).
-- bundle_state is the highest version installed per bundle: a lower
-- version is refused (ROLLBACK), and the same version with another digest
-- (EQUIVOCATION), as pc.hub_state for the Hub.
--
-- Custom detection rule ids gain the bundle namespace ext.<publisher>.<name>
-- (D1080); only a bundle install stores one.

-- +goose Up
CREATE TABLE pc.bundle_installs (
    org_id        uuid        NOT NULL REFERENCES pc.orgs (id),
    id            uuid        NOT NULL,
    publisher     text        NOT NULL CHECK (publisher ~ '^[a-z][a-z0-9-]{2,31}$'),
    name          text        NOT NULL CHECK (name ~ '^ext\.[a-z][a-z0-9-]{2,31}\.[a-z0-9][a-z0-9-]{0,62}$'),
    version       text        NOT NULL CHECK (version ~ '^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$'),
    bundle_sha256 text        NOT NULL CHECK (bundle_sha256 ~ '^[0-9a-f]{64}$'),
    pin_id        uuid,
    state         text        NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING', 'INSTALLED', 'FAILED', 'REVOKED')),
    installed_by  uuid        NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    finished_at   timestamptz,
    failure_code  text        CHECK (failure_code IS NULL OR failure_code ~ '^[A-Z0-9_]{1,64}$'),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, pin_id) REFERENCES pc.publisher_pins (org_id, id),
    FOREIGN KEY (org_id, installed_by) REFERENCES pc.users (org_id, id),
    CHECK ((state = 'FAILED') = (failure_code IS NOT NULL)),
    CHECK (state IN ('PENDING', 'FAILED') OR pin_id IS NOT NULL),
    CHECK (state = 'PENDING' OR finished_at IS NOT NULL)
);
CREATE INDEX bundle_installs_name ON pc.bundle_installs (org_id, name, state);
CREATE INDEX bundle_installs_pin ON pc.bundle_installs (org_id, pin_id) WHERE state = 'INSTALLED';

CREATE TABLE pc.bundle_items (
    org_id      uuid NOT NULL,
    install_id  uuid NOT NULL,
    kind        text NOT NULL CHECK (kind IN ('tool_package', 'openapi_spec', 'detection_rule', 'playbook', 'facts_declaration',
                                              'channel_template')),
    name        text NOT NULL CHECK (char_length(name) BETWEEN 5 AND 140 AND name LIKE 'ext.%'),
    sha256      text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    target_type text NOT NULL CHECK (target_type IN ('package_draft', 'custom_rule', 'automation', 'template')),
    target_id   text NOT NULL CHECK (char_length(target_id) BETWEEN 1 AND 160),
    state       text NOT NULL CHECK (state IN ('DRAFTED', 'TEMPLATE', 'REVOKED')),
    PRIMARY KEY (org_id, install_id, name),
    FOREIGN KEY (org_id, install_id) REFERENCES pc.bundle_installs (org_id, id)
);
CREATE INDEX bundle_items_target ON pc.bundle_items (org_id, target_type, target_id);

CREATE TABLE pc.bundle_state (
    org_id      uuid        NOT NULL REFERENCES pc.orgs (id),
    publisher   text        NOT NULL CHECK (publisher ~ '^[a-z][a-z0-9-]{2,31}$'),
    name        text        NOT NULL,
    max_version text        NOT NULL CHECK (max_version ~ '^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$'),
    -- The digest installed at max_version: the same version with another
    -- digest is equivocation.
    max_sha256  text        NOT NULL CHECK (max_sha256 ~ '^[0-9a-f]{64}$'),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, name)
);

-- An install moves PENDING -> INSTALLED | FAILED and INSTALLED -> REVOKED;
-- what it names never changes. An item moves only to REVOKED.
-- +goose StatementBegin
CREATE FUNCTION pc.bundle_install_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state NOT IN ('PENDING', 'FAILED') THEN
            RAISE EXCEPTION 'a bundle install is inserted PENDING or FAILED' USING ERRCODE = 'check_violation';
        END IF;
        NEW.created_at := now();
        RETURN NEW;
    END IF;
    IF NEW.publisher IS DISTINCT FROM OLD.publisher OR NEW.name IS DISTINCT FROM OLD.name OR NEW.version IS DISTINCT FROM OLD.version
            OR NEW.bundle_sha256 IS DISTINCT FROM OLD.bundle_sha256 OR NEW.installed_by IS DISTINCT FROM OLD.installed_by
            OR (OLD.pin_id IS NOT NULL AND NEW.pin_id IS DISTINCT FROM OLD.pin_id) THEN
        RAISE EXCEPTION 'a bundle install never changes what it names' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.state IS DISTINCT FROM OLD.state AND NOT (
            (OLD.state = 'PENDING' AND NEW.state IN ('INSTALLED', 'FAILED'))
            OR (OLD.state = 'INSTALLED' AND NEW.state = 'REVOKED')) THEN
        RAISE EXCEPTION 'a bundle install cannot go from % to %', OLD.state, NEW.state USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.state = 'PENDING' AND NEW.state <> 'PENDING' THEN
        NEW.finished_at := now();
    END IF;
    RETURN NEW;
END
$$;
CREATE FUNCTION pc.bundle_item_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF NEW.kind IS DISTINCT FROM OLD.kind OR NEW.name IS DISTINCT FROM OLD.name OR NEW.sha256 IS DISTINCT FROM OLD.sha256
            OR NEW.target_type IS DISTINCT FROM OLD.target_type OR NEW.target_id IS DISTINCT FROM OLD.target_id
            OR (NEW.state IS DISTINCT FROM OLD.state AND NEW.state <> 'REVOKED') THEN
        RAISE EXCEPTION 'a bundle item only moves to REVOKED' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER bundle_installs_guard BEFORE INSERT OR UPDATE ON pc.bundle_installs
    FOR EACH ROW EXECUTE FUNCTION pc.bundle_install_guard();
CREATE TRIGGER bundle_items_guard BEFORE UPDATE ON pc.bundle_items
    FOR EACH ROW EXECUTE FUNCTION pc.bundle_item_guard();

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['bundle_installs', 'bundle_items', 'bundle_state'] LOOP
        EXECUTE format('ALTER TABLE pc.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE pc.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($p$CREATE POLICY tenant_isolation ON pc.%I
            USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
            WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))$p$, t);
        EXECUTE format('CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.%I
            FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard()', t);
        EXECUTE format('GRANT SELECT ON pc.%I TO pc_audit_ro', t);
        IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
            EXECUTE format('GRANT SELECT, DELETE ON pc.%I TO pc_deleter', t);
        END IF;
    END LOOP;
END
$$;
-- +goose StatementEnd

GRANT SELECT, INSERT ON pc.bundle_installs TO pc_app;
GRANT UPDATE (state, pin_id, finished_at, failure_code) ON pc.bundle_installs TO pc_app;
GRANT SELECT, INSERT ON pc.bundle_items TO pc_app;
GRANT UPDATE (state) ON pc.bundle_items TO pc_app;
GRANT SELECT, INSERT ON pc.bundle_state TO pc_app;
GRANT UPDATE (max_version, max_sha256, updated_at) ON pc.bundle_state TO pc_app;

-- Bundle rule ids (D1080): ext.<publisher>.<name> beside org.<slug>.
ALTER TABLE pc.custom_detection_rules DROP CONSTRAINT custom_detection_rules_rule_id_check;
ALTER TABLE pc.custom_detection_rules ADD CONSTRAINT custom_detection_rules_rule_id_check CHECK (char_length(rule_id) <= 128
    AND (rule_id ~ '^org\.[a-z][a-z0-9_]{0,62}(\.[a-z0-9_]{1,63}){0,3}$'
         OR rule_id ~ '^ext\.[a-z][a-z0-9-]{2,31}\.[a-z][a-z0-9_]{0,62}(\.[a-z0-9_]{1,63}){0,2}$')) NOT VALID;

-- +goose Down
ALTER TABLE pc.custom_detection_rules DROP CONSTRAINT custom_detection_rules_rule_id_check;
ALTER TABLE pc.custom_detection_rules ADD CONSTRAINT custom_detection_rules_rule_id_check CHECK (char_length(rule_id) <= 128
    AND rule_id ~ '^org\.[a-z][a-z0-9_]{0,62}(\.[a-z0-9_]{1,63}){0,3}$') NOT VALID;
DROP TABLE pc.bundle_state;
DROP TABLE pc.bundle_items;
DROP TABLE pc.bundle_installs;
DROP FUNCTION pc.bundle_item_guard();
DROP FUNCTION pc.bundle_install_guard();
