-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
-- IdP-native agent access (G0 M26 D400, D401, D408; H8): the issuers an org
-- trusts for Identity Assertion JWT Authorization Grants, and which of their
-- client ids act as which enrolled agent.
--
-- pc.org_assertion_issuers: an issuer is HTTPS, pins the audience an
-- assertion must name, the algorithms it may use and, for a multi-tenant
-- issuer, the tenant. An issuer is PENDING until a second person confirms
-- it, then ACTIVE. Its issuer URL, audience and tenant can't change once it
-- has been ACTIVE. Turning one off is at once (D408.5, HR-141).
--
-- pc.org_assertion_clients: the pinned binding (HR-140). A client id of an
-- issuer acts as exactly one agent, never by name. Adding one waits for a
-- second person; removing one is at once. An assertion only names who is
-- represented: it never creates, widens or substitutes for a grant (HR-146).
-- +goose Up
CREATE TABLE pc.org_assertion_issuers (
    org_id      uuid        NOT NULL REFERENCES pc.orgs (id),
    id          uuid        NOT NULL,
    name        text        NOT NULL CHECK (name ~ '^[a-z0-9-]{1,32}$'),
    issuer      text        NOT NULL CHECK (issuer ~ '^https://[^/?#@[:space:]]+(/[^?#[:space:]]*)?$' AND char_length(issuer) <= 512),
    audience    text        NOT NULL CHECK (audience ~ '^https?://[^?#[:space:]]+$' AND char_length(audience) <= 512),
    -- Only for a multi-tenant issuer: an assertion must carry this tenant.
    tenant      text        CHECK (char_length(tenant) BETWEEN 1 AND 256),
    algorithms  text[]      NOT NULL CHECK (cardinality(algorithms) BETWEEN 1 AND 3
                                            AND algorithms <@ ARRAY['RS256', 'ES256', 'EdDSA']),
    state       text        NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING', 'ACTIVE', 'DISABLED')),
    created_by  uuid        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_by  uuid        NOT NULL,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    -- The first time the issuer became ACTIVE: from then on it is fixed.
    activated_at timestamptz,
    disabled_by uuid,
    disabled_at timestamptz,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, name),
    CHECK (state <> 'ACTIVE' OR activated_at IS NOT NULL),
    CHECK ((state = 'DISABLED') = (disabled_at IS NOT NULL)),
    CHECK ((disabled_by IS NULL) = (disabled_at IS NULL))
);
-- One live entry per issuer and tenant, so an assertion names one row.
CREATE UNIQUE INDEX org_assertion_issuers_one ON pc.org_assertion_issuers (org_id, issuer, coalesce(tenant, ''))
    WHERE state <> 'DISABLED';

-- +goose StatementBegin
CREATE FUNCTION pc.org_assertion_issuer_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pc AS $$
BEGIN
    IF OLD.activated_at IS NOT NULL AND (NEW.issuer IS DISTINCT FROM OLD.issuer OR NEW.audience IS DISTINCT FROM OLD.audience
            OR NEW.tenant IS DISTINCT FROM OLD.tenant) THEN
        RAISE EXCEPTION 'an assertion issuer''s issuer, audience and tenant are immutable once it has been active'
            USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.activated_at IS NOT NULL AND NEW.activated_at IS DISTINCT FROM OLD.activated_at THEN
        RAISE EXCEPTION 'activated_at is set once' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER org_assertion_issuer_guard BEFORE UPDATE ON pc.org_assertion_issuers
    FOR EACH ROW EXECUTE FUNCTION pc.org_assertion_issuer_guard();

CREATE TABLE pc.org_assertion_clients (
    org_id      uuid        NOT NULL REFERENCES pc.orgs (id),
    id          uuid        NOT NULL,
    issuer_id   uuid        NOT NULL,
    client_id   text        NOT NULL CHECK (char_length(client_id) BETWEEN 1 AND 512),
    agent_id    uuid        NOT NULL,
    state       text        NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING', 'ACTIVE', 'REMOVED')),
    created_by  uuid        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    activated_at timestamptz,
    removed_by  uuid,
    removed_at  timestamptz,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, issuer_id) REFERENCES pc.org_assertion_issuers (org_id, id),
    FOREIGN KEY (org_id, agent_id) REFERENCES pc.agents (org_id, id),
    CHECK (state <> 'ACTIVE' OR activated_at IS NOT NULL),
    CHECK ((state = 'REMOVED') = (removed_at IS NOT NULL)),
    CHECK ((removed_by IS NULL) = (removed_at IS NULL))
);
-- A client id of an issuer is one agent; a binding is never re-pointed.
CREATE UNIQUE INDEX org_assertion_clients_one ON pc.org_assertion_clients (org_id, issuer_id, client_id)
    WHERE state <> 'REMOVED';
CREATE INDEX org_assertion_clients_agent ON pc.org_assertion_clients (org_id, agent_id);

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['org_assertion_issuers', 'org_assertion_clients']
    LOOP
        EXECUTE format('ALTER TABLE pc.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE pc.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($p$CREATE POLICY tenant_isolation ON pc.%I
            USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
            WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))$p$, t);
        EXECUTE format('CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.%I
            FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard()', t);
        IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
            EXECUTE format('GRANT SELECT, DELETE ON pc.%I TO pc_deleter', t);
        END IF;
    END LOOP;
END
$$;
-- +goose StatementEnd

GRANT SELECT, INSERT ON pc.org_assertion_issuers, pc.org_assertion_clients TO pc_app;
GRANT UPDATE (name, issuer, audience, tenant, algorithms, state, updated_by, updated_at, activated_at, disabled_by, disabled_at)
    ON pc.org_assertion_issuers TO pc_app;
GRANT UPDATE (state, activated_at, removed_by, removed_at) ON pc.org_assertion_clients TO pc_app;
GRANT SELECT ON pc.org_assertion_issuers, pc.org_assertion_clients TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.org_assertion_clients;
DROP TABLE pc.org_assertion_issuers;
DROP FUNCTION pc.org_assertion_issuer_guard();
