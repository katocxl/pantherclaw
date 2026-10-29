-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Classification facts and the built-in signals provider (G0 M16 D80, D82;
-- HR-435, HR-441).
--
-- - A declaration has a kind: value (every declaration so far) or
--   classification, whose values are data classes, so its value type is
--   identifier.
-- - A fact records its provenance: the source that classified or observed
--   it (at most 128 characters) and the method (manual, rule or model).
--   Both or neither; the application refuses a classification fact without
--   both.
-- - A provider is built in when PantherClaw itself writes its facts: the
--   Shared Signals receiver's pc.signals, one per org, created on first use
--   and bound to neither a service account nor a gateway. No RPC creates
--   one. Only the built-in provider may declare pc.identity.risk (a
--   trigger); an active declaration of that name by any other provider is
--   deactivated here, so the receiver can claim it.

-- +goose Up
-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['fact_providers', 'fact_declarations']
    LOOP
        EXECUTE format('ALTER TABLE pc.%I NO FORCE ROW LEVEL SECURITY', t);
    END LOOP;
    UPDATE pc.fact_declarations SET active = false WHERE active AND replace(name, '.', '_') = 'pc_identity_risk';
    FOREACH t IN ARRAY ARRAY['fact_providers', 'fact_declarations']
    LOOP
        EXECUTE format('ALTER TABLE pc.%I FORCE ROW LEVEL SECURITY', t);
    END LOOP;
END
$$;
-- +goose StatementEnd

ALTER TABLE pc.fact_providers
    ADD COLUMN builtin boolean NOT NULL DEFAULT false,
    DROP CONSTRAINT fact_providers_one_source,
    -- squawk-ignore constraint-missing-not-valid
    ADD CONSTRAINT fact_providers_one_source CHECK (
        (NOT builtin AND service_account_id IS NOT NULL AND gateway_id IS NULL AND connection_id IS NULL)
        OR (NOT builtin AND service_account_id IS NULL AND gateway_id IS NOT NULL AND connection_id IS NOT NULL)
        OR (builtin AND name = 'pc.signals' AND service_account_id IS NULL AND gateway_id IS NULL AND connection_id IS NULL));
-- squawk-ignore require-concurrent-index-creation
CREATE UNIQUE INDEX fact_providers_builtin ON pc.fact_providers (org_id) WHERE builtin;

ALTER TABLE pc.fact_declarations
    ADD COLUMN kind text NOT NULL DEFAULT 'value',
    -- squawk-ignore constraint-missing-not-valid
    ADD CONSTRAINT fact_declarations_kind CHECK (kind = 'value' OR (kind = 'classification' AND value_type = 'identifier'));

ALTER TABLE pc.facts
    ADD COLUMN source text,
    ADD COLUMN method text,
    -- squawk-ignore constraint-missing-not-valid
    ADD CONSTRAINT facts_provenance CHECK (
        (source IS NULL AND method IS NULL)
        OR (source IS NOT NULL AND method IS NOT NULL AND char_length(source) BETWEEN 1 AND 128 AND method IN ('manual', 'rule', 'model')));

-- pc.identity.risk comes only from the built-in provider (HR-441).
-- +goose StatementBegin
CREATE FUNCTION pc.fact_declarations_reserved() RETURNS trigger LANGUAGE plpgsql SET search_path = pc, pg_temp AS $$
BEGIN
    IF NEW.active AND replace(NEW.name, '.', '_') = 'pc_identity_risk' AND NOT EXISTS (
        SELECT 1 FROM pc.fact_providers p WHERE p.org_id = NEW.org_id AND p.id = NEW.provider_id AND p.builtin) THEN
        RAISE EXCEPTION 'only the built-in provider declares %', NEW.name USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER fact_declarations_reserved BEFORE INSERT OR UPDATE ON pc.fact_declarations
    FOR EACH ROW EXECUTE FUNCTION pc.fact_declarations_reserved();

GRANT UPDATE (source, method) ON pc.facts TO pc_app;

-- +goose Down
REVOKE UPDATE (source, method) ON pc.facts FROM pc_app;
DROP TRIGGER fact_declarations_reserved ON pc.fact_declarations;
DROP FUNCTION pc.fact_declarations_reserved();
ALTER TABLE pc.facts DROP CONSTRAINT facts_provenance, DROP COLUMN method, DROP COLUMN source;
ALTER TABLE pc.fact_declarations DROP CONSTRAINT fact_declarations_kind, DROP COLUMN kind;
-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['fact_providers', 'fact_declarations', 'facts']
    LOOP
        EXECUTE format('ALTER TABLE pc.%I NO FORCE ROW LEVEL SECURITY', t);
    END LOOP;
    -- A built-in provider has no source the previous schema allows: remove
    -- it with its declarations and facts.
    DELETE FROM pc.facts f USING pc.fact_providers p WHERE p.org_id = f.org_id AND p.id = f.provider_id AND p.builtin;
    DELETE FROM pc.fact_declarations d USING pc.fact_providers p WHERE p.org_id = d.org_id AND p.id = d.provider_id AND p.builtin;
    DELETE FROM pc.fact_providers WHERE builtin;
    FOREACH t IN ARRAY ARRAY['fact_providers', 'fact_declarations', 'facts']
    LOOP
        EXECUTE format('ALTER TABLE pc.%I FORCE ROW LEVEL SECURITY', t);
    END LOOP;
END
$$;
-- +goose StatementEnd
DROP INDEX pc.fact_providers_builtin;
ALTER TABLE pc.fact_providers
    DROP CONSTRAINT fact_providers_one_source,
    ADD CONSTRAINT fact_providers_one_source CHECK (
        (service_account_id IS NOT NULL AND gateway_id IS NULL AND connection_id IS NULL)
        OR (service_account_id IS NULL AND gateway_id IS NOT NULL AND connection_id IS NOT NULL)),
    DROP COLUMN builtin;
