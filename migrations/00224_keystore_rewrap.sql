-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Re-wrap in place (G0 M18 S18e, D157, D171, HR-487). The keystore role
-- pc_keystore, used only by the worker's keystore.rewrap job, may replace
-- a stored key's wrapped material and its KEK id, so a deployment can move
-- its keys to another KEK (file to OpenBao) and retire the old one. pc_app
-- gets nothing new: key material stays immutable for it (HR-055).
--
-- A trigger allows the two columns to change only together: a wrapped
-- value never changes under the same kek_id, and a kek_id never changes
-- without its wrapped value. The job verifies before it writes
-- (keystore/rewrap.go). The tenant_isolation policies bind pc_keystore
-- like every role without BYPASSRLS. A pc_keystore created after this
-- migration gets the same grants from db bootstrap.

-- +goose Up
-- +goose StatementBegin
CREATE FUNCTION pc.keystore_rewrap_guard() RETURNS trigger
    LANGUAGE plpgsql AS $$
DECLARE
    wrapped_changed boolean;
BEGIN
    IF TG_TABLE_NAME = 'keys' THEN
        wrapped_changed := NEW.wrapped_private_key IS DISTINCT FROM OLD.wrapped_private_key;
    ELSE
        wrapped_changed := NEW.wrapped_key IS DISTINCT FROM OLD.wrapped_key;
    END IF;
    IF wrapped_changed <> (NEW.kek_id IS DISTINCT FROM OLD.kek_id) THEN
        RAISE EXCEPTION 'pc.%: the wrapped key and kek_id change only together', TG_TABLE_NAME
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd

CREATE TRIGGER keystore_rewrap_guard BEFORE UPDATE OF wrapped_private_key, kek_id ON pc.keys
    FOR EACH ROW EXECUTE FUNCTION pc.keystore_rewrap_guard();
CREATE TRIGGER keystore_rewrap_guard BEFORE UPDATE OF wrapped_key, kek_id ON pc.deks
    FOR EACH ROW EXECUTE FUNCTION pc.keystore_rewrap_guard();

-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_keystore') THEN
        GRANT USAGE ON SCHEMA pc TO pc_keystore;
        GRANT SELECT, UPDATE (wrapped_private_key, kek_id) ON pc.keys TO pc_keystore;
        GRANT SELECT, UPDATE (wrapped_key, kek_id) ON pc.deks TO pc_keystore;
        -- The org write barrier (00181) on every tenant row it updates.
        GRANT SELECT (id, state) ON pc.orgs TO pc_keystore;
        GRANT EXECUTE ON FUNCTION pc.org_write_guard() TO pc_keystore;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_keystore') THEN
        REVOKE UPDATE (wrapped_key, kek_id) ON pc.deks FROM pc_keystore;
        REVOKE UPDATE (wrapped_private_key, kek_id) ON pc.keys FROM pc_keystore;
        REVOKE EXECUTE ON FUNCTION pc.org_write_guard() FROM pc_keystore;
        REVOKE SELECT (id, state) ON pc.orgs FROM pc_keystore;
        REVOKE SELECT ON pc.deks, pc.keys FROM pc_keystore;
    END IF;
END $$;
-- +goose StatementEnd
DROP TRIGGER keystore_rewrap_guard ON pc.deks;
DROP TRIGGER keystore_rewrap_guard ON pc.keys;
DROP FUNCTION pc.keystore_rewrap_guard();
