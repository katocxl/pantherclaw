-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Federation replay store and federated a2a peers (G0 M35 D1021, D1023,
-- D1024; HR-772, HR-774).
--
-- pc.federation_replay keeps each peer token, confirmation and revocation
-- id (jti) a peer org sent, keyed on (peer org, kind, jti), until it can no
-- longer be accepted (a pap-fed+jwt for 120 s, a confirmation or revocation
-- for its exp plus a minute). A second use of one is refused
-- (FEDERATION_REPLAY). Expired rows are swept.
--
-- An a2a connection gains a third kind of peer: a listed agent of a trusted
-- peer org, named by the trust and the listing. Its card and URL come from
-- the peer's verified federation document, so its pin is activated by the
-- federation check itself (confirmed_operator 'federation'), never by the
-- dev seed's path; that path stays for simulated connections only. A
-- federated pin names no peer agent of this org.

-- +goose Up
CREATE TABLE pc.federation_replay (
    org_id      uuid        NOT NULL REFERENCES pc.orgs (id),
    peer_org_id uuid        NOT NULL,
    kind        text        NOT NULL CHECK (kind IN ('token', 'confirm', 'revoke')),
    jti         text        NOT NULL CHECK (char_length(jti) BETWEEN 1 AND 128),
    expires_at  timestamptz NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, peer_org_id, kind, jti)
);
CREATE INDEX federation_replay_expiry ON pc.federation_replay (org_id, expires_at);

ALTER TABLE pc.federation_replay ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.federation_replay FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.federation_replay
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.federation_replay
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();
GRANT SELECT, INSERT, DELETE ON pc.federation_replay TO pc_app;
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.federation_replay TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

-- The new columns are NULL in every row, so the checks and the foreign key
-- hold at once.
-- squawk-ignore adding-foreign-key-constraint
ALTER TABLE pc.a2a_pins
    ADD COLUMN federation_trust_id uuid,
    ADD COLUMN federation_listing  text CHECK (federation_listing ~ '^[a-z0-9-]{1,63}$'),
    ADD CONSTRAINT a2a_pins_federation CHECK ((federation_trust_id IS NULL) = (federation_listing IS NULL)
        AND (federation_trust_id IS NULL OR peer_agent_id IS NULL)) NOT VALID,
    ADD CONSTRAINT a2a_pins_federation_trust_fkey FOREIGN KEY (org_id, federation_trust_id)
        REFERENCES pc.federation_trusts (org_id, id) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.a2a_pins VALIDATE CONSTRAINT a2a_pins_federation;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.a2a_pins VALIDATE CONSTRAINT a2a_pins_federation_trust_fkey;

-- 00154's guard, with the federated peer: what it names never changes, and
-- its pin is activated by the federation check (confirmed_operator
-- 'federation'). Everything else is unchanged.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pc.a2a_pin_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'PROPOSED' OR NEW.confirmed_at IS NOT NULL OR NEW.confirmed_operator IS NOT NULL OR NEW.drifted_at IS NOT NULL THEN
            RAISE EXCEPTION 'an a2a pin is inserted PROPOSED' USING ERRCODE = 'check_violation';
        END IF;
        NEW.proposed_at := now();
        RETURN NEW;
    END IF;
    IF NEW.connection_id IS DISTINCT FROM OLD.connection_id OR NEW.card_url IS DISTINCT FROM OLD.card_url
            OR NEW.binding IS DISTINCT FROM OLD.binding OR NEW.interface_url IS DISTINCT FROM OLD.interface_url
            OR NEW.pinned_card IS DISTINCT FROM OLD.pinned_card OR NEW.card_digest IS DISTINCT FROM OLD.card_digest
            OR NEW.card_keys IS DISTINCT FROM OLD.card_keys OR NEW.skills IS DISTINCT FROM OLD.skills
            OR NEW.peer_agent_id IS DISTINCT FROM OLD.peer_agent_id OR NEW.peer_bounds IS DISTINCT FROM OLD.peer_bounds
            OR NEW.peer_limits IS DISTINCT FROM OLD.peer_limits OR NEW.max_answer_bytes IS DISTINCT FROM OLD.max_answer_bytes
            OR NEW.max_stream_seconds IS DISTINCT FROM OLD.max_stream_seconds OR NEW.proposed_by IS DISTINCT FROM OLD.proposed_by
            OR NEW.proposed_at IS DISTINCT FROM OLD.proposed_at
            OR NEW.federation_trust_id IS DISTINCT FROM OLD.federation_trust_id
            OR NEW.federation_listing IS DISTINCT FROM OLD.federation_listing THEN
        RAISE EXCEPTION 'what an a2a pin is never changes' USING ERRCODE = 'check_violation';
    END IF;
    IF NOT ((OLD.state = NEW.state)
            OR (OLD.state = 'PROPOSED' AND NEW.state IN ('ACTIVE', 'VOIDED'))
            OR (OLD.state = 'ACTIVE' AND NEW.state = 'SUPERSEDED')) THEN
        RAISE EXCEPTION 'an a2a pin moves PROPOSED to ACTIVE or VOIDED, ACTIVE to SUPERSEDED' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.state <> 'PROPOSED' AND (NEW.confirmed_by IS DISTINCT FROM OLD.confirmed_by
            OR NEW.confirmed_credential IS DISTINCT FROM OLD.confirmed_credential OR NEW.confirmed_at IS DISTINCT FROM OLD.confirmed_at
            OR NEW.confirmed_operator IS DISTINCT FROM OLD.confirmed_operator) THEN
        RAISE EXCEPTION 'an a2a pin is confirmed once' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.state = 'PROPOSED' AND NEW.state <> 'PROPOSED' THEN
        NEW.decided_at := now();
        IF NEW.state = 'ACTIVE' THEN
            NEW.confirmed_at := now();
        END IF;
        IF NEW.state = 'ACTIVE' AND NEW.federation_trust_id IS NOT NULL THEN
            -- A federated peer's pin is activated by the federation check
            -- against an ACTIVE trust, and only that way (G0 M35 D1023).
            IF NEW.confirmed_operator IS DISTINCT FROM 'federation' OR NEW.confirmed_by IS NOT NULL THEN
                RAISE EXCEPTION 'a federated a2a pin is activated by the federation check' USING ERRCODE = 'check_violation';
            END IF;
            IF NOT EXISTS (SELECT 1 FROM pc.federation_trusts t
                           WHERE t.org_id = NEW.org_id AND t.id = NEW.federation_trust_id AND t.state = 'ACTIVE') THEN
                RAISE EXCEPTION 'a federated a2a pin needs an ACTIVE trust' USING ERRCODE = 'check_violation';
            END IF;
        -- Only dev seed activates a pin without a person, and only a
        -- simulated connection's, which reaches nothing but a local
        -- simulator (HR-221; simulated is fixed at insert).
        ELSIF NEW.state = 'ACTIVE' AND NEW.confirmed_operator IS NOT NULL AND NOT EXISTS (
                SELECT 1 FROM pc.connections c WHERE c.org_id = NEW.org_id AND c.id = NEW.connection_id AND c.simulated) THEN
            RAISE EXCEPTION 'only a simulated connection''s a2a pin is activated without a person' USING ERRCODE = 'check_violation';
        END IF;
    END IF;
    IF OLD.drifted_at IS NOT NULL AND (NEW.drifted_at IS DISTINCT FROM OLD.drifted_at OR NEW.observed_digest IS DISTINCT FROM OLD.observed_digest) THEN
        RAISE EXCEPTION 'an a2a pin records its drift once' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pc.a2a_pin_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'PROPOSED' OR NEW.confirmed_at IS NOT NULL OR NEW.confirmed_operator IS NOT NULL OR NEW.drifted_at IS NOT NULL THEN
            RAISE EXCEPTION 'an a2a pin is inserted PROPOSED' USING ERRCODE = 'check_violation';
        END IF;
        NEW.proposed_at := now();
        RETURN NEW;
    END IF;
    IF NEW.connection_id IS DISTINCT FROM OLD.connection_id OR NEW.card_url IS DISTINCT FROM OLD.card_url
            OR NEW.binding IS DISTINCT FROM OLD.binding OR NEW.interface_url IS DISTINCT FROM OLD.interface_url
            OR NEW.pinned_card IS DISTINCT FROM OLD.pinned_card OR NEW.card_digest IS DISTINCT FROM OLD.card_digest
            OR NEW.card_keys IS DISTINCT FROM OLD.card_keys OR NEW.skills IS DISTINCT FROM OLD.skills
            OR NEW.peer_agent_id IS DISTINCT FROM OLD.peer_agent_id OR NEW.peer_bounds IS DISTINCT FROM OLD.peer_bounds
            OR NEW.peer_limits IS DISTINCT FROM OLD.peer_limits OR NEW.max_answer_bytes IS DISTINCT FROM OLD.max_answer_bytes
            OR NEW.max_stream_seconds IS DISTINCT FROM OLD.max_stream_seconds OR NEW.proposed_by IS DISTINCT FROM OLD.proposed_by
            OR NEW.proposed_at IS DISTINCT FROM OLD.proposed_at THEN
        RAISE EXCEPTION 'what an a2a pin is never changes' USING ERRCODE = 'check_violation';
    END IF;
    IF NOT ((OLD.state = NEW.state)
            OR (OLD.state = 'PROPOSED' AND NEW.state IN ('ACTIVE', 'VOIDED'))
            OR (OLD.state = 'ACTIVE' AND NEW.state = 'SUPERSEDED')) THEN
        RAISE EXCEPTION 'an a2a pin moves PROPOSED to ACTIVE or VOIDED, ACTIVE to SUPERSEDED' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.state <> 'PROPOSED' AND (NEW.confirmed_by IS DISTINCT FROM OLD.confirmed_by
            OR NEW.confirmed_credential IS DISTINCT FROM OLD.confirmed_credential OR NEW.confirmed_at IS DISTINCT FROM OLD.confirmed_at
            OR NEW.confirmed_operator IS DISTINCT FROM OLD.confirmed_operator) THEN
        RAISE EXCEPTION 'an a2a pin is confirmed once' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.state = 'PROPOSED' AND NEW.state <> 'PROPOSED' THEN
        NEW.decided_at := now();
        IF NEW.state = 'ACTIVE' THEN
            NEW.confirmed_at := now();
        END IF;
        IF NEW.state = 'ACTIVE' AND NEW.confirmed_operator IS NOT NULL AND NOT EXISTS (
                SELECT 1 FROM pc.connections c WHERE c.org_id = NEW.org_id AND c.id = NEW.connection_id AND c.simulated) THEN
            RAISE EXCEPTION 'only a simulated connection''s a2a pin is activated without a person' USING ERRCODE = 'check_violation';
        END IF;
    END IF;
    IF OLD.drifted_at IS NOT NULL AND (NEW.drifted_at IS DISTINCT FROM OLD.drifted_at OR NEW.observed_digest IS DISTINCT FROM OLD.observed_digest) THEN
        RAISE EXCEPTION 'an a2a pin records its drift once' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
ALTER TABLE pc.a2a_pins
    DROP CONSTRAINT a2a_pins_federation_trust_fkey,
    DROP CONSTRAINT a2a_pins_federation,
    DROP COLUMN federation_listing,
    DROP COLUMN federation_trust_id;
DROP TABLE pc.federation_replay;
