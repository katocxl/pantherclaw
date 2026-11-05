-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- MSSP partner links and partner sessions (G0 M38 D1100, D1101; FQ38-1;
-- ADR-0065; HR-810..813). A partner is an ordinary org on the same
-- deployment. A person of the partner org holding partner.manage asks a
-- customer org for a link: READ always, PROPOSE optionally, for 1 to 90
-- days. A person of the customer org holding partner.approve decides it on
-- its page with a WebAuthn step-up (decided_by, decided_credential); the API
-- refuses (STEP_UP_REQUIRED). The window starts at the approval and ends at
-- most 90 days later; the customer revokes at any time. Nobody decides a
-- link their own account asked for (the requester's hosted account, when
-- the partner user has one, is recorded at request time), which the guard
-- checks again. States only move forward; a renewal is a new REQUESTED row.
--
-- A link is visible to both of its orgs: the policy matches app.org_id
-- against partner_org or customer_org, so each side lists its own links in
-- its own tenant transaction, and nothing else ever sees them.
--
-- A partner session is a browser session of a partner person inside the
-- customer org (org_id), bound to an ACTIVE link: it opens only inside the
-- link's window, never outlives it, and every authentication checks the
-- link again (HR-811).

-- +goose Up

CREATE TABLE pc.partner_links (
    id                 uuid        PRIMARY KEY,
    partner_org        uuid        NOT NULL REFERENCES pc.orgs (id),
    customer_org       uuid        NOT NULL REFERENCES pc.orgs (id),
    -- The partner org's name when it asked, shown to the customer (the
    -- customer cannot read the partner's org row).
    partner_name       text        NOT NULL CHECK (char_length(partner_name) BETWEEN 1 AND 200),
    state              text        NOT NULL DEFAULT 'REQUESTED'
                                   CHECK (state IN ('REQUESTED', 'ACTIVE', 'DENIED', 'REVOKED', 'EXPIRED')),
    scopes             text[]      NOT NULL CHECK ('READ' = ANY (scopes) AND scopes <@ ARRAY['READ', 'PROPOSE']::text[]
                                                   AND cardinality(scopes) BETWEEN 1 AND 2
                                                   AND array_position(scopes, NULL) IS NULL),
    duration_days      integer     NOT NULL CHECK (duration_days BETWEEN 1 AND 90),
    -- Why the partner asks: plain text without control characters.
    reason             text        NOT NULL DEFAULT '' CHECK (char_length(reason) <= 500 AND reason !~ '[[:cntrl:]]'),
    -- The link this one renews, if any.
    renews             uuid,
    requested_by       uuid        NOT NULL,
    requested_account  uuid,
    requested_at       timestamptz NOT NULL DEFAULT now(),
    -- A REQUESTED link nobody decided within seven days reads as EXPIRED.
    request_expires_at timestamptz NOT NULL,
    decided_by         uuid,
    decided_credential uuid,
    decided_at         timestamptz,
    starts_at          timestamptz,
    ends_at            timestamptz,
    revoked_by         text        CHECK (revoked_by IS NULL OR char_length(revoked_by) BETWEEN 1 AND 256),
    revoked_at         timestamptz,
    end_reason         text        CHECK (end_reason IS NULL OR char_length(end_reason) <= 500 AND end_reason !~ '[[:cntrl:]]'),
    CHECK (partner_org <> customer_org),
    FOREIGN KEY (partner_org, requested_by) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (customer_org, decided_by) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (customer_org, decided_credential) REFERENCES pc.webauthn_credentials (org_id, id),
    CHECK (request_expires_at > requested_at AND request_expires_at <= requested_at + interval '7 days'),
    CHECK ((decided_at IS NULL) = (decided_by IS NULL) AND (decided_by IS NULL) = (decided_credential IS NULL)),
    CHECK ((starts_at IS NULL) = (ends_at IS NULL)),
    CHECK (starts_at IS NULL OR (decided_at IS NOT NULL AND ends_at > starts_at
                                 AND ends_at <= decided_at + interval '90 days')),
    CHECK (state <> 'ACTIVE' OR starts_at IS NOT NULL),
    CHECK ((state = 'REVOKED') = (revoked_at IS NOT NULL) AND (revoked_at IS NULL) = (revoked_by IS NULL))
);
CREATE INDEX partner_links_partner ON pc.partner_links (partner_org, requested_at DESC, id DESC);
CREATE INDEX partner_links_customer ON pc.partner_links (customer_org, requested_at DESC, id DESC);
CREATE INDEX partner_links_live ON pc.partner_links (customer_org, partner_org) WHERE state = 'ACTIVE';

-- Forward-only states (REQUESTED → ACTIVE | DENIED | REVOKED | EXPIRED;
-- ACTIVE → REVOKED | EXPIRED), a request decided once, before it expires,
-- never by the account that asked, and nothing but the decision, the
-- window and the end ever written (HR-810).
-- +goose StatementBegin
CREATE FUNCTION pc.partner_link_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
DECLARE
    decider_account uuid;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state IS DISTINCT FROM 'REQUESTED' OR NEW.decided_by IS NOT NULL OR NEW.starts_at IS NOT NULL
                OR NEW.revoked_at IS NOT NULL THEN
            RAISE EXCEPTION 'a partner link is inserted REQUESTED' USING ERRCODE = 'check_violation';
        END IF;
        NEW.requested_at := now();
        NEW.request_expires_at := now() + interval '7 days';
        RETURN NEW;
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.partner_org IS DISTINCT FROM OLD.partner_org
            OR NEW.customer_org IS DISTINCT FROM OLD.customer_org OR NEW.partner_name IS DISTINCT FROM OLD.partner_name
            OR NEW.scopes IS DISTINCT FROM OLD.scopes OR NEW.duration_days IS DISTINCT FROM OLD.duration_days
            OR NEW.reason IS DISTINCT FROM OLD.reason OR NEW.renews IS DISTINCT FROM OLD.renews
            OR NEW.requested_by IS DISTINCT FROM OLD.requested_by
            OR NEW.requested_account IS DISTINCT FROM OLD.requested_account
            OR NEW.requested_at IS DISTINCT FROM OLD.requested_at
            OR NEW.request_expires_at IS DISTINCT FROM OLD.request_expires_at THEN
        RAISE EXCEPTION 'a partner link is never rewritten' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.state IN ('DENIED', 'REVOKED', 'EXPIRED') THEN
        RAISE EXCEPTION 'an ended partner link is final' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.state = 'ACTIVE' AND NEW.state NOT IN ('ACTIVE', 'REVOKED', 'EXPIRED') THEN
        RAISE EXCEPTION 'a partner link only moves forward' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.decided_by IS NOT NULL AND (NEW.decided_by IS DISTINCT FROM OLD.decided_by
            OR NEW.decided_credential IS DISTINCT FROM OLD.decided_credential
            OR NEW.decided_at IS DISTINCT FROM OLD.decided_at
            OR NEW.starts_at IS DISTINCT FROM OLD.starts_at OR NEW.ends_at IS DISTINCT FROM OLD.ends_at) THEN
        RAISE EXCEPTION 'a partner link is decided once' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.state = 'REQUESTED' AND NEW.state IN ('ACTIVE', 'DENIED') THEN
        IF now() >= OLD.request_expires_at THEN
            RAISE EXCEPTION 'an expired partner link request cannot be decided' USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.decided_by IS NULL THEN
            RAISE EXCEPTION 'a partner link decision names its person and key' USING ERRCODE = 'check_violation';
        END IF;
        SELECT u.account_id INTO decider_account FROM pc.users u WHERE u.org_id = NEW.customer_org AND u.id = NEW.decided_by;
        IF OLD.requested_account IS NOT NULL AND decider_account IS NOT DISTINCT FROM OLD.requested_account THEN
            RAISE EXCEPTION 'nobody decides their own partner link' USING ERRCODE = 'check_violation';
        END IF;
        NEW.decided_at := now();
        IF NEW.state = 'ACTIVE' THEN
            NEW.starts_at := now();
            NEW.ends_at := now() + make_interval(days => OLD.duration_days);
        ELSE
            NEW.starts_at := NULL;
            NEW.ends_at := NULL;
        END IF;
    ELSIF OLD.decided_by IS NULL AND NEW.decided_by IS NOT NULL THEN
        RAISE EXCEPTION 'only a decision names a decider' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.state = 'REVOKED' AND OLD.state IS DISTINCT FROM 'REVOKED' THEN
        NEW.revoked_at := now();
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER partner_links_guard BEFORE INSERT OR UPDATE ON pc.partner_links
    FOR EACH ROW EXECUTE FUNCTION pc.partner_link_guard();

ALTER TABLE pc.partner_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.partner_links FORCE ROW LEVEL SECURITY;
-- Both parties see a link; nobody else does.
CREATE POLICY partner_link_parties ON pc.partner_links
    USING (partner_org = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid)
           OR customer_org = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (partner_org = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid)
                OR customer_org = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

GRANT SELECT, INSERT ON pc.partner_links TO pc_app;
GRANT UPDATE (state, decided_by, decided_credential, decided_at, starts_at, ends_at, revoked_by, revoked_at, end_reason)
    ON pc.partner_links TO pc_app;
GRANT SELECT ON pc.partner_links TO pc_audit_ro;

CREATE TABLE pc.partner_sessions (
    -- The customer org the session reads.
    org_id             uuid        NOT NULL REFERENCES pc.orgs (id),
    id                 uuid        NOT NULL,
    link_id            uuid        NOT NULL REFERENCES pc.partner_links (id),
    partner_org        uuid        NOT NULL,
    partner_user       uuid        NOT NULL,
    -- The partner person's key of the step-up the session was opened with.
    partner_credential uuid        NOT NULL,
    secret_hash        bytea       NOT NULL CHECK (octet_length(secret_hash) = 32),
    state              text        NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'ENDED')),
    end_reason         text        CHECK (end_reason IS NULL OR end_reason IN ('LOGOUT', 'EXPIRED', 'IDLE', 'LINK_ENDED',
                                                                             'PARTNER_REMOVED')),
    user_agent         text        NOT NULL DEFAULT '' CHECK (char_length(user_agent) <= 256),
    client_ip          text        NOT NULL DEFAULT '' CHECK (char_length(client_ip) <= 64),
    created_at         timestamptz NOT NULL DEFAULT now(),
    last_seen_at       timestamptz NOT NULL DEFAULT now(),
    expires_at         timestamptz NOT NULL,
    ended_at           timestamptz,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, secret_hash),
    CHECK (expires_at > created_at),
    CHECK ((state = 'ENDED') = (ended_at IS NOT NULL) AND (ended_at IS NULL) = (end_reason IS NULL))
);
CREATE INDEX partner_sessions_link ON pc.partner_sessions (org_id, link_id) WHERE state = 'ACTIVE';

-- A session opens only under an ACTIVE link of this customer and partner,
-- inside its window, and never outlives it; afterwards only its use and
-- its end are written.
-- +goose StatementBegin
CREATE FUNCTION pc.partner_session_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
DECLARE
    l pc.partner_links;
BEGIN
    IF TG_OP = 'INSERT' THEN
        SELECT * INTO l FROM pc.partner_links WHERE id = NEW.link_id;
        IF l.id IS NULL OR l.state IS DISTINCT FROM 'ACTIVE' OR l.customer_org IS DISTINCT FROM NEW.org_id
                OR l.partner_org IS DISTINCT FROM NEW.partner_org OR now() < l.starts_at OR now() >= l.ends_at
                OR NEW.expires_at > l.ends_at OR NEW.state <> 'ACTIVE' THEN
            RAISE EXCEPTION 'a partner session needs an active link' USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.state = 'ENDED' AND NEW.state <> 'ENDED' THEN
        RAISE EXCEPTION 'an ended partner session is final' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.org_id IS DISTINCT FROM OLD.org_id OR NEW.id IS DISTINCT FROM OLD.id
            OR NEW.link_id IS DISTINCT FROM OLD.link_id OR NEW.partner_org IS DISTINCT FROM OLD.partner_org
            OR NEW.partner_user IS DISTINCT FROM OLD.partner_user
            OR NEW.partner_credential IS DISTINCT FROM OLD.partner_credential
            OR NEW.secret_hash IS DISTINCT FROM OLD.secret_hash
            OR NEW.created_at IS DISTINCT FROM OLD.created_at OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
        RAISE EXCEPTION 'a partner session is never rewritten' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER partner_sessions_guard BEFORE INSERT OR UPDATE ON pc.partner_sessions
    FOR EACH ROW EXECUTE FUNCTION pc.partner_session_guard();

ALTER TABLE pc.partner_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.partner_sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.partner_sessions
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

GRANT SELECT, INSERT ON pc.partner_sessions TO pc_app;
GRANT UPDATE (state, end_reason, ended_at, last_seen_at) ON pc.partner_sessions TO pc_app;
GRANT SELECT (org_id, id, link_id, partner_org, partner_user, partner_credential, state, end_reason, user_agent, client_ip,
    created_at, last_seen_at, expires_at, ended_at) ON pc.partner_sessions TO pc_audit_ro;

-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.partner_links, pc.partner_sessions TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE pc.partner_sessions;
DROP FUNCTION pc.partner_session_guard();
DROP TABLE pc.partner_links;
DROP FUNCTION pc.partner_link_guard();
