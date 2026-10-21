-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Customer-approved support access, requests (G0 M13 D32, D38; ADR-0034;
-- HR-385, HR-386). A member of the operator's support staff (a user of the
-- staff org whose linked account is on the staff list) asks a customer org
-- for read-only access for a named task and at most 72 hours, after a
-- security-key step-up in the staff org. The request lives in the customer
-- org, where its org admins see it; one of them approves or denies it with
-- a step-up of their own. Nobody ever decides their own request: the
-- deciding user's linked account must not be the requester's (HR-386),
-- which a trigger checks again. A request nobody decided within seven days
-- reads as EXPIRED and can no longer be decided.

-- +goose Up

CREATE TABLE pc.support_access_requests (
    org_id             uuid        NOT NULL REFERENCES pc.orgs (id),
    id                 uuid        NOT NULL,
    -- Who asked: their hosted account, and as what the staff org knew them.
    requester_account  uuid        NOT NULL,
    requester_email    text        NOT NULL DEFAULT '' CHECK (char_length(requester_email) <= 320),
    requester_name     text        NOT NULL DEFAULT '' CHECK (char_length(requester_name) <= 200),
    staff_org          uuid        NOT NULL,
    staff_user         uuid        NOT NULL,
    staff_credential   uuid        NOT NULL,
    -- The named task: plain text without control characters.
    task               text        NOT NULL CHECK (char_length(task) BETWEEN 1 AND 200 AND task !~ '[[:cntrl:]]'),
    scope              text        NOT NULL CHECK (scope IN ('READ_ONLY', 'READ_ONLY_PLUS_EVIDENCE')),
    duration_hours     integer     NOT NULL CHECK (duration_hours BETWEEN 1 AND 72),
    state              text        NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING', 'APPROVED', 'DENIED')),
    created_at         timestamptz NOT NULL DEFAULT now(),
    expires_at         timestamptz NOT NULL,
    decided_by         uuid,
    decided_credential uuid,
    decided_at         timestamptz,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, decided_by) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, decided_credential) REFERENCES pc.webauthn_credentials (org_id, id),
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '7 days'),
    CHECK ((state = 'PENDING') = (decided_at IS NULL)),
    CHECK ((decided_at IS NULL) = (decided_by IS NULL) AND (decided_by IS NULL) = (decided_credential IS NULL))
);
CREATE INDEX support_access_requests_created ON pc.support_access_requests (org_id, created_at DESC, id DESC);
CREATE INDEX support_access_requests_requester ON pc.support_access_requests (org_id, requester_account);

-- A request is decided once, before it expires, by an org user whose
-- linked account is not the requester's; nothing else ever changes.
-- +goose StatementBegin
CREATE FUNCTION pc.support_access_request_guard() RETURNS trigger
    LANGUAGE plpgsql AS $$
DECLARE
    decider_account uuid;
BEGIN
    IF OLD.state <> 'PENDING' THEN
        RAISE EXCEPTION 'a decided support request is final' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.org_id IS DISTINCT FROM OLD.org_id OR NEW.id IS DISTINCT FROM OLD.id
        OR NEW.requester_account IS DISTINCT FROM OLD.requester_account
        OR NEW.requester_email IS DISTINCT FROM OLD.requester_email
        OR NEW.requester_name IS DISTINCT FROM OLD.requester_name
        OR NEW.staff_org IS DISTINCT FROM OLD.staff_org OR NEW.staff_user IS DISTINCT FROM OLD.staff_user
        OR NEW.staff_credential IS DISTINCT FROM OLD.staff_credential
        OR NEW.task IS DISTINCT FROM OLD.task OR NEW.scope IS DISTINCT FROM OLD.scope
        OR NEW.duration_hours IS DISTINCT FROM OLD.duration_hours
        OR NEW.created_at IS DISTINCT FROM OLD.created_at OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
        RAISE EXCEPTION 'a support request is never rewritten' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.state <> 'PENDING' THEN
        IF now() >= OLD.expires_at THEN
            RAISE EXCEPTION 'an expired support request cannot be decided' USING ERRCODE = 'check_violation';
        END IF;
        SELECT u.account_id INTO decider_account FROM pc.users u WHERE u.org_id = NEW.org_id AND u.id = NEW.decided_by;
        IF decider_account IS NOT DISTINCT FROM NEW.requester_account THEN
            RAISE EXCEPTION 'nobody decides their own support request' USING ERRCODE = 'check_violation';
        END IF;
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER support_access_requests_guard BEFORE UPDATE ON pc.support_access_requests
    FOR EACH ROW EXECUTE FUNCTION pc.support_access_request_guard();

ALTER TABLE pc.support_access_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.support_access_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.support_access_requests
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

GRANT SELECT, INSERT ON pc.support_access_requests TO pc_app;
GRANT UPDATE (state, decided_by, decided_credential, decided_at) ON pc.support_access_requests TO pc_app;
GRANT SELECT ON pc.support_access_requests TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.support_access_requests;
DROP FUNCTION pc.support_access_request_guard();
