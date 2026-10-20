-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Invitations accepted in the browser (G0 UI D8; PN-012.3; HR-352). Opening
-- /invite/{token} starts a sign-in without an org that carries the
-- invitation, bound to that browser like every sign-in (binding_hash):
-- the request keeps only the token's SHA-256 hash and the invitation's org,
-- and drops both when its callback consumes it. The invitation is then
-- accepted once, before it expires, and only if the provider-verified email
-- of the signed-in account equals the invitation's email
-- (INVITATION_EMAIL_MISMATCH otherwise). An accepted invitation records the
-- account and whether it was accepted in the browser or by pclaw.

-- +goose Up
ALTER TABLE pc.account_login_requests
    ADD COLUMN invitation_org_id uuid,
    ADD COLUMN invitation_token_hash bytea CHECK (invitation_token_hash IS NULL OR octet_length(invitation_token_hash) = 32);
ALTER TABLE pc.account_login_requests
    ADD CONSTRAINT account_login_requests_invitation
        CHECK ((invitation_org_id IS NULL) = (invitation_token_hash IS NULL)) NOT VALID,
    ADD CONSTRAINT account_login_requests_invitation_consumed
        CHECK (state = 'PENDING' OR invitation_token_hash IS NULL) NOT VALID;
-- The new columns are NULL in every row: the scans below find nothing to
-- refuse, and validating blocks neither reads nor writes.
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.account_login_requests VALIDATE CONSTRAINT account_login_requests_invitation;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.account_login_requests VALIDATE CONSTRAINT account_login_requests_invitation_consumed;
GRANT UPDATE (invitation_org_id, invitation_token_hash) ON pc.account_login_requests TO pc_app;

ALTER TABLE pc.invitations
    ADD COLUMN accepted_account_id uuid,
    ADD COLUMN accepted_via text CHECK (accepted_via IS NULL OR accepted_via IN ('CLI', 'BROWSER'));
ALTER TABLE pc.invitations
    ADD CONSTRAINT invitations_accepted_via
        CHECK (accepted_via IS NULL OR (state = 'ACCEPTED' AND accepted_at IS NOT NULL)) NOT VALID,
    ADD CONSTRAINT invitations_browser_account
        CHECK (accepted_via IS DISTINCT FROM 'BROWSER' OR accepted_account_id IS NOT NULL) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.invitations VALIDATE CONSTRAINT invitations_accepted_via;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.invitations VALIDATE CONSTRAINT invitations_browser_account;
GRANT UPDATE (accepted_account_id, accepted_via) ON pc.invitations TO pc_app;
GRANT SELECT (accepted_account_id, accepted_via) ON pc.invitations TO pc_audit_ro;

-- +goose Down
REVOKE SELECT (accepted_account_id, accepted_via) ON pc.invitations FROM pc_audit_ro;
ALTER TABLE pc.invitations
    DROP CONSTRAINT invitations_browser_account,
    DROP CONSTRAINT invitations_accepted_via,
    DROP COLUMN accepted_via,
    DROP COLUMN accepted_account_id;
ALTER TABLE pc.account_login_requests
    DROP CONSTRAINT account_login_requests_invitation_consumed,
    DROP CONSTRAINT account_login_requests_invitation,
    DROP COLUMN invitation_token_hash,
    DROP COLUMN invitation_org_id;
