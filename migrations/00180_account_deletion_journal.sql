-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
-- F12/D49/D55: every tenant step stays in its own RLS transaction.
-- +goose Up
-- D47 account pseudonymisation and F20 personal sign-in metadata erasure.
-- Invoker guards permit these writes only in the accounts purpose while
-- the journal is DELETING, reached after F19 confirms the external copy.
ALTER TABLE pc.accounts ADD COLUMN deleted_at timestamptz;
CREATE TABLE pc.account_deletions (
    account_id uuid PRIMARY KEY REFERENCES pc.accounts(id),
    journal_id uuid NOT NULL DEFAULT gen_random_uuid(),
    state text NOT NULL CHECK (state IN ('PREPARING','ROLLING_BACK','INTENT_PENDING','DELETING','DONE','REFUSED')),
    record_digest text NOT NULL DEFAULT '' CHECK(record_digest='' OR record_digest ~ '^[0-9a-f]{64}$'),
    event_recorded boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE pc.account_deletions ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.account_deletions FORCE ROW LEVEL SECURITY;
CREATE POLICY account_context ON pc.account_deletions
 USING (account_id = NULLIF(current_setting('app.account_id',true),'')::uuid OR current_setting('app.purpose',true) = 'accounts')
 WITH CHECK (current_setting('app.purpose',true) = 'accounts');
GRANT SELECT,INSERT,UPDATE ON pc.account_deletions TO pc_app;

-- +goose StatementBegin
CREATE FUNCTION pc.account_tombstone_guard() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pc AS $$
BEGIN
    IF current_setting('app.purpose',true) IS DISTINCT FROM 'accounts'
       OR NOT EXISTS(SELECT FROM pc.account_deletions WHERE account_id=NEW.id AND state='DELETING')
       OR OLD.deleted_at IS NOT NULL OR NEW.deleted_at IS NULL
       OR NEW.issuer <> 'deleted' OR NEW.subject = OLD.subject
       OR NEW.subject !~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
       OR NEW.email <> '' OR NEW.display_name <> '' OR NEW.email_verified THEN
        RAISE EXCEPTION 'account tombstone requires confirmed deletion journal' USING ERRCODE='check_violation';
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER account_tombstone_guard BEFORE UPDATE OF issuer,subject,deleted_at ON pc.accounts FOR EACH ROW EXECUTE FUNCTION pc.account_tombstone_guard();
GRANT UPDATE(issuer,subject,deleted_at) ON pc.accounts TO pc_app;

-- +goose StatementBegin
CREATE FUNCTION pc.account_personal_metadata_guard() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pc AS $$
BEGIN
    IF current_setting('app.purpose',true) IS DISTINCT FROM 'accounts'
       OR NOT EXISTS(SELECT FROM pc.account_deletions WHERE account_id=NEW.account_id AND state='DELETING')
       OR NEW.client_ip <> '' THEN
        RAISE EXCEPTION 'personal metadata erasure requires confirmed deletion journal' USING ERRCODE='check_violation';
    END IF;
    IF TG_TABLE_NAME = 'account_sessions' THEN
        IF NEW.user_agent <> '' THEN RAISE EXCEPTION 'personal metadata must be empty' USING ERRCODE='check_violation'; END IF;
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER account_personal_metadata_guard BEFORE UPDATE OF client_ip,user_agent ON pc.account_sessions FOR EACH ROW EXECUTE FUNCTION pc.account_personal_metadata_guard();
CREATE TRIGGER account_personal_metadata_guard BEFORE UPDATE OF client_ip ON pc.account_events FOR EACH ROW EXECUTE FUNCTION pc.account_personal_metadata_guard();
GRANT UPDATE(user_agent,client_ip) ON pc.account_sessions TO pc_app;
GRANT UPDATE(client_ip) ON pc.account_events TO pc_app;
ALTER TABLE pc.account_events DROP CONSTRAINT account_events_kind_check;
ALTER TABLE pc.account_events ADD CONSTRAINT account_events_kind_check CHECK(kind IN ('SIGNED_IN','SESSION_STARTED','SESSION_ENDED','ORG_CREATED','ORG_CREATE_REFUSED','INVITATION_ACCEPTED','INVITATION_REFUSED','ACCOUNT_DELETED'));

CREATE TABLE pc.account_deletion_steps (
    org_id uuid NOT NULL REFERENCES pc.orgs(id),
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    state text NOT NULL CHECK (state IN ('PREPARED','DELETED')),
    PRIMARY KEY(org_id,id),
    FOREIGN KEY(org_id,user_id) REFERENCES pc.users(org_id,id)
);
CREATE INDEX account_deletion_steps_user ON pc.account_deletion_steps(org_id,user_id);
ALTER TABLE pc.account_deletion_steps ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.account_deletion_steps FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.account_deletion_steps
 USING (org_id = NULLIF(current_setting('app.org_id',true),'')::uuid)
 WITH CHECK (org_id = NULLIF(current_setting('app.org_id',true),'')::uuid);
GRANT SELECT,INSERT,UPDATE,DELETE ON pc.account_deletion_steps TO pc_app;

-- No identity, account ID or tenant data: the digest is not an identifier
-- usable to read pc.accounts. The tenant predicate is bounded to its input.
CREATE TABLE pc.identity_deletion_guards (
    identity_hash bytea PRIMARY KEY CHECK(octet_length(identity_hash)=32),
    state text NOT NULL CHECK(state IN ('PREPARING','DELETING'))
);
ALTER TABLE pc.identity_deletion_guards ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.identity_deletion_guards FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_read ON pc.identity_deletion_guards FOR SELECT
 USING (encode(identity_hash,'hex') = current_setting('app.identity_hash',true) OR current_setting('app.purpose',true) = 'accounts');
CREATE POLICY identity_insert ON pc.identity_deletion_guards FOR INSERT WITH CHECK(current_setting('app.purpose',true) = 'accounts');
CREATE POLICY identity_update ON pc.identity_deletion_guards FOR UPDATE USING(current_setting('app.purpose',true) = 'accounts') WITH CHECK(current_setting('app.purpose',true) = 'accounts');
CREATE POLICY identity_delete ON pc.identity_deletion_guards FOR DELETE USING(current_setting('app.purpose',true) = 'accounts');
GRANT SELECT,INSERT,UPDATE,DELETE ON pc.identity_deletion_guards TO pc_app;

-- +goose StatementBegin
CREATE FUNCTION pc.identity_available(p_issuer text,p_subject text,p_lock boolean DEFAULT false) RETURNS boolean
LANGUAGE plpgsql SET search_path=pg_catalog,pc AS $$
DECLARE h bytea; previous text; blocked boolean;
BEGIN
    h := sha256(convert_to(octet_length(p_issuer)::text || ':' || p_issuer || p_subject,'UTF8'));
    IF p_lock THEN
        PERFORM pg_advisory_xact_lock_shared(('x' || left(encode(h,'hex'),16))::bit(64)::bigint);
    END IF;
    previous := current_setting('app.identity_hash',true);
    PERFORM set_config('app.identity_hash',encode(h,'hex'),true);
    SELECT EXISTS(SELECT FROM pc.identity_deletion_guards WHERE identity_hash=h) INTO blocked;
    PERFORM set_config('app.identity_hash',coalesce(previous,''),true);
    RETURN NOT blocked;
EXCEPTION WHEN OTHERS THEN
    PERFORM set_config('app.identity_hash',coalesce(previous,''),true);
    RAISE;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION pc.identity_available(text,text,boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pc.identity_available(text,text,boolean) TO pc_app;

-- All identity-bearing mutations acquire the same shared identity lock
-- before any account row lock. The deletion starter holds it exclusively.
-- +goose StatementBegin
CREATE FUNCTION pc.account_identity_guard() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pc AS $$
DECLARE issuer_value text; subject_value text; account_value uuid; previous text;
BEGIN
    IF TG_TABLE_NAME = 'users' THEN
        IF NEW.state <> 'ACTIVE' THEN RETURN NEW; END IF;
        issuer_value := NEW.issuer; subject_value := NEW.subject; account_value := NEW.account_id;
    ELSIF TG_TABLE_NAME = 'account_sessions' THEN
        IF NEW.state <> 'ACTIVE' THEN RETURN NEW; END IF;
        account_value := NEW.account_id;
        previous := current_setting('app.account_id',true);
        PERFORM set_config('app.account_id',account_value::text,true);
        SELECT issuer,subject INTO STRICT issuer_value,subject_value FROM pc.accounts WHERE id=account_value;
        PERFORM set_config('app.account_id',coalesce(previous,''),true);
    ELSE
        IF TG_TABLE_NAME IN ('sessions','cli_sessions') THEN
            IF NEW.state <> 'ACTIVE' THEN RETURN NEW; END IF;
        END IF;
        IF NEW.user_id IS NULL THEN RETURN NEW; END IF;
        SELECT issuer,subject,account_id INTO STRICT issuer_value,subject_value,account_value FROM pc.users WHERE org_id=NEW.org_id AND id=NEW.user_id;
    END IF;
    IF NOT pc.identity_available(issuer_value,subject_value,true) THEN
        RAISE EXCEPTION 'account deletion pending' USING ERRCODE='check_violation';
    END IF;
    IF account_value IS NOT NULL THEN
        previous := current_setting('app.account_id',true);
        PERFORM set_config('app.account_id',account_value::text,true);
        PERFORM id FROM pc.accounts WHERE id=account_value AND deleted_at IS NULL FOR SHARE;
        IF NOT FOUND THEN RAISE EXCEPTION 'account unavailable' USING ERRCODE='check_violation'; END IF;
        PERFORM set_config('app.account_id',coalesce(previous,''),true);
    END IF;
    RETURN NEW;
EXCEPTION WHEN OTHERS THEN
    IF previous IS NOT NULL THEN PERFORM set_config('app.account_id',previous,true); END IF;
    RAISE;
END $$;
-- +goose StatementEnd
CREATE TRIGGER account_identity_guard BEFORE INSERT OR UPDATE ON pc.users FOR EACH ROW EXECUTE FUNCTION pc.account_identity_guard();
CREATE TRIGGER account_identity_guard BEFORE INSERT OR UPDATE ON pc.sessions FOR EACH ROW EXECUTE FUNCTION pc.account_identity_guard();
CREATE TRIGGER account_identity_guard BEFORE INSERT OR UPDATE ON pc.cli_sessions FOR EACH ROW EXECUTE FUNCTION pc.account_identity_guard();
CREATE TRIGGER account_identity_guard BEFORE INSERT OR UPDATE ON pc.role_bindings FOR EACH ROW EXECUTE FUNCTION pc.account_identity_guard();
CREATE TRIGGER account_identity_guard BEFORE INSERT OR UPDATE ON pc.account_sessions FOR EACH ROW EXECUTE FUNCTION pc.account_identity_guard();

ALTER TABLE pc.account_login_requests ADD COLUMN deletion_account_id uuid REFERENCES pc.accounts(id);
CREATE INDEX account_login_requests_deletion_account ON pc.account_login_requests(deletion_account_id) WHERE deletion_account_id IS NOT NULL;
GRANT UPDATE(deletion_account_id) ON pc.account_login_requests TO pc_app;
ALTER TABLE pc.account_sessions ADD COLUMN deletion_reauthenticated_at timestamptz;
GRANT UPDATE(deletion_reauthenticated_at) ON pc.account_sessions TO pc_app;
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT FROM pg_roles WHERE rolname='pc_deleter') THEN GRANT SELECT,DELETE ON pc.account_deletion_steps TO pc_deleter; END IF;
 IF EXISTS(SELECT FROM pg_roles WHERE rolname='pc_backup') THEN GRANT SELECT ON pc.account_deletions,pc.account_deletion_steps,pc.identity_deletion_guards TO pc_backup; END IF;
END $$;
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
    INSERT INTO pc.cross_org_list_audit (purpose, max_rows, caller, subject)
    VALUES (left(p_purpose, 64), p_max_rows, session_user,
            CASE WHEN p_purpose IN ('account_memberships','account_users') THEN NULLIF(current_setting('app.account_id', true), '')
                 WHEN p_purpose = 'billing_link_lookup' THEN left(current_setting('app.billing_provider', true) || ':'
                     || current_setting('app.billing_kind', true) || ':' || current_setting('app.billing_ref', true), 600) END);
    CASE p_purpose
        WHEN 'orgs' THEN
            RETURN QUERY SELECT o.id, o.id FROM pc.orgs o WHERE o.state = 'ACTIVE' ORDER BY o.id LIMIT p_max_rows;
        WHEN 'orgs_all' THEN
            -- Every org, whatever its state (G0 M13 D6).
            RETURN QUERY SELECT o.id, o.id FROM pc.orgs o ORDER BY o.id LIMIT p_max_rows;
        WHEN 'orgs_lapsed' THEN
            -- Active orgs whose plan lapsed (G0 M13 D34, HR-393): the
            -- daily job reminds their admins and deletes them on day 90.
            RETURN QUERY
                SELECT o.id, o.id
                FROM pc.orgs o
                JOIN pc.org_entitlements e ON e.org_id = o.id
                WHERE o.state = 'ACTIVE' AND e.lapsed_at IS NOT NULL
                ORDER BY 1
                LIMIT p_max_rows;
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
        WHEN 'policy_rollouts_due' THEN
            -- Active orgs with a policy rollout in SHADOW or PILOT, or one
            -- completed less than 7 days ago (G0 M11.1, D12, D31).
            RETURN QUERY
                SELECT o.id, o.id
                FROM pc.orgs o
                WHERE o.state = 'ACTIVE'
                  AND EXISTS (SELECT 1 FROM pc.policy_rollouts r
                              WHERE r.org_id = o.id
                                AND (r.stage IN ('SHADOW', 'PILOT')
                                     OR (r.stage = 'COMPLETE' AND r.completed_at > now() - interval '7 days')))
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'account_users' THEN
            RETURN QUERY SELECT u.org_id,u.id FROM pc.accounts a
            JOIN pc.users u ON u.account_id=a.id OR (u.account_id IS NULL AND u.issuer=a.issuer AND u.subject=a.subject)
            WHERE a.id=NULLIF(current_setting('app.account_id',true),'')::uuid
            ORDER BY 1 LIMIT p_max_rows;
        WHEN 'account_memberships' THEN
            -- The active memberships of one hosted account (G0 UI D8,
            -- HR-349): (org, user) pairs of the active users of active orgs
            -- with the (issuer, subject) of the account the caller set in
            -- app.account_id for this transaction — linked already or not,
            -- never matched by email (HR-348). Without the setting the
            -- purpose matches nothing.
            RETURN QUERY
                SELECT u.org_id, u.id
                FROM pc.accounts a
                JOIN pc.users u ON u.issuer = a.issuer AND u.subject = a.subject
                JOIN pc.orgs o ON o.id = u.org_id
                WHERE a.id = (SELECT NULLIF(current_setting('app.account_id', true), '')::uuid)
                  AND (u.account_id IS NULL OR u.account_id = a.id)
                  AND u.state = 'ACTIVE' AND o.state = 'ACTIVE'
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'billing_link_lookup' THEN
            -- The org of one billing ref (G0 UI D37): the (org, link) pair
            -- of the link with the provider, kind and ref the caller set in
            -- app.billing_provider, app.billing_kind and app.billing_ref for
            -- this transaction. Without them the purpose matches nothing.
            RETURN QUERY
                SELECT l.org_id, l.id
                FROM pc.billing_links l
                WHERE l.provider = (SELECT NULLIF(current_setting('app.billing_provider', true), ''))
                  AND l.kind = (SELECT NULLIF(current_setting('app.billing_kind', true), ''))
                  AND l.ref = (SELECT NULLIF(current_setting('app.billing_ref', true), ''))
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
    INSERT INTO pc.cross_org_list_audit (purpose, max_rows, caller, subject)
    VALUES (left(p_purpose, 64), p_max_rows, session_user,
            CASE WHEN p_purpose = 'account_memberships' THEN NULLIF(current_setting('app.account_id', true), '')
                 WHEN p_purpose = 'billing_link_lookup' THEN left(current_setting('app.billing_provider', true) || ':'
                     || current_setting('app.billing_kind', true) || ':' || current_setting('app.billing_ref', true), 600) END);
    CASE p_purpose
        WHEN 'orgs' THEN
            RETURN QUERY SELECT o.id, o.id FROM pc.orgs o WHERE o.state = 'ACTIVE' ORDER BY o.id LIMIT p_max_rows;
        WHEN 'orgs_all' THEN
            -- Every org, whatever its state (G0 M13 D6).
            RETURN QUERY SELECT o.id, o.id FROM pc.orgs o ORDER BY o.id LIMIT p_max_rows;
        WHEN 'orgs_lapsed' THEN
            -- Active orgs whose plan lapsed (G0 M13 D34, HR-393): the
            -- daily job reminds their admins and deletes them on day 90.
            RETURN QUERY
                SELECT o.id, o.id
                FROM pc.orgs o
                JOIN pc.org_entitlements e ON e.org_id = o.id
                WHERE o.state = 'ACTIVE' AND e.lapsed_at IS NOT NULL
                ORDER BY 1
                LIMIT p_max_rows;
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
        WHEN 'policy_rollouts_due' THEN
            -- Active orgs with a policy rollout in SHADOW or PILOT, or one
            -- completed less than 7 days ago (G0 M11.1, D12, D31).
            RETURN QUERY
                SELECT o.id, o.id
                FROM pc.orgs o
                WHERE o.state = 'ACTIVE'
                  AND EXISTS (SELECT 1 FROM pc.policy_rollouts r
                              WHERE r.org_id = o.id
                                AND (r.stage IN ('SHADOW', 'PILOT')
                                     OR (r.stage = 'COMPLETE' AND r.completed_at > now() - interval '7 days')))
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'account_memberships' THEN
            -- The active memberships of one hosted account (G0 UI D8,
            -- HR-349): (org, user) pairs of the active users of active orgs
            -- with the (issuer, subject) of the account the caller set in
            -- app.account_id for this transaction — linked already or not,
            -- never matched by email (HR-348). Without the setting the
            -- purpose matches nothing.
            RETURN QUERY
                SELECT u.org_id, u.id
                FROM pc.accounts a
                JOIN pc.users u ON u.issuer = a.issuer AND u.subject = a.subject
                JOIN pc.orgs o ON o.id = u.org_id
                WHERE a.id = (SELECT NULLIF(current_setting('app.account_id', true), '')::uuid)
                  AND (u.account_id IS NULL OR u.account_id = a.id)
                  AND u.state = 'ACTIVE' AND o.state = 'ACTIVE'
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'billing_link_lookup' THEN
            -- The org of one billing ref (G0 UI D37): the (org, link) pair
            -- of the link with the provider, kind and ref the caller set in
            -- app.billing_provider, app.billing_kind and app.billing_ref for
            -- this transaction. Without them the purpose matches nothing.
            RETURN QUERY
                SELECT l.org_id, l.id
                FROM pc.billing_links l
                WHERE l.provider = (SELECT NULLIF(current_setting('app.billing_provider', true), ''))
                  AND l.kind = (SELECT NULLIF(current_setting('app.billing_kind', true), ''))
                  AND l.ref = (SELECT NULLIF(current_setting('app.billing_ref', true), ''))
                ORDER BY 1
                LIMIT p_max_rows;
        ELSE
            RAISE EXCEPTION 'cross_org_list: unknown purpose';
    END CASE;
END;
$$;
-- +goose StatementEnd


ALTER TABLE pc.account_sessions DROP COLUMN deletion_reauthenticated_at;
ALTER TABLE pc.account_login_requests DROP COLUMN deletion_account_id;
DROP TRIGGER account_identity_guard ON pc.account_sessions;
DROP TRIGGER account_identity_guard ON pc.role_bindings;
DROP TRIGGER account_identity_guard ON pc.cli_sessions;
DROP TRIGGER account_identity_guard ON pc.sessions;
DROP TRIGGER account_identity_guard ON pc.users;
DROP FUNCTION pc.account_identity_guard();
DROP FUNCTION pc.identity_available(text,text,boolean);
DROP TABLE pc.identity_deletion_guards;
DROP TABLE pc.account_deletion_steps;
DROP TRIGGER account_tombstone_guard ON pc.accounts;
DROP FUNCTION pc.account_tombstone_guard();
DROP TRIGGER account_personal_metadata_guard ON pc.account_sessions;
DROP TRIGGER account_personal_metadata_guard ON pc.account_events;
DROP FUNCTION pc.account_personal_metadata_guard();
DROP TABLE pc.account_deletions;
REVOKE UPDATE(issuer,subject,deleted_at) ON pc.accounts FROM pc_app;
REVOKE UPDATE(user_agent,client_ip) ON pc.account_sessions FROM pc_app;
REVOKE UPDATE(client_ip) ON pc.account_events FROM pc_app;
ALTER TABLE pc.accounts DROP COLUMN deleted_at;
-- Existing deletion audit rows deliberately make downgrade fail closed;
-- a migration never deletes audit history to satisfy an older enum.
ALTER TABLE pc.account_events DROP CONSTRAINT account_events_kind_check;
ALTER TABLE pc.account_events ADD CONSTRAINT account_events_kind_check CHECK(kind IN ('SIGNED_IN','SESSION_STARTED','SESSION_ENDED','ORG_CREATED','ORG_CREATE_REFUSED','INVITATION_ACCEPTED','INVITATION_REFUSED'));
