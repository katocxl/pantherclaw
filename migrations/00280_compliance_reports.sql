-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
-- Compliance reports (G0 M25 D301, D303; F894, F896; HR-605, HR-606).
--
-- A report is an evidence pack of scope compliance. Its pack lasts 7 days;
-- this row does not: it keeps the framework, the period and the digest of
-- compliance.json, so the same parameters can be exported again and an equal
-- digest shows nothing changed. The framework lives here and in the report,
-- not in the pack's scope, because a manifest gains no member (D301). A row
-- is written once with its pack and takes its digest once, when the pack is
-- built; pc_app may not delete it or change anything else.

-- +goose Up
ALTER TABLE pc.evidence_packs
    DROP CONSTRAINT evidence_packs_scope_kind_check,
    ADD CONSTRAINT evidence_packs_scope_kind_check
        CHECK (scope_kind IN ('transactions', 'run', 'agent', 'time_range', 'range', 'automation_execution', 'compliance')) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.evidence_packs VALIDATE CONSTRAINT evidence_packs_scope_kind_check;

CREATE TABLE pc.compliance_reports (
    org_id        uuid        NOT NULL REFERENCES pc.orgs (id),
    id            uuid        NOT NULL,
    pack_id       uuid        NOT NULL,
    framework     text        NOT NULL CHECK (framework IN ('OWASP_ASI', 'NIST_AI_RMF', 'EU_AI_ACT_DEPLOYER', 'ISO_42001', 'SOC2')),
    period_start  timestamptz NOT NULL,
    period_end    timestamptz NOT NULL,
    created_by    uuid        NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    report_sha256 bytea       CHECK (octet_length(report_sha256) = 32),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, pack_id),
    FOREIGN KEY (org_id, pack_id) REFERENCES pc.evidence_packs (org_id, id),
    CHECK (period_end > period_start AND period_end - period_start <= interval '366 days')
);
CREATE INDEX compliance_reports_framework ON pc.compliance_reports (org_id, framework, id DESC);

ALTER TABLE pc.compliance_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.compliance_reports FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.compliance_reports
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.compliance_reports
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();

-- The digest is set once, and nothing else of a row ever changes (HR-606).
-- +goose StatementBegin
CREATE FUNCTION pc.compliance_report_digest_once() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pc, pg_temp AS $$
BEGIN
    IF OLD.report_sha256 IS NOT NULL
        OR (NEW.org_id, NEW.id, NEW.pack_id, NEW.framework, NEW.period_start, NEW.period_end, NEW.created_by, NEW.created_at)
            IS DISTINCT FROM
           (OLD.org_id, OLD.id, OLD.pack_id, OLD.framework, OLD.period_start, OLD.period_end, OLD.created_by, OLD.created_at) THEN
        RAISE EXCEPTION 'compliance report % takes its digest once and changes nothing else', OLD.id USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER compliance_reports_digest_once BEFORE UPDATE ON pc.compliance_reports
    FOR EACH ROW EXECUTE FUNCTION pc.compliance_report_digest_once();

-- pc_app inserts no digest and no time.
GRANT SELECT ON pc.compliance_reports TO pc_app;
GRANT INSERT (org_id, id, pack_id, framework, period_start, period_end, created_by) ON pc.compliance_reports TO pc_app;
GRANT UPDATE (report_sha256) ON pc.compliance_reports TO pc_app;
GRANT SELECT ON pc.compliance_reports TO pc_audit_ro;
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.compliance_reports TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE pc.compliance_reports;
DROP FUNCTION pc.compliance_report_digest_once();
DELETE FROM pc.evidence_packs WHERE scope_kind = 'compliance';
ALTER TABLE pc.evidence_packs
    DROP CONSTRAINT evidence_packs_scope_kind_check,
    ADD CONSTRAINT evidence_packs_scope_kind_check
        CHECK (scope_kind IN ('transactions', 'run', 'agent', 'time_range', 'range', 'automation_execution')) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.evidence_packs VALIDATE CONSTRAINT evidence_packs_scope_kind_check;
