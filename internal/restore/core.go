// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package restore

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	rapp "github.com/katocxl/pantherclaw/internal/response/app"
	rdomain "github.com/katocxl/pantherclaw/internal/response/domain"
)

var machineID = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)

func validateObject(e Event) error {
	if e.Kind == "security.kill_switch_engaged" && e.Object.ID != e.Org.String() {
		return errors.New("restore: kill switch object is another organization")
	}
	if e.Kind == "package.signing_key.revoked" {
		if e.RevocationReason != "ROTATED" && e.RevocationReason != "COMPROMISED" {
			return errors.New("restore: invalid package key revocation reason")
		}
	} else if e.RevocationReason != "" {
		return errors.New("restore: unexpected revocation reason")
	}
	switch e.Object.Type {
	case "signing_key", "package_signing_key":
		if !machineID.MatchString(e.Object.ID) {
			return errors.New("restore: invalid signing key id")
		}
	case "sealed_credential":
		conn, version, ok := strings.Cut(e.Object.ID, "/")
		if !ok {
			return errors.New("restore: invalid sealed credential id")
		}
		if _, err := ids.ParseUUID(conn); err != nil {
			return errors.New("restore: invalid connection id")
		}
		v, err := strconv.ParseInt(version, 10, 32)
		if err != nil || v < 1 || strconv.FormatInt(v, 10) != version {
			return errors.New("restore: invalid credential version")
		}
	default:
		if _, err := ids.ParseUUID(e.Object.ID); err != nil {
			return fmt.Errorf("restore: invalid %s id", e.Object.Type)
		}
	}
	if e.Kind != "response.contain" {
		if e.Containment != nil {
			return errors.New("restore: unexpected containment metadata")
		}
		return nil
	}
	c := e.Containment
	if c == nil || c.ActionID.IsZero() || c.ControlID.IsZero() || c.ControlID.String() != e.Object.ID || len(c.ScopeID) > 300 || len(c.Operation) > 200 {
		return errors.New("restore: missing or invalid containment metadata")
	}
	if c.Source != "PERSON" && c.Source != "SOAR" && c.Source != "PLAYBOOK" {
		return errors.New("restore: invalid containment source")
	}
	control, err := (rdomain.Control{ScopeType: c.ScopeType, ScopeID: c.ScopeID, Control: c.Control, Operation: c.Operation, Reason: "re-applied after restore"}).Canonical()
	if err != nil || control.ScopeID != c.ScopeID {
		return errors.New("restore: invalid or noncanonical containment scope")
	}
	return nil
}

func registerCore(r *Registry) {
	// All statements are fixed, tenant-filtered, conditional tightening
	// transitions. Existing revoked/disabled/ended objects are no-ops.
	statements := map[string][]string{
		"signing_key.revoked":                {`UPDATE pc.keys SET state='REVOKED', state_changed_at=now() WHERE org_id=$1 AND kid=$2 AND state IN ('ACTIVE','RETIRING')`},
		"gateway.revoked":                    {`UPDATE pc.gateways SET state='REVOKED',revoked_by='operator:restore',revoked_at=now(),revoke_reason='re-applied after restore',config_version=config_version+1 WHERE org_id=$1 AND id=$2::uuid AND state='ACTIVE'`, `UPDATE pc.gateway_certs SET state='REVOKED',revoked_at=now(),revoke_reason='restored_revocation',superseded_at=NULL WHERE org_id=$1 AND gateway_id=$2::uuid AND state<>'REVOKED'`},
		"gateway.certificate_revoked":        {`UPDATE pc.gateway_certs SET state='REVOKED',revoked_at=now(),revoke_reason='restored_revocation',superseded_at=NULL WHERE org_id=$1 AND id=$2::uuid AND state<>'REVOKED'`},
		"access.api_key_revoked":             {`UPDATE pc.api_keys SET state='REVOKED',revoked_at=now() WHERE org_id=$1 AND id=$2::uuid AND state='ACTIVE'`},
		"access.service_account_key_revoked": {`UPDATE pc.service_account_keys SET state='REVOKED',revoked_at=now() WHERE org_id=$1 AND id=$2::uuid AND state='ACTIVE'`},
		"access.service_account_disabled":    {`UPDATE pc.service_accounts SET state='DISABLED',updated_at=now() WHERE org_id=$1 AND id=$2::uuid AND state='ACTIVE'`},
		"access.user_disabled":               {`UPDATE pc.users SET state='DISABLED',updated_at=now() WHERE org_id=$1 AND id=$2::uuid AND state='ACTIVE'`},
		"access.invitation_revoked":          {`UPDATE pc.invitations SET state='REVOKED',revoked_at=now() WHERE org_id=$1 AND id=$2::uuid AND state='PENDING'`},
		"authn.webauthn_suspended":           {`UPDATE pc.webauthn_credentials SET state='SUSPENDED',state_reason='CLONE_SUSPECTED',changed_at=now(),changed_by='operator:restore' WHERE org_id=$1 AND id=$2::uuid AND state='ACTIVE'`},
		"authn.webauthn_removed":             {`UPDATE pc.webauthn_credentials SET state='REMOVED',state_reason='ADMIN_REMOVED',changed_at=now(),changed_by='operator:restore' WHERE org_id=$1 AND id=$2::uuid AND state<>'REMOVED'`},
		"identity.issuer_disabled":           {`UPDATE pc.trusted_issuers SET state=CASE WHEN state='PROPOSED' THEN 'WITHDRAWN' ELSE 'DISABLED' END,closed_at=now(),closed_by='operator:restore' WHERE org_id=$1 AND entry_id=$2::uuid AND state IN ('ACTIVE','PROPOSED')`},
		"authn.sessions_revoked":             {`UPDATE pc.sessions SET state='ENDED',ended_at=now(),end_reason='ADMIN_REVOKED' WHERE org_id=$1 AND user_id=$2::uuid AND state='ACTIVE'`, `UPDATE pc.cli_sessions SET state='REVOKED',revoked_at=now(),revoke_reason='RESTORE_REAPPLIED' WHERE org_id=$1 AND user_id=$2::uuid AND state='ACTIVE'`},
		"connection.quarantined":             {`UPDATE pc.connections SET state='QUARANTINED',quarantine_reason='manual',revision=revision+1,updated_at=now(),updated_by='operator:restore' WHERE org_id=$1 AND id=$2::uuid AND state='ACTIVE'`},
		"agents.agent_suspended":             {`UPDATE pc.agents SET state='SUSPENDED',suspended_from=state,updated_at=now() WHERE org_id=$1 AND id=$2::uuid AND state NOT IN ('SUSPENDED','RETIRED')`},
	}
	for kind, statements := range statements {
		r.handlers[kind] = func(ctx context.Context, tx db.TenantTx, e Event) error {
			for _, sql := range statements {
				if _, err := tx.Exec(ctx, sql, tx.OrgID(), e.Object.ID); err != nil {
					return err
				}
			}
			return nil
		}
	}
	for _, kind := range []string{"authn.session_revoked", "authn.session_ended"} {
		r.handlers[kind] = endSession
	}
	r.handlers["package.signing_key.revoked"] = func(ctx context.Context, tx db.TenantTx, e Event) error {
		_, err := tx.Exec(ctx, `UPDATE pc.package_signing_keys SET state='REVOKED',revoked_by='operator:restore',revoked_at=now(),revoke_reason=$3 WHERE org_id=$1 AND kid=$2 AND state='ACTIVE'`, tx.OrgID(), e.Object.ID, e.RevocationReason)
		return err
	}
	r.handlers["grant.revoked"] = func(ctx context.Context, tx db.TenantTx, e Event) error {
		id, err := ids.ParseUUID(e.Object.ID)
		if err != nil {
			return err
		}
		_, err = dbq.New(tx).RevokeGrantTree(ctx, "re-applied after restore", tx.OrgID(), id)
		return err
	}
	r.handlers["connection.sealed_revoked"] = func(ctx context.Context, tx db.TenantTx, e Event) error {
		connection, version, _ := strings.Cut(e.Object.ID, "/")
		_, err := tx.Exec(ctx, `UPDATE pc.credentials SET state='REVOKED',revoked_at=now(),revoked_by='operator:restore' WHERE org_id=$1 AND connection_id=$2::uuid AND version=$3::integer AND state<>'REVOKED'`, tx.OrgID(), connection, version)
		return err
	}
	r.handlers["security.kill_switch_engaged"] = func(ctx context.Context, tx db.TenantTx, e Event) error {
		if e.Object.ID != tx.OrgID().String() {
			return errors.New("restore: kill switch object is another organization")
		}
		q := dbq.New(tx)
		if err := q.InsertContainment(ctx, tx.OrgID()); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE pc.org_containment SET kill_switch=true,epoch=epoch+1,engaged_by='operator:restore',engaged_at=now(),engage_reason='re-applied after restore',updated_at=now() WHERE org_id=$1 AND NOT kill_switch`, tx.OrgID())
		return err
	}
	r.handlers["response.contain"] = func(ctx context.Context, tx db.TenantTx, e Event) error {
		return rapp.ReapplyControl(ctx, tx, *e.Containment, e.Actor)
	}
}

func endSession(ctx context.Context, tx db.TenantTx, e Event) error {
	sql := `UPDATE pc.sessions SET state='ENDED',ended_at=now(),end_reason='ADMIN_REVOKED' WHERE org_id=$1 AND id=$2::uuid AND state='ACTIVE'`
	if e.Object.Type == "cli_session" {
		sql = `UPDATE pc.cli_sessions SET state='REVOKED',revoked_at=now(),revoke_reason='RESTORE_REAPPLIED' WHERE org_id=$1 AND id=$2::uuid AND state='ACTIVE'`
	}
	_, err := tx.Exec(ctx, sql, tx.OrgID(), e.Object.ID)
	return err
}
