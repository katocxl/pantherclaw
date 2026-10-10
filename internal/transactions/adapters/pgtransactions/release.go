// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgtransactions

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"time"

	agents "github.com/katocxl/pantherclaw/internal/agents/app"
	"github.com/katocxl/pantherclaw/internal/budgets/adapters/pgbudgets"
	bdomain "github.com/katocxl/pantherclaw/internal/budgets/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/transactions/app"
	"github.com/katocxl/pantherclaw/internal/transactions/domain"
	"github.com/katocxl/pantherclaw/internal/waitlist/adapters/pgwaitlist"
)

var _ app.ReleaseStore = (*Store)(nil)

// claimReleased is the dedupe claim's state once its action did not
// happen (pipeline.ClaimReleased): an exact repeat is decided again.
const claimReleased = "RELEASED"

// releasable locks the reconciliation and checks that c may release it now
// (HR-192, G0 M7 design decision 3): c holds transaction.reconcile where the
// run's agent lives, the task is an open unknown outcome, and c is none of
// the run's launcher, its represented principal, the agent's owner and its
// backup owner.
func releasable(ctx context.Context, q *dbq.Queries, c tenancy.Caller, id ids.UUID) (dbq.ReconciliationByIDRow, error) {
	k, err := q.ReconciliationByID(ctx, c.Org, id)
	if db.IsNoRows(err) {
		return k, app.ErrReconciliationNotFound
	} else if err != nil {
		return k, err
	}
	if err := reconciles(ctx, q, c, k.AgentID); err != nil {
		return k, err
	}
	if err := domain.CheckReleasable(domain.TaskKind(k.Kind), domain.TaskState(k.State)); err != nil {
		return k, err
	}
	p, err := q.ReleaseParties(ctx, c.Org, k.TransactionID)
	if err != nil {
		return k, err
	}
	return k, domain.CheckIndependent(c.Principal.ID, domain.Party{
		Launcher: orZero(p.LauncherUserID), Principal: orZero(p.PrincipalUserID), Owner: orZero(p.OwnerUserID),
		BackupOwner: orZero(p.BackupOwnerUserID),
	})
}

// reconciles checks that c holds transaction.reconcile where agent lives.
func reconciles(ctx context.Context, q *dbq.Queries, c tenancy.Caller, agent ids.UUID) error {
	a, err := q.GetAgent(ctx, c.Org, agent)
	if err != nil {
		return err
	}
	path, err := agents.PathOf(ctx, q, a)
	if err != nil {
		return err
	}
	return c.Require(td.PermTransactionReconcile, path)
}

func orZero(p *ids.UUID) ids.UUID {
	if p == nil {
		return ids.UUID{}
	}
	return *p
}

// Releasable implements app.ReleaseStore.
func (s *Store) Releasable(ctx context.Context, c tenancy.Caller, id ids.UUID) (string, time.Time, error) {
	var refusal string
	var now time.Time
	err := s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		_, err := releasable(ctx, q, c, id)
		if refusal = app.Refusal(err); refusal != "" {
			err = nil
		}
		if err != nil {
			return err
		}
		now, err = q.DBNow(ctx)
		return err
	})
	return refusal, now, err
}

// BeginRelease implements app.ReleaseStore.
func (s *Store) BeginRelease(ctx context.Context, c tenancy.Caller, r app.ReleaseRequest) (domain.Release, error) {
	var out domain.Release
	err := s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		k, err := releasable(ctx, q, c, r.Reconciliation)
		if err != nil {
			return err
		}
		if err := shown(ctx, q, c.Org, k.TransactionID, r.Evidence); err != nil {
			return err
		}
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		out = domain.Release{
			Reconciliation: k.ID, Transaction: k.TransactionID, Basis: r.Basis, Evidence: r.Evidence,
			ExpiresAt: domain.ReleaseExpiry(now),
		}
		return nil
	})
	return out, err
}

// Release implements app.ReleaseStore (HR-192, HR-004, HR-003, HR-007).
// Everything happens in one transaction, or nothing does.
func (s *Store) Release(ctx context.Context, c tenancy.Caller, r app.ReleaseRequest, expiresAt time.Time, a app.Assertion,
	sign app.Sign,
) (app.Reconciliation, error) {
	user, session := c.Principal.ID, c.Session
	var out app.Reconciliation
	err := s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		k, err := releasable(ctx, q, c, r.Reconciliation)
		if err != nil {
			return err
		}
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		if err := domain.CheckReleaseLive(expiresAt, now); err != nil {
			return err
		}
		if err := shown(ctx, q, c.Org, k.TransactionID, r.Evidence); err != nil {
			return err
		}
		doc := domain.Release{
			Reconciliation: k.ID, Transaction: k.TransactionID, Basis: r.Basis, Evidence: r.Evidence, ExpiresAt: expiresAt,
		}
		binding, err := doc.Binding()
		if err != nil {
			return err
		}
		// The person's ceremony must have signed exactly this release: its
		// challenge is the binding of this basis, evidence and expiry.
		rec := k.ID
		cer, err := q.ReleaseCeremony(ctx, dbq.ReleaseCeremonyParams{
			OrgID: c.Org, ID: a.Ceremony, ReconciliationID: &rec, UserID: user, SessionID: session,
		})
		switch {
		case db.IsNoRows(err):
			return domain.ErrReleaseMismatch
		case err != nil:
			return err
		case !cer.Live:
			return domain.ErrReleaseExpired
		case !bytes.Equal(cer.Challenge, binding[:]):
			return domain.ErrReleaseMismatch
		}
		n, err := q.ConsumeReleaseCeremony(ctx, dbq.ConsumeReleaseCeremonyParams{
			OrgID: c.Org, ID: a.Ceremony, ReconciliationID: &rec, UserID: user, SessionID: session, Challenge: binding[:],
		})
		if err != nil {
			return err
		}
		if n != 1 {
			return domain.ErrReleaseMismatch
		}

		evidence, basis, credential := r.Evidence, r.Basis, a.Credential
		if evidence == nil {
			evidence = []ids.UUID{}
		}
		if n, err = q.ReleaseReconciliation(ctx, dbq.ReleaseReconciliationParams{
			UserID: &user, SessionID: &session, CredentialID: &credential, AuthenticatorData: a.AuthenticatorData,
			ClientDataJson: a.ClientDataJSON, Signature: a.Signature, Basis: &basis, Evidence: evidence, OrgID: c.Org, ID: k.ID,
		}); err != nil {
			return err
		}
		if n != 1 {
			return domain.ErrNotOpen // released once (HR-004)
		}
		// The held budget is released and an exact repeat is decided again
		// (HR-003, HR-007).
		if k.PermitID != nil {
			if err := pgbudgets.Settle(ctx, q, c.Org, *k.PermitID, bdomain.Release); err != nil {
				return err
			}
			if err := q.SettleDedupeClaim(ctx, claimReleased, c.Org, k.TransactionID); err != nil {
				return err
			}
		}

		actor := evdomain.Actor{Type: string(td.KindUser), ID: user.String()}
		te, err := q.TransactionEffect(ctx, c.Org, k.TransactionID)
		if err != nil {
			return err
		}
		if err := appendEffect(ctx, tx, q, app.Effect{
			Org: c.Org, Transaction: k.TransactionID, State: domain.NoneConfirmed, Basis: "person", Person: &user,
			Observations: r.Evidence, Required: defs.Level(deref(te.EffectLevelRequired, string(defs.LevelAcceptance))),
			Achieved: defs.Level(deref(te.EffectLevelAchieved, "")), Reason: "RELEASED_BY_PERSON", At: now,
		}, actor, sign); err != nil {
			return err
		}
		sum := sha256.Sum256([]byte(basis))
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: "transaction.reconciliation_released", Actor: actor, Outcome: audit.Success, ReasonCode: "NOT_OCCURRED",
			Object: &audit.Object{Type: "reconciliation", ID: k.ID.String()},
			Details: map[string]string{
				"transaction": k.TransactionID.String(), "basis_sha256": hex.EncodeToString(sum[:]),
				"binding": base64.RawURLEncoding.EncodeToString(binding[:]), "expires_at": expiresAt.UTC().Format(time.RFC3339),
				"evidence": strconv.Itoa(len(evidence)), "session": session.String(), "security_key": credential.String(),
				"ceremony": a.Ceremony.String(),
			},
		}); err != nil {
			return err
		}
		if err := pgwaitlist.CloseReconciliation(ctx, tx, c.Org, k.TransactionID, pgwaitlist.ResolvedNotOccurred, actor); err != nil {
			return err
		}
		if err := s.released(ctx, tx, q, c.Org, k); err != nil {
			return err
		}
		row, err := q.ReconciliationOf(ctx, c.Org, k.ID)
		if err != nil {
			return err
		}
		out = app.ReconciliationOf(row)
		return nil
	})
	return out, err
}

// released tells the org's admins that a person released an unknown
// outcome (G0 M7 design decision 3): ids and the operation only.
func (s *Store) released(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, k dbq.ReconciliationByIDRow) error {
	if s.Notify == nil {
		return nil
	}
	admins, err := q.OrgUsersWithRoles(ctx, org, []string{string(td.RoleOrgAdmin)})
	if err != nil {
		return err
	}
	t, err := q.TransactionSummary(ctx, org, k.TransactionID)
	if err != nil {
		return err
	}
	_, err = s.Notify.Enqueue(ctx, tx, napp.Message{
		Org: org, Type: "transaction.reconciliation_released", Personal: admins,
		Params:    map[string]string{"operation": t.Operation, "agent": k.AgentID.String(), "reconciliation": k.ID.String()},
		Subject:   &napp.Subject{Type: "reconciliation", ID: k.ID},
		DedupeKey: "reconciliation_released:" + k.ID.String(),
	})
	return err
}

// SpendRelease implements app.ReleaseStore.
func (s *Store) SpendRelease(ctx context.Context, c tenancy.Caller, reconciliation, ceremony ids.UUID) {
	_ = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rec := reconciliation
		return dbq.New(tx).SpendReleaseCeremony(ctx, dbq.SpendReleaseCeremonyParams{
			OrgID: c.Org, ID: ceremony, ReconciliationID: &rec, UserID: c.Principal.ID, SessionID: c.Session,
		})
	})
}
