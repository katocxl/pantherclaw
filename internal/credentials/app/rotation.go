// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"strconv"
	"time"

	"github.com/katocxl/pantherclaw/internal/credentials/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/protect"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	txapp "github.com/katocxl/pantherclaw/internal/transactions/app"
	txdomain "github.com/katocxl/pantherclaw/internal/transactions/domain"
)

// Target-confirmed rotation of a GitHub App key (G0 M20 S20c, D253, D259,
// F424; HR-517..520). A person with connection.manage asks for a rotation
// after the preview of who shares the credential (HR-252); a person with
// credential.seal seals the new key as a CANDIDATE, which no gateway
// configuration serves (HR-517); the connection's gateway tests it at
// GitHub under a lease that carries it; activation goes through the
// protect surface credential.rotate with a step-up and needs a passed test
// (HR-518); a rollback is possible while the rotation is ACTIVATING, at
// most 24 hours (HR-519); and the old credential is REVOKED only when
// GitHub refuses the old key under a confirmation lease (HR-520). The
// server never opens either key (HR-060).

// Rotation errors.
var (
	ErrRotationNotFound = pcerr.New(pcerr.NotFound, "ROTATION_NOT_FOUND", "no such credential rotation")
	ErrRotationOpen     = pcerr.New(pcerr.FailedPrecondition, "ROTATION_IN_PROGRESS",
		"a credential rotation of this connection is in progress: finish or cancel it first")
	ErrRotationKind = pcerr.New(pcerr.FailedPrecondition, "ROTATION_NOT_GITHUB_APP",
		"only a connection whose active credential is a GitHub App key can be rotated")
	ErrRotationState = pcerr.New(pcerr.FailedPrecondition, "ROTATION_STATE",
		"the rotation is not in a state that allows this")
	ErrRotationUntested = pcerr.New(pcerr.FailedPrecondition, "ROTATION_UNTESTED",
		"activation needs the candidate to have passed its test at GitHub")
	ErrRotationTesting = pcerr.New(pcerr.FailedPrecondition, "ROTATION_TEST_RUNNING",
		"the rotation's test or confirmation is still running")
	ErrRollbackClosed = pcerr.New(pcerr.FailedPrecondition, "ROLLBACK_CLOSED",
		"the rollback window is closed: it ends when confirmation starts or 24 hours after activation")
	ErrRotationInstallation = pcerr.New(pcerr.InvalidArgument, "ROTATION_INSTALLATION",
		"the new key must be sealed for the same GitHub App, installation and account as the connection")
	ErrRotationPreview = pcerr.New(pcerr.FailedPrecondition, "PREVIEW_STALE",
		"a rotation first discloses every workload sharing the credential: preview it and confirm the preview's digest, which no longer matches")
	ErrRotationReason = pcerr.New(pcerr.InvalidArgument, "ROTATION_REASON", "a reason is 1 to 500 characters")
)

// Rotation operations, as the tasks name them.
const (
	opRotationTest    = "github.app.rotation_test"
	opRotationConfirm = "github.app.rotation_confirm"
	// rotationSystem revokes what a rotation's result decides.
	rotationSystem = "system:credential_rotation"
)

// Rotation is a credential rotation.
type Rotation = dbq.PcCredentialRotation

// Previewer returns the digest of the preview of who shares a credential
// version (HR-252; response/app's credential preview), in tx.
type Previewer func(ctx context.Context, tx db.TenantTx, connection ids.UUID, version int32) ([]byte, error)

// WithRotations sets the preview a rotation request confirms.
func (s *Service) WithRotations(p Previewer) *Service {
	s.preview = p
	return s
}

// OnRotationChange sets what runs in the transaction of every rotation
// change: the recompute that raises or remediates unconfirmed_rotation.
func (s *Service) OnRotationChange(f func(ctx context.Context, tx db.TenantTx) error) {
	s.changed = f
}

func rotationOf(r Rotation) domain.Rotation {
	out := domain.Rotation{State: domain.RotationState(r.State)}
	if r.TestPassedAt != nil {
		out.TestPassedAt = *r.TestPassedAt
	}
	if r.ActivatedAt != nil {
		out.ActivatedAt = *r.ActivatedAt
	}
	if r.RollbackUntil != nil {
		out.RollbackUntil = *r.RollbackUntil
	}
	return out
}

func digestText(d []byte) string { return "sha256:" + hex.EncodeToString(d) }

// lockRotation locks a rotation after closing the org's passed rollback
// windows.
func (s *Service) lockRotation(ctx context.Context, tx db.TenantTx, c tenancy.Caller, id ids.UUID) (Rotation, error) {
	if err := s.closeWindows(ctx, tx); err != nil {
		return Rotation{}, err
	}
	r, err := dbq.New(tx).LockCredentialRotation(ctx, c.Org, id)
	if db.IsNoRows(err) {
		return r, ErrRotationNotFound
	}
	return r, err
}

// closeWindows moves the org's ACTIVATING rotations whose rollback window
// passed to AWAITING_OLD_REMOVAL, audited.
func (s *Service) closeWindows(ctx context.Context, tx db.TenantTx) error {
	closed, err := dbq.New(tx).CloseRollbackWindows(ctx, tx.OrgID())
	if err != nil {
		return err
	}
	for _, r := range closed {
		if err := s.rotationAudit(ctx, tx, evdomain.Actor{Type: "system", ID: rotationSystem}, "credential.rotation_window_closed",
			r.ConnectionID, r.ID, nil); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) rotationAudit(ctx context.Context, tx db.TenantTx, actor evdomain.Actor, name string, conn, rotation ids.UUID,
	details map[string]string,
) error {
	if details == nil {
		details = map[string]string{}
	}
	details["rotation"] = rotation.String()
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: actor, Outcome: audit.Success, Object: &audit.Object{Type: "connection", ID: conn.String()}, Details: details,
	})
	if err != nil || s.changed == nil {
		return err
	}
	return s.changed(ctx, tx)
}

// RequestRotation opens a rotation of a connection's GitHub App key
// (connection.manage), after the requester saw the preview of who shares
// the active credential: digest must be that preview's (HR-252).
func (s *Service) RequestRotation(ctx context.Context, connection ids.UUID, digest []byte) (Rotation, error) {
	c, err := s.caller(ctx, td.PermConnectionManage)
	if err != nil {
		return Rotation{}, err
	}
	var out Rotation
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		conn, err := held(q.LockConnection(ctx, c.Org, connection))
		if err != nil {
			return err
		}
		active, err := q.ActiveCredential(ctx, c.Org, conn.ID)
		if db.IsNoRows(err) || (err == nil && active.Kind != domain.KindGitHubApp) {
			return ErrRotationKind
		} else if err != nil {
			return err
		}
		if _, err := q.OpenCredentialRotation(ctx, c.Org, conn.ID); err == nil {
			return ErrRotationOpen
		} else if !db.IsNoRows(err) {
			return err
		}
		if s.preview == nil {
			return ErrRotationPreview
		}
		want, err := s.preview(ctx, tx, conn.ID, active.Version)
		if err != nil {
			return err
		}
		if len(digest) == 0 || string(want) != string(digest) {
			return ErrRotationPreview
		}
		out, err = q.InsertCredentialRotation(ctx, dbq.InsertCredentialRotationParams{
			OrgID: c.Org, ID: ids.NewV7(), ConnectionID: conn.ID, OldCredentialID: active.ID, PreviewDigest: digestText(want),
			RequestedBy: c.Principal.String(),
		})
		if err != nil {
			return err
		}
		return s.rotationAudit(ctx, tx, c.Actor(), "credential.rotation_requested", conn.ID, out.ID, map[string]string{
			"old_version": strconv.Itoa(int(active.Version)), "preview_digest": out.PreviewDigest,
		})
	})
	return out, err
}

// SealCandidate stores the rotation's new key, sealed by pclaw seal to the
// gateway's broker key, as a CANDIDATE (credential.seal): the next version,
// bound like any upload, for the same App, installation and account. No
// gateway configuration carries it (HR-517).
func (s *Service) SealCandidate(ctx context.Context, rotation ids.UUID, in PutInput) (Metadata, error) {
	c, err := s.caller(ctx, td.PermCredentialSeal)
	if err != nil {
		return Metadata{}, err
	}
	if err := checkPut(&in); err != nil {
		return Metadata{}, err
	}
	if in.Kind != domain.KindGitHubApp {
		return Metadata{}, ErrRotationKind
	}
	var out Metadata
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		r, err := s.lockRotation(ctx, tx, c, rotation)
		if err != nil {
			return err
		}
		if r.ConnectionID != in.Connection {
			return ErrRotationNotFound
		}
		if r.State != string(domain.RotationRequested) {
			return ErrRotationState
		}
		conn, key, err := sealable(ctx, q, c.Org, in)
		if err != nil {
			return err
		}
		gh, err := q.ConnectionInstallation(ctx, c.Org, conn.ID)
		if db.IsNoRows(err) {
			return ErrRotationInstallation
		} else if err != nil {
			return err
		}
		if (domain.Installation{AppClientID: gh.AppClientID, ID: gh.InstallationID, Account: gh.AccountLogin}) != *in.GitHub {
			return ErrRotationInstallation
		}
		var scheme *string
		if in.Scheme != "" {
			scheme = &in.Scheme
		}
		row, err := q.InsertCandidateCredential(ctx, dbq.InsertCandidateCredentialParams{
			OrgID: c.Org, ID: ids.NewV7(), ConnectionID: conn.ID, Version: in.Version, BrokerKeyID: key.ID, Sealed: in.Sealed,
			AllowedHosts: conn.AllowedHosts, Header: in.Header, Scheme: scheme, CreatedBy: c.Principal.String(), Kind: in.Kind,
		})
		if err != nil {
			return err
		}
		if n, err := q.SealRotationCandidate(ctx, &row.ID, c.Org, r.ID); err != nil {
			return err
		} else if n != 1 {
			return ErrRotationState
		}
		sum := sha256.Sum256(in.Sealed)
		out = Metadata{
			ID: row.ID, ConnectionID: conn.ID, Version: row.Version, BrokerKeyID: key.ID, BrokerKeyFingerprint: key.Fingerprint,
			AllowedHosts: conn.AllowedHosts, Header: in.Header, Scheme: scheme, State: row.State, CreatedBy: c.Principal.String(),
			CreatedAt: row.CreatedAt, Kind: in.Kind,
		}
		return s.rotationAudit(ctx, tx, c.Actor(), "credential.rotation_candidate_sealed", conn.ID, r.ID, map[string]string{
			"version": strconv.Itoa(int(row.Version)), "broker_key_fingerprint": key.Fingerprint, "sealed_sha256": hex.EncodeToString(sum[:]),
		})
	})
	return out, err
}

// rotationTask leases a rotation's test or confirmation to the
// connection's gateway; the task holds the rotation's id only.
func rotationTask(ctx context.Context, q *dbq.Queries, org ids.OrgID, r Rotation, purpose txdomain.Purpose) (ids.UUID, error) {
	request, err := json.Marshal(map[string]string{"rotation": r.ID.String()}, json.Deterministic(true))
	if err != nil {
		return ids.UUID{}, err
	}
	op := opRotationTest
	if purpose == txdomain.PurposeRotationConfirm {
		op = opRotationConfirm
	}
	task := ids.NewV7()
	return task, q.InsertRotationTask(ctx, dbq.InsertRotationTaskParams{
		OrgID: org, ID: task, Purpose: string(purpose), ConnectionID: r.ConnectionID, Operation: op, Request: request,
	})
}

// open reports whether a rotation's task is still pending or leased.
func open(ctx context.Context, q *dbq.Queries, org ids.OrgID, task *ids.UUID) (bool, error) {
	if task == nil {
		return false, nil
	}
	return q.RotationTaskOpen(ctx, org, *task)
}

// TestRotation leases the candidate's test at GitHub to the connection's
// gateway (connection.manage): GET /app and the installation read with a
// JWT signed by the candidate; no token is minted. A test whose lease
// expired unreported may be asked for again.
func (s *Service) TestRotation(ctx context.Context, rotation ids.UUID) (Rotation, error) {
	c, err := s.caller(ctx, td.PermConnectionManage)
	if err != nil {
		return Rotation{}, err
	}
	var out Rotation
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		r, err := s.lockRotation(ctx, tx, c, rotation)
		if err != nil {
			return err
		}
		switch {
		case r.State == string(domain.RotationTesting) && r.TestPassedAt == nil:
			if running, err := open(ctx, q, c.Org, r.TestVerificationID); err != nil {
				return err
			} else if running {
				return ErrRotationTesting
			}
		case r.State != string(domain.RotationCandidateSealed):
			return ErrRotationState
		}
		task, err := rotationTask(ctx, q, c.Org, r, txdomain.PurposeRotationTest)
		if err != nil {
			return err
		}
		if n, err := q.StartRotationTest(ctx, &task, c.Org, r.ID); err != nil {
			return err
		} else if n != 1 {
			return ErrRotationState
		}
		if err := s.rotationAudit(ctx, tx, c.Actor(), "credential.rotation_test_requested", r.ConnectionID, r.ID,
			map[string]string{"task": task.String()}); err != nil {
			return err
		}
		out, err = q.GetCredentialRotation(ctx, c.Org, r.ID)
		return err
	})
	return out, err
}

// StepUp is a browser session's last step-up.
type StepUp = stepup.StepUp

// ActivateRotation activates a tested candidate (credential.rotate, CUSTODY;
// HR-518): a person with credential.seal and a fresh security-key step-up,
// after a passed target test. The candidate becomes ACTIVE and the old key
// SUPERSEDED, the gateway's configuration changes, and the rollback window
// starts. When the org protects CUSTODY it is held for a distinct
// publisher instead.
func (s *Service) ActivateRotation(ctx context.Context, rotation ids.UUID, su StepUp) (Rotation, error) {
	c, err := s.caller(ctx, protect.SurfaceCredentialRotate.Permission())
	if err != nil {
		return Rotation{}, err
	}
	var out Rotation
	var pending *protect.PendingError
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		if err := stepup.Check(ctx, tx, c, su, now); err != nil {
			return err
		}
		r, err := s.lockRotation(ctx, tx, c, rotation)
		if err != nil {
			return err
		}
		if err := activatable(r); err != nil {
			return err
		}
		conn, err := q.GetConnection(ctx, c.Org, r.ConnectionID)
		if err != nil {
			return err
		}
		pending, err = s.protect.Hold(ctx, tx, c, rotationChange(conn, r, rotationPayload{Rotation: r.ID}), func(ctx context.Context) error {
			return s.activate(ctx, tx, c, r.ID)
		})
		if err != nil {
			return err
		}
		out, err = q.GetCredentialRotation(ctx, c.Org, r.ID)
		return err
	})
	if err == nil && pending != nil {
		return Rotation{}, pending
	}
	return out, err
}

// activatable checks that a rotation may be activated (HR-518).
func activatable(r Rotation) error {
	d := rotationOf(r)
	if err := d.Activate(true, time.Now()); err != nil {
		switch err {
		case domain.ErrRotationNotSafe:
			return ErrRotationUntested
		default:
			return ErrRotationState
		}
	}
	return nil
}

// Protected rotation actions: both go through credential.rotate (D274).
const (
	actionActivate = "activate"
	actionRollback = "rollback"
)

// rotationPayload is a protected activation's or rollback's stored
// payload: ids and the person's reason only.
type rotationPayload struct {
	Rotation ids.UUID `json:"rotation"`
	// Action is actionRollback for a rollback; empty is an activation.
	Action string `json:"action,omitzero"`
	Reason string `json:"reason,omitzero"`
}

// rotationChange is an activation or a rollback as a protected change:
// metadata only.
func rotationChange(conn dbq.PcConnection, r Rotation, p rotationPayload) protect.Change {
	action := actionActivate
	if p.Action == actionRollback {
		action = actionRollback
	}
	summary := map[string]string{
		"connection": conn.ID.String(), "connection_name": conn.Name, "rotation": r.ID.String(), "action": action,
		"old_version_id": r.OldCredentialID.String(), "preview_digest": r.PreviewDigest,
	}
	if r.CandidateCredentialID != nil {
		summary["candidate_version_id"] = r.CandidateCredentialID.String()
	}
	if p.Reason != "" {
		summary["reason"] = p.Reason
	}
	return protect.Change{
		Category: protect.Custody, Surface: protect.SurfaceCredentialRotate, Subject: conn.ID.String(), SubjectID: conn.ID,
		Summary: summary, Widening: []string{"credential"}, Payload: p,
	}
}

// activate makes the candidate ACTIVE and the old key SUPERSEDED, in that
// order of the rotation first (the credential trigger allows both only
// while it is ACTIVATING), and bumps the gateway's configuration.
func (s *Service) activate(ctx context.Context, tx db.TenantTx, c tenancy.Caller, id ids.UUID) error {
	q := dbq.New(tx)
	r, err := q.LockCredentialRotation(ctx, c.Org, id)
	if err != nil {
		return err
	}
	if err := activatable(r); err != nil {
		return err
	}
	conn, err := q.LockConnection(ctx, c.Org, r.ConnectionID)
	if err != nil {
		return err
	}
	by := c.Principal.String()
	if n, err := q.ActivateCredentialRotation(ctx, &by, c.Org, r.ID); err != nil {
		return err
	} else if n != 1 {
		return ErrRotationState
	}
	if n, err := q.SupersedeCredential(ctx, c.Org, r.OldCredentialID); err != nil {
		return err
	} else if n != 1 {
		return ErrRotationState
	}
	if n, err := q.ActivateCandidateCredential(ctx, c.Org, *r.CandidateCredentialID); err != nil {
		return err
	} else if n != 1 {
		return ErrRotationState
	}
	if _, err := q.BumpGatewayConfig(ctx, c.Org, conn.GatewayID); err != nil {
		return err
	}
	if err := s.rotationAudit(ctx, tx, c.Actor(), "credential.rotation_activated", conn.ID, r.ID, map[string]string{
		"old_version_id": r.OldCredentialID.String(), "candidate_version_id": r.CandidateCredentialID.String(),
		"weakening": "sealed_replaced",
	}); err != nil {
		return err
	}
	if s.notify != nil {
		if _, err := s.notify.Enqueue(ctx, tx, napp.Message{Org: c.Org, Type: "security.connection_weakened", Params: map[string]string{
			"connection": conn.Name, "user": by, "change": "credential rotated",
		}}); err != nil {
			return err
		}
	}
	return nil
}

// ApplyProtectedRotate re-runs a confirmed protected activation or
// rollback as its author (a protect.Applier).
func (s *Service) ApplyProtectedRotate(ctx context.Context, tx db.TenantTx, author tenancy.Caller, payload []byte) error {
	var p rotationPayload
	if err := json.Unmarshal(payload, &p); err != nil || p.Rotation.IsZero() {
		return ErrRotationNotFound
	}
	c, err := s.caller(tenancy.WithCaller(ctx, author), protect.SurfaceCredentialRotate.Permission())
	if err != nil {
		return err
	}
	if p.Action == actionRollback {
		return s.rollBack(ctx, tx, c, p.Rotation, p.Reason)
	}
	return s.activate(ctx, tx, c, p.Rotation)
}

// ProtectedRotateState is the state a protected activation's re-run must
// still find (a protect.State): the rotation's state, its passed test and
// its candidate.
func (s *Service) ProtectedRotateState(ctx context.Context, tx db.TenantTx, payload []byte) ([]byte, error) {
	var p rotationPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, ErrRotationNotFound
	}
	r, err := dbq.New(tx).GetCredentialRotation(ctx, tx.OrgID(), p.Rotation)
	if db.IsNoRows(err) {
		return []byte("none"), nil
	} else if err != nil {
		return nil, err
	}
	passed, candidate := "untested", "none"
	if r.TestPassedAt != nil {
		passed = r.TestPassedAt.UTC().Format(time.RFC3339Nano)
	}
	if r.CandidateCredentialID != nil {
		candidate = r.CandidateCredentialID.String()
	}
	return fmt.Appendf(nil, "%s/%s/%s/%s", r.ID, r.State, passed, candidate), nil
}

// RollBackRotation makes the old key ACTIVE again and revokes the
// candidate (HR-519): only while the rotation is ACTIVATING, before
// confirmation starts and within 24 hours of activation. It puts a key
// the org may believe compromised back into the gateway's configuration,
// so it is gated as activation is (credential.rotate, CUSTODY; D274): a
// person with credential.seal and a fresh security-key step-up, held for a
// distinct publisher when the org protects CUSTODY.
func (s *Service) RollBackRotation(ctx context.Context, rotation ids.UUID, reason string, su StepUp) (Rotation, error) {
	c, err := s.caller(ctx, protect.SurfaceCredentialRotate.Permission())
	if err != nil {
		return Rotation{}, err
	}
	if n := len([]rune(reason)); n < 1 || n > 500 {
		return Rotation{}, ErrRotationReason
	}
	var out Rotation
	var pending *protect.PendingError
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		if err := stepup.Check(ctx, tx, c, su, now); err != nil {
			return err
		}
		r, err := s.lockRotation(ctx, tx, c, rotation)
		if err != nil {
			return err
		}
		if !rotationOf(r).CanRollBack(now) {
			return ErrRollbackClosed
		}
		conn, err := q.GetConnection(ctx, c.Org, r.ConnectionID)
		if err != nil {
			return err
		}
		p := rotationPayload{Rotation: r.ID, Action: actionRollback, Reason: reason}
		pending, err = s.protect.Hold(ctx, tx, c, rotationChange(conn, r, p), func(ctx context.Context) error {
			return s.rollBack(ctx, tx, c, r.ID, reason)
		})
		if err != nil {
			return err
		}
		out, err = q.GetCredentialRotation(ctx, c.Org, r.ID)
		return err
	})
	if err == nil && pending != nil {
		return Rotation{}, pending
	}
	return out, err
}

// rollBack revokes the candidate, makes the old key ACTIVE again and ends
// the rotation ROLLED_BACK, in that order while it is still ACTIVATING
// within its window, and bumps the gateway's configuration.
func (s *Service) rollBack(ctx context.Context, tx db.TenantTx, c tenancy.Caller, id ids.UUID, reason string) error {
	q := dbq.New(tx)
	r, err := q.LockCredentialRotation(ctx, c.Org, id)
	if err != nil {
		return err
	}
	now, err := q.DBNow(ctx)
	if err != nil {
		return err
	}
	if !rotationOf(r).CanRollBack(now) {
		return ErrRollbackClosed
	}
	conn, err := q.LockConnection(ctx, c.Org, r.ConnectionID)
	if err != nil {
		return err
	}
	by := c.Principal.String()
	// The candidate leaves ACTIVE first: one ACTIVE per connection.
	if n, err := q.RevokeCredentialByID(ctx, &by, c.Org, *r.CandidateCredentialID); err != nil {
		return err
	} else if n != 1 {
		return ErrRotationState
	}
	if n, err := q.ReactivateCredential(ctx, c.Org, r.OldCredentialID); err != nil {
		return err
	} else if n != 1 {
		return ErrRotationState
	}
	if n, err := q.RollBackCredentialRotation(ctx, &reason, c.Org, r.ID); err != nil {
		return err
	} else if n != 1 {
		return ErrRollbackClosed
	}
	if _, err := q.BumpGatewayConfig(ctx, c.Org, conn.GatewayID); err != nil {
		return err
	}
	if err := s.rotationAudit(ctx, tx, c.Actor(), "credential.rotation_rolled_back", conn.ID, r.ID, map[string]string{
		"reason": reason, "weakening": "sealed_restored",
	}); err != nil {
		return err
	}
	if s.notify != nil {
		if _, err := s.notify.Enqueue(ctx, tx, napp.Message{Org: c.Org, Type: "security.connection_weakened", Params: map[string]string{
			"connection": conn.Name, "user": by, "change": "credential rotation rolled back",
		}}); err != nil {
			return err
		}
	}
	return nil
}

// ConfirmRotation leases the confirmation that GitHub refuses the old key
// to the connection's gateway (connection.manage), once the person deleted
// it in the App's settings. From ACTIVATING it closes the rollback window
// first. A confirmation that GitHub did not refuse, or whose lease expired
// unreported, may be asked for again.
func (s *Service) ConfirmRotation(ctx context.Context, rotation ids.UUID) (Rotation, error) {
	c, err := s.caller(ctx, td.PermConnectionManage)
	if err != nil {
		return Rotation{}, err
	}
	var out Rotation
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		r, err := s.lockRotation(ctx, tx, c, rotation)
		if err != nil {
			return err
		}
		switch domain.RotationState(r.State) {
		case domain.RotationAwaitingOldRemoval:
		case domain.RotationActivating:
			if _, err := q.AwaitOldRemoval(ctx, c.Org, r.ID); err != nil {
				return err
			}
		case domain.RotationConfirming:
			if running, err := open(ctx, q, c.Org, r.ConfirmVerificationID); err != nil {
				return err
			} else if running {
				return ErrRotationTesting
			}
			if _, err := q.AwaitOldRemoval(ctx, c.Org, r.ID); err != nil {
				return err
			}
		default:
			return ErrRotationState
		}
		task, err := rotationTask(ctx, q, c.Org, r, txdomain.PurposeRotationConfirm)
		if err != nil {
			return err
		}
		if n, err := q.StartRotationConfirm(ctx, &task, c.Org, r.ID); err != nil {
			return err
		} else if n != 1 {
			return ErrRotationState
		}
		if err := s.rotationAudit(ctx, tx, c.Actor(), "credential.rotation_confirm_requested", r.ConnectionID, r.ID,
			map[string]string{"task": task.String()}); err != nil {
			return err
		}
		out, err = q.GetCredentialRotation(ctx, c.Org, r.ID)
		return err
	})
	return out, err
}

// CancelRotation ends a rotation before activation (connection.manage):
// the candidate, if sealed, is REVOKED; the old key is untouched.
func (s *Service) CancelRotation(ctx context.Context, rotation ids.UUID, reason string) (Rotation, error) {
	c, err := s.caller(ctx, td.PermConnectionManage)
	if err != nil {
		return Rotation{}, err
	}
	if n := len([]rune(reason)); n < 1 || n > 500 {
		return Rotation{}, ErrRotationReason
	}
	var out Rotation
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		r, err := s.lockRotation(ctx, tx, c, rotation)
		if err != nil {
			return err
		}
		if err := s.fail(ctx, tx, c.Actor(), r, reason); err != nil {
			return err
		}
		out, err = q.GetCredentialRotation(ctx, c.Org, r.ID)
		return err
	})
	return out, err
}

// fail ends a rotation before activation and revokes its candidate.
func (s *Service) fail(ctx context.Context, tx db.TenantTx, actor evdomain.Actor, r Rotation, reason string) error {
	q, org := dbq.New(tx), tx.OrgID()
	if n, err := q.FailCredentialRotation(ctx, &reason, org, r.ID); err != nil {
		return err
	} else if n != 1 {
		return ErrRotationState
	}
	if r.CandidateCredentialID != nil {
		by := rotationSystem
		if _, err := q.RevokeCredentialByID(ctx, &by, org, *r.CandidateCredentialID); err != nil {
			return err
		}
	}
	return s.rotationAudit(ctx, tx, actor, "credential.rotation_failed", r.ConnectionID, r.ID, map[string]string{"reason": reason})
}

// GetRotation returns a rotation (connection.read).
func (s *Service) GetRotation(ctx context.Context, rotation ids.UUID) (Rotation, error) {
	c, err := s.caller(ctx, td.PermConnectionRead)
	if err != nil {
		return Rotation{}, err
	}
	var out Rotation
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		if err := s.closeWindows(ctx, tx); err != nil {
			return err
		}
		var err error
		out, err = dbq.New(tx).GetCredentialRotation(ctx, c.Org, rotation)
		if db.IsNoRows(err) {
			return ErrRotationNotFound
		}
		return err
	})
	return out, err
}

// ListRotations lists a connection's rotations, newest first
// (connection.read).
func (s *Service) ListRotations(ctx context.Context, connection ids.UUID) ([]Rotation, error) {
	c, err := s.caller(ctx, td.PermConnectionRead)
	if err != nil {
		return nil, err
	}
	var out []Rotation
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		if err := s.closeWindows(ctx, tx); err != nil {
			return err
		}
		var err error
		out, err = dbq.New(tx).ListCredentialRotations(ctx, c.Org, connection)
		return err
	})
	return out, err
}

// LeaseRequest builds a rotation lease's request for the claiming gateway
// (pgtransactions.RotationLeases, D259): the candidate for a test while the
// rotation is TESTING, the old key for a confirmation while it is
// CONFIRMING, in the sealed form of the gateway's configuration and only
// when sealed to this gateway's broker key for a connection it serves. nil
// cancels a task whose rotation moved on or whose credential this gateway
// may not have.
func (s *Service) LeaseRequest(ctx context.Context, tx db.TenantTx, gateway, task ids.UUID, purpose txdomain.Purpose) ([]byte, error) {
	q, org := dbq.New(tx), tx.OrgID()
	r, err := q.RotationOfTask(ctx, &task, org)
	if db.IsNoRows(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	state := "SUPERSEDED"
	switch {
	case purpose == txdomain.PurposeRotationTest && r.State == string(domain.RotationTesting) && r.TestPassedAt == nil:
		state = "CANDIDATE"
	case purpose == txdomain.PurposeRotationConfirm && r.State == string(domain.RotationConfirming):
	default:
		return nil, nil
	}
	cred, err := q.GatewayRotationCredential(ctx, dbq.GatewayRotationCredentialParams{OrgID: org, ID: r.CredentialID, GatewayID: gateway, State: state})
	if db.IsNoRows(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	lease := domain.RotationLease{Rotation: r.ID.String(), Credential: domain.RotationCredential{
		ID: cred.ID.String(), Version: cred.Version, BrokerKey: cred.BrokerKeyID.String(), Sealed: cred.Sealed, AllowedHosts: cred.AllowedHosts,
		Header: cred.Header, Scheme: deref(cred.Scheme), Kind: cred.Kind,
	}}
	if purpose == txdomain.PurposeRotationConfirm && r.CandidateCredentialID != nil {
		// The control: GET /app is asked with the active (new) key too (D274).
		lease.Active = r.CandidateCredentialID.String()
	}
	return json.Marshal(lease, json.Deterministic(true))
}

// ReportRotation applies a rotation lease's report
// (pgtransactions.RotationLeases). A test passes only when GitHub accepted
// the candidate as the App and for the installation; only a definite
// refusal (401, 403, 404, or another App) fails the rotation and revokes
// the candidate, and anything else leaves it TESTING (D274). A confirmation
// confirms only when GitHub refused the old key with 401 while accepting
// the active key for the App at the same moment, and the old key then is
// REVOKED (HR-520, D274); any other answer returns the rotation to
// AWAITING_OLD_REMOVAL.
func (s *Service) ReportRotation(ctx context.Context, tx db.TenantTx, gateway ids.UUID, task dbq.LeasedRotationTaskRow, rep txapp.Report,
) (txapp.Applied, error) {
	q, org := dbq.New(tx), tx.OrgID()
	if err := q.FinishVerification(ctx, "DONE", org, task.ID); err != nil {
		return txapp.Applied{}, err
	}
	done := txapp.Applied{Done: true}
	p := domain.ProbeOf(rep.Fields)
	actor := evdomain.Actor{Type: "gateway", ID: gateway.String()}
	details := map[string]string{
		"task": task.ID.String(), "app_status": strconv.Itoa(p.AppStatus), "app_matches": strconv.FormatBool(p.AppMatches),
		"installation_status": strconv.Itoa(p.InstallationStatus), "active_app_status": strconv.Itoa(p.ActiveStatus),
	}
	r, err := q.LockCredentialRotation(ctx, org, task.RotationID)
	if err != nil {
		return done, err
	}
	switch txdomain.Purpose(task.Purpose) {
	case txdomain.PurposeRotationTest:
		if r.State != string(domain.RotationTesting) || r.TestPassedAt != nil || r.TestVerificationID == nil || *r.TestVerificationID != task.ID {
			return done, nil
		}
		if !p.TestPassed() && !p.TestRefused() {
			// No answer, a rate limit or a server error proves nothing: the
			// rotation stays TESTING for another test (D274).
			details["result"] = "inconclusive"
			return done, s.rotationAudit(ctx, tx, actor, "credential.rotation_tested", r.ConnectionID, r.ID, details)
		}
		if !p.TestPassed() {
			details["result"] = "failed"
			reason := fmt.Sprintf("the candidate failed its test at GitHub (GET /app %d, installation %d)", p.AppStatus, p.InstallationStatus)
			if err := s.fail(ctx, tx, actor, r, reason); err != nil {
				return done, err
			}
			return done, s.rotationAudit(ctx, tx, actor, "credential.rotation_tested", r.ConnectionID, r.ID, details)
		}
		if _, err := q.PassRotationTest(ctx, org, r.ID); err != nil {
			return done, err
		}
		details["result"] = "passed"
		return done, s.rotationAudit(ctx, tx, actor, "credential.rotation_tested", r.ConnectionID, r.ID, details)
	case txdomain.PurposeRotationConfirm:
		if r.State != string(domain.RotationConfirming) || r.ConfirmVerificationID == nil || *r.ConfirmVerificationID != task.ID {
			return done, nil
		}
		if !p.OldKeyRefused() {
			if _, err := q.AwaitOldRemoval(ctx, org, r.ID); err != nil {
				return done, err
			}
			return done, s.rotationAudit(ctx, tx, actor, "credential.rotation_not_confirmed", r.ConnectionID, r.ID, details)
		}
		by := rotationSystem
		if n, err := q.RevokeCredentialByID(ctx, &by, org, r.OldCredentialID); err != nil {
			return done, err
		} else if n != 1 {
			return done, ErrRotationState
		}
		if n, err := q.ConfirmCredentialRotation(ctx, org, r.ID); err != nil {
			return done, err
		} else if n != 1 {
			return done, ErrRotationState
		}
		details["old_version_id"] = r.OldCredentialID.String()
		return done, s.rotationAudit(ctx, tx, actor, "credential.rotation_confirmed", r.ConnectionID, r.ID, details)
	}
	return done, txapp.ErrLease
}
