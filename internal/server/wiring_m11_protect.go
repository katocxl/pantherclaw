// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect/v2"

	covapp "github.com/katocxl/pantherclaw/internal/coverage/app"
	defsapp "github.com/katocxl/pantherclaw/internal/definitions/app"
	defsdomain "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	policyapp "github.com/katocxl/pantherclaw/internal/policy/app"
	"github.com/katocxl/pantherclaw/internal/policy/rollout"
	"github.com/katocxl/pantherclaw/internal/protect"
	"github.com/katocxl/pantherclaw/internal/protect/adapters/protectrpc"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m11Protect is the protected-change Gate every hooked surface shares and
// the compromised-publisher use cases (G0 M11 part 2 D42, D43).
type m11Protect struct {
	gate       *protect.Gate
	publishers *protect.Publishers
}

// newM11Protect builds the Gate and the publishers. The change ceremony
// (internal/changes) is wired as the Gate's Requests in phase 2; until
// then a category that is turned on refuses its changes
// (PROTECTED_CHANGES_UNAVAILABLE) and nothing protected applies.
func newM11Protect(d apiDeps) m11Protect {
	gate := &protect.Gate{}
	pub := &protect.Publishers{Pool: d.pool, Gate: gate, Undo: map[string]protect.Rollback{
		// Automations pause through core-B's Pauser and promotions revoke through
		// govern; until those are merged their ROLLBACK is refused (D72 P1).
		protect.ItemAutomationVersion: notYet, protect.ItemPromotion: notYet,
	}}
	pub.On = append(pub.On, policyOnCompromise)
	if d.billing != nil {
		pub.Editions = d.billing
	}
	gate.Compromise = pub
	return m11Protect{gate: gate, publishers: pub}
}

// registerM11Protect serves ProtectedChangeService and PublisherService and
// holds the M6 surfaces' custody changes (connection settings, route
// modes, sealed credentials) behind the Gate. The procedure permissions
// are in procedures_m11_protect.go.
func registerM11Protect(rs *connect.Server, d apiDeps) {
	p := d.m11protect
	if d.m6 != nil {
		d.m6.connections.WithProtect(p.gate)
		d.m6.credentials.WithProtect(p.gate)
	}
	svc := &protect.Service{Pool: d.pool, Gate: p.gate, Failures: &failures.Sink{}}
	pantherclawv1connect.RegisterProtectedChangeServiceHandler(rs, protectrpc.NewChanges(svc))
	pantherclawv1connect.RegisterPublisherServiceHandler(rs, protectrpc.NewPublishers(p.publishers))
	if d.web != nil {
		d.web.WithProtect(protectPages{Service: svc, Publishers: p.publishers})
	}
}

// protectPages is the step-up use cases of the protected-change pages
// (D53).
type protectPages struct {
	*protect.Service
	*protect.Publishers
}

func (p protectPages) ProtectedChange(ctx context.Context, request ids.UUID) (dbq.PcProtectedChange, error) {
	return p.ByRequest(ctx, request)
}

// protectCoverage holds coverage exclusions behind the Gate.
func protectCoverage(svc *covapp.Service, p m11Protect) {
	if p.gate == nil {
		return
	}
	svc.Protect = p.gate
	p.gate.Register(protect.SurfaceExclusionCreate, svc.ApplyProtectedExclusion, svc.ProtectedExclusionState)
}

// protectPackages holds package activations behind the Gate.
func protectPackages(a *defsapp.Admin, d apiDeps) *defsapp.Admin {
	if p := d.m11protect; p.gate != nil {
		a.Protect = protect.PackageGate{Pool: d.pool, Gate: p.gate}
		p.gate.Register(protect.SurfacePackageActivate, a.ApplyProtectedActivation, a.ProtectedActivationState)
		if p.publishers != nil {
			packageUndo(a, p.publishers)
		}
	}
	return a
}

func notYet(context.Context, string) error { return protect.ErrRollbackNotYet }

// policyOnCompromise voids the person's pending M11.1 policy change
// requests and halts the open policy rollouts they created or confirmed,
// in the marking transaction (G0 M11 D43, D72 P1).
func policyOnCompromise(ctx context.Context, tx db.TenantTx, user ids.UUID, _ time.Time, by tapp.Caller) (map[string]string, error) {
	q := dbq.New(tx)
	org := tx.OrgID()
	principal := td.PrincipalRef{Kind: td.KindUser, ID: user}.String()
	pending, err := q.PendingPolicyChangeRequestsBy(ctx, org, principal)
	if err != nil {
		return nil, err
	}
	reason := rollout.VoidCompromised
	for _, id := range pending {
		if _, err := q.DecidePolicyChangeRequest(ctx, dbq.DecidePolicyChangeRequestParams{
			State: policyapp.ChangeVoided, Reason: &reason, OrgID: org, ID: id,
		}); err != nil {
			return nil, err
		}
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: "policy.change_voided", Actor: by.Actor(), Outcome: audit.Success,
			Object: &audit.Object{Type: "policy_change_request", ID: id.String()}, Details: map[string]string{"reason": reason},
		}); err != nil {
			return nil, err
		}
	}
	open, err := q.LockOpenPolicyRollouts(ctx, org)
	if err != nil {
		return nil, err
	}
	halted := 0
	for _, r := range open {
		theirs, err := q.PolicyRolloutConfirmedBy(ctx, dbq.PolicyRolloutConfirmedByParams{
			OrgID: org, RolloutID: r.ID, Principal: principal, UserID: user, VersionID: r.VersionID,
		})
		if err != nil {
			return nil, err
		}
		if !theirs {
			continue
		}
		if err := rollout.Halt(ctx, tx, by.Actor(), r, reason); err != nil {
			return nil, err
		}
		halted++
	}
	return map[string]string{
		"policy_requests_voided": strconv.Itoa(len(pending)), "policy_rollouts_halted": strconv.Itoa(halted),
	}, nil
}

func init() {
	// The policy versions exist only once the gate is registered: their
	// ROLLBACK review rolls back to the version published before (D72 P1).
	policyGateExtensions = append(policyGateExtensions, func(d apiDeps, v *policyapp.Versions) {
		if d.m11protect.publishers != nil {
			d.m11protect.publishers.Undo[protect.ItemPolicyVersion] = policyRollback(d.pool, v)
		}
		if v.Changes != nil && d.m11protect.publishers != nil {
			v.Changes.WithCompromise(d.m11protect.publishers)
		}
	})
}

// policyRollback rolls a published version back to the one published
// before it, as the reviewer; a version no longer published has nothing to
// roll back.
func policyRollback(pool *db.Pool, v *policyapp.Versions) protect.Rollback {
	return func(ctx context.Context, item string) error {
		id, err := ids.ParseUUID(item)
		if err != nil {
			return protect.ErrNotExposed
		}
		c, err := tapp.CallerFrom(ctx)
		if err != nil {
			return err
		}
		var before dbq.PolicyVersionBeforeRow
		err = pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
			var err error
			before, err = dbq.New(tx).PolicyVersionBefore(ctx, c.Org, id)
			return err
		}, db.ReadOnly())
		switch {
		case db.IsNoRows(err):
			return protect.ErrRollbackNoEarlier
		case err != nil:
			return err
		case !before.Current:
			return protect.ErrRollbackNotCurrent
		}
		_, err = v.Rollback(ctx, before.BeforeID, &id)
		return err
	}
}

// packageUndo quarantines an exposed package version and revokes an
// exposed org package key as COMPROMISED (F596), as the reviewer.
func packageUndo(a *defsapp.Admin, p *protect.Publishers) {
	p.Undo[protect.ItemPackageVersion] = func(ctx context.Context, item string) error {
		i := strings.LastIndex(item, "@")
		if i <= 0 || i == len(item)-1 {
			return protect.ErrNotExposed
		}
		_, err := a.Transition(ctx, item[:i], item[i+1:], defsdomain.StateQuarantined)
		return err
	}
	p.Undo[protect.ItemPackageKey] = func(ctx context.Context, kid string) error {
		_, _, err := a.RevokeKey(ctx, kid, defsapp.RevokeCompromised)
		return err
	}
}
