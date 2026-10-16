// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect/v2"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	covapp "github.com/katocxl/pantherclaw/internal/coverage/app"
	defsapp "github.com/katocxl/pantherclaw/internal/definitions/app"
	defsdomain "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
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

// newM11Protect builds the Gate and the publishers. registerM11Protect
// connects them to the core's change ceremony (the Gate's Requests); without
// it a category cannot be turned on (PROTECTED_CHANGES_UNAVAILABLE).
func newM11Protect(d apiDeps) m11Protect {
	gate := &protect.Gate{}
	pub := &protect.Publishers{Pool: d.pool, Gate: gate, Undo: map[string]protect.Rollback{
		// Automations pause through core-B's Pauser and promotions revoke through
		// govern; until those are merged their ROLLBACK is refused (D72 P1).
		protect.ItemAutomationVersion: notYet, protect.ItemPromotion: notYet,
		protect.ItemPolicyChange: keepOnly, protect.ItemProtectedChange: keepOnly,
	}}
	pub.On = append(pub.On, policyOnCompromise)
	if d.billing != nil {
		pub.Editions = d.billing
	}
	gate.Compromise = pub
	probeM11("protect.gate", gate)
	probeM11("protect.publishers", pub)
	return m11Protect{gate: gate, publishers: pub}
}

// registerM11Protect serves ProtectedChangeService and PublisherService,
// holds the M6 surfaces' custody changes (connection settings, route
// modes, sealed credentials) behind the Gate and connects protect to the
// core's change ceremony and automations. The procedure permissions are
// in procedures_m11_protect.go.
func registerM11Protect(rs *connect.Server, d apiDeps, core *automationsCore) {
	p := d.m11protect
	if d.m6 != nil {
		d.m6.connections.WithProtect(p.gate)
		d.m6.credentials.WithProtect(p.gate)
	}
	if core != nil {
		protectCore(p, core)
	}
	svc := &protect.Service{Pool: d.pool, Gate: p.gate, Failures: &failures.Sink{}}
	pantherclawv1connect.RegisterProtectedChangeServiceHandler(rs, protectrpc.NewChanges(svc))
	pantherclawv1connect.RegisterPublisherServiceHandler(rs, protectrpc.NewPublishers(p.publishers))
	if d.web != nil {
		d.web.WithProtect(protectPages{Service: svc, Publishers: p.publishers})
	}
}

// protectCore makes the core's change ceremony carry protected changes and
// clearings (D6, D42, D43), blocks compromised people from confirming any
// change request and from counting toward a ceiling (D11's
// CompromiseChecker), and on marking voids their change requests, pauses
// the automations whose ceiling they approved (D54) and exposes the
// automations they confirmed.
func protectCore(p m11Protect, core *automationsCore) {
	core.changes.Compromise = p.publishers
	core.svc.Compromise = p.publishers
	if core.grants != nil {
		p.publishers.Undo[protect.ItemGrant] = grantUndo(core.grants)
	}
	p.gate.Requests = protect.Ceremony{Changes: core.changes}
	protect.Register(core.changes, p.gate, p.publishers)
	pub := p.publishers
	pub.On = append(pub.On,
		func(ctx context.Context, tx db.TenantTx, user ids.UUID, _ time.Time, by tapp.Caller) (map[string]string, error) {
			voided, err := core.changes.VoidByPerson(ctx, tx, by, user, rollout.VoidCompromised)
			return map[string]string{"change_requests_voided": strconv.Itoa(len(voided))}, err
		},
		func(ctx context.Context, tx db.TenantTx, user ids.UUID, _ time.Time, _ tapp.Caller) (map[string]string, error) {
			ceilings, err := dbq.New(tx).CeilingsApprovedBy(ctx, tx.OrgID(), user)
			if err != nil {
				return nil, err
			}
			autos := make([]ids.UUID, 0, len(ceilings))
			for _, c := range ceilings {
				autos = append(autos, c.AutomationID)
			}
			var paused []ids.UUID
			if len(autos) > 0 {
				if paused, err = core.svc.Pause(ctx, tx.Pgx(), tx.OrgID(), autodomain.PauseSelector{Automations: autos},
					autodomain.PauseCompromisedPublisher); err != nil {
					return nil, err
				}
			}
			return map[string]string{"automations_paused": strconv.Itoa(len(paused))}, nil
		})
	if pub.Sources == nil {
		pub.Sources = map[string]protect.ExposureSource{}
	}
	pub.Sources[protect.ItemAutomationVersion] = func(ctx context.Context, tx db.TenantTx, user ids.UUID, since time.Time) ([]protect.Item, error) {
		rows, err := dbq.New(tx).ExposedAutomationConfirmations(ctx, tx.OrgID(), user, since)
		if err != nil {
			return nil, err
		}
		out := make([]protect.Item, 0, len(rows))
		for _, r := range rows {
			out = append(out, protect.Item{Kind: protect.ItemAutomationVersion, ID: r.ItemID, Label: r.Label, At: r.At})
		}
		return out, nil
	}
	// ROLLBACK of an automation a compromised person confirmed pauses it.
	pub.Undo[protect.ItemAutomationVersion] = func(ctx context.Context, item string) error {
		id, err := ids.ParseUUID(item)
		if err != nil {
			return protect.ErrNotExposed
		}
		c, err := tapp.CallerFrom(ctx)
		if err != nil {
			return err
		}
		return core.svc.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := core.svc.Pause(ctx, tx.Pgx(), c.Org, autodomain.PauseSelector{Automations: []ids.UUID{id}},
				autodomain.PauseCompromisedPublisher)
			return err
		})
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
	pending, err := q.PendingPolicyChangeRequestsBy(ctx, org, principal, user)
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
// before it, as the reviewer (D90 Q1, L3). A version no longer published
// has nothing left to roll back (already rolled back counts as done). A
// loosening rollback that only opened a change request is not done yet:
// it returns ROLLBACK_PENDING_CONFIRMATION and nothing is recorded.
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
			return nil
		}
		out, err := v.Rollback(ctx, before.BeforeID, &id)
		if err != nil {
			return err
		}
		if out.Version.State != policyapp.StatePublished {
			if out.ChangeRequest != nil {
				return protect.RollbackPending(out.ChangeRequest.ID)
			}
			return protect.RollbackPending(ids.UUID{})
		}
		return nil
	}
}

// packageUndo quarantines an exposed package version and revokes an
// exposed org package key as COMPROMISED (F596), as the reviewer. A
// version already quarantined or retired, or a key already revoked,
// counts as done (D90 L3).
func packageUndo(a *defsapp.Admin, p *protect.Publishers) {
	p.Undo[protect.ItemPackageVersion] = func(ctx context.Context, item string) error {
		i := strings.LastIndex(item, "@")
		if i <= 0 || i == len(item)-1 {
			return protect.ErrNotExposed
		}
		name, version := item[:i], item[i+1:]
		vs, err := a.List(ctx, name)
		if err != nil {
			return err
		}
		for _, v := range vs {
			if v.Version == version && (v.State == defsdomain.StateQuarantined || v.State == defsdomain.StateRetired) {
				return nil
			}
		}
		_, err = a.Transition(ctx, name, version, defsdomain.StateQuarantined)
		return err
	}
	p.Undo[protect.ItemPackageKey] = func(ctx context.Context, kid string) error {
		keys, err := a.ListKeys(ctx)
		if err != nil {
			return err
		}
		for _, k := range keys {
			if k.KID == kid && k.State != defsapp.KeyActive {
				return nil
			}
		}
		_, _, err = a.RevokeKey(ctx, kid, defsapp.RevokeCompromised)
		return err
	}
}

// grantUndo revokes an exposed grant (and its children) as the reviewer
// (D90 Q2); a grant already revoked counts as done.
func grantUndo(grants *grantsapp.Service) protect.Rollback {
	return func(ctx context.Context, item string) error {
		id, err := gdomain.ParseGrantID(item)
		if err != nil {
			return protect.ErrNotExposed
		}
		v, err := grants.Get(ctx, id)
		if err != nil {
			return err
		}
		if v.Grant.State != gdomain.StateActive {
			return nil
		}
		_, err = grants.Revoke(ctx, id, protect.ReasonCompromisedPublisher)
		return err
	}
}

func keepOnly(context.Context, string) error { return protect.ErrKeepOnly }
