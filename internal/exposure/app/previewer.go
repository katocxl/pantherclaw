// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"slices"
	"strings"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/exposure/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// Entitlements reports the current edition (billing.Service).
type Entitlements interface {
	Current(ctx context.Context) (billing.Entitlements, error)
}

// API errors.
var (
	ErrEdition = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED",
		"breach radius needs the Team edition or above")
	ErrChange = pcerr.New(pcerr.InvalidArgument, "REDUCTION_INVALID", "the reduction names no subject it can preview")
)

// Reduction kinds the previewer understands (D27, ReductionChange.Kind).
const (
	KindContain              = "contain"
	KindRevokeGrant          = "revoke_grant"
	KindNarrowGrant          = "narrow_grant"
	KindRevokeCredential     = "revoke_credential"
	KindRotateCredential     = "rotate_credential"
	KindQuarantineConnection = "quarantine_connection"
	KindSuspendAgent         = "suspend_agent"
)

// Containment controls (D21).
const (
	ControlDenyAll       = "DENY_ALL"
	ControlHoldWrites    = "HOLD_WRITES"
	ControlDenyOperation = "DENY_OPERATION"
)

// Previewer implements reflexdomain.ReachPreviewer on the org's live
// inputs (F259): it computes reach before and after the reduction in a
// read-only tenant transaction and stores nothing. The caller checks its
// own permission; the previewer checks the edition.
type Previewer struct {
	Pool *db.Pool
	Ents Entitlements
}

var _ reflexdomain.ReachPreviewer = (*Previewer)(nil)

// Entitled reports whether the edition offers breach radius; without
// entitlements wired the answer is no (fail closed).
func Entitled(ctx context.Context, e Entitlements) error {
	if e == nil {
		return ErrEdition
	}
	ent, err := e.Current(ctx)
	if err != nil {
		return err
	}
	if !ent.BreachRadius() {
		return ErrEdition
	}
	return nil
}

// PreviewReduction implements reflexdomain.ReachPreviewer.
func (p *Previewer) PreviewReduction(ctx context.Context, org ids.OrgID, c reflexdomain.ReductionChange) (reflexdomain.ReachDiff, error) {
	if err := Entitled(ctx, p.Ents); err != nil {
		return reflexdomain.ReachDiff{}, err
	}
	var out reflexdomain.ReachDiff
	err := p.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		change, notes, err := ChangeOf(ctx, dbq.New(tx), org, c)
		if err != nil {
			return err
		}
		d, err := Preview(ctx, tx, change)
		if err != nil {
			return err
		}
		out = DiffOf(d)
		out.Note = strings.Join(append(notes,
			"computed from live grants, policy, coverage and credentials; the credential view never shrinks with a control"), "; ")
		return nil
	}, db.ReadOnly())
	return out, err
}

func parse(s reflexdomain.Subject) (ids.UUID, error) {
	u, err := ids.ParseUUID(s.ID)
	if err != nil {
		return ids.UUID{}, ErrChange
	}
	return u, nil
}

// ChangeOf maps a reduction to the domain change, with notes on what the
// preview cannot model.
func ChangeOf(ctx context.Context, q *dbq.Queries, org ids.OrgID, c reflexdomain.ReductionChange) (domain.Change, []string, error) {
	var out domain.Change
	var notes []string
	if len(c.Subjects) == 0 {
		return out, nil, ErrChange
	}
	restrict := func(x domain.Restriction) {
		switch c.Control {
		case ControlHoldWrites:
			x.Hold = true
		case ControlDenyOperation:
			x.Operation = c.Operation
		}
		out.Restrictions = append(out.Restrictions, x)
	}
	for _, s := range c.Subjects {
		id, err := parse(s)
		if err != nil {
			return out, nil, err
		}
		switch {
		case c.Kind == KindRevokeGrant && s.Type == reflexdomain.SubjectGrant:
			out.RevokeGrants = append(out.RevokeGrants, id)
		case c.Kind == KindQuarantineConnection && s.Type == reflexdomain.SubjectConnection:
			out.QuarantineConnections = append(out.QuarantineConnections, id)
		case c.Kind == KindSuspendAgent && s.Type == reflexdomain.SubjectAgent:
			out.Restrictions = append(out.Restrictions, domain.Restriction{Agent: &id})
		case c.Kind == KindRevokeCredential || c.Kind == KindRotateCredential:
			conn := id
			if s.Type == reflexdomain.SubjectCredential {
				if conn, err = q.ExposureCredentialConnection(ctx, org, id); db.IsNoRows(err) {
					return out, nil, ErrChange
				} else if err != nil {
					return out, nil, err
				}
			} else if s.Type != reflexdomain.SubjectConnection {
				return out, nil, ErrChange
			}
			if c.Kind == KindRotateCredential {
				notes = append(notes, "a rotated credential keeps its scope: reach is unchanged")
				continue
			}
			out.RevokeCredentials = append(out.RevokeCredentials, conn)
		case c.Kind == KindNarrowGrant:
			notes = append(notes, "narrowing a grant is not previewed: reach is shown unchanged")
		case c.Kind == KindContain:
			switch s.Type {
			case reflexdomain.SubjectAgent:
				restrict(domain.Restriction{Agent: &id})
			case reflexdomain.SubjectGrant:
				for _, g := range append([]ids.UUID{id}, descendants(ctx, q, org, id)...) {
					restrict(domain.Restriction{Grant: &g})
				}
			case reflexdomain.SubjectConnection:
				restrict(domain.Restriction{Connection: &id})
			case reflexdomain.SubjectRun:
				r, err := q.ExposureRunGrant(ctx, org, id)
				if db.IsNoRows(err) {
					return out, nil, ErrChange
				} else if err != nil {
					return out, nil, err
				}
				if r.GrantID == nil {
					notes = append(notes, "a run without a grant of its own uses its agent's: its containment leaves the agent's reach")
					continue
				}
				restrict(domain.Restriction{Grant: r.GrantID})
			case reflexdomain.SubjectUser:
				gs, err := q.ExposurePrincipalGrants(ctx, org, &id)
				if err != nil {
					return out, nil, err
				}
				for _, g := range gs {
					restrict(domain.Restriction{Grant: &g})
				}
			case reflexdomain.SubjectResource:
				notes = append(notes, "resource containment is not previewed: reach is shown unchanged")
			default:
				return out, nil, ErrChange
			}
		default:
			return out, nil, ErrChange
		}
	}
	return out, notes, nil
}

func descendants(ctx context.Context, q *dbq.Queries, org ids.OrgID, grant ids.UUID) []ids.UUID {
	rows, err := q.ExposureGrantLineage(ctx, org)
	if err != nil {
		return nil
	}
	var out []ids.UUID
	for _, r := range rows {
		if r.AncestorID == grant {
			out = append(out, r.GrantID)
		}
	}
	return out
}

// ReachOf summarises current rights (effective and credential views).
func ReachOf(rights []domain.Right) reflexdomain.Reach {
	var r reflexdomain.Reach
	groups := map[string]bool{}
	for _, x := range rights {
		if x.View == domain.Observed || !x.Label.Current() {
			continue
		}
		groups[x.ResourceGroup] = true
		switch x.Label {
		case domain.Usable:
			r.Usable++
		case domain.Conditional:
			r.Conditional++
		default:
			r.Uncertain++
		}
	}
	r.Resources = len(groups)
	return r
}

// DiffOf maps a domain diff to the port's.
func DiffOf(d domain.Diff) reflexdomain.ReachDiff {
	out := reflexdomain.ReachDiff{Before: ReachOf(d.BeforeRights), After: ReachOf(d.AfterRights)}
	for _, r := range d.Disruption {
		if r.Agent == nil {
			continue
		}
		s := reflexdomain.Subject{Type: reflexdomain.SubjectAgent, ID: r.Agent.String()}
		if !slices.Contains(out.Disruption, s) {
			out.Disruption = append(out.Disruption, s)
		}
	}
	return out
}
