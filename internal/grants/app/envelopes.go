// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"strconv"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/grants/domain"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// EnvelopeRequest replaces the guardrail at one scope.
type EnvelopeRequest struct {
	Scope domain.Scope
	// Revision is the revision the change is based on: 0 when the scope has
	// no guardrail yet.
	Revision       int
	Name           string
	Bounds         domain.Bounds
	Requirements   []domain.Requirement
	Limits         domain.Limits
	Settings       domain.Settings
	MinAttestation int
}

// PutEnvelope creates or revises the guardrail at a scope. Only a person
// holding guardrails.manage at that scope may (HR-161). The result says
// whether the change widens anything; narrowings apply to existing grants
// at once (HR-046), because the repository increments the containment
// epoch and every decision evaluates the guardrail itself.
func (s *Service) PutEnvelope(ctx context.Context, req EnvelopeRequest) (domain.Envelope, domain.Change, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return domain.Envelope{}, domain.Change{}, err
	}
	if !c.Human() {
		return domain.Envelope{}, domain.Change{}, ErrHumanOnly
	}
	path, err := s.Subjects.ScopePath(ctx, c.Org, req.Scope)
	if err != nil {
		return domain.Envelope{}, domain.Change{}, err
	}
	if err := s.Authz.Require(c, PermGuardrailsManage, path); err != nil {
		return domain.Envelope{}, domain.Change{}, err
	}
	cur := domain.Envelope{Org: c.Org, Scope: req.Scope} // no guardrail: the defaults
	found, err := s.Repo.Envelopes(ctx, c.Org, []domain.Scope{req.Scope})
	if err != nil {
		return domain.Envelope{}, domain.Change{}, err
	}
	if len(found) > 0 {
		cur = found[0]
	}
	if cur.Revision != req.Revision {
		return domain.Envelope{}, domain.Change{}, ErrRevisionChanged
	}
	next := domain.Envelope{
		ID: cur.ID, Org: c.Org, Revision: cur.Revision + 1, Scope: req.Scope, Name: req.Name,
		Bounds: req.Bounds, Requirements: req.Requirements, Limits: req.Limits, Settings: req.Settings, MinAttestation: req.MinAttestation,
	}
	if next.ID.IsZero() {
		next.ID = domain.NewEnvelopeID()
	}
	if err := next.Validate(); err != nil {
		return domain.Envelope{}, domain.Change{}, apiError(err)
	}
	lookup, err := s.lookup(ctx, c.Org, domain.Bounds{}, next.Limits)
	if err != nil {
		return domain.Envelope{}, domain.Change{}, err
	}
	if err := next.CheckDispatched(lookup); err != nil {
		return domain.Envelope{}, domain.Change{}, apiError(err)
	}
	change := domain.Compare(cur, next)
	ev := audit.Event{
		Name: "guardrails.changed", Actor: c.Actor(), Outcome: audit.Success,
		Object: &audit.Object{Type: "envelope", ID: next.ID.String()},
		Details: map[string]string{
			"scope": next.Scope.String(), "revision": strconv.Itoa(next.Revision),
			"widens": strconv.FormatBool(change.Widens), "change": change.Detail,
		},
	}
	if err := s.Repo.PutEnvelope(ctx, c.Org, next, change.Widens, ev); err != nil {
		return domain.Envelope{}, domain.Change{}, apiError(err)
	}
	next.ChangedBy, next.RevisedAt = ev.Actor.Type+":"+ev.Actor.ID, s.Clock.Now()
	return next, change, nil
}

// Envelope returns the guardrail at a scope, for holders of
// guardrails.read there.
func (s *Service) Envelope(ctx context.Context, scope domain.Scope) (domain.Envelope, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return domain.Envelope{}, err
	}
	path, err := s.Subjects.ScopePath(ctx, c.Org, scope)
	if err != nil {
		return domain.Envelope{}, err
	}
	if err := s.Authz.Require(c, PermGuardrailsRead, path); err != nil {
		return domain.Envelope{}, err
	}
	found, err := s.Repo.Envelopes(ctx, c.Org, []domain.Scope{scope})
	if err != nil {
		return domain.Envelope{}, err
	}
	if len(found) == 0 {
		return domain.Envelope{}, ErrEnvelopeNotFound
	}
	return found[0], nil
}
