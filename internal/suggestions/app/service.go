// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"
	"slices"
	"strings"

	"github.com/katocxl/pantherclaw/internal/automations/securitysteps"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	exapp "github.com/katocxl/pantherclaw/internal/exposure/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	"github.com/katocxl/pantherclaw/internal/suggestions/domain"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	tapp "github.com/katocxl/pantherclaw/internal/transactions/app"
)

// API errors of the service.
var (
	ErrEdition = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED",
		"policy suggestions need the Business edition or above")
	ErrNotFound = pcerr.New(pcerr.NotFound, "SUGGESTION_NOT_FOUND", "policy suggestion not found")
	ErrState    = pcerr.New(pcerr.FailedPrecondition, "SUGGESTION_NOT_OPEN",
		"only an open suggestion can be dismissed or drafted")
	ErrReason = pcerr.New(pcerr.InvalidArgument, "SUGGESTION_REASON_INVALID",
		"a dismissal needs a reason of 10-1000 characters")
	ErrUnwired = pcerr.New(pcerr.FailedPrecondition, "SUGGESTION_DRAFTS_UNAVAILABLE",
		"this server cannot store policy drafts")
)

// Service serves policy suggestions (D92) on editions with
// PostureRemediation. A suggestion is visible only to a caller who holds
// both posture.read and grant.read where its agent lives (HR-444); a
// suggestion the caller cannot see is not found.
type Service struct {
	Pool *db.Pool
	Ents exapp.Entitlements
	// Drafts stores a suggestion's policy draft; it has no publish path
	// (HR-442).
	Drafts securitysteps.PolicyDrafts
}

// visibleWith are the permissions a suggestion is visible under (HR-444).
var visibleWith = []td.Permission{td.PermPostureRead, td.PermGrantRead}

type session struct {
	c      tenancy.Caller
	tx     db.TenantTx
	q      *dbq.Queries
	scopes []*tapp.AgentScope
}

// sees reports whether the caller may see suggestions about agent.
func (x *session) sees(ctx context.Context, agent ids.UUID) (bool, error) {
	for _, s := range x.scopes {
		ok, err := s.Can(ctx, agent)
		if db.IsNoRows(err) {
			return false, nil
		} else if err != nil || !ok {
			return false, err
		}
	}
	return true, nil
}

func (s *Service) entitled(ctx context.Context) error {
	if s.Ents == nil {
		return ErrEdition
	}
	e, err := s.Ents.Current(ctx)
	if err != nil {
		return err
	}
	if !e.PostureRemediation() {
		return ErrEdition
	}
	return nil
}

func (s *Service) run(ctx context.Context, perm td.Permission, ro bool, fn func(context.Context, *session) error) error {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return err
	}
	for _, p := range append([]td.Permission{perm}, visibleWith...) {
		if !c.CanAnywhere(p) {
			return td.ErrPermissionDenied(p)
		}
	}
	if err := s.entitled(ctx); err != nil {
		return err
	}
	var opts []db.TxOption
	if ro {
		opts = append(opts, db.ReadOnly())
	}
	return s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		x := &session{c: c, tx: tx, q: q}
		for _, p := range visibleWith {
			x.scopes = append(x.scopes, tapp.NewAgentScope(c, q, p))
		}
		return fn(ctx, x)
	}, opts...)
}

// List lists the suggestions the caller may see, newest first, filtered
// by agent in SQL before the page is cut.
func (s *Service) List(ctx context.Context, states []domain.State, kind domain.Kind, size int32, token string,
) ([]dbq.PcPolicySuggestion, string, error) {
	p, err := page.Parse(size, token)
	if err != nil {
		return nil, "", err
	}
	var out []dbq.PcPolicySuggestion
	var next string
	err = s.run(ctx, td.PermPostureRead, true, func(ctx context.Context, x *session) error {
		all, agents, err := visible(ctx, x)
		if err != nil {
			return err
		}
		st := make([]string, 0, len(states))
		for _, v := range states {
			st = append(st, string(v))
		}
		params := dbq.ListPolicySuggestionsParams{
			OrgID: x.c.Org, States: st, AllAgents: all, AgentIds: agents, MaxRows: p.Limit(),
		}
		if kind != "" {
			k := string(kind)
			params.Kind = &k
		}
		if !p.After.IsZero() {
			params.Before = &p.After
		}
		rows, err := x.q.ListPolicySuggestions(ctx, params)
		if err != nil {
			return err
		}
		out, next = page.Finish(p, rows, func(r dbq.PcPolicySuggestion) ids.UUID { return r.ID })
		return nil
	})
	return out, next, err
}

// visible returns the agents whose suggestions the caller sees: every one
// when both permissions hold at org scope, else the intersection.
func visible(ctx context.Context, x *session) (bool, []ids.UUID, error) {
	all := true
	var agents []ids.UUID
	for _, perm := range visibleWith {
		v, err := exapp.VisibleAgents(ctx, x.c, x.q, perm)
		if err != nil {
			return false, nil, err
		}
		switch {
		case v.All:
		case all:
			all, agents = false, slices.Clone(v.IDs)
		default:
			agents = slices.DeleteFunc(agents, func(a ids.UUID) bool { return !slices.Contains(v.IDs, a) })
		}
	}
	if agents == nil {
		agents = []ids.UUID{}
	}
	return all, agents, nil
}

func (x *session) suggestion(ctx context.Context, id ids.UUID, lock bool) (dbq.PcPolicySuggestion, error) {
	get := x.q.GetPolicySuggestion
	if lock {
		get = x.q.LockPolicySuggestion
	}
	r, err := get(ctx, x.c.Org, id)
	if db.IsNoRows(err) {
		return r, ErrNotFound
	} else if err != nil {
		return r, err
	}
	// A suggestion the caller may not see is not found (never disclosed).
	if ok, err := x.sees(ctx, r.AgentID); err != nil {
		return r, err
	} else if !ok {
		return r, ErrNotFound
	}
	return r, nil
}

// Get returns a suggestion the caller may see.
func (s *Service) Get(ctx context.Context, id ids.UUID) (dbq.PcPolicySuggestion, error) {
	var out dbq.PcPolicySuggestion
	err := s.run(ctx, td.PermPostureRead, true, func(ctx context.Context, x *session) error {
		var err error
		out, err = x.suggestion(ctx, id, false)
		return err
	})
	return out, err
}

// Dismiss dismisses an open suggestion with a reason, under posture.manage
// where its agent lives.
func (s *Service) Dismiss(ctx context.Context, id ids.UUID, reason string) (dbq.PcPolicySuggestion, error) {
	reason = strings.TrimSpace(reason)
	if domain.CheckDismissReason(reason) != nil {
		return dbq.PcPolicySuggestion{}, ErrReason
	}
	var out dbq.PcPolicySuggestion
	err := s.run(ctx, td.PermPostureManage, false, func(ctx context.Context, x *session) error {
		r, err := x.suggestion(ctx, id, true)
		if err != nil {
			return err
		}
		if ok, err := tapp.NewAgentScope(x.c, x.q, td.PermPostureManage).Can(ctx, r.AgentID); err != nil {
			return err
		} else if !ok {
			return td.ErrPermissionDenied(td.PermPostureManage)
		}
		actor := x.c.Actor()
		by := actorString(actor.Type + ":" + actor.ID)
		out, err = x.q.DismissPolicySuggestion(ctx, dbq.DismissPolicySuggestionParams{
			OrgID: x.c.Org, ID: id, DismissedBy: &by, DismissReason: &reason,
		})
		if db.IsNoRows(err) {
			return ErrState
		} else if err != nil {
			return err
		}
		_, err = audit.Record(ctx, x.tx, audit.Event{
			Name: "suggestion.dismissed", Actor: actor, Outcome: audit.Success,
			Object:  &audit.Object{Type: "policy_suggestion", ID: id.String()},
			Details: map[string]string{"finding": r.PostureFindingID.String(), "reason": reason},
		})
		return err
	})
	return out, err
}

// Draft turns an open suggestion into a policy DRAFT (D92, HR-442): the
// published bundle (or a new one) with the suggestion's FORBID rule for its
// agent, keeping every operation an earlier rule of that agent already
// forbade, so a draft never forbids less than what is published. It is
// stored with the caller as its author and never published: publishing
// goes through the M11.1 gate. Needs policy.author at the org.
func (s *Service) Draft(ctx context.Context, id ids.UUID) (dbq.PcPolicySuggestion, int, error) {
	var out dbq.PcPolicySuggestion
	var version int
	err := s.run(ctx, td.PermPolicyAuthor, false, func(ctx context.Context, x *session) error {
		if !x.c.Can(td.PermPolicyAuthor, td.OrgPath(x.c.Org)) {
			return td.ErrPermissionDenied(td.PermPolicyAuthor)
		}
		if s.Drafts == nil {
			return ErrUnwired
		}
		r, err := x.suggestion(ctx, id, true)
		if err != nil {
			return err
		}
		if domain.State(r.State) != domain.Open {
			return ErrState
		}
		var proposed []pdomain.Rule
		if err := json.Unmarshal(r.Proposed, &proposed); err != nil {
			return err
		}
		base, _, err := s.Drafts.Published(ctx, x.tx.Pgx(), x.c.Org)
		if err != nil {
			return err
		}
		draft := securitysteps.RestrictionDraft(base, map[ids.UUID][]string{r.AgentID: DraftOperations(base, r.AgentID, proposed)},
			domain.WindowDays)
		v, n, err := s.Drafts.CreateDraft(ctx, x.tx.Pgx(), x.c.Org, draft, x.c.Actor())
		if err != nil {
			return err
		}
		version = n
		out, err = x.q.DraftPolicySuggestion(ctx, &v, x.c.Org, id)
		if db.IsNoRows(err) {
			return ErrState
		} else if err != nil {
			return err
		}
		_, err = audit.Record(ctx, x.tx, audit.Event{
			Name: "suggestion.drafted", Actor: x.c.Actor(), Outcome: audit.Success,
			Object: &audit.Object{Type: "policy_suggestion", ID: id.String()},
			Details: map[string]string{
				"finding": r.PostureFindingID.String(), "policy_version_id": v.String(), "state": "DRAFT",
			},
		})
		return err
	})
	return out, version, err
}

// DraftOperations are the operations a suggestion's draft forbids its
// agent: the proposed ones, plus any the published bundle's rule for that
// agent already forbids (RestrictionDraft replaces that rule).
func DraftOperations(base *pdomain.Bundle, agent ids.UUID, proposed []pdomain.Rule) []string {
	var ops []string
	for _, r := range proposed {
		ops = append(ops, r.Operations...)
	}
	if base != nil {
		want := securitysteps.RestrictionRuleID(agent)
		for _, r := range base.Rules {
			if r.ID == want && r.Kind == pdomain.Forbid {
				ops = append(ops, r.Operations...)
			}
		}
	}
	slices.Sort(ops)
	return slices.Compact(ops)
}

func actorString(s string) string {
	if len(s) > 128 {
		return s[:128]
	}
	return s
}
