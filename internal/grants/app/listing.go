// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"strconv"
	"time"

	"github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	tdomain "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// PermBudgetRead lets a caller see a grant's budget accounts.
const PermBudgetRead = tdomain.PermBudgetRead

// GrantFilter narrows ListGrants; zero fields do not filter.
type GrantFilter struct {
	AgentID *ids.UUID
	Parent  domain.GrantID
	State   domain.State
}

// BudgetAccount is the stored state of one budget account (one rule,
// grouping key and period of a grant or guardrail).
type BudgetAccount struct {
	ID            ids.UUID
	OwnerKind     string // "grant" or "envelope"
	OwnerID       ids.UUID
	Rule          string
	PeriodStart   time.Time
	Rank          int
	Currency      string
	Reserved      money.Decimal
	Spent         money.Decimal
	ReservedCount int64
	SpentCount    int64
}

// Listing reads grants, guardrails and budget accounts for the API. It is
// separate from Repository because the decision pipeline never lists.
type Listing interface {
	// ListGrants returns up to limit grants older than before (zero: from
	// the newest), newest first.
	ListGrants(ctx context.Context, org ids.OrgID, f GrantFilter, before ids.UUID, limit int32) ([]domain.Grant, error)
	// EnvelopeByID returns one revision of a guardrail; revision 0 is the
	// current one.
	EnvelopeByID(ctx context.Context, org ids.OrgID, id domain.EnvelopeID, revision int) (domain.Envelope, error)
	// ListEnvelopes returns up to limit guardrails after the given id,
	// oldest first; an empty kind lists every scope kind.
	ListEnvelopes(ctx context.Context, org ids.OrgID, after ids.UUID, limit int32, kind domain.ScopeKind) ([]domain.Envelope, error)
	// BudgetAccounts returns the latest period of every budget account
	// the owners (grants and guardrails) hold.
	BudgetAccounts(ctx context.Context, org ids.OrgID, owners []ids.UUID) ([]BudgetAccount, error)
}

// GrantPage is one page of grants.
type GrantPage struct {
	Items []domain.Grant
	Next  string
}

// List lists the grants the caller may read (grant.read where each
// grant's agent lives), newest first. Grants the caller may not read are
// left out of the page, never reported.
func (s *Service) List(ctx context.Context, pr page.Request, f GrantFilter) (GrantPage, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return GrantPage{}, err
	}
	rows, err := s.Listing.ListGrants(ctx, c.Org, f, pr.After, pr.Limit())
	if err != nil {
		return GrantPage{}, err
	}
	var out GrantPage
	rows, out.Next = page.Finish(pr, rows, func(g domain.Grant) ids.UUID { return g.ID.UUID() })
	readable := map[ids.UUID]bool{}
	for _, g := range rows {
		ok, seen := readable[g.AgentID]
		if !seen {
			a, err := s.agent(ctx, c.Org, g.AgentID)
			if err != nil {
				return GrantPage{}, err
			}
			ok = c.Can(PermGrantRead, a.Path)
			readable[g.AgentID] = ok
		}
		if ok {
			out.Items = append(out.Items, g)
		}
	}
	return out, nil
}

// EnvelopeByID returns one revision of a guardrail (guardrails.read where
// its scope is managed); revision 0 is the current one.
func (s *Service) EnvelopeByID(ctx context.Context, id domain.EnvelopeID, revision int) (domain.Envelope, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return domain.Envelope{}, err
	}
	e, err := s.Listing.EnvelopeByID(ctx, c.Org, id, revision)
	if errors.Is(err, ErrNotFound) {
		return domain.Envelope{}, ErrEnvelopeNotFound
	}
	if err != nil {
		return domain.Envelope{}, err
	}
	path, err := s.scopePath(ctx, c.Org, e.Scope)
	if err != nil {
		return domain.Envelope{}, err
	}
	if !c.Can(PermGuardrailsRead, path) {
		// Not readable here: indistinguishable from absent.
		return domain.Envelope{}, ErrEnvelopeNotFound
	}
	return e, nil
}

// EnvelopePage is one page of guardrails.
type EnvelopePage struct {
	Items []domain.Envelope
	Next  string
}

// Envelopes lists the guardrails the caller may read, oldest first.
func (s *Service) Envelopes(ctx context.Context, pr page.Request, kind domain.ScopeKind) (EnvelopePage, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return EnvelopePage{}, err
	}
	rows, err := s.Listing.ListEnvelopes(ctx, c.Org, pr.After, pr.Limit(), kind)
	if err != nil {
		return EnvelopePage{}, err
	}
	var out EnvelopePage
	rows, out.Next = page.Finish(pr, rows, func(e domain.Envelope) ids.UUID { return e.ID.UUID() })
	for _, e := range rows {
		path, err := s.scopePath(ctx, c.Org, e.Scope)
		if err != nil {
			return EnvelopePage{}, err
		}
		if c.Can(PermGuardrailsRead, path) {
			out.Items = append(out.Items, e)
		}
	}
	return out, nil
}

// AccountState is a budget account with the rule that defines it.
type AccountState struct {
	BudgetAccount
	Grouping string
	Period   string
	Limit    *money.Decimal // nil: the rule only counts
	MaxCount *int64         // nil: the rule has no count limit
}

// Available is what is left of the amount limit, or nil without one.
func (a AccountState) Available() *money.Decimal {
	if a.Limit == nil {
		return nil
	}
	used, err := a.Spent.Add(a.Reserved)
	if err != nil {
		return nil
	}
	left, err := a.Limit.Sub(used)
	if err != nil {
		return nil
	}
	return &left
}

// BudgetState returns the budget accounts a grant's actions debit: its
// guardrails' first, then its chain's from the root down (F113, F119).
// Accounts appear once an action has debited them.
func (s *Service) BudgetState(ctx context.Context, id domain.GrantID) ([]AccountState, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return nil, err
	}
	chain, err := s.Repo.Chain(ctx, c.Org, id)
	if errors.Is(err, ErrNotFound) || (err == nil && len(chain) == 0) {
		return nil, ErrGrantNotFound
	}
	if err != nil {
		return nil, err
	}
	leaf := chain[len(chain)-1]
	agent, err := s.agent(ctx, c.Org, leaf.AgentID)
	if err != nil {
		return nil, err
	}
	if err := s.Authz.Require(c, PermBudgetRead, agent.Path); err != nil {
		return nil, err
	}
	envs, err := s.Repo.Envelopes(ctx, c.Org, scopesFor(agent, leaf.EnvironmentID, leaf.Principal))
	if err != nil {
		return nil, err
	}
	rules := map[ids.UUID]domain.Limits{}
	owners := make([]ids.UUID, 0, len(envs)+len(chain))
	for _, e := range envs {
		rules[e.ID.UUID()] = e.Limits
		owners = append(owners, e.ID.UUID())
	}
	for _, g := range chain {
		rules[g.ID.UUID()] = g.Limits
		owners = append(owners, g.ID.UUID())
	}
	accounts, err := s.Listing.BudgetAccounts(ctx, c.Org, owners)
	if err != nil {
		return nil, err
	}
	out := make([]AccountState, 0, len(accounts))
	for _, a := range accounts {
		st := AccountState{BudgetAccount: a}
		for _, r := range rules[a.OwnerID].Budgets {
			if r.ID != a.Rule {
				continue
			}
			st.Grouping, st.Period = string(r.Grouping), string(r.Period)
			if r.Limit != "" {
				if l, err := money.Parse(r.Limit); err == nil {
					st.Limit = &l
				}
			}
			if r.MaxCount != "" {
				if n, err := strconv.ParseInt(r.MaxCount, 10, 64); err == nil {
					st.MaxCount = &n
				}
			}
		}
		out = append(out, st)
	}
	order := map[ids.UUID]int{}
	for i, o := range owners {
		order[o] = i
	}
	slices.SortStableFunc(out, func(a, b AccountState) int {
		return cmp.Or(cmp.Compare(a.Rank, b.Rank), cmp.Compare(order[a.OwnerID], order[b.OwnerID]),
			cmp.Compare(a.Rule, b.Rule), a.PeriodStart.Compare(b.PeriodStart))
	})
	return out, nil
}

// scopePath is where a stored guardrail's permissions are checked; a scope
// that no longer exists falls back to the org.
func (s *Service) scopePath(ctx context.Context, org ids.OrgID, sc domain.Scope) (tdomain.Path, error) {
	path, err := s.Subjects.ScopePath(ctx, org, sc)
	if errors.Is(err, ErrNotFound) {
		return tdomain.OrgPath(org), nil
	}
	return path, err
}
