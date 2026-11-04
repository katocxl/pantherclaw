// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline

import (
	"context"
	"slices"
	"strings"

	"github.com/katocxl/pantherclaw/internal/actionir"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The share step (G0 M30 D935; HR-707). An action that shares to the public
// holds for a person (SHARE_PUBLIC); one that shares to an account the org
// has not listed as its own holds too (SHARE_ACCOUNT_NOT_OWNED), and an
// empty list owns nothing, so every account share holds. An owned account
// has no effect. The step only ever adds a hold: nothing here allows
// anything, lowers a decision or removes a requirement.

// Reason codes and level of a share hold.
const (
	// ReasonSharePublic: the action shares to the public.
	ReasonSharePublic = "SHARE_PUBLIC"
	// ReasonShareAccountNotOwned: the action shares to an account not on the
	// org's owned list.
	ReasonShareAccountNotOwned = "SHARE_ACCOUNT_NOT_OWNED"
	// ShareLevel is the source of the hold's requirement.
	ShareLevel = "share"
)

// OwnedAccounts is the port the share step reads the org's owned accounts
// through: the listed values of one kind. A Reader that does not implement
// it owns nothing, so every account share holds (fail closed).
type OwnedAccounts interface {
	OwnedAccounts(ctx context.Context, org ids.OrgID, kind string) ([]string, error)
}

// actionShares are the action's shares: those the gateway mapper put in
// the ActionIR and those the pinned definition's share extractors read from
// the values the Authority holds, so a channel that builds ActionIR without
// the mapper cannot leave a share out. Unique, in a stable order.
func (s *state) actionShares() ([]actionir.Destination, error) {
	out := slices.Clone(s.a.Shares)
	if s.def != nil && s.vals != nil {
		more, err := s.def.Shares(s.vals)
		if err != nil {
			return nil, err
		}
		out = append(out, more...)
	}
	slices.SortFunc(out, func(a, b actionir.Destination) int {
		if c := strings.Compare(a.Kind, b.Kind); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	return slices.Compact(out), nil
}

// shares holds an action that shares to the public or to an account the org
// does not own (D935).
func (p *Pipeline) shares(ctx context.Context, s *state) {
	all, err := s.actionShares()
	if err != nil {
		s.missing(StepBoundaries, err, "the action's share destinations")
		return
	}
	if len(all) == 0 {
		return
	}
	owned := map[string][]string{}
	port, _ := p.Reader.(OwnedAccounts)
	var public bool
	var notOwned []string
	for _, d := range all {
		if d.Kind == actionir.SharePublic {
			public = true
			continue
		}
		list, read := owned[d.Kind]
		if !read && port != nil {
			if list, err = port.OwnedAccounts(ctx, s.req.Org, d.Kind); err != nil {
				s.missing(StepFacts, err, "the org's owned accounts")
				return
			}
			owned[d.Kind] = list
		}
		if !slices.Contains(list, d.ID) {
			notOwned = append(notOwned, d.Kind+" "+d.ID)
		}
	}
	reason := ""
	if public {
		reason = ReasonSharePublic
		s.cl.add(StepRequirements, adomain.RequireApproval, ReasonSharePublic,
			"approval by "+string(td.RoleApprover)+" is required: the action shares to the public", ShareLevel)
	}
	if len(notOwned) > 0 {
		if reason == "" {
			reason = ReasonShareAccountNotOwned
		}
		s.cl.add(StepRequirements, adomain.RequireApproval, ReasonShareAccountNotOwned,
			"approval by "+string(td.RoleApprover)+" is required: the action shares to accounts not on the org's owned list ("+
				strings.Join(notOwned, ", ")+")", ShareLevel)
	}
	if reason == "" {
		return
	}
	a := pdomain.ApprovalRequirement{Role: string(td.RoleApprover), Count: 1}
	s.ev.Approvals = append(s.ev.Approvals, a)
	s.ev.Requirements = append(s.ev.Requirements, input(&a, nil, apdomain.Source{Level: ShareLevel, Reason: reason}))
}
