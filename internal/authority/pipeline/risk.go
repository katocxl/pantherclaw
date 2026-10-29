// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline

import (
	"context"
	"slices"
	"time"

	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	papp "github.com/katocxl/pantherclaw/internal/policy/app"
)

// RiskWindow is how long an identity-risk fact counts as open (G0 M16
// D82): an older one is absent.
const RiskWindow = 24 * time.Hour

// identityRisk reads the pc.identity.risk facts about the run's
// represented person and its launcher, when a person, for a policy whose
// rules read `principal` (step 6, G0 M16 D82, founder decision F8). The
// facts come only from the built-in signals provider (HR-441); a missing
// or older fact is no risk, and the newest open one is what policy sees.
// Risk only makes rules match, so it never allows anything.
func (p *Pipeline) identityRisk(ctx context.Context, s *state) bool {
	if s.policy == nil || s.run == nil || !s.policy.Compiled.UsesPrincipal(s.a.Operation) {
		return true
	}
	var people []string
	for _, pr := range []gdomain.Principal{s.run.Principal, s.run.Launcher} {
		if pr.Kind == gdomain.PrincipalUser && !pr.ID.IsZero() && !slices.Contains(people, pr.ID.String()) {
			people = append(people, pr.ID.String())
		}
	}
	for _, id := range people {
		got, err := p.Reader.Facts(ctx, s.req.Org, s.connID(), fdomain.SubjectUser, id, []string{fdomain.NameIdentityRisk})
		if err != nil {
			s.missing(StepFacts, err, "the identity-risk facts")
			return false
		}
		f, ok := got[fdomain.NameIdentityRisk]
		if !ok || f.Value.Type != fdomain.TypeObject || s.cont.Now.Sub(f.ObservedAt) > RiskWindow {
			continue
		}
		// at is when the identity provider says the event happened; the
		// window counts from when the receiver recorded it.
		event, _ := f.Value.Object["event"].(string)
		at, ok := f.Value.Object["at"].(int64)
		if !ok {
			at = f.ObservedAt.Unix()
		}
		if s.risk == nil || at > s.risk.At {
			s.risk = &papp.Risk{Event: event, At: at}
		}
		s.used = append(s.used, f)
	}
	return true
}
