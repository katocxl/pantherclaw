// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"errors"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

var containmentHold = domain.Requirement{Kind: domain.KindContainment, Count: 1, Independent: true}

func responder() domain.Person {
	p := veteran()
	p.Bindings = []domain.RoleBinding{{Role: "responder", CreatedAt: now.Add(-30 * day)}}
	return p
}

// TestHR248_OnlyAnIndependentResponderReleasesAContainmentHold (G0 M10
// D44): a write held by HOLD_WRITES is released only by a person holding
// incident.respond with a security key. A plain approver cannot release
// it, and neither can a responder who launched the run, is its principal or
// an ancestor's, owns the agent or issued the grant.
func TestHR248_OnlyAnIndependentResponderReleasesAContainmentHold(t *testing.T) {
	c := ctx()
	r := containmentHold
	ok, code := domain.Check(r, responder(), c, ids.UUID{})
	wantCode(t, "an independent responder", ok, code, "")
	admin := responder()
	admin.Bindings = []domain.RoleBinding{{Role: "security_admin", CreatedAt: now.Add(-30 * day)}}
	ok, code = domain.Check(r, admin, c, ids.UUID{})
	wantCode(t, "a security admin", ok, code, "")

	ok, code = domain.Check(r, veteran(), c, ids.UUID{})
	wantCode(t, "a plain approver", ok, code, domain.IneligibleNoRole)
	if ok, _ := domain.MayRespond(r, veteran(), c); ok {
		t.Error("a plain approver may decline a containment hold")
	}

	launcher := responder()
	c.Run.Launcher = userP(launcher.UserID)
	ok, code = domain.Check(r, launcher, c, ids.UUID{})
	wantCode(t, "the responder who launched the run", ok, code, domain.IneligibleLauncher)
	if ok, _ := domain.MayRespond(r, launcher, c); ok {
		t.Error("the launcher may decline their own containment hold")
	}
	c = ctx()
	for name, edit := range map[string]func(*domain.Context, ids.UUID) string{
		"principal": func(c *domain.Context, u ids.UUID) string {
			c.Run.Principal = userP(u)
			return domain.IneligiblePrincipal
		},
		"ancestor": func(c *domain.Context, u ids.UUID) string {
			c.Run.Ancestors = append(c.Run.Ancestors, userP(u))
			return domain.IneligibleAncestor
		},
		"owner": func(c *domain.Context, u ids.UUID) string {
			c.Owners = append(c.Owners, u)
			return domain.IneligibleOwner
		},
		"grant issuer": func(c *domain.Context, u ids.UUID) string {
			c.GrantIssuers = append(c.GrantIssuers, u)
			return domain.IneligibleGrantIssuer
		},
	} {
		p, cc := responder(), ctx()
		want := edit(&cc, p.UserID)
		ok, code := domain.Check(r, p, cc, ids.UUID{})
		wantCode(t, "the "+name, ok, code, want)
	}

	self := responder()
	self.Bindings = []domain.RoleBinding{{Role: "responder", CreatedAt: now.Add(-time.Hour), SelfGranted: true}}
	ok, code = domain.Check(r, self, c, ids.UUID{})
	wantCode(t, "a self-granted responder", ok, code, domain.IneligibleSelfGrant)
	keyless := responder()
	keyless.Credentials = nil
	ok, code = domain.Check(r, keyless, c, ids.UUID{})
	wantCode(t, "no key", ok, code, domain.IneligibleNoCredential)

	// A responder does not approve an ordinary action hold.
	ok, code = domain.Check(domain.Requirement{Kind: domain.KindApproval, Role: "approver", Count: 1}, responder(), c, ids.UUID{})
	wantCode(t, "a responder approving an action", ok, code, domain.IneligibleNoRole)
}

// TestHR248_ContainmentRequirementShape: only one independent responder,
// with no role, subject or people fact, is a valid containment hold; it
// merges into one requirement and sorts after approvals, before step-ups.
func TestHR248_ContainmentRequirementShape(t *testing.T) {
	ok := domain.Input{Kind: domain.KindContainment, Count: 1, Independent: true}
	for _, bad := range []domain.Input{
		{Kind: domain.KindContainment, Count: 2, Independent: true},
		{Kind: domain.KindContainment, Count: 1},
		{Kind: domain.KindContainment, Count: 1, Independent: true, Role: "approver"},
		{Kind: domain.KindContainment, Count: 1, Independent: true, Subject: domain.SubjectLauncher},
		{Kind: domain.KindContainment, Count: 1, Independent: true, IndependentOf: "github.pull.people"},
	} {
		if err := bad.Validate(); !errors.Is(err, domain.ErrRequirementInvalid) {
			t.Errorf("%+v: %v", bad, err)
		}
	}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	step := domain.Input{Kind: domain.KindStepUp, Subject: domain.SubjectLauncher, Method: domain.MethodWebAuthn}
	appr := domain.Input{Kind: domain.KindApproval, Role: "approver", Count: 1}
	reqs, _, err := domain.Merge([]domain.Input{step, ok, appr, ok})
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 3 || reqs[0].Kind != domain.KindApproval || reqs[1].Kind != domain.KindContainment || reqs[2].Kind != domain.KindStepUp ||
		reqs[1].Count != 1 || !reqs[1].Independent {
		t.Fatalf("merged %+v", reqs)
	}
}
