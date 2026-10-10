// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"errors"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/approvals/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

var now = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

const day = 24 * time.Hour

// veteran is an enabled approver whose account, role and key are a month old.
func veteran() domain.Person {
	return domain.Person{
		UserID: ids.NewV7(), Enabled: true, JoinedAt: now.Add(-30 * day),
		Bindings:    []domain.RoleBinding{{Role: "approver", CreatedAt: now.Add(-30 * day)}},
		Credentials: []domain.Credential{{ID: ids.NewV7(), CreatedAt: now.Add(-30 * day)}},
	}
}

func userP(u ids.UUID) gdomain.Principal {
	return gdomain.Principal{Kind: gdomain.PrincipalUser, ID: u}
}

func ctx() domain.Context {
	return domain.Context{
		Run: domain.RunPeople{Launcher: userP(ids.NewV7()), Principal: userP(ids.NewV7())}, Owners: []ids.UUID{ids.NewV7()},
		GrantIssuers: []ids.UUID{ids.NewV7()}, Cooldowns: domain.DefaultCooldowns(), Now: now,
	}
}

func wantCode(t *testing.T, name string, ok bool, code, want string) {
	t.Helper()
	if want == "" && !ok {
		t.Errorf("%s: refused with %s", name, code)
	}
	if want != "" && (ok || code != want) {
		t.Errorf("%s: ok=%v %s, want refused with %s", name, ok, code, want)
	}
}

// TestHR036_LauncherPrincipalAndAncestorsNeverApprove (decision 3, T-002):
// every approval is independent of the run's launcher and principal and
// those of every ancestor run, whether or not the requirement says
// independent.
func TestHR036_LauncherPrincipalAndAncestorsNeverApprove(t *testing.T) {
	r := approver(1, false)
	p := veteran()
	c := ctx()
	ok, code := domain.Check(r, p, c, ids.UUID{})
	wantCode(t, "an unrelated approver", ok, code, "")
	c.Run.Launcher = userP(p.UserID)
	ok, code = domain.Check(r, p, c, ids.UUID{})
	wantCode(t, "the launcher", ok, code, domain.IneligibleLauncher)
	c = ctx()
	c.Run.Principal = userP(p.UserID)
	ok, code = domain.Check(r, p, c, ids.UUID{})
	wantCode(t, "the principal", ok, code, domain.IneligiblePrincipal)
	c = ctx()
	c.Run.Ancestors = []gdomain.Principal{userP(ids.NewV7()), userP(p.UserID)}
	ok, code = domain.Check(r, p, c, ids.UUID{})
	wantCode(t, "an ancestor run's principal", ok, code, domain.IneligibleAncestor)
	// A service account launcher with the same id is not this person.
	c = ctx()
	c.Run.Launcher = gdomain.Principal{Kind: gdomain.PrincipalServiceAccount, ID: p.UserID}
	ok, code = domain.Check(r, p, c, ids.UUID{})
	wantCode(t, "a service account sharing the id", ok, code, "")
}

// TestHR170_IndependentExcludesOwnersAndTheGrantIssuer (decision 3).
func TestHR170_IndependentExcludesOwnersAndTheGrantIssuer(t *testing.T) {
	p := veteran()
	c := ctx()
	c.Owners = append(c.Owners, p.UserID)
	ok, code := domain.Check(approver(1, false), p, c, ids.UUID{})
	wantCode(t, "an owner, not independent", ok, code, "")
	ok, code = domain.Check(approver(1, true), p, c, ids.UUID{})
	wantCode(t, "an owner, independent", ok, code, domain.IneligibleOwner)
	c = ctx()
	c.GrantIssuers = []ids.UUID{p.UserID}
	ok, code = domain.Check(approver(1, true), p, c, ids.UUID{})
	wantCode(t, "the grant's issuer, independent", ok, code, domain.IneligibleGrantIssuer)
}

// TestHR170_RoleCredentialAndStateDecideEligibility: a disabled person, a
// person without the role on the agent's scope path, or without an active
// credential, never counts; nor does an assertion with a credential that
// is no longer active.
func TestHR170_RoleCredentialAndStateDecideEligibility(t *testing.T) {
	r, c := approver(1, false), ctx()
	p := veteran()
	p.Enabled = false
	ok, code := domain.Check(r, p, c, ids.UUID{})
	wantCode(t, "disabled", ok, code, domain.IneligibleDisabled)
	p = veteran()
	p.Bindings = nil
	ok, code = domain.Check(r, p, c, ids.UUID{})
	wantCode(t, "no role in scope", ok, code, domain.IneligibleNoRole)
	p = veteran()
	p.Bindings[0].Role = "security_admin"
	ok, code = domain.Check(r, p, c, ids.UUID{})
	wantCode(t, "another role", ok, code, domain.IneligibleNoRole)
	p = veteran()
	p.Credentials = nil
	ok, code = domain.Check(r, p, c, ids.UUID{})
	wantCode(t, "no credential", ok, code, domain.IneligibleNoCredential)
	p = veteran()
	ok, code = domain.Check(r, p, c, ids.NewV7())
	wantCode(t, "a removed credential", ok, code, domain.IneligibleCredentialRevoked)
	ok, code = domain.Check(r, p, c, p.Credentials[0].ID)
	wantCode(t, "an active credential", ok, code, "")
}

// TestHR035_CooldownsHold (decision 5): for two or more approvers the
// account must be 7 days old, the role binding and the credential 24 hours;
// a self-granted role counts only after 24 hours for every approval; orgs
// may lengthen the periods, never shorten them.
func TestHR035_CooldownsHold(t *testing.T) {
	c := ctx()
	young := veteran()
	young.JoinedAt = now.Add(-2 * day)
	ok, code := domain.Check(approver(1, false), young, c, ids.UUID{})
	wantCode(t, "a new account, one approver", ok, code, "")
	ok, code = domain.Check(approver(2, false), young, c, ids.UUID{})
	wantCode(t, "a new account, two approvers", ok, code, domain.IneligibleAccountTooNew)

	fresh := veteran()
	fresh.Bindings[0].CreatedAt = now.Add(-time.Hour)
	ok, code = domain.Check(approver(1, false), fresh, c, ids.UUID{})
	wantCode(t, "a fresh role granted by someone else, one approver", ok, code, "")
	ok, code = domain.Check(approver(2, false), fresh, c, ids.UUID{})
	wantCode(t, "a fresh role, two approvers", ok, code, domain.IneligibleRoleCooldown)
	fresh.Bindings[0].SelfGranted = true
	ok, code = domain.Check(approver(1, false), fresh, c, ids.UUID{})
	wantCode(t, "a fresh self-granted role", ok, code, domain.IneligibleSelfGrant)
	fresh.Bindings[0].CreatedAt = now.Add(-25 * time.Hour)
	ok, code = domain.Check(approver(1, false), fresh, c, ids.UUID{})
	wantCode(t, "a self-granted role after 24 hours", ok, code, "")

	newKey := veteran()
	newKey.Credentials[0].CreatedAt = now.Add(-time.Hour)
	ok, code = domain.Check(approver(2, false), newKey, c, newKey.Credentials[0].ID)
	wantCode(t, "a new key, two approvers", ok, code, domain.IneligibleCredentialTooNew)
	ok, code = domain.Check(approver(1, false), newKey, c, newKey.Credentials[0].ID)
	wantCode(t, "a new key, one approver", ok, code, "")

	// Shortened settings are raised to the minimum; lengthened ones apply.
	c.Cooldowns = domain.Cooldowns{AccountAge: time.Hour, SelfGrantDelay: time.Minute}
	ok, code = domain.Check(approver(2, false), young, c, ids.UUID{})
	wantCode(t, "a shortened account cooldown", ok, code, domain.IneligibleAccountTooNew)
	c.Cooldowns = domain.Cooldowns{AccountAge: 60 * day}
	ok, code = domain.Check(approver(2, false), veteran(), c, ids.UUID{})
	wantCode(t, "a lengthened account cooldown", ok, code, domain.IneligibleAccountTooNew)
}

// TestHR035_TwoPersonNeedsTwoUsersAndTwoCredentials (T-027): the same
// person twice, or one credential used by two people, counts once; voided
// responses count for nothing.
func TestHR035_TwoPersonNeedsTwoUsersAndTwoCredentials(t *testing.T) {
	reqs := []domain.Requirement{approver(2, false)}
	alice, bob := ids.NewV7(), ids.NewV7()
	k1, k2, k3 := ids.NewV7(), ids.NewV7(), ids.NewV7()
	for _, c := range []struct {
		name string
		rs   []domain.Response
		met  bool
	}{
		{"one person twice", []domain.Response{{UserID: alice, CredentialID: k1}, {UserID: alice, CredentialID: k2}}, false},
		{"two people, one key", []domain.Response{{UserID: alice, CredentialID: k1}, {UserID: bob, CredentialID: k1}}, false},
		{"two people, two keys", []domain.Response{{UserID: alice, CredentialID: k1}, {UserID: bob, CredentialID: k3}}, true},
		{"one voided", []domain.Response{{UserID: alice, CredentialID: k1}, {UserID: bob, CredentialID: k3, Voided: true}}, false},
		{"an unknown requirement", []domain.Response{{UserID: alice, CredentialID: k1}, {UserID: bob, CredentialID: k3, Requirement: 1}}, false},
	} {
		if got := domain.Met(reqs, c.rs); got != c.met {
			t.Errorf("%s: met=%v, want %v", c.name, got, c.met)
		}
	}
}

// TestHR170_OneResponseCountsTowardOneRequirement: with two requirements,
// one person's response fills only the one it was recorded for, and the
// next response goes to the first requirement still short.
func TestHR170_OneResponseCountsTowardOneRequirement(t *testing.T) {
	stepUp := domain.Requirement{Kind: domain.KindStepUp, Subject: domain.SubjectLauncher, Method: domain.MethodWebAuthn}
	reqs := []domain.Requirement{approver(1, false), stepUp}
	alice := ids.NewV7()
	rs := []domain.Response{{UserID: alice, CredentialID: ids.NewV7(), Requirement: 0}}
	if domain.Met(reqs, rs) {
		t.Fatal("one response satisfied two requirements")
	}
	if got := domain.Tally(reqs, rs); got[0] != 1 || got[1] != 0 {
		t.Fatalf("tally %v", got)
	}
	i, ok := domain.Next(reqs, rs, func(int) bool { return true })
	if !ok || i != 1 {
		t.Fatalf("next = %d, %v; want the step-up", i, ok)
	}
	if _, ok := domain.Next(reqs, rs, func(i int) bool { return i == 0 }); ok {
		t.Fatal("a person only eligible for a full requirement was given one")
	}
}

// TestHR170_StepUpIsOnlyTheNamedPerson (decision 4): a step-up counts only
// from the launcher or principal it names, and a subject that is not a
// person cannot step up at all.
func TestHR170_StepUpIsOnlyTheNamedPerson(t *testing.T) {
	stepUp := domain.Requirement{Kind: domain.KindStepUp, Subject: domain.SubjectLauncher, Method: domain.MethodWebAuthn}
	p := veteran()
	p.Bindings = nil // a step-up needs no approver role
	c := ctx()
	ok, code := domain.Check(stepUp, p, c, ids.UUID{})
	wantCode(t, "someone else", ok, code, domain.IneligibleNotStepUpSubject)
	c.Run.Launcher = userP(p.UserID)
	ok, code = domain.Check(stepUp, p, c, ids.UUID{})
	wantCode(t, "the launcher", ok, code, "")
	c.Run.Launcher = gdomain.Principal{Kind: gdomain.PrincipalInstance, ID: ids.NewV7()}
	if _, err := domain.StepUpUser(stepUp, c.Run); !errors.Is(err, domain.ErrStepUpSubjectNotAPerson) {
		t.Fatalf("a child run's launcher: %v", err)
	}
	c.Run.Principal = gdomain.Principal{Kind: gdomain.PrincipalServiceAccount, ID: ids.NewV7()}
	stepUp.Subject = domain.SubjectPrincipal
	if _, err := domain.StepUpUser(stepUp, c.Run); !errors.Is(err, domain.ErrStepUpSubjectNotAPerson) {
		t.Fatalf("a service account principal: %v", err)
	}
}

// TestHR176_ARestorationIsDecidedByAnotherRestorer (decision 11): a person
// holding a role with agent.restore, other than the requester, with an
// active key; an approver's role does not qualify, and a restorer's role
// does not approve actions.
func TestHR176_ARestorationIsDecidedByAnotherRestorer(t *testing.T) {
	c := ctx()
	restorer := veteran()
	restorer.Bindings = []domain.RoleBinding{{Role: "responder", CreatedAt: now.Add(-30 * day)}}
	r := domain.RestoreRequirement
	ok, code := domain.Check(r, restorer, c, ids.UUID{})
	wantCode(t, "a responder", ok, code, "")
	admin := restorer
	admin.Bindings = []domain.RoleBinding{{Role: "security_admin", CreatedAt: now.Add(-30 * day)}}
	ok, code = domain.Check(r, admin, c, ids.UUID{})
	wantCode(t, "a security admin", ok, code, "")

	c.Requester = restorer.UserID
	ok, code = domain.Check(r, restorer, c, ids.UUID{})
	wantCode(t, "the requester", ok, code, domain.IneligibleRequester)
	c.Requester = ids.NewV7()

	ok, code = domain.Check(r, veteran(), c, ids.UUID{})
	wantCode(t, "an approver", ok, code, domain.IneligibleNoRole)
	ok, code = domain.Check(domain.Requirement{Kind: domain.KindApproval, Role: "approver", Count: 1}, restorer, c, ids.UUID{})
	wantCode(t, "a responder approving an action", ok, code, domain.IneligibleNoRole)

	self := restorer
	self.Bindings = []domain.RoleBinding{{Role: "responder", CreatedAt: now.Add(-time.Hour), SelfGranted: true}}
	ok, code = domain.Check(r, self, c, ids.UUID{})
	wantCode(t, "a self-granted responder", ok, code, domain.IneligibleSelfGrant)
	keyless := restorer
	keyless.Credentials = nil
	ok, code = domain.Check(r, keyless, c, ids.UUID{})
	wantCode(t, "no key", ok, code, domain.IneligibleNoCredential)
	if ok, _ := domain.MayRespond(r, restorer, c); !ok {
		t.Error("a restorer may decline a restoration")
	}
}
