// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/github/app"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestHR207_AnIdentityManagerExemptsAccountsThatAreNotPeople (founder
// decision 2026-10-13): a person holding github.identity.manage registers
// a bot or a machine user as not a person, with a reason, and removes it
// again; each change is audited and notified. Nobody else may, a service
// account may not, an account is exempted once, a bad id, login or reason
// is refused, and so is an account someone linked as their own, now or
// before: it is a person. Anyone who reads users lists the exemptions.
func TestHR207_AnIdentityManagerExemptsAccountsThatAreNotPeople(t *testing.T) {
	e := newEnv(t)
	n := &notices{}
	e.svc.Notify = n
	admin, dev := e.person(t, "admin"), e.person(t, "dev")
	asAdmin, asDev := e.as(admin, td.KindUser, td.RoleOrgAdmin), e.as(dev, td.KindUser, td.RoleDeveloper)

	ex, err := e.svc.Exempt(asAdmin, 4100, "release-bot[bot]", "the release workflow's GitHub App")
	if err != nil || ex.GithubUserID != 4100 || ex.CreatedBy != (td.PrincipalRef{Kind: td.KindUser, ID: admin}).String() {
		t.Fatalf("exempted %+v %v", ex, err)
	}
	if _, err := e.svc.Exempt(asAdmin, 4101, "deploy-machine", "a machine user for deploy keys"); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		id     int64
		login  string
		reason string
		want   error
	}{
		"twice":          {4100, "release-bot[bot]", "again", app.ErrExempted},
		"no id":          {0, "x", "r", app.ErrExemptionBad},
		"a bad login":    {4102, "-x", "r", app.ErrExemptionBad},
		"no reason":      {4102, "x", " ", app.ErrExemptionBad},
		"a control char": {4102, "x", "a\nb", app.ErrExemptionBad},
	} {
		if _, err := e.svc.Exempt(asAdmin, c.id, c.login, c.reason); !errors.Is(err, c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	e.exec(t, "INSERT INTO pc.github_identity_history (org_id, github_user_id, user_id) VALUES ($1, 4200, $2)", e.org, dev)
	if _, err := e.svc.Exempt(asAdmin, 4200, "dev-alt", "a machine user"); !errors.Is(err, app.ErrExemptPerson) {
		t.Errorf("an account a person once linked: %v", err)
	}
	if _, err := e.svc.Exempt(asDev, 4102, "x", "r"); err == nil {
		t.Error("a developer exempted an account")
	}
	if _, err := e.svc.Exempt(e.as(ids.NewV7(), td.KindServiceAccount, td.RoleOrgAdmin), 4102, "x", "r"); !errors.Is(err, app.ErrHumanOnly) {
		t.Errorf("a service account: %v", err)
	}
	all, err := e.svc.Exemptions(e.as(dev, td.KindUser, td.RoleAuditor))
	if err != nil || len(all) != 2 || all[0].GithubLogin != "deploy-machine" {
		t.Fatalf("listed %+v %v", all, err)
	}
	if err := e.svc.RemoveExemption(asDev, 4100); err == nil {
		t.Error("a developer removed an exemption")
	}
	if err := e.svc.RemoveExemption(asAdmin, 4100); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.RemoveExemption(asAdmin, 4100); !errors.Is(err, app.ErrNotExempted) {
		t.Fatalf("removed twice: %v", err)
	}
	if a := e.count(t, `SELECT count(*) FROM pc.ledger_entries WHERE kind IN ('audit.github.account_exempted', 'audit.github.exemption_removed')`); a != 3 ||
		len(n.got) != 3 || n.got[2].Type != "security.github_exemption_removed" || n.got[2].Params["github_login"] != "release-bot[bot]" {
		t.Fatalf("%d audited, notices %+v", a, n.got)
	}
}
