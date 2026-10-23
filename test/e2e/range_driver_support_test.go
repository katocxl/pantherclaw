// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"fmt"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/entitlements"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	"github.com/katocxl/pantherclaw/internal/support"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type rangeSupportPlans struct{}

func (rangeSupportPlans) Mode() entitlements.Mode { return entitlements.ModeExternal }
func (rangeSupportPlans) For(context.Context, ids.OrgID) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: billing.Enterprise, Status: billing.StatusValid}, nil
}

// supportProbe uses app-role service calls, FORCE RLS and the real audit
// writer. Admin access only seeds identities/registered test credentials.
func (d *rangeDriver) supportProbe(st domain.Step) (domain.Observation, error) {
	var w struct {
		Attack string `json:"attack"`
	}
	if err := json.Unmarshal(st.With, &w); err != nil {
		return domain.Observation{}, err
	}
	ctx := context.Background()
	staffOrg := ids.New[ids.Org]()
	account, staff, twin, admin := ids.NewV7(), ids.NewV7(), ids.NewV7(), ids.NewV7()
	staffKey, twinKey, adminKey := ids.NewV7(), ids.NewV7(), ids.NewV7()
	d.s.db.AdminExec(d.t, "INSERT INTO pc.orgs(id,name) VALUES($1,'range staff')", staffOrg)
	d.s.db.AdminExec(d.t, "INSERT INTO pc.accounts(id,issuer,subject,email) VALUES($1,'https://range.test',$2,'staff@range.test')", account, account.String())
	for i, p := range []struct {
		org       ids.OrgID
		user, key ids.UUID
		account   *ids.UUID
	}{
		{staffOrg, staff, staffKey, &account}, {d.s.org, twin, twinKey, &account}, {d.s.org, admin, adminKey, nil},
	} {
		subject := p.user.String()
		if p.account != nil {
			subject = account.String()
		}
		d.s.db.AdminExec(d.t, "INSERT INTO pc.users(org_id,id,issuer,subject,email,account_id) VALUES($1,$2,'https://range.test',$3,'range@range.test',$4)", p.org, p.user, subject, p.account)
		d.s.db.AdminExec(d.t, `INSERT INTO pc.webauthn_credentials(org_id,id,user_id,credential_id,public_key,alg,backup_eligible,backup_state,attestation_fmt,name) VALUES($1,$2,$3,$4,$5,-7,false,false,'none','range key')`, p.org, p.key, p.user, p.key[:], bytes.Repeat([]byte{byte(i + 1)}, 32))
		d.s.db.AdminExec(d.t, "INSERT INTO pc.role_bindings(org_id,id,role,user_id,scope_type,created_by) VALUES($1,$2,'org_admin',$3,'ORG','range')", p.org, ids.NewV7(), p.user)
	}
	person := func(org ids.OrgID, user ids.UUID) tapp.Caller {
		return tapp.Caller{
			Subject: td.Subject{Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: user}, Bindings: []td.Binding{{Role: td.RoleOrgAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: org.UUID()}}}}, Credential: tapp.CredBrowserSession, Session: ids.NewV7(),
		}
	}
	adminCtx := tapp.WithCaller(ctx, person(d.s.org, admin))
	twinCtx := tapp.WithCaller(ctx, person(d.s.org, twin))
	fresh := func(key ids.UUID) *stepup.StepUp { return &stepup.StepUp{Credential: key, At: time.Now()} }
	svc := support.New(d.s.pool, support.Config{StaffOrg: staffOrg, Staff: []support.Identity{{Issuer: "https://range.test", Subject: account.String()}}}, rangeSupportPlans{}, nil, nil)
	stf := support.Staff{Caller: person(staffOrg, staff), StepUp: fresh(staffKey)}
	var attackErr error
	switch w.Attack {
	case "self_approval", "revoked_session":
		r, err := svc.Request(ctx, stf, support.RequestInput{Org: d.s.org, Task: "Range support incident", Hours: 1})
		if err != nil {
			return domain.Observation{}, err
		}
		if w.Attack == "self_approval" {
			_, _, attackErr = svc.Decide(twinCtx, r.ID, true, fresh(twinKey))
			break
		}
		_, g, err := svc.Decide(adminCtx, r.ID, true, fresh(adminKey))
		if err != nil {
			return domain.Observation{}, err
		}
		o, err := svc.Open(ctx, stf, d.s.org, r.ID)
		if err != nil {
			return domain.Observation{}, err
		}
		c, err := svc.Authenticate(ctx, o.Secret, "/pantherclaw.v1.AgentService/ListAgents")
		if err != nil {
			return domain.Observation{}, fmt.Errorf("approved session: %w", err)
		}
		if c.CanAnywhere(td.PermRoleBind) {
			return domain.Observation{}, fmt.Errorf("support session obtained admin permissions")
		}
		if _, err := svc.Revoke(adminCtx, g.ID); err != nil {
			return domain.Observation{}, err
		}
		_, attackErr = svc.Authenticate(ctx, o.Secret, "/pantherclaw.v1.AgentService/ListAgents")
	case "unregistered_holder":
		_, attackErr = svc.ActivateBreakGlass(twinCtx, "Range outage", 1, fresh(twinKey))
	case "stale_key":
		if _, err := svc.SetHolders(adminCtx, []support.Designation{{User: twin, Role: td.RoleAuditor}}); err != nil {
			return domain.Observation{}, err
		}
		_, attackErr = svc.ActivateBreakGlass(twinCtx, "Range outage", 1, &stepup.StepUp{Credential: twinKey, At: time.Now().Add(-6 * time.Minute)})
	default:
		return domain.Observation{}, fmt.Errorf("unsupported attack")
	}
	if attackErr == nil {
		return domain.Observation{Outcome: domain.OutcomeAllow}, nil
	}
	return domain.Observation{Outcome: domain.OutcomeRefused, Reason: pcerr.ReasonOf(attackErr)}, nil
}
