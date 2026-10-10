// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pgapprovals is the PostgreSQL side of approvals (G0 M5 part 2):
// recording a hold inside the finalization, consuming an approval after
// checking every approver's eligibility again, and expiring a request at
// use. Every function runs inside the caller's tenant transaction, so a
// hold, its slots, its waitlist entry and its audit events commit or roll
// back with the decision.
package pgapprovals

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"slices"
	"time"

	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Eligibility is everything apdomain.Check needs about one request and the
// people it is asked of, read in the caller's transaction (HR-170).
type Eligibility struct {
	SubjectKind  string
	Requirements []apdomain.Requirement
	Context      apdomain.Context
	People       map[ids.UUID]apdomain.Person
	// RequestedBy is a restoration's requester.
	RequestedBy ids.UUID
}

// deciderRoles are the default roles that decide a request of kind: those
// holding approval.respond (decision 2), or agent.restore for a
// restoration (decision 11).
func deciderRoles(subjectKind string) []string {
	p := td.PermApprovalRespond
	if subjectKind == subjectRestoration {
		p = td.PermAgentRestore
	}
	var out []string
	for _, r := range td.Roles() {
		if r.Has(p) {
			out = append(out, string(r.Name))
		}
	}
	return out
}

// subjectRestoration is the subject kind of a restoration request.
const subjectRestoration = "RESTORATION"

func principal(user, sa, instance *ids.UUID) gdomain.Principal {
	switch {
	case user != nil:
		return gdomain.Principal{Kind: gdomain.PrincipalUser, ID: *user}
	case sa != nil:
		return gdomain.Principal{Kind: gdomain.PrincipalServiceAccount, ID: *sa}
	case instance != nil:
		return gdomain.Principal{Kind: gdomain.PrincipalInstance, ID: *instance}
	}
	return gdomain.Principal{}
}

func seconds(s *int32, def time.Duration) time.Duration {
	if s == nil {
		return def
	}
	return time.Duration(*s) * time.Second
}

// LoadEligibility reads a request's requirements and the eligibility of
// users, by the database clock.
func LoadEligibility(ctx context.Context, q *dbq.Queries, org ids.OrgID, request ids.UUID, users []ids.UUID) (Eligibility, error) {
	row, err := q.ApprovalEligibilityContext(ctx, org, request)
	if err != nil {
		return Eligibility{}, err
	}
	now, err := q.DBNow(ctx)
	if err != nil {
		return Eligibility{}, err
	}
	out := Eligibility{SubjectKind: row.SubjectKind, People: map[ids.UUID]apdomain.Person{}}
	if row.RequestedBy != nil {
		out.RequestedBy = *row.RequestedBy
	}
	if err := json.Unmarshal(row.Requirements, &out.Requirements); err != nil {
		return Eligibility{}, fmt.Errorf("approvals: request %s: requirements: %w", request, err)
	}
	cd, err := q.ApprovalCooldowns(ctx, org)
	if err != nil {
		return Eligibility{}, err
	}
	def := apdomain.DefaultCooldowns()
	c := apdomain.Context{Now: now, Cooldowns: apdomain.Cooldowns{
		AccountAge: seconds(cd.MinAccountAgeS, def.AccountAge), RoleAge: seconds(cd.MinRoleAgeS, def.RoleAge),
		CredentialAge: seconds(cd.MinCredentialAgeS, def.CredentialAge), SelfGrantDelay: seconds(cd.SelfGrantDelayS, def.SelfGrantDelay),
	}}
	for _, o := range []*ids.UUID{row.OwnerUserID, row.BackupOwnerUserID} {
		if o != nil {
			c.Owners = append(c.Owners, *o)
		}
	}
	if row.RunID != nil {
		c.Run.Launcher = principal(row.LauncherUserID, row.LauncherSaID, row.LauncherInstanceID)
		c.Run.Principal = principal(row.PrincipalUserID, row.PrincipalSaID, nil)
		ancestors, err := q.RunAncestors(ctx, org, *row.RunID)
		if err != nil {
			return Eligibility{}, err
		}
		for _, a := range ancestors {
			c.Run.Ancestors = append(c.Run.Ancestors, principal(a.LauncherUserID, a.LauncherSaID, a.LauncherInstanceID),
				principal(a.PrincipalUserID, a.PrincipalSaID, nil))
		}
	}
	if row.GrantID != nil {
		if c.GrantIssuers, err = q.ChainIssuers(ctx, org, *row.GrantID); err != nil {
			return Eligibility{}, err
		}
	}
	c.Requester = out.RequestedBy
	out.Context = c
	if len(users) == 0 {
		return out, nil
	}
	us, err := q.EligibilityUsers(ctx, org, users)
	if err != nil {
		return Eligibility{}, err
	}
	for _, u := range us {
		out.People[u.ID] = apdomain.Person{UserID: u.ID, Enabled: u.State == "ACTIVE", JoinedAt: u.CreatedAt}
	}
	bs, err := q.EligibilityBindings(ctx, dbq.EligibilityBindingsParams{
		OrgID: org, Ids: users, Roles: deciderRoles(row.SubjectKind), BusinessUnitID: row.BusinessUnitID, TeamID: row.TeamID,
		EnvironmentID: row.EnvironmentID,
	})
	if err != nil {
		return Eligibility{}, err
	}
	for _, b := range bs {
		p, ok := out.People[b.UserID]
		if !ok {
			continue
		}
		p.Bindings = append(p.Bindings, apdomain.RoleBinding{
			Role: b.Role, CreatedAt: b.CreatedAt, SelfGranted: b.CreatedBy == td.PrincipalRef{Kind: td.KindUser, ID: b.UserID}.String(),
		})
		out.People[b.UserID] = p
	}
	creds, err := q.EligibilityCredentials(ctx, org, users)
	if err != nil {
		return Eligibility{}, err
	}
	for _, k := range creds {
		if p, ok := out.People[k.UserID]; ok {
			p.Credentials = append(p.Credentials, apdomain.Credential{ID: k.ID, CreatedAt: k.CreatedAt})
			out.People[k.UserID] = p
		}
	}
	return out, nil
}

// counted is a response with whether it still counts.
type counted struct {
	ID       ids.UUID
	Response apdomain.Response
	Code     string
}

// tally reads a request's counting responses and checks each one's
// eligibility again (HR-170): a response counts only while its person is
// still eligible for the requirement it was recorded for.
func tally(ctx context.Context, q *dbq.Queries, org ids.OrgID, request ids.UUID) (Eligibility, []counted, error) {
	rows, err := q.CountingResponses(ctx, org, request)
	if err != nil {
		return Eligibility{}, nil, err
	}
	var users []ids.UUID
	for _, r := range rows {
		if !slices.Contains(users, r.UserID) {
			users = append(users, r.UserID)
		}
	}
	e, err := LoadEligibility(ctx, q, org, request, users)
	if err != nil {
		return Eligibility{}, nil, err
	}
	out := make([]counted, 0, len(rows))
	for _, r := range rows {
		c := counted{ID: r.ID, Response: apdomain.Response{UserID: r.UserID, CredentialID: r.CredentialID, Requirement: int(r.Requirement)}}
		req := int(r.Requirement)
		if req < 0 || req >= len(e.Requirements) {
			c.Response.Voided, c.Code = true, apdomain.IneligibleNoRole
		} else if ok, code := apdomain.Check(e.Requirements[req], e.People[r.UserID], e.Context, r.CredentialID); !ok {
			c.Response.Voided, c.Code = true, code
		}
		out = append(out, c)
	}
	return e, out, nil
}

func responses(cs []counted) []apdomain.Response {
	out := make([]apdomain.Response, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.Response)
	}
	return out
}

// voidReason maps an ineligibility code to the void reason the schema
// records.
func voidReason(code string) string {
	switch code {
	case apdomain.IneligibleDisabled:
		return "USER_DISABLED"
	case apdomain.IneligibleNoRole, apdomain.IneligibleRoleCooldown, apdomain.IneligibleSelfGrant:
		return "ROLE_REMOVED"
	case apdomain.IneligibleCredentialRevoked:
		return "CREDENTIAL_REMOVED"
	}
	return "NOT_ELIGIBLE"
}
