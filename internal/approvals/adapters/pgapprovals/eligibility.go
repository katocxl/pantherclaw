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
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
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
	// PeopleLists are, for each fact an independent requirement names, the
	// people it lists now and the users linked to them; Context.Authorship
	// is read from them (G0 M8, HR-207, F158).
	PeopleLists []apdomain.PeopleList
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
	if out.PeopleLists, err = peopleLists(ctx, q, org, request, out.Requirements); err != nil {
		return Eligibility{}, err
	}
	c.Authorship = map[string]apdomain.Authorship{}
	for _, l := range out.PeopleLists {
		c.Authorship[l.Fact] = l.Authorship()
	}
	// Whoever was linked to those people when the request was created stays
	// excluded, whatever happened to their links since (G0 M8 P2f).
	linked, err := q.RequestLinkedPeople(ctx, org, request)
	if err != nil {
		return Eligibility{}, err
	}
	for _, r := range linked {
		if a, ok := c.Authorship[r.Fact]; ok && !slices.Contains(a.Users, r.UserID) {
			a.Users = append(a.Users, r.UserID)
			c.Authorship[r.Fact] = a
		}
	}
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
	verified, err := q.VerifiedGitHubUsers(ctx, org, users)
	if err != nil {
		return Eligibility{}, err
	}
	for _, u := range verified {
		if p, ok := out.People[u]; ok {
			p.GitHubVerified = true
			out.People[u] = p
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

// peopleLists reads, for each fact an independent requirement names, the
// people it lists now about the held action's target and the users linked
// to them (G0 M8, HR-207). The fact is read as it is when a person
// responds, so a commit pushed after the hold excludes its pusher too. A
// fact that is not known, does not decode, says it is incomplete, does not
// name its author and pushers, or holds an id that is not a positive
// integer leaves the list incomplete, and nobody counts as independent.
// The approval page shows the same lists (F158).
func peopleLists(ctx context.Context, q *dbq.Queries, org ids.OrgID, request ids.UUID, reqs []apdomain.Requirement) (
	[]apdomain.PeopleList, error,
) {
	var out []apdomain.PeopleList
	for _, r := range reqs {
		name := r.IndependentOf
		if name == "" || slices.ContainsFunc(out, func(l apdomain.PeopleList) bool { return l.Fact == name }) {
			continue
		}
		l := apdomain.PeopleList{Fact: name}
		raw, err := q.RequestSubjectFact(ctx, name, org, request)
		switch {
		case db.IsNoRows(err):
			l.Gaps = []string{apdomain.PeopleNotKnown}
		case err != nil:
			return nil, err
		default:
			if v, err := fdomain.DecodeValue(fdomain.TypeObject, raw); err != nil {
				l.Gaps = []string{apdomain.PeopleUnreadable}
			} else {
				l = apdomain.ListPeople(name, v.Object)
			}
		}
		if ghIDs := l.GitHubIDs(); len(ghIDs) > 0 {
			links, err := q.LinkedGitHubUsers(ctx, org, ghIDs)
			if err != nil {
				return nil, err
			}
			for _, k := range links {
				l.Link(k.GithubUserID, k.UserID)
			}
			former, err := q.FormerGitHubUsers(ctx, org, ghIDs)
			if err != nil {
				return nil, err
			}
			for _, k := range former {
				l.Formerly(k.GithubUserID, k.UserID)
			}
		}
		out = append(out, l)
	}
	return out, nil
}

// snapshotLinkedPeople keeps, for each people fact an independent
// requirement of a new request names, the users linked now to the people
// it lists (G0 M8 P2f, HR-207): they stay excluded from the request even
// if they unlink before it is decided.
func snapshotLinkedPeople(ctx context.Context, q *dbq.Queries, org ids.OrgID, request ids.UUID, reqs []apdomain.Requirement) error {
	lists, err := peopleLists(ctx, q, org, request, reqs)
	if err != nil {
		return err
	}
	for _, l := range lists {
		var users []ids.UUID
		for _, p := range l.People {
			if p.User != nil && !slices.Contains(users, *p.User) {
				users = append(users, *p.User)
			}
		}
		if len(users) == 0 {
			continue
		}
		if err := q.InsertRequestLinkedPeople(ctx, dbq.InsertRequestLinkedPeopleParams{
			OrgID: org, RequestID: request, Fact: l.Fact, UserIds: users,
		}); err != nil {
			return err
		}
	}
	return nil
}
