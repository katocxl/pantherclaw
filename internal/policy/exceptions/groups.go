// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package exceptions

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/cohorts"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	papp "github.com/katocxl/pantherclaw/internal/policy/app"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Exception groups (G0 M18 D154; F602, HR-477, T-209). A group waives one
// exceptable rule, for the listed operations, for the agents of a fleet
// cohort. It is requested and approved like an exception: PENDING until
// its EXCEPTION change request is confirmed, then ACTIVE for at most 30
// days. Membership is a snapshot taken in the confirming transaction: one
// exception row per agent the cohort holds then, each with the group's
// id. An agent that joins the cohort later is not covered, and the
// database refuses a member row for a group that is no longer PENDING.

// MaxGroupMembers is the most agents one group's snapshot holds (a
// cohort resolves to at most this many).
const MaxGroupMembers = cohorts.MaxMembers * 2

// Errors of the group use cases.
var (
	ErrGroupInvalid = pcerr.New(pcerr.InvalidArgument, "INVALID_POLICY_EXCEPTION_GROUP",
		"an exception group names a rule, a cohort, 1 to 16 distinct exact operations, a reason of 1 to 500 characters and a duration of a minute to 30 days")
	ErrGroupNotFound  = pcerr.New(pcerr.NotFound, "POLICY_EXCEPTION_GROUP_NOT_FOUND", "policy exception group not found")
	ErrCohortNotFound = pcerr.New(pcerr.NotFound, "COHORT_NOT_FOUND", "cohort not found")
)

// Group is one stored exception group.
type Group = dbq.PcPolicyExceptionGroup

// GroupRequest describes an exception group. A nil Owner makes the
// requester its owner.
type GroupRequest struct {
	Rule       string
	Cohort     ids.UUID
	Operations []string
	Reason     string
	ExpiresIn  time.Duration
	Owner      *ids.UUID
}

func (r GroupRequest) valid() bool {
	if r.Cohort.IsZero() {
		return false
	}
	// The same bounds as one agent's exception; any agent id stands in.
	return Request{Rule: r.Rule, Agent: r.Cohort, Operations: r.Operations, Reason: r.Reason, ExpiresIn: r.ExpiresIn}.valid()
}

// GroupSummary is what confirmers are shown of a group request. Reason is
// the requester's untrusted text; the agents are those the cohort holds
// when the last confirmation is given.
type GroupSummary struct {
	Kind            string   `json:"kind"`
	Group           string   `json:"group"`
	Bundle          string   `json:"bundle"`
	Rule            string   `json:"rule"`
	RuleKind        string   `json:"rule_kind"`
	RuleSummary     string   `json:"rule_summary"`
	Cohort          string   `json:"cohort"`
	CohortName      string   `json:"cohort_name"`
	Operations      []string `json:"operations"`
	Owner           string   `json:"owner"`
	RequestedExpiry string   `json:"requested_expiry"`
	Reason          string   `json:"reason"`
	Sentence        string   `json:"sentence"`
}

// GroupDigest is the digest a group's change request binds: SHA-256 of
// the JCS form of everything the group waives and for which cohort.
func GroupDigest(g Group) ([32]byte, error) {
	ops := slices.Clone(g.Operations)
	slices.Sort(ops)
	raw, err := json.Marshal(map[string]any{
		"id": g.ID.String(), "org": g.OrgID.String(), "group": true, "cohort_id": g.CohortID.String(), "bundle_id": g.BundleID,
		"rule_id": g.RuleID, "rule_digest": hex.EncodeToString(g.RuleDigest), "operations": ops, "reason": g.Reason,
		"owner_id": g.OwnerID.String(), "requested_by": g.RequestedBy.String(),
		"requested_expiry": g.RequestedExpiry.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return [32]byte{}, err
	}
	v := jsontext.Value(raw)
	if err := v.Canonicalize(); err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(v), nil
}

func summarizeGroup(g Group, r pdomain.Rule, cohortName string) GroupSummary {
	expiry := g.RequestedExpiry.UTC().Format(time.RFC3339)
	return GroupSummary{
		Kind: "EXCEPTION_GROUP", Group: g.ID.String(), Bundle: g.BundleID, Rule: r.ID, RuleKind: string(r.Kind), RuleSummary: r.Summary,
		Cohort: g.CohortID.String(), CohortName: cohortName, Operations: g.Operations, Owner: g.OwnerID.String(),
		RequestedExpiry: expiry, Reason: g.Reason,
		Sentence: "Rule " + r.ID + " would not apply to the agents cohort " + cohortName + " holds when this is approved, for " +
			strings.Join(g.Operations, ", ") + " until " + expiry + " at the latest (looser). Agents that join the cohort later stay covered by the rule.",
	}
}

// RequestGroup records a PENDING exception group and its EXCEPTION change
// request: as RequestException, for a fleet cohort instead of one agent.
func (s *Service) RequestGroup(ctx context.Context, r GroupRequest) (Group, ChangeRequest, error) {
	var out Group
	var cr ChangeRequest
	var base ids.UUID
	var binding [32]byte
	var summary GroupSummary
	if !r.valid() {
		return out, cr, ErrGroupInvalid
	}
	c, err := requester(ctx, td.PermPolicyExceptionRequest)
	if err != nil {
		return out, cr, err
	}
	if err := s.largeFleet(ctx); err != nil {
		return out, cr, err
	}
	if s.Changes == nil {
		return out, cr, ErrNoChangeRequests
	}
	owner := c.Principal.ID
	if r.Owner != nil {
		owner = *r.Owner
	}
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		rule, bundle, pub, err := exceptableRule(ctx, q, c.Org, r.Rule, r.Operations)
		if err != nil {
			return err
		}
		co, err := q.GetFleetCohort(ctx, c.Org, r.Cohort)
		if db.IsNoRows(err) {
			return ErrCohortNotFound
		} else if err != nil {
			return err
		}
		if u, err := q.GetUser(ctx, c.Org, owner); db.IsNoRows(err) || (err == nil && u.State != "ACTIVE") {
			return ErrOwner
		} else if err != nil {
			return err
		}
		digest := pdomain.RuleDigest(rule)
		ops := slices.Clone(r.Operations)
		slices.Sort(ops)
		out, err = q.InsertPolicyExceptionGroup(ctx, dbq.InsertPolicyExceptionGroupParams{
			OrgID: c.Org, ID: ids.NewV7(), CohortID: co.ID, BundleID: bundle, RuleID: rule.ID, RuleDigest: digest[:],
			Operations: ops, Reason: strings.TrimSpace(r.Reason), OwnerID: owner, RequestedBy: c.Principal.ID,
			ExpiresInSeconds: int64(r.ExpiresIn / time.Second),
		})
		if err != nil {
			return err
		}
		gd, err := GroupDigest(out)
		if err != nil {
			return err
		}
		base, summary = pub, summarizeGroup(out, rule, co.Name)
		binding, err = papp.ChangeBinding(papp.ChangeException, c.Org, out.ID, base, gd, summary)
		if err != nil {
			return err
		}
		return s.auditGroup(ctx, tx, c.Actor(), out, "policy.exception_group_requested", nil)
	})
	if err != nil {
		return out, cr, err
	}
	req, err := s.Changes.Request(ctx, papp.ChangeException, out.ID, base, binding, summary)
	if err != nil {
		if derr := s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := s.DeclineGroup(ctx, tx, c.Org, out.ID)
			return err
		}); derr != nil {
			return out, cr, errors.Join(err, derr)
		}
		return out, cr, err
	}
	return out, ChangeRequest{ID: req.ID, URL: req.URL}, nil
}

// exceptableRule returns the published rule a request names, checked as
// RequestException checks it, with the bundle id and the published
// version.
func exceptableRule(ctx context.Context, q *dbq.Queries, org ids.OrgID, id string, ops []string) (pdomain.Rule, string, ids.UUID, error) {
	pub, err := q.GetPublishedPolicy(ctx, org)
	if db.IsNoRows(err) {
		return pdomain.Rule{}, "", ids.UUID{}, ErrNoPolicy
	} else if err != nil {
		return pdomain.Rule{}, "", ids.UUID{}, err
	}
	b, err := decodeBundle(pub.Bundle)
	if err != nil {
		return pdomain.Rule{}, "", ids.UUID{}, err
	}
	i := slices.IndexFunc(b.Rules, func(x pdomain.Rule) bool { return x.ID == id })
	if i < 0 {
		return pdomain.Rule{}, "", ids.UUID{}, ErrRuleNotFound
	}
	rule := b.Rules[i]
	if !rule.Exceptable {
		return pdomain.Rule{}, "", ids.UUID{}, ErrNotExceptable
	}
	for _, op := range ops {
		if !rule.CoversOperation(op) {
			return pdomain.Rule{}, "", ids.UUID{}, ErrOperation
		}
	}
	return rule, b.ID, pub.ID, nil
}

// ActivateGroup activates a pending group in the confirming transaction
// (HR-477). It re-checks the rule as Activate does (else ErrBaseChanged),
// that the cohort still exists (else ErrBaseChanged) and that the
// requested expiry has not passed (else ErrRequestExpired). It then takes
// the snapshot: one member row per agent the cohort holds now, retired
// agents left out, all activated with the group, whose owner is told
// once.
func (s *Service) ActivateGroup(ctx context.Context, tx db.TenantTx, org ids.OrgID, id ids.UUID) (Group, error) {
	q := dbq.New(tx)
	g, err := q.LockPolicyExceptionGroup(ctx, org, id)
	if db.IsNoRows(err) {
		return g, ErrGroupNotFound
	} else if err != nil {
		return g, err
	}
	switch g.State {
	case StatePending:
	case StateRevoked:
		return g, ErrRevoked
	case StateExpired:
		return g, ErrRequestExpired
	default:
		return g, ErrNotPending
	}
	if err := ruleHolds(ctx, q, org, g.BundleID, g.RuleID, g.RuleDigest); err != nil {
		return g, err
	}
	now, err := q.DBNow(ctx)
	if err != nil {
		return g, err
	}
	if !g.RequestedExpiry.After(now) {
		return g, ErrRequestExpired
	}
	agents, err := cohorts.Resolve(ctx, tx, g.CohortID, MaxGroupMembers)
	if errors.Is(err, cohorts.ErrNotFound) {
		return g, ErrBaseChanged
	} else if err != nil {
		return g, err
	}
	for _, a := range agents {
		if _, err := q.InsertPolicyExceptionGroupMember(ctx, dbq.InsertPolicyExceptionGroupMemberParams{
			ID: ids.NewV7(), AgentID: a, OrgID: org, GroupID: g.ID,
		}); err != nil {
			return g, err
		}
	}
	members, err := q.ActivatePolicyExceptionGroupMembers(ctx, org, g.ID)
	if err != nil {
		return g, err
	}
	if len(members) != len(agents) {
		return g, ErrRequestExpired
	}
	g, err = q.ActivatePolicyExceptionGroup(ctx, org, g.ID)
	if db.IsNoRows(err) {
		return g, ErrRequestExpired
	} else if err != nil {
		return g, err
	}
	for _, x := range members {
		if err := s.audit(ctx, tx, system, x, "policy.exception_activated", map[string]string{
			"expires": x.ExpiresAt.UTC().Format(time.RFC3339), "group": g.ID.String(),
		}); err != nil {
			return g, err
		}
	}
	if err := s.auditGroup(ctx, tx, system, g, "policy.exception_group_activated", map[string]string{
		"expires": g.ExpiresAt.UTC().Format(time.RFC3339),
	}); err != nil {
		return g, err
	}
	return g, s.notifyGroup(ctx, tx, g, "policy.exception_activated", "")
}

// DeclineGroup closes a pending group whose change request ended without
// approval.
func (s *Service) DeclineGroup(ctx context.Context, tx db.TenantTx, org ids.OrgID, id ids.UUID) (Group, error) {
	g, err := dbq.New(tx).DeclinePolicyExceptionGroup(ctx, org, id)
	if db.IsNoRows(err) {
		return g, ErrNotPending
	} else if err != nil {
		return g, err
	}
	return g, s.auditGroup(ctx, tx, system, g, "policy.exception_group_declined", nil)
}

// RevokeGroup ends a pending or active group and every open member row
// at once (a person holding policy.publish, any time).
func (s *Service) RevokeGroup(ctx context.Context, id ids.UUID, reason string) (Group, error) {
	var out Group
	reason = strings.TrimSpace(reason)
	if n := utf8.RuneCountInString(reason); n < 1 || n > MaxReason {
		return out, ErrGroupInvalid
	}
	c, err := requester(ctx, td.PermPolicyPublish)
	if err != nil {
		return out, err
	}
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		var err error
		out, err = q.RevokePolicyExceptionGroup(ctx, dbq.RevokePolicyExceptionGroupParams{
			RevokedBy: &c.Principal.ID, RevokedReason: &reason, OrgID: c.Org, ID: id,
		})
		if db.IsNoRows(err) {
			if _, gerr := q.GetPolicyExceptionGroup(ctx, c.Org, id); db.IsNoRows(gerr) {
				return ErrGroupNotFound
			}
			return ErrNotOpen
		} else if err != nil {
			return err
		}
		members, err := q.RevokePolicyExceptionGroupMembers(ctx, dbq.RevokePolicyExceptionGroupMembersParams{
			RevokedBy: &c.Principal.ID, RevokedReason: &reason, OrgID: c.Org, GroupID: id,
		})
		if err != nil {
			return err
		}
		for _, x := range members {
			if err := s.audit(ctx, tx, c.Actor(), x, "policy.exception_revoked", map[string]string{"group": id.String()}); err != nil {
				return err
			}
		}
		return s.auditGroup(ctx, tx, c.Actor(), out, "policy.exception_group_revoked", map[string]string{
			"members_revoked": strconv.Itoa(len(members)),
		})
	})
	return out, err
}

// ListedGroup is a group as read, with an open one past its expiry read
// as EXPIRED, and the agents its snapshot holds.
type ListedGroup struct {
	Group
	EffectiveState string
	Agents         []ids.UUID
}

// GetGroup returns one group with its agents (policy.read at the org).
func (s *Service) GetGroup(ctx context.Context, id ids.UUID) (ListedGroup, error) {
	var out ListedGroup
	c, err := reader(ctx)
	if err != nil {
		return out, err
	}
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		g, err := q.ReadPolicyExceptionGroup(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrGroupNotFound
		} else if err != nil {
			return err
		}
		out = listedGroup(dbq.ListPolicyExceptionGroupsPageRow(g))
		out.Agents, err = q.PolicyExceptionGroupAgents(ctx, c.Org, id)
		return err
	}, db.ReadOnly())
	return out, err
}

// GroupFilter narrows a group listing.
type GroupFilter struct {
	Cohort *ids.UUID
	State  *string
}

// ListGroups lists groups newest first, without their agents (policy.read
// at the org).
func (s *Service) ListGroups(ctx context.Context, f GroupFilter, size int32, token string) ([]ListedGroup, string, error) {
	p, err := page.Parse(size, token)
	if err != nil {
		return nil, "", err
	}
	c, err := reader(ctx)
	if err != nil {
		return nil, "", err
	}
	var out []ListedGroup
	var next string
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		var before *ids.UUID
		if !p.After.IsZero() {
			before = &p.After
		}
		rows, err := dbq.New(tx).ListPolicyExceptionGroupsPage(ctx, dbq.ListPolicyExceptionGroupsPageParams{
			OrgID: c.Org, CohortID: f.Cohort, State: f.State, Before: before, MaxRows: p.Limit(),
		})
		if err != nil {
			return err
		}
		rows, next = page.Finish(p, rows, func(x dbq.ListPolicyExceptionGroupsPageRow) ids.UUID { return x.ID })
		for _, x := range rows {
			out = append(out, listedGroup(x))
		}
		return nil
	}, db.ReadOnly())
	return out, next, err
}

func listedGroup(x dbq.ListPolicyExceptionGroupsPageRow) ListedGroup {
	return ListedGroup{Group: Group{
		OrgID: x.OrgID, ID: x.ID, CohortID: x.CohortID, BundleID: x.BundleID, RuleID: x.RuleID, RuleDigest: x.RuleDigest,
		Operations: x.Operations, Reason: x.Reason, OwnerID: x.OwnerID, RequestedBy: x.RequestedBy,
		RequestedExpiry: x.RequestedExpiry, State: x.State, ActivatedAt: x.ActivatedAt, ExpiresAt: x.ExpiresAt, Members: x.Members,
		RevokedBy: x.RevokedBy, RevokedReason: x.RevokedReason, CreatedAt: x.CreatedAt,
	}, EffectiveState: x.EffectiveState}
}

// sweepGroups is the group half of Sweep, in its transaction: groups past
// their expiry become EXPIRED (their member rows expire with the
// exceptions), pending ones whose request ended are declined, and owners
// of groups ending within a day are told once.
func (s *Service) sweepGroups(ctx context.Context, tx db.TenantTx, org ids.OrgID) error {
	q := dbq.New(tx)
	expired, err := q.ExpirePolicyExceptionGroups(ctx, org, maxPerSweep)
	if err != nil {
		return err
	}
	for _, g := range expired {
		if err := s.auditGroup(ctx, tx, system, g, "policy.exception_group_expired", nil); err != nil {
			return err
		}
	}
	declined, err := q.DeclineEndedPolicyExceptionGroups(ctx, org, maxPerSweep)
	if err != nil {
		return err
	}
	for _, g := range declined {
		if err := s.auditGroup(ctx, tx, system, g, "policy.exception_group_declined", nil); err != nil {
			return err
		}
	}
	expiring, err := q.ExpiringPolicyExceptionGroups(ctx, org, int64(ExpiringWithin/time.Second), maxPerSweep)
	if err != nil {
		return err
	}
	for _, g := range expiring {
		if err := s.notifyGroup(ctx, tx, g, "policy.exception_expiring", "policy.exception_expiring:"+g.ID.String()); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) auditGroup(ctx context.Context, tx db.TenantTx, actor evdomain.Actor, g Group, name string, extra map[string]string) error {
	details := map[string]string{
		"bundle": g.BundleID, "rule": g.RuleID, "cohort": g.CohortID.String(), "operations": strings.Join(g.Operations, ","),
		"owner": g.OwnerID.String(), "reason_length": strconv.Itoa(utf8.RuneCountInString(g.Reason)),
	}
	if g.Members != nil {
		details["members"] = strconv.Itoa(int(*g.Members))
	}
	for k, v := range extra {
		details[k] = v
	}
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: actor, Outcome: audit.Success, Object: &audit.Object{Type: "policy_exception_group", ID: g.ID.String()},
		Details: details,
	})
	return err
}

// notifyGroup tells a group's owner once, with the cohort's id and how
// many agents the snapshot holds in place of one agent (HR-158: ids and
// counts, never a name or the reason).
func (s *Service) notifyGroup(ctx context.Context, tx db.TenantTx, g Group, typ, dedupe string) error {
	if s.Notify == nil {
		return nil
	}
	n := 0
	if g.Members != nil {
		n = int(*g.Members)
	}
	_, err := s.Notify.Enqueue(ctx, tx, napp.Message{
		Org: g.OrgID, Type: typ, Personal: []ids.UUID{g.OwnerID}, PersonalOnly: true, DedupeKey: dedupe,
		Params: map[string]string{
			"rule": g.RuleID, "agent": strconv.Itoa(n) + " agents of cohort " + g.CohortID.String(),
			"operations": strings.Join(g.Operations, ", "), "expires": g.ExpiresAt.UTC().Format("2006-01-02 15:04 UTC"),
			"exception": g.ID.String(),
		},
	})
	return err
}

// Editions reports the licence's entitlements.
type Editions interface {
	Current(ctx context.Context) (billing.Entitlements, error)
}

// ErrGroupEdition: requesting an exception group needs the Enterprise
// edition (D161). Groups already approved keep applying, and reading or
// revoking them works in every edition.
var ErrGroupEdition = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED",
	"exception groups need the Enterprise edition")

// largeFleet refuses unless the licence includes large-fleet
// administration (fail closed without an edition source).
func (s *Service) largeFleet(ctx context.Context) error {
	if s.Editions == nil {
		return ErrGroupEdition
	}
	e, err := s.Editions.Current(ctx)
	if err != nil {
		return err
	}
	if !e.LargeFleetAdmin() {
		return ErrGroupEdition
	}
	return nil
}
