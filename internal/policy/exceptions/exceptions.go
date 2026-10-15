// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package exceptions manages policy exceptions (G0 M11.1 D14; F208–F210,
// HR-235, founder decision F2). An exception waives one rule the publisher
// marked exceptable, for one agent and the listed operations, for at most
// 30 days. A person asks for it; it applies only once its EXCEPTION change
// request is confirmed like a loosening of the policy (F1), and the
// database clock then sets when it ends. It is never extended: renewal is
// a new request. Grants, guardrails, containment, identity, budgets,
// missing or stale facts, coverage and route modes are not policy rules,
// so no exception reaches them.
package exceptions

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Bounds of a request (D14).
const (
	MaxDuration   = 30 * 24 * time.Hour
	MinDuration   = time.Minute
	MaxOperations = 16
	MaxReason     = 500
)

// States.
const (
	StatePending  = "PENDING"
	StateActive   = "ACTIVE"
	StateDeclined = "DECLINED"
	StateRevoked  = "REVOKED"
	StateExpired  = "EXPIRED"
)

// Errors of the exception use cases.
var (
	ErrInvalid = pcerr.New(pcerr.InvalidArgument, "INVALID_POLICY_EXCEPTION",
		"an exception names a rule, an agent, 1 to 16 distinct exact operations, a reason of 1 to 500 characters and a duration of a minute to 30 days")
	ErrHumanOnly     = pcerr.New(pcerr.PermissionDenied, "HUMAN_ONLY", "only a person can do this")
	ErrNotFound      = pcerr.New(pcerr.NotFound, "POLICY_EXCEPTION_NOT_FOUND", "policy exception not found")
	ErrNoPolicy      = pcerr.New(pcerr.FailedPrecondition, "POLICY_NOT_PUBLISHED", "no policy is published")
	ErrRuleNotFound  = pcerr.New(pcerr.NotFound, "POLICY_RULE_NOT_FOUND", "the published policy has no such rule")
	ErrNotExceptable = pcerr.New(pcerr.FailedPrecondition, "POLICY_RULE_NOT_EXCEPTABLE",
		"the rule is not exceptable: only a rule its publisher marked exceptable can be waived")
	ErrOperation = pcerr.New(pcerr.InvalidArgument, "OPERATION_OUTSIDE_RULE",
		"every operation must be an exact operation inside the rule's scope")
	ErrAgentNotFound = pcerr.New(pcerr.NotFound, "AGENT_NOT_FOUND", "agent not found")
	ErrOwner         = pcerr.New(pcerr.InvalidArgument, "INVALID_EXCEPTION_OWNER", "the owner must be an active person of the organization")
	ErrNotOpen       = pcerr.New(pcerr.FailedPrecondition, "POLICY_EXCEPTION_NOT_OPEN", "the exception is no longer pending or active")
	ErrNotPending    = pcerr.New(pcerr.FailedPrecondition, "POLICY_EXCEPTION_NOT_PENDING",
		"the exception is no longer pending, or its requested expiry has passed")
	// ErrBaseChanged and ErrRequestExpired void an EXCEPTION change request at
	// its last confirmation (D23): BASE_CHANGED when the rule changed, is no
	// longer exceptable or published, or the agent was retired; EXPIRED when
	// the requested expiry has passed.
	ErrBaseChanged = pcerr.New(pcerr.FailedPrecondition, "BASE_CHANGED",
		"the rule is no longer exceptable as requested in the published policy, or the agent is retired")
	ErrRequestExpired = pcerr.New(pcerr.FailedPrecondition, "EXPIRED", "the requested expiry of the exception has passed")
	// ErrNoChangeRequests: without the change-request mechanism an exception
	// could never be approved, so none is requested (fail closed).
	ErrNoChangeRequests = pcerr.New(pcerr.FailedPrecondition, "CHANGE_REQUESTS_UNAVAILABLE",
		"policy change requests are not available on this server")
)

var operationPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+){1,7}$`)

// Notifier enqueues notifications (M5).
type Notifier interface {
	Enqueue(ctx context.Context, tx db.TenantTx, m napp.Message) (napp.Enqueued, error)
}

// ChangeRequest is the EXCEPTION change request created for a request.
type ChangeRequest struct {
	ID  ids.UUID
	URL string
}

// ChangeRequester creates the EXCEPTION change request (D11) whose
// approval activates the exception, in the request's transaction.
type ChangeRequester interface {
	RequestException(ctx context.Context, tx db.TenantTx, x Exception, base ids.UUID, digest [32]byte, summary Summary) (ChangeRequest, error)
}

// Service runs the exception use cases.
type Service struct {
	Pool    *db.Pool
	Notify  Notifier
	Changes ChangeRequester
}

// Exception is one stored exception.
type Exception = dbq.PcPolicyException

// Request describes an exception. A nil Owner makes the requester its
// owner.
type Request struct {
	Rule       string
	Agent      ids.UUID
	Operations []string
	Reason     string
	ExpiresIn  time.Duration
	Owner      *ids.UUID
}

func (r Request) valid() bool {
	reason := strings.TrimSpace(r.Reason)
	n := utf8.RuneCountInString(reason)
	if n < 1 || n > MaxReason || r.ExpiresIn < MinDuration || r.ExpiresIn > MaxDuration || r.Rule == "" || len(r.Rule) > 64 ||
		len(r.Operations) < 1 || len(r.Operations) > MaxOperations || r.Agent.IsZero() {
		return false
	}
	seen := map[string]bool{}
	for _, op := range r.Operations {
		if !operationPattern.MatchString(op) || seen[op] {
			return false
		}
		seen[op] = true
	}
	return true
}

// Summary is what confirmers are shown of a request (the change request's
// summary). Reason is the requester's untrusted text.
type Summary struct {
	Kind            string   `json:"kind"`
	Exception       string   `json:"exception"`
	Bundle          string   `json:"bundle"`
	Rule            string   `json:"rule"`
	RuleKind        string   `json:"rule_kind"`
	RuleSummary     string   `json:"rule_summary"`
	Agent           string   `json:"agent"`
	AgentName       string   `json:"agent_name"`
	Operations      []string `json:"operations"`
	Owner           string   `json:"owner"`
	RequestedExpiry string   `json:"requested_expiry"`
	Reason          string   `json:"reason"`
	Sentence        string   `json:"sentence"`
}

// Digest is the exception digest a change request binds (D11): SHA-256 of
// the JCS form of everything the exception waives and for whom.
func Digest(x Exception) ([32]byte, error) {
	ops := slices.Clone(x.Operations)
	slices.Sort(ops)
	raw, err := json.Marshal(map[string]any{
		"id": x.ID.String(), "org": x.OrgID.String(), "bundle_id": x.BundleID, "rule_id": x.RuleID,
		"rule_digest": hex.EncodeToString(x.RuleDigest), "agent_id": x.AgentID.String(), "operations": ops,
		"reason": x.Reason, "owner_id": x.OwnerID.String(), "requested_by": x.RequestedBy.String(),
		"requested_expiry": x.RequestedExpiry.UTC().Format(time.RFC3339Nano),
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

// requester is the caller, who must be a person signed in as themselves.
func requester(ctx context.Context, p td.Permission) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	if !c.Human() || c.Credential == tenancy.CredAPIKey {
		return c, ErrHumanOnly
	}
	return c, c.Require(p, td.OrgPath(c.Org))
}

// RequestException records a PENDING exception and its EXCEPTION change
// request (HR-235): only a person holding policy.exception.request asks,
// for a rule that is exceptable in the published version, and only for
// exact operations inside the rule's scope.
func (s *Service) RequestException(ctx context.Context, r Request) (Exception, ChangeRequest, error) {
	var out Exception
	var cr ChangeRequest
	if !r.valid() {
		return out, cr, ErrInvalid
	}
	c, err := requester(ctx, td.PermPolicyExceptionRequest)
	if err != nil {
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
		pub, err := q.GetPublishedPolicy(ctx, c.Org)
		if db.IsNoRows(err) {
			return ErrNoPolicy
		} else if err != nil {
			return err
		}
		b, err := decodeBundle(pub.Bundle)
		if err != nil {
			return err
		}
		i := slices.IndexFunc(b.Rules, func(x pdomain.Rule) bool { return x.ID == r.Rule })
		if i < 0 {
			return ErrRuleNotFound
		}
		rule := b.Rules[i]
		if !rule.Exceptable {
			return ErrNotExceptable
		}
		for _, op := range r.Operations {
			if !rule.CoversOperation(op) {
				return ErrOperation
			}
		}
		agent, err := q.GetAgent(ctx, c.Org, r.Agent)
		if db.IsNoRows(err) || (err == nil && agent.State == "RETIRED") {
			return ErrAgentNotFound
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
		out, err = q.InsertPolicyException(ctx, dbq.InsertPolicyExceptionParams{
			OrgID: c.Org, ID: ids.NewV7(), BundleID: b.ID, RuleID: rule.ID, RuleDigest: digest[:], AgentID: r.Agent,
			Operations: ops, Reason: strings.TrimSpace(r.Reason), OwnerID: owner, RequestedBy: c.Principal.ID,
			ExpiresInSeconds: int64(r.ExpiresIn / time.Second),
		})
		if err != nil {
			return err
		}
		xd, err := Digest(out)
		if err != nil {
			return err
		}
		cr, err = s.Changes.RequestException(ctx, tx, out, pub.ID, xd, summarize(out, rule, agent.Name))
		if err != nil {
			return err
		}
		return s.audit(ctx, tx, c.Actor(), out, "policy.exception_requested", map[string]string{"change_request": cr.ID.String()})
	})
	return out, cr, err
}

func summarize(x Exception, r pdomain.Rule, agentName string) Summary {
	expiry := x.RequestedExpiry.UTC().Format(time.RFC3339)
	return Summary{
		Kind: "EXCEPTION", Exception: x.ID.String(), Bundle: x.BundleID, Rule: r.ID, RuleKind: string(r.Kind), RuleSummary: r.Summary,
		Agent: x.AgentID.String(), AgentName: agentName, Operations: x.Operations, Owner: x.OwnerID.String(),
		RequestedExpiry: expiry, Reason: x.Reason,
		Sentence: "Rule " + r.ID + " would not apply to agent " + agentName + " for " + strings.Join(x.Operations, ", ") +
			" until " + expiry + " at the latest (looser).",
	}
}

// Activate is the EXCEPTION change request's apply callback: in the
// confirming transaction it re-checks that the rule still exists in the
// published version, is exceptable and has the digest the exception names,
// that the agent is not retired (else ErrBaseChanged) and that the
// requested expiry has not passed (else ErrRequestExpired), D23. Then the
// pending exception becomes ACTIVE, the database clock sets its expiry and
// its owner is told.
func (s *Service) Activate(ctx context.Context, tx db.TenantTx, org ids.OrgID, id ids.UUID) (Exception, error) {
	q := dbq.New(tx)
	x, err := q.GetPolicyException(ctx, org, id)
	if db.IsNoRows(err) {
		return x, ErrNotFound
	} else if err != nil {
		return x, err
	}
	if x.State != StatePending {
		return x, ErrNotPending
	}
	if err := baseHolds(ctx, q, x); err != nil {
		return x, err
	}
	x, err = q.ActivatePolicyException(ctx, org, id)
	if db.IsNoRows(err) {
		// Still pending (checked above, in this transaction): only the
		// requested expiry can have stopped it.
		return x, ErrRequestExpired
	} else if err != nil {
		return x, err
	}
	if err := s.audit(ctx, tx, system, x, "policy.exception_activated", map[string]string{
		"expires": x.ExpiresAt.UTC().Format(time.RFC3339),
	}); err != nil {
		return x, err
	}
	return x, s.notify(ctx, tx, x, "policy.exception_activated", "")
}

// baseHolds reports ErrBaseChanged unless the exception's rule is still in
// the published version, exceptable and unchanged, and its agent is not
// retired.
func baseHolds(ctx context.Context, q *dbq.Queries, x Exception) error {
	pub, err := q.GetPublishedPolicy(ctx, x.OrgID)
	if db.IsNoRows(err) {
		return ErrBaseChanged
	} else if err != nil {
		return err
	}
	b, err := decodeBundle(pub.Bundle)
	if err != nil {
		return err
	}
	i := slices.IndexFunc(b.Rules, func(r pdomain.Rule) bool { return r.ID == x.RuleID })
	if b.ID != x.BundleID || i < 0 || !b.Rules[i].Exceptable {
		return ErrBaseChanged
	}
	if d := pdomain.RuleDigest(b.Rules[i]); !bytes.Equal(d[:], x.RuleDigest) {
		return ErrBaseChanged
	}
	agent, err := q.GetAgent(ctx, x.OrgID, x.AgentID)
	if db.IsNoRows(err) || (err == nil && agent.State == "RETIRED") {
		return ErrBaseChanged
	}
	return err
}

// Decline closes a pending exception whose change request ended without
// approval (declined, expired or voided).
func (s *Service) Decline(ctx context.Context, tx db.TenantTx, org ids.OrgID, id ids.UUID) (Exception, error) {
	x, err := dbq.New(tx).DeclinePolicyException(ctx, org, id)
	if db.IsNoRows(err) {
		return x, ErrNotPending
	} else if err != nil {
		return x, err
	}
	return x, s.audit(ctx, tx, system, x, "policy.exception_declined", nil)
}

// RevokeException ends a pending or active exception at once (a person
// holding policy.publish, any time).
func (s *Service) RevokeException(ctx context.Context, id ids.UUID, reason string) (Exception, error) {
	var out Exception
	reason = strings.TrimSpace(reason)
	if n := utf8.RuneCountInString(reason); n < 1 || n > MaxReason {
		return out, ErrInvalid
	}
	c, err := requester(ctx, td.PermPolicyPublish)
	if err != nil {
		return out, err
	}
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = dbq.New(tx).RevokePolicyException(ctx, dbq.RevokePolicyExceptionParams{
			RevokedBy: &c.Principal.ID, RevokedReason: &reason, OrgID: c.Org, ID: id,
		})
		if db.IsNoRows(err) {
			if _, gerr := dbq.New(tx).GetPolicyException(ctx, c.Org, id); db.IsNoRows(gerr) {
				return ErrNotFound
			}
			return ErrNotOpen
		} else if err != nil {
			return err
		}
		return s.audit(ctx, tx, c.Actor(), out, "policy.exception_revoked", nil)
	})
	return out, err
}

// Listed is an exception as read, with an open one past its expiry read
// as EXPIRED.
type Listed struct {
	Exception
	EffectiveState string
}

// GetException returns one exception (policy.read at the org).
func (s *Service) GetException(ctx context.Context, id ids.UUID) (Listed, error) {
	var out Listed
	c, err := reader(ctx)
	if err != nil {
		return out, err
	}
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		x, err := dbq.New(tx).ReadPolicyException(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		out = listed(dbq.ListPolicyExceptionsPageRow(x))
		return nil
	})
	return out, err
}

// Filter narrows a listing.
type Filter struct {
	Agent *ids.UUID
	Rule  *string
	State *string
}

// ListExceptions lists exceptions newest first (policy.read at the org).
func (s *Service) ListExceptions(ctx context.Context, f Filter, size int32, token string) ([]Listed, string, error) {
	p, err := page.Parse(size, token)
	if err != nil {
		return nil, "", err
	}
	c, err := reader(ctx)
	if err != nil {
		return nil, "", err
	}
	var out []Listed
	var next string
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		var before *ids.UUID
		if !p.After.IsZero() {
			before = &p.After
		}
		rows, err := dbq.New(tx).ListPolicyExceptionsPage(ctx, dbq.ListPolicyExceptionsPageParams{
			OrgID: c.Org, AgentID: f.Agent, RuleID: f.Rule, State: f.State, Before: before, MaxRows: p.Limit(),
		})
		if err != nil {
			return err
		}
		rows, next = page.Finish(p, rows, func(x dbq.ListPolicyExceptionsPageRow) ids.UUID { return x.ID })
		for _, x := range rows {
			out = append(out, listed(x))
		}
		return nil
	})
	return out, next, err
}

func listed(x dbq.ListPolicyExceptionsPageRow) Listed {
	return Listed{Exception: Exception{
		OrgID: x.OrgID, ID: x.ID, BundleID: x.BundleID, RuleID: x.RuleID, RuleDigest: x.RuleDigest, AgentID: x.AgentID,
		Operations: x.Operations, Reason: x.Reason, OwnerID: x.OwnerID, RequestedBy: x.RequestedBy,
		RequestedExpiry: x.RequestedExpiry, State: x.State, ActivatedAt: x.ActivatedAt, ExpiresAt: x.ExpiresAt,
		RevokedBy: x.RevokedBy, RevokedReason: x.RevokedReason, CreatedAt: x.CreatedAt,
	}, EffectiveState: x.EffectiveState}
}

func reader(ctx context.Context) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	return c, c.Require(td.PermPolicyRead, td.OrgPath(c.Org))
}

// ActiveFor returns the exceptions that can waive a rule for an agent now,
// by the database clock, in the caller's transaction (the Authority's
// snapshot read).
func ActiveFor(ctx context.Context, tx db.TenantTx, org ids.OrgID, agent ids.UUID) ([]pdomain.Exception, error) {
	rows, err := dbq.New(tx).ActivePolicyExceptionsForAgent(ctx, org, agent)
	if err != nil {
		return nil, err
	}
	out := make([]pdomain.Exception, 0, len(rows))
	for _, x := range rows {
		out = append(out, pdomain.Exception{
			ID: x.ID.String(), Rule: x.RuleID, RuleDigest: hex.EncodeToString(x.RuleDigest),
			Operations: slices.Clone(x.Operations), ExpiresAt: x.ExpiresAt.UTC(),
		})
	}
	return out, nil
}

// system is the audit actor of approvals and the sweep.
var system = evdomain.Actor{Type: "system", ID: "policy-exceptions"}

func (s *Service) audit(ctx context.Context, tx db.TenantTx, actor evdomain.Actor, x Exception, name string, extra map[string]string) error {
	details := map[string]string{
		"bundle": x.BundleID, "rule": x.RuleID, "agent": x.AgentID.String(), "operations": strings.Join(x.Operations, ","),
		"owner": x.OwnerID.String(), "reason_length": strconv.Itoa(utf8.RuneCountInString(x.Reason)),
	}
	for k, v := range extra {
		details[k] = v
	}
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: actor, Outcome: audit.Success, Object: &audit.Object{Type: "policy_exception", ID: x.ID.String()},
		Details: details,
	})
	return err
}

// notify tells an exception's owner (only them) of its activation or its
// coming expiry, with the rule, agent and operations in fixed words and
// never its reason (HR-158).
func (s *Service) notify(ctx context.Context, tx db.TenantTx, x Exception, typ, dedupe string) error {
	if s.Notify == nil {
		return nil
	}
	agent, err := dbq.New(tx).GetAgent(ctx, x.OrgID, x.AgentID)
	if err != nil {
		return err
	}
	_, err = s.Notify.Enqueue(ctx, tx, napp.Message{
		Org: x.OrgID, Type: typ, Personal: []ids.UUID{x.OwnerID}, PersonalOnly: true, DedupeKey: dedupe,
		Params: map[string]string{
			"rule": x.RuleID, "agent": agent.Name, "operations": strings.Join(x.Operations, ", "),
			"expires": x.ExpiresAt.UTC().Format("2006-01-02 15:04 UTC"), "exception": x.ID.String(),
		},
	})
	return err
}

func decodeBundle(raw []byte) (*pdomain.Bundle, error) {
	var b pdomain.Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, err
	}
	return &b, nil
}
