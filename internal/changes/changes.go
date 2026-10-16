// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package changes is the generic M11 BINDING ceremony (G0 M11 part 2 D6;
// HR-272, HR-292, HR-293): a change request asks to apply exact content
// (named by its digest) of one domain's kind to one subject. It applies
// only when `required` distinct people, each eligible for its kind and not
// marked compromised, confirm it with distinct security keys in a BINDING
// ceremony over its binding, on the /changes/{id} page. The confirmation
// that reaches the required count runs the kind's Apply in the same
// transaction. New content or a new state of the subject voids pending
// requests (Void); a request expires 24 hours after it was made, by the
// database clock.
//
// Domains register their kinds: automations (ENABLE, ROLLOUT), protected
// changes (one kind per category) and compromised publishers (CLEAR).
package changes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"regexp"
	"slices"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

	autoports "github.com/katocxl/pantherclaw/internal/automations/ports"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Domains.
const (
	DomainAutomation = "automation"
	DomainProtected  = "protected"
	DomainPublisher  = "publisher"
)

// States.
const (
	StatePending  = "PENDING"
	StateApproved = "APPROVED"
	StateDeclined = "DECLINED"
	StateExpired  = "EXPIRED"
	StateVoided   = "VOIDED"
)

// Void reasons used by this package.
const (
	VoidReplaced    = "REPLACED"
	VoidNotEligible = "CONFIRMER_NOT_ELIGIBLE"
)

// Path is the page people confirm change requests on.
const Path = "/changes"

// Bounds.
const (
	MaxSummaryBytes  = 16 << 10
	MaxDeclineReason = 500
	TTL              = 24 * time.Hour
)

var kindPattern = regexp.MustCompile(`^[A-Z][A-Z_]{1,40}$`)

// Errors.
var (
	ErrNotFound   = pcerr.New(pcerr.NotFound, "CHANGE_NOT_FOUND", "change request not found")
	ErrNotPending = pcerr.New(pcerr.FailedPrecondition, "CHANGE_NOT_PENDING",
		"the change request was approved, declined, voided or has expired")
	ErrExpired = pcerr.New(pcerr.FailedPrecondition, "CHANGE_EXPIRED", "the change request has expired")
	ErrVoided  = pcerr.New(pcerr.FailedPrecondition, "CHANGE_VOIDED",
		"the change request was voided: what it would change is no longer what was confirmed")
	ErrSamePerson = pcerr.New(pcerr.PermissionDenied, "SAME_PERSON", "each confirmation must come from a different person")
	ErrSameKey    = pcerr.New(pcerr.PermissionDenied, "SAME_KEY", "each confirmation needs a different security key")
	ErrNotEligible = pcerr.New(pcerr.PermissionDenied, "NOT_ELIGIBLE",
		"you cannot confirm this change: it needs permissions you do not hold where it acts")
	ErrCompromised = pcerr.New(pcerr.PermissionDenied, "PUBLISHER_COMPROMISED",
		"you are marked as a compromised publisher and cannot confirm changes")
	ErrBrowserSession = pcerr.New(pcerr.PermissionDenied, "BROWSER_SESSION_REQUIRED",
		"only a person signed in on the change page confirms a change")
	ErrAssertion     = pcerr.New(pcerr.InvalidArgument, "CHANGE_CEREMONY", "the security key did not sign this change request")
	ErrDeclineReason = pcerr.New(pcerr.InvalidArgument, "REASON_REQUIRED", "a reason of 1 to 500 characters is required")
	ErrHumanOnly     = pcerr.New(pcerr.PermissionDenied, "HUMAN_ONLY", "only a person can do this")
	ErrUnknownKind   = pcerr.New(pcerr.FailedPrecondition, "CHANGE_KIND_UNAVAILABLE", "this kind of change cannot be requested here")
	ErrTooLarge      = pcerr.New(pcerr.InvalidArgument, "CHANGE_TOO_LARGE", "the change is too large to show for confirmation")
)

// VoidError, returned by Apply, voids the request with Reason instead of
// applying it.
type VoidError struct{ Reason string }

func (e *VoidError) Error() string { return "changes: request voided: " + e.Reason }

// Confirmation is one person's confirmation.
type Confirmation struct {
	User       ids.UUID
	Credential ids.UUID
	At         time.Time
}

// Request is a change waiting for, or done with, confirmations.
type Request struct {
	Org           ids.OrgID
	ID            ids.UUID
	Domain        string
	Kind          string
	Subject       ids.UUID
	ContentDigest [32]byte
	Binding       [32]byte
	Summary       []byte // JSON object
	Required      int
	State         string
	RequestedBy   string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	DecidedAt     *time.Time
	DecidedReason string
	Confirmations []Confirmation
	URL           string
}

// Confirmers returns the confirming people in confirmation order.
func (r Request) Confirmers() []ids.UUID {
	out := make([]ids.UUID, 0, len(r.Confirmations))
	for _, c := range r.Confirmations {
		out = append(out, c.User)
	}
	return out
}

// Handler is one kind's rules (D6). Permission is what a person needs to
// see the domain's requests. Required says how many people must confirm
// (1 or 2, fixed at request time). Eligible says whether a person may
// confirm now (checked at confirmation and again for every earlier
// confirmer when the last one applies it). Apply runs in the confirming
// transaction with every confirmer; a *VoidError voids the request.
type Handler struct {
	Permission td.Permission
	Required   func(ctx context.Context, tx db.TenantTx, r Request) (int, error)
	Eligible   func(ctx context.Context, tx db.TenantTx, r Request, user ids.UUID) (ok bool, reason string, err error)
	Apply      func(ctx context.Context, tx db.TenantTx, r Request, confirmers []ids.UUID) error
}

// Assertion is a verified BINDING ceremony a confirmation consumes.
type Assertion struct {
	Ceremony   ids.UUID
	Credential ids.UUID
}

// Service serves change requests.
type Service struct {
	Pool      *db.Pool
	PublicURL string
	// Compromise reports compromised people (protect, D43); nil: nobody.
	Compromise autoports.CompromiseChecker

	mu       sync.RWMutex
	handlers map[string]Handler
}

// New returns the service.
func New(pool *db.Pool, publicURL string) *Service {
	return &Service{Pool: pool, PublicURL: publicURL, handlers: map[string]Handler{}}
}

func key(domain, kind string) string { return domain + "/" + kind }

// Register sets a kind's handler. A kind without one is never requested.
func (s *Service) Register(domain, kind string, h Handler) {
	if !kindPattern.MatchString(kind) || h.Required == nil || h.Eligible == nil || h.Apply == nil {
		panic("changes: invalid handler for " + key(domain, kind))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handlers == nil {
		s.handlers = map[string]Handler{}
	}
	s.handlers[key(domain, kind)] = h
}

func (s *Service) handler(domain, kind string) (Handler, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	h, ok := s.handlers[key(domain, kind)]
	return h, ok
}

// URL is the page of one change request.
func (s *Service) URL(org ids.OrgID, id ids.UUID) string {
	return s.PublicURL + Path + "/" + id.String() + "?org=" + org.String()
}

func digest64(d []byte) string { return base64.RawURLEncoding.EncodeToString(d) }

// Binding is what each confirmer's key signs: SHA-256 of JCS({domain,
// kind, org, subject_id, content_digest, summary_digest}), digests
// base64url without padding (the construction of the M11.1 policy change
// binding).
func Binding(domain, kind string, org ids.OrgID, subject ids.UUID, content [32]byte, summary []byte) ([32]byte, error) {
	sv := jsontext.Value(bytes.Clone(summary))
	if err := sv.Canonicalize(); err != nil {
		return [32]byte{}, err
	}
	sd := sha256.Sum256(sv)
	b, err := json.Marshal(map[string]string{
		"domain": domain, "kind": kind, "org": org.String(), "subject_id": subject.String(),
		"content_digest": digest64(content[:]), "summary_digest": digest64(sd[:]),
	}, json.Deterministic(true))
	if err != nil {
		return [32]byte{}, err
	}
	v := jsontext.Value(b)
	if err := v.Canonicalize(); err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(v), nil
}

func record(ctx context.Context, tx db.TenantTx, c tapp.Caller, name string, r Request, details map[string]string) error {
	if details == nil {
		details = map[string]string{}
	}
	details["domain"], details["kind"], details["subject"] = r.Domain, r.Kind, r.Subject.String()
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: c.Actor(), Outcome: audit.Success, Object: &audit.Object{Type: "change_request", ID: r.ID.String()},
		Details: details,
	})
	return err
}

// Requested is what Request creates.
type Requested struct {
	Domain   string
	Kind     string
	Subject  ids.UUID
	Content  [32]byte
	Summary  any
	Required int // 0: ask the handler
}

// Request creates a change request; the calling use case checked the
// caller's permission to ask for it. The caller must be a person. A
// pending request of the same kind for the same subject with the same
// binding is returned as it is; another one is voided (REPLACED). It runs
// in its own transaction.
func (s *Service) Request(ctx context.Context, in Requested) (Request, error) {
	caller, err := tapp.CallerFrom(ctx)
	if err != nil {
		return Request{}, err
	}
	var out Request
	err = s.Pool.InTenantTx(ctx, caller.Org, func(ctx context.Context, tx db.TenantTx) error {
		out, err = s.RequestTx(ctx, tx, caller, in)
		return err
	})
	if db.IsUniqueViolation(err) {
		return Request{}, db.ErrLostRace
	}
	if err != nil {
		return Request{}, err
	}
	return s.get(ctx, caller.Org, out.ID)
}

// RequestTx is Request in the caller's transaction.
func (s *Service) RequestTx(ctx context.Context, tx db.TenantTx, caller tapp.Caller, in Requested) (Request, error) {
	if !caller.Human() {
		return Request{}, ErrHumanOnly
	}
	h, ok := s.handler(in.Domain, in.Kind)
	if !ok {
		return Request{}, ErrUnknownKind
	}
	raw, err := json.Marshal(in.Summary, json.Deterministic(true))
	if err != nil {
		return Request{}, err
	}
	if len(raw) > MaxSummaryBytes || len(raw) < 2 || raw[0] != '{' {
		return Request{}, ErrTooLarge
	}
	binding, err := Binding(in.Domain, in.Kind, caller.Org, in.Subject, in.Content, raw)
	if err != nil {
		return Request{}, err
	}
	q := dbq.New(tx)
	if err := s.expire(ctx, tx, q, caller); err != nil {
		return Request{}, err
	}
	pending, err := q.ListChangeRequests(ctx, dbq.ListChangeRequestsParams{
		OrgID: caller.Org, Domain: &in.Domain, SubjectID: &in.Subject, States: []string{StatePending}, MaxRows: 20,
	})
	if err != nil {
		return Request{}, err
	}
	for _, p := range pending {
		if p.Kind != in.Kind {
			continue
		}
		if bytes.Equal(p.Binding, binding[:]) {
			return s.of(caller.Org, dbq.GetChangeRequestRow(p)), nil
		}
		if err := s.decide(ctx, tx, q, caller, s.of(caller.Org, dbq.GetChangeRequestRow(p)), StateVoided, VoidReplaced); err != nil {
			return Request{}, err
		}
	}
	req := Request{
		Org: caller.Org, ID: ids.NewV7(), Domain: in.Domain, Kind: in.Kind, Subject: in.Subject, ContentDigest: in.Content,
		Binding: binding, Summary: raw, State: StatePending, RequestedBy: caller.Principal.String(),
	}
	req.Required = in.Required
	if req.Required == 0 {
		if req.Required, err = h.Required(ctx, tx, req); err != nil {
			return Request{}, err
		}
	}
	req.Required = min(max(req.Required, 1), 2)
	if err := q.InsertChangeRequest(ctx, dbq.InsertChangeRequestParams{
		OrgID: caller.Org, ID: req.ID, Domain: req.Domain, Kind: req.Kind, SubjectID: req.Subject,
		ContentDigest: req.ContentDigest[:], Binding: binding[:], Summary: raw, Required: int16(req.Required), //nolint:gosec // 1..2
		RequestedBy: req.RequestedBy, TtlSeconds: int32(TTL / time.Second),
	}); err != nil {
		return Request{}, err
	}
	if err := record(ctx, tx, caller, "change.requested", req, map[string]string{
		"required": strconv.Itoa(req.Required), "binding": digest64(binding[:]), "content_digest": digest64(req.ContentDigest[:]),
	}); err != nil {
		return Request{}, err
	}
	req.URL = s.URL(caller.Org, req.ID)
	return req, nil
}

// expire records every pending request past its expiry as EXPIRED.
func (s *Service) expire(ctx context.Context, tx db.TenantTx, q *dbq.Queries, caller tapp.Caller) error {
	rows, err := q.ExpireChangeRequests(ctx, caller.Org)
	if err != nil {
		return err
	}
	for _, r := range rows {
		if err := record(ctx, tx, caller, "change.expired", Request{ID: r.ID, Domain: r.Domain, Kind: r.Kind}, nil); err != nil {
			return err
		}
	}
	return nil
}

// Void voids every pending request of domain about subject (new content or
// a new state of the subject), in the caller's transaction. It returns the
// voided ids.
func (s *Service) Void(ctx context.Context, tx db.TenantTx, actor tapp.Caller, domain string, subject ids.UUID, reason string) ([]ids.UUID, error) {
	rows, err := dbq.New(tx).VoidChangeRequests(ctx, dbq.VoidChangeRequestsParams{
		Reason: &reason, OrgID: tx.OrgID(), Domain: domain, SubjectID: subject,
	})
	if err != nil {
		return nil, err
	}
	out := make([]ids.UUID, 0, len(rows))
	for _, r := range rows {
		if err := record(ctx, tx, actor, "change.voided", Request{ID: r.ID, Domain: domain, Kind: r.Kind, Subject: subject},
			map[string]string{"reason": reason}); err != nil {
			return nil, err
		}
		out = append(out, r.ID)
	}
	return out, nil
}

// VoidByPerson voids every pending request a person asked for or
// confirmed (a compromised publisher, D43), in the caller's transaction.
func (s *Service) VoidByPerson(ctx context.Context, tx db.TenantTx, actor tapp.Caller, user ids.UUID, reason string) ([]ids.UUID, error) {
	rows, err := dbq.New(tx).VoidChangeRequestsConfirmedBy(ctx, dbq.VoidChangeRequestsConfirmedByParams{
		Reason: &reason, OrgID: tx.OrgID(), RequestedBy: td.PrincipalRef{Kind: td.KindUser, ID: user}.String(), UserID: user,
	})
	if err != nil {
		return nil, err
	}
	out := make([]ids.UUID, 0, len(rows))
	for _, r := range rows {
		if err := record(ctx, tx, actor, "change.voided", Request{ID: r.ID, Domain: r.Domain, Kind: r.Kind},
			map[string]string{"reason": reason}); err != nil {
			return nil, err
		}
		out = append(out, r.ID)
	}
	return out, nil
}

// Get returns one request with its confirmations, for a person who may see
// its domain's requests.
func (s *Service) Get(ctx context.Context, id ids.UUID) (Request, error) {
	caller, err := tapp.CallerFrom(ctx)
	if err != nil {
		return Request{}, err
	}
	r, err := s.get(ctx, caller.Org, id)
	if err != nil {
		return Request{}, err
	}
	if !s.mayRead(caller, r) {
		return Request{}, ErrNotFound
	}
	return r, nil
}

func (s *Service) mayRead(caller tapp.Caller, r Request) bool {
	h, ok := s.handler(r.Domain, r.Kind)
	if !ok {
		return false
	}
	return caller.Can(h.Permission, td.OrgPath(caller.Org)) || caller.Principal.String() == r.RequestedBy
}

func (s *Service) get(ctx context.Context, org ids.OrgID, id ids.UUID) (Request, error) {
	var out Request
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = s.load(ctx, dbq.New(tx), org, id)
		return err
	}, db.ReadOnly())
	return out, err
}

func (s *Service) load(ctx context.Context, q *dbq.Queries, org ids.OrgID, id ids.UUID) (Request, error) {
	r, err := q.GetChangeRequest(ctx, org, id)
	if db.IsNoRows(err) {
		return Request{}, ErrNotFound
	} else if err != nil {
		return Request{}, err
	}
	out := s.of(org, r)
	return out, s.confirmations(ctx, q, org, &out)
}

func (s *Service) confirmations(ctx context.Context, q *dbq.Queries, org ids.OrgID, r *Request) error {
	rows, err := q.ListChangeConfirmations(ctx, org, r.ID)
	if err != nil {
		return err
	}
	r.Confirmations = r.Confirmations[:0]
	for _, x := range rows {
		r.Confirmations = append(r.Confirmations, Confirmation{User: x.UserID, Credential: x.CredentialID, At: x.ConfirmedAt})
	}
	return nil
}

// of converts a row; a pending request past its expiry reads as EXPIRED.
func (s *Service) of(org ids.OrgID, r dbq.GetChangeRequestRow) Request {
	out := Request{
		Org: org, ID: r.ID, Domain: r.Domain, Kind: r.Kind, Subject: r.SubjectID, Summary: r.Summary, Required: int(r.Required),
		State: r.State, RequestedBy: r.RequestedBy, CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt, DecidedAt: r.DecidedAt,
		URL: s.URL(org, r.ID),
	}
	copy(out.ContentDigest[:], r.ContentDigest)
	copy(out.Binding[:], r.Binding)
	if r.DecidedReason != nil {
		out.DecidedReason = *r.DecidedReason
	}
	if r.Expired && r.State == StatePending {
		out.State, out.DecidedReason = StateExpired, StateExpired
	}
	return out
}

// Filter narrows List.
type Filter struct {
	Domain  string
	Subject ids.UUID
	States  []string
	Before  ids.UUID
	Limit   int
}

// List lists the requests the caller may see, newest first.
func (s *Service) List(ctx context.Context, f Filter) ([]Request, error) {
	caller, err := tapp.CallerFrom(ctx)
	if err != nil {
		return nil, err
	}
	p := dbq.ListChangeRequestsParams{OrgID: caller.Org, States: f.States, MaxRows: int32(min(max(f.Limit, 1), 200))} //nolint:gosec // bounded
	if p.States == nil {
		p.States = []string{}
	}
	if f.Domain != "" {
		p.Domain = &f.Domain
	}
	if !f.Subject.IsZero() {
		p.SubjectID = &f.Subject
	}
	if !f.Before.IsZero() {
		p.BeforeID = &f.Before
	}
	var out []Request
	err = s.Pool.InTenantTx(ctx, caller.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		rows, err := q.ListChangeRequests(ctx, p)
		if err != nil {
			return err
		}
		for _, r := range rows {
			x := s.of(caller.Org, dbq.GetChangeRequestRow(r))
			if !s.mayRead(caller, x) {
				continue
			}
			if err := s.confirmations(ctx, q, caller.Org, &x); err != nil {
				return err
			}
			out = append(out, x)
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// browser checks that the caller is a person signed in on the page.
func browser(caller tapp.Caller) error {
	if !caller.Human() || caller.Credential != tapp.CredBrowserSession || caller.Session.IsZero() {
		return ErrBrowserSession
	}
	return nil
}

// eligible checks one person against the kind's rules and the compromise
// list.
func (s *Service) eligible(ctx context.Context, tx db.TenantTx, h Handler, r Request, user ids.UUID) error {
	if s.Compromise != nil {
		bad, err := s.Compromise.Compromised(ctx, tx.Pgx(), r.Org, user)
		if err != nil {
			return err
		}
		if bad {
			return ErrCompromised
		}
	}
	ok, reason, err := h.Eligible(ctx, tx, r, user)
	switch {
	case err != nil:
		return err
	case !ok:
		return pcerr.Wrap(ErrNotEligible, pcerr.PermissionDenied, "NOT_ELIGIBLE", reason)
	}
	return nil
}

// MayConfirm reports whether the caller may confirm r now (the page's
// button): it does not re-check eligibility, which BeginConfirm does.
func MayConfirm(caller tapp.Caller, r Request) bool {
	return r.State == StatePending && browser(caller) == nil &&
		!slices.ContainsFunc(r.Confirmations, func(x Confirmation) bool { return x.User == caller.Principal.ID })
}

// Pending lists the pending requests the caller may still confirm.
func (s *Service) Pending(ctx context.Context) ([]Request, error) {
	caller, err := tapp.CallerFrom(ctx)
	if err != nil {
		return nil, err
	}
	all, err := s.List(ctx, Filter{States: []string{StatePending}, Limit: 200})
	if err != nil {
		return nil, err
	}
	out := all[:0]
	for _, r := range all {
		if MayConfirm(caller, r) {
			out = append(out, r)
		}
	}
	return out, nil
}

// BeginConfirm checks that the caller may confirm the request now and
// returns it: the page then starts a BINDING ceremony over its binding.
func (s *Service) BeginConfirm(ctx context.Context, id ids.UUID) (Request, error) {
	caller, err := tapp.CallerFrom(ctx)
	if err != nil {
		return Request{}, err
	}
	if err := browser(caller); err != nil {
		return Request{}, err
	}
	var out Request
	err = s.Pool.InTenantTx(ctx, caller.Org, func(ctx context.Context, tx db.TenantTx) error {
		r, err := s.load(ctx, dbq.New(tx), caller.Org, id)
		if err != nil {
			return err
		}
		out = r
		h, ok := s.handler(r.Domain, r.Kind)
		switch {
		case !ok:
			return ErrUnknownKind
		case r.State == StateExpired:
			return ErrExpired
		case r.State != StatePending:
			return ErrNotPending
		case slices.ContainsFunc(r.Confirmations, func(x Confirmation) bool { return x.User == caller.Principal.ID }):
			return ErrSamePerson
		}
		return s.eligible(ctx, tx, h, r, caller.Principal.ID)
	}, db.ReadOnly())
	return out, err
}

// Confirm records the caller's confirmation with the ceremony that signed
// the request's binding. The confirmation that reaches the required count,
// counting only earlier confirmers who are still eligible, applies the
// change in the same transaction and approves the request.
func (s *Service) Confirm(ctx context.Context, id ids.UUID, a Assertion) (Request, error) {
	caller, err := tapp.CallerFrom(ctx)
	if err != nil {
		return Request{}, err
	}
	if err := browser(caller); err != nil {
		return Request{}, err
	}
	var voided string
	var expired bool
	err = s.Pool.InTenantTx(ctx, caller.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		row, err := q.LockChangeRequest(ctx, caller.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if row.Expired && row.State == StatePending {
			expired = true // committed: the expiry is recorded
			return s.expire(ctx, tx, q, caller)
		}
		if row.State != StatePending {
			return ErrNotPending
		}
		req := s.of(caller.Org, dbq.GetChangeRequestRow(row))
		if err := s.confirmations(ctx, q, caller.Org, &req); err != nil {
			return err
		}
		h, ok := s.handler(req.Domain, req.Kind)
		if !ok {
			return ErrUnknownKind
		}
		for _, x := range req.Confirmations {
			switch {
			case x.User == caller.Principal.ID:
				return ErrSamePerson
			case x.Credential == a.Credential:
				return ErrSameKey
			}
		}
		if err := s.eligible(ctx, tx, h, req, caller.Principal.ID); err != nil {
			return err
		}
		if err := consume(ctx, q, caller, req, a); err != nil {
			return err
		}
		if n, err := q.InsertChangeConfirmation(ctx, dbq.InsertChangeConfirmationParams{
			OrgID: caller.Org, RequestID: id, UserID: caller.Principal.ID, CredentialID: a.Credential,
		}); err != nil {
			return err
		} else if n != 1 {
			return ErrSamePerson
		}
		// Only earlier confirmers who are still eligible count (D7), in
		// confirmation order, then the caller.
		var confirmers []ids.UUID
		if len(req.Confirmations)+1 >= req.Required {
			for _, x := range req.Confirmations {
				switch err := s.eligible(ctx, tx, h, req, x.User); {
				case err == nil:
					confirmers = append(confirmers, x.User)
				case errors.Is(err, ErrNotEligible) || errors.Is(err, ErrCompromised):
				default:
					return err
				}
			}
		}
		confirmers = append(confirmers, caller.Principal.ID)
		if err := record(ctx, tx, caller, "change.confirmed", req, map[string]string{
			"confirmations": strconv.Itoa(len(req.Confirmations) + 1), "counted": strconv.Itoa(len(confirmers)),
			"required": strconv.Itoa(req.Required), "security_key": a.Credential.String(), "ceremony": a.Ceremony.String(),
			"session": caller.Session.String(),
		}); err != nil {
			return err
		}
		if len(confirmers) < req.Required {
			return nil
		}
		req.Confirmations = append(req.Confirmations, Confirmation{User: caller.Principal.ID, Credential: a.Credential})
		if err := h.Apply(ctx, tx, req, confirmers); err != nil {
			return err
		}
		return s.decide(ctx, tx, q, caller, req, StateApproved, "")
	})
	var ve *VoidError
	switch {
	case err == nil && expired:
		return Request{}, ErrExpired
	case errors.As(err, &ve):
		voided = ve.Reason
		if err := s.Pool.InTenantTx(ctx, caller.Org, func(ctx context.Context, tx db.TenantTx) error {
			q := dbq.New(tx)
			r, err := s.load(ctx, q, caller.Org, id)
			if err != nil {
				return err
			}
			return s.decide(ctx, tx, q, caller, r, StateVoided, voided)
		}); err != nil {
			return Request{}, err
		}
	case errors.Is(err, db.ErrLostRace):
		return Request{}, ErrNotPending
	case err != nil:
		return Request{}, err
	}
	out, err := s.get(ctx, caller.Org, id)
	if err == nil && voided != "" {
		return out, ErrVoided
	}
	return out, err
}

// decide ends a pending request and audits it.
func (s *Service) decide(ctx context.Context, tx db.TenantTx, q *dbq.Queries, caller tapp.Caller, r Request, state, reason string) error {
	p := dbq.DecideChangeRequestParams{State: state, OrgID: caller.Org, ID: r.ID}
	if reason != "" {
		p.Reason = &reason
	}
	n, err := q.DecideChangeRequest(ctx, p)
	if err != nil {
		return err
	}
	if n != 1 {
		return db.ErrLostRace
	}
	details := map[string]string{}
	name := "change.approved"
	switch state {
	case StateVoided:
		name, details["reason"] = "change.voided", reason
	case StateDeclined:
		sum := sha256.Sum256([]byte(reason))
		name, details["reason_sha256"] = "change.declined", digest64(sum[:])
	case StateApproved:
		details["confirmations"] = strconv.Itoa(len(r.Confirmations))
	}
	return record(ctx, tx, caller, name, r, details)
}

// consume consumes the caller's open BINDING ceremony for the request in
// this browser session once, and only if it signed exactly the request's
// binding within its 5 minutes (HR-033, HR-153).
func consume(ctx context.Context, q *dbq.Queries, caller tapp.Caller, req Request, a Assertion) error {
	rid := req.ID
	cer, err := q.ChangeRequestCeremony(ctx, dbq.ChangeRequestCeremonyParams{
		OrgID: caller.Org, ID: a.Ceremony, RequestID: &rid, UserID: caller.Principal.ID, SessionID: caller.Session,
	})
	switch {
	case db.IsNoRows(err):
		return ErrAssertion
	case err != nil:
		return err
	case !cer.Live || !bytes.Equal(cer.Challenge, req.Binding[:]):
		return ErrAssertion
	}
	n, err := q.ConsumeChangeRequestCeremony(ctx, dbq.ConsumeChangeRequestCeremonyParams{
		OrgID: caller.Org, ID: a.Ceremony, RequestID: &rid, UserID: caller.Principal.ID, SessionID: caller.Session,
		Challenge: req.Binding[:],
	})
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrAssertion
	}
	return nil
}

// Decline ends a pending request (DECLINED) with a reason, by its
// requester or a person eligible to confirm it.
func (s *Service) Decline(ctx context.Context, id ids.UUID, reason string) (Request, error) {
	caller, err := tapp.CallerFrom(ctx)
	if err != nil {
		return Request{}, err
	}
	if n := utf8.RuneCountInString(reason); !utf8.ValidString(reason) || n < 1 || n > MaxDeclineReason {
		return Request{}, ErrDeclineReason
	}
	if !caller.Human() {
		return Request{}, ErrHumanOnly
	}
	var expired bool
	err = s.Pool.InTenantTx(ctx, caller.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		row, err := q.LockChangeRequest(ctx, caller.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		req := s.of(caller.Org, dbq.GetChangeRequestRow(row))
		if !s.mayRead(caller, req) {
			return ErrNotFound
		}
		if row.Expired && row.State == StatePending {
			expired = true
			return s.expire(ctx, tx, q, caller)
		}
		if row.State != StatePending {
			return ErrNotPending
		}
		if req.RequestedBy != caller.Principal.String() {
			h, ok := s.handler(req.Domain, req.Kind)
			if !ok {
				return ErrUnknownKind
			}
			if err := s.eligible(ctx, tx, h, req, caller.Principal.ID); err != nil {
				return err
			}
		}
		return s.decide(ctx, tx, q, caller, req, StateDeclined, reason)
	})
	switch {
	case err == nil && expired:
		return Request{}, ErrExpired
	case errors.Is(err, db.ErrLostRace):
		return Request{}, ErrNotPending
	case err != nil:
		return Request{}, err
	}
	return s.get(ctx, caller.Org, id)
}
