// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"slices"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	tdomain "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Change requests (G0 M11.1 design decision 11; HR-231, F1, F2). One
// mechanism serves every change that loosens what is enforced: a PUBLISH
// of a version that is not provably tighter (this package), a ROLLOUT pilot
// (S2) and an EXCEPTION (S3). A request needs confirmations from 2
// distinct persons holding policy.publish when the org has at least two
// such persons at request time, else from the one; each confirmation is a
// security-key BINDING ceremony over the request's binding, on the
// /policy-changes page, with distinct persons and distinct keys. On the
// last confirmation, in the same transaction, the base is checked again,
// the owning kind's apply callback runs and the request is APPROVED. A
// request expires 24 hours after it was made, by the database clock.

// ChangeKind is what a change request changes.
type ChangeKind string

// Change kinds.
const (
	ChangePublish   ChangeKind = "PUBLISH"
	ChangeRollout   ChangeKind = "ROLLOUT"
	ChangeException ChangeKind = "EXCEPTION"
)

// Change request states.
const (
	ChangePending  = "PENDING"
	ChangeApproved = "APPROVED"
	ChangeDeclined = "DECLINED"
	ChangeExpired  = "EXPIRED"
	ChangeVoided   = "VOIDED"
)

// Void reasons.
const (
	VoidBaseChanged = "BASE_CHANGED"
	VoidStaleTests  = "STALE_TESTS"
)

// ChangesPath is the page people confirm change requests on.
const ChangesPath = "/policy-changes"

// MaxSummaryBytes caps a request's summary (the classified changes).
const MaxSummaryBytes = 256 << 10

// MaxDeclineReason caps a decline's reason, stored and shown as untrusted
// text.
const MaxDeclineReason = 500

// Change request errors.
var (
	ErrChangeNotFound   = pcerr.New(pcerr.NotFound, "POLICY_CHANGE_NOT_FOUND", "policy change request not found")
	ErrChangeNotPending = pcerr.New(pcerr.FailedPrecondition, "POLICY_CHANGE_NOT_PENDING",
		"the change request was approved, declined, voided or has expired")
	ErrChangeExpired = pcerr.New(pcerr.FailedPrecondition, "POLICY_CHANGE_EXPIRED", "the change request has expired")
	ErrChangePending = pcerr.New(pcerr.FailedPrecondition, "POLICY_CHANGE_PENDING",
		"another change request for this already waits for confirmation; confirm or decline it first")
	ErrChangeVoided = pcerr.New(pcerr.FailedPrecondition, "POLICY_CHANGE_VOIDED",
		"the change request was voided: what it would change is no longer what was confirmed")
	ErrSamePerson = pcerr.New(pcerr.PermissionDenied, "SAME_PERSON", "each confirmation must come from a different person")
	ErrSameKey    = pcerr.New(pcerr.PermissionDenied, "SAME_KEY", "each confirmation needs a different security key")
	// ErrBrowserSession: only a person signed in on the page confirms.
	ErrBrowserSession = pcerr.New(pcerr.PermissionDenied, "BROWSER_SESSION_REQUIRED",
		"only a person signed in on the policy changes page confirms a change")
	// ErrChangeAssertion: the ceremony did not sign this request's binding.
	ErrChangeAssertion = pcerr.New(pcerr.InvalidArgument, "POLICY_CHANGE_CEREMONY",
		"the security key did not sign this change request")
	ErrDeclineReason = pcerr.New(pcerr.InvalidArgument, "REASON_REQUIRED", "a reason of 1 to 500 characters is required")
)

// VoidError, returned by an apply callback, voids the request with Reason
// instead of applying it.
type VoidError struct{ Reason string }

func (e *VoidError) Error() string { return "policy: change request voided: " + e.Reason }

// Confirmation is one person's confirmation.
type Confirmation struct {
	Principal  ids.UUID
	Credential ids.UUID
	At         time.Time
}

// ChangeRequest is a change waiting for, or done with, confirmations.
type ChangeRequest struct {
	ID            ids.UUID
	Kind          ChangeKind
	Subject       ids.UUID
	Base          ids.UUID // zero: none
	Binding       [32]byte
	Summary       []byte // JSON
	Required      int
	State         string
	RequestedBy   string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	DecidedAt     *time.Time
	DecidedReason string
	Confirmations []Confirmation
	URL           string
	// DefinitionsDigest and CatalogDigest are the org's current digests,
	// set for the apply callback (CheckTestsCurrent).
	DefinitionsDigest, CatalogDigest [32]byte
}

// ApplyFunc applies an approved request in the transaction that approves
// it; an error rolls everything back (a *VoidError voids the request).
type ApplyFunc func(ctx context.Context, tx db.TenantTx, req ChangeRequest) error

// Assertion is a verified BINDING ceremony a confirmation consumes.
type Assertion struct {
	Ceremony   ids.UUID
	Credential ids.UUID
}

// Notifier queues a notification in the caller's transaction (M5).
type Notifier interface {
	Enqueue(ctx context.Context, tx db.TenantTx, m napp.Message) (napp.Enqueued, error)
}

// CurrentDigests returns the digests of the org's active definitions and
// fact catalog now (D7a).
type CurrentDigests func(ctx context.Context, org ids.OrgID) (definitions, catalog [32]byte, err error)

// Changes serves change requests.
type Changes struct {
	pool      *db.Pool
	notify    Notifier
	publicURL string
	digests   CurrentDigests
	mu        sync.RWMutex
	apply     map[ChangeKind]ApplyFunc
}

// NewChanges returns the change requests. n may be nil (no notifications);
// digests may not.
func NewChanges(pool *db.Pool, n Notifier, publicURL string, digests CurrentDigests) *Changes {
	return &Changes{pool: pool, notify: n, publicURL: publicURL, digests: digests, apply: map[ChangeKind]ApplyFunc{}}
}

// Register sets the apply callback of a kind (its owning stream's). A
// request of a kind without one is never created.
func (c *Changes) Register(kind ChangeKind, f ApplyFunc) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.apply[kind] = f
}

func (c *Changes) applier(kind ChangeKind) ApplyFunc {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.apply[kind]
}

// URL is the page of one change request.
func (c *Changes) URL(org ids.OrgID, id ids.UUID) string {
	return c.publicURL + ChangesPath + "/" + id.String() + "?org=" + org.String()
}

func digest64(d [32]byte) string { return base64.RawURLEncoding.EncodeToString(d[:]) }

// ChangeBinding is what each confirmer's key signs: SHA-256 of
// JCS({kind, org, subject_id, base_version_id, content_digest |
// exception_digest, summary_digest}), hashes base64url without padding,
// base_version_id "" when there is none.
func ChangeBinding(kind ChangeKind, org ids.OrgID, subject, base ids.UUID, digest [32]byte, summary any) ([32]byte, error) {
	raw, err := json.Marshal(summary, json.Deterministic(true))
	if err != nil {
		return [32]byte{}, err
	}
	sv := jsontext.Value(raw)
	if err := sv.Canonicalize(); err != nil {
		return [32]byte{}, err
	}
	doc := map[string]string{
		"kind": string(kind), "org": org.String(), "subject_id": subject.String(), "base_version_id": "",
		"summary_digest": digest64(sha256.Sum256(sv)),
	}
	if !base.IsZero() {
		doc["base_version_id"] = base.String()
	}
	if kind == ChangeException {
		doc["exception_digest"] = digest64(digest)
	} else {
		doc["content_digest"] = digest64(digest)
	}
	b, err := json.Marshal(doc, json.Deterministic(true))
	if err != nil {
		return [32]byte{}, err
	}
	v := jsontext.Value(b)
	if err := v.Canonicalize(); err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(v), nil
}

// publisherRoles are the default roles holding policy.publish.
func publisherRoles() []string {
	var out []string
	for _, r := range tdomain.Roles() {
		if r.Has(tdomain.PermPolicyPublish) {
			out = append(out, string(r.Name))
		}
	}
	return out
}

// publishers are the active persons holding policy.publish at the org.
func publishers(ctx context.Context, q *dbq.Queries, org ids.OrgID) ([]ids.UUID, error) {
	return q.OrgUsersWithRoles(ctx, org, publisherRoles())
}

func record(ctx context.Context, tx db.TenantTx, c tapp.Caller, name string, id ids.UUID, details map[string]string) error {
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: c.Actor(), Outcome: audit.Success, Object: &audit.Object{Type: "policy_change_request", ID: id.String()},
		Details: details,
	})
	return err
}

// Request creates a change request (the calling use case checked the
// caller's permission; the caller must be a person). A pending request for
// the same subject with the same binding is returned as it is; one with
// another base is voided (BASE_CHANGED); any other pending one refuses
// with ErrChangePending. Eligible confirmers are notified.
func (c *Changes) Request(ctx context.Context, kind ChangeKind, subjectID, baseVersionID ids.UUID, binding [32]byte, summary any) (ChangeRequest, error) {
	caller, err := tapp.CallerFrom(ctx)
	if err != nil {
		return ChangeRequest{}, err
	}
	if !caller.Human() {
		return ChangeRequest{}, ErrHumanOnly
	}
	if c.applier(kind) == nil || c.digests == nil {
		return ChangeRequest{}, ErrGateUnavailable
	}
	raw, err := json.Marshal(summary, json.Deterministic(true))
	if err != nil {
		return ChangeRequest{}, err
	}
	if len(raw) > MaxSummaryBytes {
		return ChangeRequest{}, pcerr.New(pcerr.InvalidArgument, "POLICY_CHANGE_TOO_LARGE", "the change is too large to show for confirmation")
	}
	var base *ids.UUID
	if !baseVersionID.IsZero() {
		base = &baseVersionID
	}
	id := ids.NewV7()
	err = c.pool.InTenantTx(ctx, caller.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if _, err := q.ExpirePolicyChangeRequests(ctx, caller.Org); err != nil {
			return err
		}
		switch cur, err := q.PendingPolicyChangeRequest(ctx, caller.Org, string(kind), subjectID); {
		case db.IsNoRows(err):
		case err != nil:
			return err
		case bytes.Equal(cur.Binding, binding[:]):
			id = cur.ID
			return nil
		case !sameBase(cur.BaseVersionID, base):
			if _, err := q.DecidePolicyChangeRequest(ctx, dbq.DecidePolicyChangeRequestParams{
				State: ChangeVoided, Reason: new(VoidBaseChanged), OrgID: caller.Org, ID: cur.ID,
			}); err != nil {
				return err
			}
			if err := record(ctx, tx, caller, "policy.change_voided", cur.ID, map[string]string{"reason": VoidBaseChanged}); err != nil {
				return err
			}
		default:
			return ErrChangePending
		}
		people, err := publishers(ctx, q, caller.Org)
		if err != nil {
			return err
		}
		required := int16(1)
		if len(people) >= 2 {
			required = 2
		}
		if err := q.InsertPolicyChangeRequest(ctx, dbq.InsertPolicyChangeRequestParams{
			OrgID: caller.Org, ID: id, Kind: string(kind), SubjectID: subjectID, BaseVersionID: base, Binding: binding[:],
			Summary: raw, Required: required, RequestedBy: caller.Principal.String(),
		}); err != nil {
			return err
		}
		details := map[string]string{
			"kind": string(kind), "subject": subjectID.String(), "required": strconv.Itoa(int(required)),
			"binding": digest64(binding),
		}
		if base != nil {
			details["base_version"] = base.String()
		}
		if err := record(ctx, tx, caller, "policy.change_requested", id, details); err != nil {
			return err
		}
		if c.notify == nil {
			return nil
		}
		_, err = c.notify.Enqueue(ctx, tx, napp.Message{
			Org: caller.Org, Type: "policy.change_requested", Personal: people,
			Params:  map[string]string{"request": id.String(), "kind": string(kind), "user": caller.Principal.String()},
			Subject: &napp.Subject{Type: "policy_change_request", ID: id},
		})
		return err
	})
	if db.IsUniqueViolation(err) {
		return ChangeRequest{}, ErrChangePending
	}
	if err != nil {
		return ChangeRequest{}, err
	}
	return c.get(ctx, caller.Org, id)
}

func sameBase(a, b *ids.UUID) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// Get returns one change request with its confirmations (policy.read).
func (c *Changes) Get(ctx context.Context, id ids.UUID) (ChangeRequest, error) {
	caller, err := tapp.CallerFrom(ctx)
	if err != nil {
		return ChangeRequest{}, err
	}
	if err := caller.Require(tdomain.PermPolicyRead, tdomain.OrgPath(caller.Org)); err != nil {
		return ChangeRequest{}, err
	}
	return c.get(ctx, caller.Org, id)
}

func (c *Changes) get(ctx context.Context, org ids.OrgID, id ids.UUID) (ChangeRequest, error) {
	var out ChangeRequest
	err := c.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		r, err := q.GetPolicyChangeRequest(ctx, org, id)
		if db.IsNoRows(err) {
			return ErrChangeNotFound
		} else if err != nil {
			return err
		}
		out = c.of(org, dbq.ListPolicyChangeRequestsRow(r))
		return c.confirmations(ctx, q, org, &out)
	}, db.ReadOnly())
	return out, err
}

func (c *Changes) confirmations(ctx context.Context, q *dbq.Queries, org ids.OrgID, r *ChangeRequest) error {
	rows, err := q.ListPolicyChangeConfirmations(ctx, org, r.ID)
	if err != nil {
		return err
	}
	r.Confirmations = r.Confirmations[:0]
	for _, x := range rows {
		r.Confirmations = append(r.Confirmations, Confirmation{Principal: x.PrincipalID, Credential: x.CredentialID, At: x.CreatedAt})
	}
	return nil
}

// of converts a row; a pending request past its expiry reads as EXPIRED.
func (c *Changes) of(org ids.OrgID, r dbq.ListPolicyChangeRequestsRow) ChangeRequest {
	out := ChangeRequest{
		ID: r.ID, Kind: ChangeKind(r.Kind), Subject: r.SubjectID, Summary: r.Summary, Required: int(r.Required),
		State: r.State, RequestedBy: r.RequestedBy, CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt, DecidedAt: r.DecidedAt,
		URL: c.URL(org, r.ID),
	}
	copy(out.Binding[:], r.Binding)
	if r.BaseVersionID != nil {
		out.Base = *r.BaseVersionID
	}
	if r.DecidedReason != nil {
		out.DecidedReason = *r.DecidedReason
	}
	if r.Expired {
		out.State, out.DecidedReason = ChangeExpired, ChangeExpired
	}
	return out
}

// List lists change requests, newest first, optionally only those in one
// state (policy.read).
func (c *Changes) List(ctx context.Context, state string, limit int) ([]ChangeRequest, error) {
	caller, err := tapp.CallerFrom(ctx)
	if err != nil {
		return nil, err
	}
	if err := caller.Require(tdomain.PermPolicyRead, tdomain.OrgPath(caller.Org)); err != nil {
		return nil, err
	}
	var filter *string
	if state != "" {
		filter = &state
	}
	var out []ChangeRequest
	err = c.pool.InTenantTx(ctx, caller.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		rows, err := q.ListPolicyChangeRequests(ctx, caller.Org, filter, int32(min(max(limit, 1), 200)))
		if err != nil {
			return err
		}
		for _, r := range rows {
			x := c.of(caller.Org, r)
			if state != "" && x.State != state {
				continue // pending in the table, expired by the clock
			}
			if err := c.confirmations(ctx, q, caller.Org, &x); err != nil {
				return err
			}
			out = append(out, x)
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// MayConfirm reports whether the caller may confirm r now: a person
// signed in on the page, holding policy.publish, who has not confirmed it.
func MayConfirm(caller tapp.Caller, r ChangeRequest) bool {
	return r.State == ChangePending && confirmer(caller) == nil &&
		!slices.ContainsFunc(r.Confirmations, func(x Confirmation) bool { return x.Principal == caller.Principal.ID })
}

// confirmer checks that the caller may confirm or decline a change: a
// person holding policy.publish at the org, signed in on the page.
func confirmer(caller tapp.Caller) error {
	if err := caller.Require(tdomain.PermPolicyPublish, tdomain.OrgPath(caller.Org)); err != nil {
		return err
	}
	if !caller.Human() || caller.Credential != tapp.CredBrowserSession || caller.Session.IsZero() {
		return ErrBrowserSession
	}
	return nil
}

// Pending lists the pending requests the caller may still confirm (the
// page's list).
func (c *Changes) Pending(ctx context.Context) ([]ChangeRequest, error) {
	caller, err := tapp.CallerFrom(ctx)
	if err != nil {
		return nil, err
	}
	all, err := c.List(ctx, ChangePending, 200)
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
func (c *Changes) BeginConfirm(ctx context.Context, id ids.UUID) (ChangeRequest, error) {
	caller, err := tapp.CallerFrom(ctx)
	if err != nil {
		return ChangeRequest{}, err
	}
	if err := confirmer(caller); err != nil {
		return ChangeRequest{}, err
	}
	r, err := c.get(ctx, caller.Org, id)
	if err != nil {
		return ChangeRequest{}, err
	}
	switch {
	case r.State == ChangeExpired:
		return r, ErrChangeExpired
	case r.State != ChangePending:
		return r, ErrChangeNotPending
	case slices.ContainsFunc(r.Confirmations, func(x Confirmation) bool { return x.Principal == caller.Principal.ID }):
		return r, ErrSamePerson
	}
	return r, nil
}

// Confirm records the caller's confirmation with the ceremony that signed
// the request's binding (HR-231). The confirmation that reaches the
// required count applies the change in the same transaction: the base
// must still be the published version (else VOIDED BASE_CHANGED), then
// the kind's apply callback runs and the request is APPROVED.
func (c *Changes) Confirm(ctx context.Context, id ids.UUID, a Assertion) (ChangeRequest, error) {
	caller, err := tapp.CallerFrom(ctx)
	if err != nil {
		return ChangeRequest{}, err
	}
	if err := confirmer(caller); err != nil {
		return ChangeRequest{}, err
	}
	if c.digests == nil {
		return ChangeRequest{}, ErrGateUnavailable
	}
	defsDigest, catalogDigest, err := c.digests(ctx, caller.Org)
	if err != nil {
		return ChangeRequest{}, err
	}
	var voided string
	var expired bool
	err = c.pool.InTenantTx(ctx, caller.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		row, err := q.LockPolicyChangeRequest(ctx, caller.Org, id)
		if db.IsNoRows(err) {
			return ErrChangeNotFound
		} else if err != nil {
			return err
		}
		if row.Expired {
			if _, err := q.ExpirePolicyChangeRequests(ctx, caller.Org); err != nil {
				return err
			}
			expired = true // committed: the expiry is recorded
			return nil
		}
		if row.State != ChangePending {
			return ErrChangeNotPending
		}
		req := c.of(caller.Org, dbq.ListPolicyChangeRequestsRow(row))
		if err := c.confirmations(ctx, q, caller.Org, &req); err != nil {
			return err
		}
		for _, x := range req.Confirmations {
			switch {
			case x.Principal == caller.Principal.ID:
				return ErrSamePerson
			case x.Credential == a.Credential:
				return ErrSameKey
			}
		}
		if err := consumeCeremony(ctx, q, caller, req, a); err != nil {
			return err
		}
		if err := q.InsertPolicyChangeConfirmation(ctx, dbq.InsertPolicyChangeConfirmationParams{
			OrgID: caller.Org, RequestID: id, PrincipalID: caller.Principal.ID, CredentialID: a.Credential,
		}); err != nil {
			return err
		}
		n := len(req.Confirmations) + 1
		if err := record(ctx, tx, caller, "policy.change_confirmed", id, map[string]string{
			"kind": string(req.Kind), "confirmations": strconv.Itoa(n), "required": strconv.Itoa(req.Required),
			"security_key": a.Credential.String(), "ceremony": a.Ceremony.String(), "session": caller.Session.String(),
		}); err != nil {
			return err
		}
		if n < req.Required {
			return nil
		}
		if req.Kind == ChangePublish || req.Kind == ChangeRollout {
			cur, err := q.LockPublishedPolicyVersion(ctx, caller.Org)
			if db.IsNoRows(err) {
				cur, err = ids.UUID{}, nil
			}
			if err != nil {
				return err
			}
			if cur != req.Base {
				voided = VoidBaseChanged
				return c.void(ctx, tx, q, caller, id, voided)
			}
		}
		apply := c.applier(req.Kind)
		if apply == nil {
			return ErrGateUnavailable
		}
		req.DefinitionsDigest, req.CatalogDigest = defsDigest, catalogDigest
		if err := apply(ctx, tx, req); err != nil {
			return err
		}
		if err := oneRow(q.DecidePolicyChangeRequest(ctx, dbq.DecidePolicyChangeRequestParams{
			State: ChangeApproved, OrgID: caller.Org, ID: id,
		})); err != nil {
			return err
		}
		return record(ctx, tx, caller, "policy.change_approved", id, map[string]string{
			"kind": string(req.Kind), "subject": req.Subject.String(), "confirmations": strconv.Itoa(n),
		})
	})
	var ve *VoidError
	switch {
	case err == nil && expired:
		return ChangeRequest{}, ErrChangeExpired
	case errors.As(err, &ve):
		voided = ve.Reason
		if err := c.pool.InTenantTx(ctx, caller.Org, func(ctx context.Context, tx db.TenantTx) error {
			return c.void(ctx, tx, dbq.New(tx), caller, id, voided)
		}); err != nil {
			return ChangeRequest{}, err
		}
	case errors.Is(err, db.ErrLostRace):
		return ChangeRequest{}, ErrChangeNotPending
	case err != nil:
		return ChangeRequest{}, err
	}
	out, err := c.get(ctx, caller.Org, id)
	if err == nil && voided != "" {
		return out, ErrChangeVoided
	}
	return out, err
}

func (c *Changes) void(ctx context.Context, tx db.TenantTx, q *dbq.Queries, caller tapp.Caller, id ids.UUID, reason string) error {
	if err := oneRow(q.DecidePolicyChangeRequest(ctx, dbq.DecidePolicyChangeRequestParams{
		State: ChangeVoided, Reason: &reason, OrgID: caller.Org, ID: id,
	})); err != nil {
		return err
	}
	return record(ctx, tx, caller, "policy.change_voided", id, map[string]string{"reason": reason})
}

// consumeCeremony consumes the caller's open BINDING ceremony for the
// request in this browser session once, and only if it signed exactly the
// request's binding within its 5 minutes (HR-033, HR-153).
func consumeCeremony(ctx context.Context, q *dbq.Queries, caller tapp.Caller, req ChangeRequest, a Assertion) error {
	rid := req.ID
	cer, err := q.PolicyChangeCeremony(ctx, dbq.PolicyChangeCeremonyParams{
		OrgID: caller.Org, ID: a.Ceremony, RequestID: &rid, UserID: caller.Principal.ID, SessionID: caller.Session,
	})
	switch {
	case db.IsNoRows(err):
		return ErrChangeAssertion
	case err != nil:
		return err
	case !cer.Live || !bytes.Equal(cer.Challenge, req.Binding[:]):
		return ErrChangeAssertion
	}
	n, err := q.ConsumePolicyChangeCeremony(ctx, dbq.ConsumePolicyChangeCeremonyParams{
		OrgID: caller.Org, ID: a.Ceremony, RequestID: &rid, UserID: caller.Principal.ID, SessionID: caller.Session,
		Challenge: req.Binding[:],
	})
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrChangeAssertion
	}
	return nil
}

// Decline ends a pending request (DECLINED), by a person who may confirm
// it, with a reason.
func (c *Changes) Decline(ctx context.Context, id ids.UUID, reason string) (ChangeRequest, error) {
	caller, err := tapp.CallerFrom(ctx)
	if err != nil {
		return ChangeRequest{}, err
	}
	if n := utf8.RuneCountInString(reason); !utf8.ValidString(reason) || n < 1 || n > MaxDeclineReason {
		return ChangeRequest{}, ErrDeclineReason
	}
	if err := confirmer(caller); err != nil {
		return ChangeRequest{}, err
	}
	var expired bool
	err = c.pool.InTenantTx(ctx, caller.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		row, err := q.LockPolicyChangeRequest(ctx, caller.Org, id)
		if db.IsNoRows(err) {
			return ErrChangeNotFound
		} else if err != nil {
			return err
		}
		if row.Expired {
			if _, err := q.ExpirePolicyChangeRequests(ctx, caller.Org); err != nil {
				return err
			}
			expired = true // committed: the expiry is recorded
			return nil
		}
		if row.State != ChangePending {
			return ErrChangeNotPending
		}
		if err := oneRow(q.DecidePolicyChangeRequest(ctx, dbq.DecidePolicyChangeRequestParams{
			State: ChangeDeclined, Reason: &reason, OrgID: caller.Org, ID: id,
		})); err != nil {
			return err
		}
		sum := sha256.Sum256([]byte(reason))
		return record(ctx, tx, caller, "policy.change_declined", id, map[string]string{
			"kind": row.Kind, "reason_sha256": digest64(sum),
		})
	})
	switch {
	case err == nil && expired:
		return ChangeRequest{}, ErrChangeExpired
	case errors.Is(err, db.ErrLostRace):
		return ChangeRequest{}, ErrChangeNotPending
	case err != nil:
		return ChangeRequest{}, err
	}
	return c.get(ctx, caller.Org, id)
}

// CheckTestsCurrent voids an approval (STALE_TESTS) unless the newest
// passing test run of version's content ran against the org's current
// definitions and fact catalog, as req carries them.
func CheckTestsCurrent(ctx context.Context, tx db.TenantTx, org ids.OrgID, version ids.UUID, req ChangeRequest) (ids.UUID, error) {
	run, err := dbq.New(tx).LatestPassedTestRun(ctx, org, version)
	if db.IsNoRows(err) {
		return ids.UUID{}, &VoidError{Reason: VoidStaleTests}
	} else if err != nil {
		return ids.UUID{}, err
	}
	if !bytes.Equal(run.DefinitionsDigest, req.DefinitionsDigest[:]) || !bytes.Equal(run.CatalogDigest, req.CatalogDigest[:]) {
		return ids.UUID{}, &VoidError{Reason: VoidStaleTests}
	}
	return run.ID, nil
}

// oneRow is db.ExpectOneRow for an :execrows query.
func oneRow(n int64, err error) error {
	if err != nil {
		return err
	}
	if n != 1 {
		return db.ErrLostRace
	}
	return nil
}
