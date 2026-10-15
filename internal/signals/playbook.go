// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package signals

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"slices"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The identity playbook (G0 M10 D38; HR-262, founder decision F1). Off by
// default. Enabling or changing it needs a request confirmed by two
// distinct people holding signals.manage, each with a distinct security
// key, each in a BINDING ceremony over the request's binding on
// /integrations/playbook/{id}/confirm; disabling needs one. Nothing else
// changes it: no API call, key or link. When enabled, an accepted event
// of one of its types about a person matched by OIDC issuer and subject
// (never by email alone, D46) asks Response to contain that person (a
// principal DENY_ALL) and the grants they issued, and voids their waiting
// approvals. Lifting those controls is a restoration only (D24).

// Playbook request kinds and states.
const (
	PlaybookEnable  = "ENABLE"
	PlaybookDisable = "DISABLE"
	PlaybookChange  = "CHANGE"

	RequestPending  = "PENDING"
	RequestApplied  = "APPLIED"
	RequestDeclined = "DECLINED"
	RequestExpired  = "EXPIRED"
	RequestVoided   = "VOIDED"
)

// PlaybookPath is where a playbook request is confirmed.
const PlaybookPath = "/integrations/playbook"

// MaxPlaybookReason caps a decline's reason (untrusted text).
const MaxPlaybookReason = 500

// Playbook errors.
var (
	ErrPlaybookInvalid = pcerr.New(pcerr.InvalidArgument, "INVALID_PLAYBOOK_REQUEST",
		"enabling or changing the playbook names 1 to 6 distinct Shared Signals event types it acts on; disabling names none")
	ErrPlaybookUnavailable = pcerr.New(pcerr.FailedPrecondition, "PLAYBOOK_UNAVAILABLE",
		"containment is not available on this server, so the identity playbook cannot be enabled")
	ErrPlaybookState = pcerr.New(pcerr.FailedPrecondition, "PLAYBOOK_STATE",
		"enable a disabled playbook, change or disable an enabled one")
	ErrPlaybookPending = pcerr.New(pcerr.FailedPrecondition, "PLAYBOOK_REQUEST_PENDING",
		"another playbook request waits for confirmation; confirm or decline it first")
	ErrRequestNotFound   = pcerr.New(pcerr.NotFound, "PLAYBOOK_REQUEST_NOT_FOUND", "playbook request not found")
	ErrRequestNotPending = pcerr.New(pcerr.FailedPrecondition, "PLAYBOOK_REQUEST_NOT_PENDING",
		"the playbook request was applied, declined, voided or has expired")
	ErrRequestExpired  = pcerr.New(pcerr.FailedPrecondition, "PLAYBOOK_REQUEST_EXPIRED", "the playbook request has expired")
	ErrRequestVoided   = pcerr.New(pcerr.FailedPrecondition, "PLAYBOOK_REQUEST_VOIDED", "the playbook changed since the request was made")
	ErrSamePerson      = pcerr.New(pcerr.PermissionDenied, "SAME_PERSON", "each confirmation must come from a different person")
	ErrSameKey         = pcerr.New(pcerr.PermissionDenied, "SAME_KEY", "each confirmation needs a different security key")
	ErrBrowserSession  = pcerr.New(pcerr.PermissionDenied, "BROWSER_SESSION_REQUIRED", "only a person signed in on the page confirms")
	ErrCeremony        = pcerr.New(pcerr.InvalidArgument, "PLAYBOOK_CEREMONY", "the security key did not sign this playbook request")
	ErrPlaybookReason  = pcerr.New(pcerr.InvalidArgument, "REASON_REQUIRED", "a reason of 1 to 500 characters is required")
	errPlaybookVoidKey = "BASE_CHANGED"
)

// Playbook is the org's playbook.
type Playbook struct {
	Enabled   bool
	Events    []string
	Version   int
	Request   *ids.UUID
	UpdatedAt time.Time
}

// Confirmation is one person's confirmation of a playbook request.
type Confirmation struct {
	Principal  ids.UUID
	Credential ids.UUID
	At         time.Time
}

// PlaybookRequest is a playbook change waiting for, or done with, its
// confirmations.
type PlaybookRequest struct {
	ID            ids.UUID
	Kind          string
	Events        []string
	BaseVersion   int
	Binding       [32]byte
	Required      int
	State         string
	RequestedBy   ids.UUID
	CreatedAt     time.Time
	ExpiresAt     time.Time
	DecidedAt     *time.Time
	DecidedReason string
	Confirmations []Confirmation
	URL           string
}

// Assertion is a verified BINDING ceremony a confirmation consumes.
type Assertion struct {
	Ceremony   ids.UUID
	Credential ids.UUID
}

// PlaybookBinding is what each confirmation signs: SHA-256 of the canonical
// request (version 1): kind, org, request id, the event types in order and
// the playbook version it changes.
func PlaybookBinding(kind string, org ids.OrgID, id ids.UUID, events []string, base int) ([32]byte, error) {
	sorted := slices.Clone(events)
	slices.Sort(sorted)
	if sorted == nil {
		sorted = []string{}
	}
	raw, err := json.Marshal(struct {
		V       int      `json:"v"`
		Purpose string   `json:"purpose"`
		Kind    string   `json:"kind"`
		Org     string   `json:"org"`
		Request string   `json:"request"`
		Events  []string `json:"events"`
		Base    int      `json:"base_version"`
	}{1, "pantherclaw.identity_playbook", kind, org.String(), id.String(), sorted, base}, json.Deterministic(true))
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(raw), nil
}

func validPlaybookEvents(kind string, events []string) bool {
	if kind == PlaybookDisable {
		return len(events) == 0
	}
	if len(events) == 0 || len(events) > len(Handled) {
		return false
	}
	seen := map[string]bool{}
	for _, e := range events {
		if !handled(e) || seen[e] {
			return false
		}
		seen[e] = true
	}
	return true
}

// GetPlaybook returns the org's playbook (signals.read).
func (s *Service) GetPlaybook(ctx context.Context) (Playbook, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Playbook{}, err
	}
	if err := c.Require(PermRead, td.OrgPath(c.Org)); err != nil {
		return Playbook{}, err
	}
	var out Playbook
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		out, err = playbookOf(ctx, dbq.New(tx), c.Org)
		return err
	}, db.ReadOnly())
	return out, err
}

func playbookOf(ctx context.Context, q *dbq.Queries, org ids.OrgID) (Playbook, error) {
	r, err := q.GetIdentityPlaybook(ctx, org)
	if db.IsNoRows(err) {
		return Playbook{Events: []string{}}, nil
	} else if err != nil {
		return Playbook{}, err
	}
	return Playbook{Enabled: r.Enabled, Events: r.Events, Version: int(r.Version), Request: r.RequestID, UpdatedAt: r.UpdatedAt}, nil
}

// RequestPlaybookChange asks for the playbook to be enabled, changed or
// disabled (a person holding signals.manage, Business). It applies only
// once confirmed: ENABLE and CHANGE by two people with two keys, DISABLE
// by one. Without containment on this server the playbook cannot be
// enabled or changed (fail closed).
func (s *Service) RequestPlaybookChange(ctx context.Context, kind string, events []string) (PlaybookRequest, error) {
	c, err := s.manager(ctx, kind != PlaybookDisable)
	if err != nil {
		return PlaybookRequest{}, err
	}
	switch kind {
	case PlaybookEnable, PlaybookChange, PlaybookDisable:
	default:
		return PlaybookRequest{}, ErrPlaybookInvalid
	}
	if !validPlaybookEvents(kind, events) {
		return PlaybookRequest{}, ErrPlaybookInvalid
	}
	if kind != PlaybookDisable && s.container == nil {
		return PlaybookRequest{}, ErrPlaybookUnavailable
	}
	if events == nil {
		events = []string{}
	}
	id := ids.NewV7()
	var out PlaybookRequest
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := q.EnsureIdentityPlaybook(ctx, c.Org); err != nil {
			return err
		}
		pb, err := q.LockIdentityPlaybook(ctx, c.Org)
		if err != nil {
			return err
		}
		if (kind == PlaybookEnable) == pb.Enabled {
			return ErrPlaybookState
		}
		if _, err := q.ExpireIdentityPlaybookRequests(ctx, c.Org); err != nil {
			return err
		}
		binding, err := PlaybookBinding(kind, c.Org, id, events, int(pb.Version))
		if err != nil {
			return err
		}
		required := int16(2)
		if kind == PlaybookDisable {
			required = 1
		}
		err = q.InsertIdentityPlaybookRequest(ctx, dbq.InsertIdentityPlaybookRequestParams{
			OrgID: c.Org, ID: id, Kind: kind, Events: events, BaseVersion: pb.Version, Binding: binding[:], Required: required,
			RequestedBy: c.Principal.ID,
		})
		if db.IsUniqueViolation(err) {
			return ErrPlaybookPending
		} else if err != nil {
			return err
		}
		if err := s.auditPlaybook(ctx, tx, c, "signals.playbook_requested", id, map[string]string{
			"kind": kind, "events": eventsDetail(events), "required": strconv.Itoa(int(required)),
		}); err != nil {
			return err
		}
		out, err = s.request(ctx, q, c.Org, id)
		return err
	})
	return out, err
}

// PlaybookRequest returns one request (signals.read).
func (s *Service) PlaybookRequest(ctx context.Context, id ids.UUID) (PlaybookRequest, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return PlaybookRequest{}, err
	}
	if err := c.Require(PermRead, td.OrgPath(c.Org)); err != nil {
		return PlaybookRequest{}, err
	}
	var out PlaybookRequest
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		out, err = s.request(ctx, dbq.New(tx), c.Org, id)
		return err
	}, db.ReadOnly())
	return out, err
}

// PlaybookRequests returns the last 50 requests, newest first
// (signals.read).
func (s *Service) PlaybookRequests(ctx context.Context) ([]PlaybookRequest, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return nil, err
	}
	if err := c.Require(PermRead, td.OrgPath(c.Org)); err != nil {
		return nil, err
	}
	var out []PlaybookRequest
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		rows, err := q.ListIdentityPlaybookRequests(ctx, c.Org)
		if err != nil {
			return err
		}
		for _, r := range rows {
			p := s.requestOf(c.Org, dbq.GetIdentityPlaybookRequestRow(r))
			if err := confirmationsOf(ctx, q, c.Org, &p); err != nil {
				return err
			}
			out = append(out, p)
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

func (s *Service) request(ctx context.Context, q *dbq.Queries, org ids.OrgID, id ids.UUID) (PlaybookRequest, error) {
	r, err := q.GetIdentityPlaybookRequest(ctx, org, id)
	if db.IsNoRows(err) {
		return PlaybookRequest{}, ErrRequestNotFound
	} else if err != nil {
		return PlaybookRequest{}, err
	}
	out := s.requestOf(org, r)
	return out, confirmationsOf(ctx, q, org, &out)
}

func (s *Service) requestOf(_ ids.OrgID, r dbq.GetIdentityPlaybookRequestRow) PlaybookRequest {
	out := PlaybookRequest{
		ID: r.ID, Kind: r.Kind, Events: r.Events, BaseVersion: int(r.BaseVersion), Required: int(r.Required), State: r.State,
		RequestedBy: r.RequestedBy, CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt, DecidedAt: r.DecidedAt,
		URL: s.base + PlaybookPath + "/" + r.ID.String() + "/confirm",
	}
	copy(out.Binding[:], r.Binding)
	if r.DecidedReason != nil {
		out.DecidedReason = *r.DecidedReason
	}
	if out.State == RequestPending && r.Expired {
		out.State = RequestExpired
	}
	return out
}

func confirmationsOf(ctx context.Context, q *dbq.Queries, org ids.OrgID, r *PlaybookRequest) error {
	rows, err := q.ListIdentityPlaybookConfirmations(ctx, org, r.ID)
	if err != nil {
		return err
	}
	for _, c := range rows {
		r.Confirmations = append(r.Confirmations, Confirmation{Principal: c.PrincipalID, Credential: c.CredentialID, At: c.CreatedAt})
	}
	return nil
}

// MayConfirm reports whether caller may confirm r now: a person holding
// signals.manage on a browser session who has not confirmed it yet.
func MayConfirm(c tenancy.Caller, r PlaybookRequest) bool {
	if r.State != RequestPending || confirmer(c) != nil {
		return false
	}
	return !slices.ContainsFunc(r.Confirmations, func(x Confirmation) bool { return x.Principal == c.Principal.ID })
}

func confirmer(c tenancy.Caller) error {
	if err := c.Require(PermManage, td.OrgPath(c.Org)); err != nil {
		return err
	}
	if !c.Human() || c.Credential != tenancy.CredBrowserSession || c.Session.IsZero() {
		return ErrBrowserSession
	}
	return nil
}

// BeginConfirm checks that the caller may confirm the request now and
// returns it, whose binding the page's BINDING ceremony signs.
func (s *Service) BeginConfirm(ctx context.Context, id ids.UUID) (PlaybookRequest, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return PlaybookRequest{}, err
	}
	if err := confirmer(c); err != nil {
		return PlaybookRequest{}, err
	}
	var out PlaybookRequest
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		out, err = s.request(ctx, dbq.New(tx), c.Org, id)
		if err != nil {
			return err
		}
		return pendingFor(c, out)
	}, db.ReadOnly())
	return out, err
}

func pendingFor(c tenancy.Caller, r PlaybookRequest) error {
	switch {
	case r.State == RequestExpired:
		return ErrRequestExpired
	case r.State != RequestPending:
		return ErrRequestNotPending
	case slices.ContainsFunc(r.Confirmations, func(x Confirmation) bool { return x.Principal == c.Principal.ID }):
		return ErrSamePerson
	}
	return nil
}

// Confirm records the caller's confirmation (HR-262): the BINDING ceremony
// of this browser session over exactly the request's binding is consumed
// once; the person and the key must differ from every earlier
// confirmation's. The last confirmation applies the change in the same
// transaction, from the playbook version the request was made against
// (VOIDED otherwise).
func (s *Service) Confirm(ctx context.Context, id ids.UUID, a Assertion) (PlaybookRequest, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return PlaybookRequest{}, err
	}
	if err := confirmer(c); err != nil {
		return PlaybookRequest{}, err
	}
	var out PlaybookRequest
	var voided bool
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		row, err := q.LockIdentityPlaybookRequest(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrRequestNotFound
		} else if err != nil {
			return err
		}
		req := s.requestOf(c.Org, dbq.GetIdentityPlaybookRequestRow(row))
		if err := confirmationsOf(ctx, q, c.Org, &req); err != nil {
			return err
		}
		if err := pendingFor(c, req); err != nil {
			return err
		}
		if slices.ContainsFunc(req.Confirmations, func(x Confirmation) bool { return x.Credential == a.Credential }) {
			return ErrSameKey
		}
		if req.Kind != PlaybookDisable && s.container == nil {
			return ErrPlaybookUnavailable
		}
		if err := consumePlaybookCeremony(ctx, q, c, req, a); err != nil {
			return err
		}
		n, err := q.InsertIdentityPlaybookConfirmation(ctx, dbq.InsertIdentityPlaybookConfirmationParams{
			OrgID: c.Org, RequestID: id, PrincipalID: c.Principal.ID, CredentialID: a.Credential,
		})
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrSameKey
		}
		confirmations := len(req.Confirmations) + 1
		if err := s.auditPlaybook(ctx, tx, c, "signals.playbook_confirmed", id, map[string]string{
			"kind": req.Kind, "confirmations": strconv.Itoa(confirmations), "required": strconv.Itoa(req.Required),
			"security_key": a.Credential.String(),
		}); err != nil {
			return err
		}
		if confirmations >= req.Required {
			if voided, err = s.applyPlaybook(ctx, tx, q, c, req); err != nil {
				return err
			}
		}
		out, err = s.request(ctx, q, c.Org, id)
		return err
	})
	if err == nil && voided {
		return out, ErrRequestVoided
	}
	return out, err
}

// applyPlaybook applies an approved request; voided is true when the
// playbook changed since the request was made.
func (s *Service) applyPlaybook(ctx context.Context, tx db.TenantTx, q *dbq.Queries, c tenancy.Caller, req PlaybookRequest) (bool, error) {
	if _, err := q.LockIdentityPlaybook(ctx, c.Org); err != nil {
		return false, err
	}
	rid := req.ID
	n, err := q.ApplyIdentityPlaybook(ctx, dbq.ApplyIdentityPlaybookParams{
		Enabled: req.Kind != PlaybookDisable, Events: req.Events, RequestID: &rid, OrgID: c.Org,
		BaseVersion: int32(req.BaseVersion), //nolint:gosec // G115: a small version counter
	})
	if err != nil {
		return false, err
	}
	state, reason := RequestApplied, (*string)(nil)
	if n == 0 {
		v := errPlaybookVoidKey
		state, reason = RequestVoided, &v
	}
	if m, err := q.DecideIdentityPlaybookRequest(ctx, dbq.DecideIdentityPlaybookRequestParams{
		State: state, Reason: reason, OrgID: c.Org, ID: req.ID,
	}); err != nil || m != 1 {
		if err == nil {
			err = ErrRequestNotPending
		}
		return false, err
	}
	if state == RequestVoided {
		return true, s.auditPlaybook(ctx, tx, c, "signals.playbook_voided", req.ID, map[string]string{"reason": errPlaybookVoidKey})
	}
	if err := s.auditPlaybook(ctx, tx, c, "signals.playbook_changed", req.ID, map[string]string{
		"kind": req.Kind, "events": eventsDetail(req.Events), "version": strconv.Itoa(req.BaseVersion + 1),
	}); err != nil {
		return false, err
	}
	if s.notify != nil {
		if _, err := s.notify.Enqueue(ctx, tx, napp.Message{
			Org: c.Org, Type: "signals.playbook_changed", DedupeKey: "signals.playbook_changed:" + req.ID.String(),
			Params: map[string]string{"change": req.Kind, "request": req.ID.String()},
		}); err != nil {
			return false, err
		}
	}
	return false, nil
}

// consumePlaybookCeremony consumes the caller's open BINDING ceremony for
// the request in this browser session once, and only if it signed exactly
// the request's binding within its 5 minutes (HR-033, HR-153).
func consumePlaybookCeremony(ctx context.Context, q *dbq.Queries, c tenancy.Caller, req PlaybookRequest, a Assertion) error {
	rid := req.ID
	cer, err := q.IdentityPlaybookCeremony(ctx, dbq.IdentityPlaybookCeremonyParams{
		OrgID: c.Org, ID: a.Ceremony, RequestID: &rid, UserID: c.Principal.ID, SessionID: c.Session,
	})
	switch {
	case db.IsNoRows(err):
		return ErrCeremony
	case err != nil:
		return err
	case !cer.Live || !bytes.Equal(cer.Challenge, req.Binding[:]):
		return ErrCeremony
	}
	n, err := q.ConsumeIdentityPlaybookCeremony(ctx, dbq.ConsumeIdentityPlaybookCeremonyParams{
		OrgID: c.Org, ID: a.Ceremony, RequestID: &rid, UserID: c.Principal.ID, SessionID: c.Session, Challenge: req.Binding[:],
	})
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrCeremony
	}
	return nil
}

// DeclinePlaybookRequest ends a pending request (DECLINED) with a reason,
// by a person holding signals.manage.
func (s *Service) DeclinePlaybookRequest(ctx context.Context, id ids.UUID, reason string) (PlaybookRequest, error) {
	c, err := s.manager(ctx, false)
	if err != nil {
		return PlaybookRequest{}, err
	}
	if n := utf8.RuneCountInString(reason); !utf8.ValidString(reason) || n < 1 || n > MaxPlaybookReason {
		return PlaybookRequest{}, ErrPlaybookReason
	}
	var out PlaybookRequest
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		n, err := q.DecideIdentityPlaybookRequest(ctx, dbq.DecideIdentityPlaybookRequestParams{
			State: RequestDeclined, Reason: &reason, OrgID: c.Org, ID: id,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			if _, err := s.request(ctx, q, c.Org, id); err != nil {
				return err
			}
			return ErrRequestNotPending
		}
		if err := s.auditPlaybook(ctx, tx, c, "signals.playbook_declined", id, nil); err != nil {
			return err
		}
		out, err = s.request(ctx, q, c.Org, id)
		return err
	})
	return out, err
}

func (s *Service) auditPlaybook(ctx context.Context, tx db.TenantTx, c tenancy.Caller, name string, id ids.UUID, details map[string]string) error {
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: c.Actor(), Outcome: audit.Success,
		Object: &audit.Object{Type: "identity_playbook_request", ID: id.String()}, Details: details,
	})
	return err
}

// eventsDetail lists event types by their short names for audit details.
func eventsDetail(events []string) string {
	out := ""
	for i, e := range events {
		if i > 0 {
			out += ","
		}
		out += ShortName(e)
	}
	return out
}
