// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package signals

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/telemetry"
	"github.com/katocxl/pantherclaw/internal/signals/setverify"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Receiver limits (D37, HR-261).
const (
	// MaxBody is the largest request body read.
	MaxBody = setverify.MaxToken
	// RateLimit and RateWindow bound the header-valid tokens of one
	// transmitter; IPRateLimit bounds the requests of one source address
	// before anything is parsed (D64 L2).
	RateLimit   = 120
	IPRateLimit = 240
	RateWindow  = time.Minute
	// ContentType is the RFC 8935 push media type.
	ContentType = "application/secevent+jwt"
)

// Event type URIs PantherClaw acts on (names, not credentials).
//
//nolint:gosec // G101: event type URIs that name credential events
const (
	TypeSessionRevoked          = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
	TypeCredentialChange        = "https://schemas.openid.net/secevent/caep/event-type/credential-change"
	TypeAccountDisabled         = "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
	TypeAccountPurged           = "https://schemas.openid.net/secevent/risc/event-type/account-purged"
	TypeCredentialCompromise    = "https://schemas.openid.net/secevent/risc/event-type/credential-compromise"
	TypeCredentialChangeRequire = "https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required"
	TypeVerification            = "https://schemas.openid.net/secevent/ssf/event-type/verification"
)

// Handled lists the event types that open a case (D37).
var Handled = []string{
	TypeSessionRevoked, TypeCredentialChange, TypeAccountDisabled, TypeAccountPurged, TypeCredentialCompromise,
	TypeCredentialChangeRequire,
}

// ShortName is the last path segment of an event type URI.
func ShortName(eventType string) string { return eventType[strings.LastIndexByte(eventType, '/')+1:] }

func handled(t string) bool {
	for _, h := range Handled {
		if t == h {
			return true
		}
	}
	return false
}

// Outcomes of a received event.
const (
	OutcomeAccepted     = "ACCEPTED"
	OutcomeUnmatched    = "UNMATCHED"
	OutcomeIgnored      = "IGNORED"
	OutcomeVerification = "VERIFICATION"
)

// Received is an accepted, recorded event that matched a person.
type Received struct {
	Org         ids.OrgID
	Transmitter ids.UUID
	Event       ids.UUID
	EventType   string
	User        ids.UUID
	MatchBasis  string
	IssuedAt    time.Time
}

// Sink handles an accepted event in the receiver's transaction: it opens a
// case and runs the identity playbook when enabled (D37, D38).
type Sink interface {
	Received(ctx context.Context, tx db.TenantTx, r Received) error
}

// Receiver serves POST /v1/ssf/{org}/{transmitter} (RFC 8935 push).
type Receiver struct {
	s       *Service
	limiter *httpx.Limiter
	byIP    *httpx.Limiter
}

// Receiver returns the push endpoint's handler; clientIP resolves the
// source address behind trusted proxies (nil: the remote address).
func (s *Service) Receiver(clientIP httpx.ClientIPFunc) *Receiver {
	return &Receiver{
		s: s, limiter: httpx.NewLimiter(RateLimit, RateWindow, s.clock),
		byIP: httpx.NewLimiter(IPRateLimit, RateWindow, s.clock).WithClientIP(clientIP),
	}
}

// Mount installs the endpoint on mux.
func (h *Receiver) Mount(mux *http.ServeMux) {
	mux.Handle(http.MethodPost+" "+EndpointPath, h)
}

// errorBody is the RFC 8935 §2.3 error response.
type errorBody struct {
	Err         string `json:"err"`
	Description string `json:"description"`
}

func writeError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, errorBody{Err: code, Description: desc})
}

// ServeHTTP verifies and records one SET. It answers 202 once the event is
// recorded, 400 with an RFC 8935 error when it is refused, 404 for an
// unknown or inactive transmitter (the same answer for both), and 429 when
// the transmitter sends too much.
func (h *Receiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	org, err1 := ids.Parse[ids.Org](r.PathValue("org"))
	tid, err2 := ids.ParseUUID(r.PathValue("transmitter"))
	if err1 != nil || err2 != nil {
		writeError(w, http.StatusNotFound, setverify.CodeInvalidRequest, "unknown transmitter")
		return
	}
	// A source address is limited before anything is read; a transmitter's
	// budget counts only well-formed tokens, so junk from others cannot
	// spend it (D64 L2).
	if !h.byIP.AllowRequest(r) {
		tooMany(w, r)
		return
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != ContentType {
		writeError(w, http.StatusBadRequest, setverify.CodeInvalidRequest, "the content type must be "+ContentType)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
	if err != nil || len(body) > MaxBody {
		writeError(w, http.StatusBadRequest, setverify.CodeInvalidRequest, "the body is larger than 64 KiB")
		return
	}
	token := strings.TrimSpace(string(body))
	if err := setverify.CheckHeader(token); err != nil {
		var ve *setverify.Error
		desc := ""
		if errors.As(err, &ve) {
			desc = ve.Description
		}
		writeError(w, http.StatusBadRequest, setverify.CodeOf(err), desc)
		return
	}
	if !h.limiter.Allow(org.String() + "/" + tid.String()) {
		tooMany(w, r)
		return
	}
	status, code, desc := h.s.receive(r.Context(), org, tid, token)
	if status == http.StatusAccepted {
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusAccepted)
		return
	}
	writeError(w, status, code, desc)
}

// receive verifies and records one token for transmitter tid of org.
func (s *Service) receive(ctx context.Context, org ids.OrgID, tid ids.UUID, token string) (status int, code, desc string) {
	var t dbq.GetSSFTransmitterRow
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		t, err = dbq.New(tx).GetSSFTransmitter(ctx, org, tid)
		return err
	}, db.ReadOnly())
	if db.IsNoRows(err) || (err == nil && t.State != StateActive) {
		return http.StatusNotFound, setverify.CodeInvalidRequest, "unknown transmitter"
	} else if err != nil {
		s.log.ErrorContext(ctx, "signals.load_failed", pclog.Err(err))
		return http.StatusServiceUnavailable, setverify.CodeInvalidRequest, "try again later"
	}
	if err := s.business(ctx); err != nil {
		// A lapsed licence accepts nothing and says so once (D5).
		s.lapsed(ctx, org)
		return http.StatusNotFound, setverify.CodeInvalidRequest, "unknown transmitter"
	}
	keys, err := s.keysFor(tid, t.Issuer, t.JwksUri)
	if err != nil {
		return s.refused(ctx, org, tid, setverify.CodeInvalidKey, "the transmitter's key set is not usable")
	}
	set, err := setverify.Verify(ctx, setverify.Transmitter{Issuer: t.Issuer, Audience: t.Audience, Keys: keys}, token, s.clock.Now())
	if err != nil {
		var desc string
		var ve *setverify.Error
		if errors.As(err, &ve) {
			desc = ve.Description
		}
		return s.refused(ctx, org, tid, setverify.CodeOf(err), desc)
	}
	replay := false
	err = s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		replay, err = s.record(ctx, tx, org, tid, t.Issuer, set)
		return err
	})
	switch {
	case err != nil:
		s.log.ErrorContext(ctx, "signals.record_failed", slog.String("transmitter", tid.String()), pclog.Err(err))
		return http.StatusServiceUnavailable, setverify.CodeInvalidRequest, "try again later"
	case replay:
		return s.refused(ctx, org, tid, setverify.CodeInvalidRequest, "this jti was already received")
	}
	return http.StatusAccepted, "", ""
}

// refused counts a refusal on the transmitter and returns the answer.
func (s *Service) refused(ctx context.Context, org ids.OrgID, tid ids.UUID, code, desc string) (int, string, string) {
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		c := code
		return dbq.New(tx).SSFRefused(ctx, &c, org, tid)
	})
	if err != nil {
		s.log.WarnContext(ctx, "signals.count_failed", pclog.Err(err))
	}
	s.log.InfoContext(ctx, "signals.refused", slog.String("transmitter", tid.String()), slog.String("code", code))
	return http.StatusBadRequest, code, desc
}

// record stores a verified event once per (transmitter, jti) and hands an
// accepted one to the sink. replay is true when the jti was seen.
func (s *Service) record(ctx context.Context, tx db.TenantTx, org ids.OrgID, tid ids.UUID, issuer string, set setverify.SET) (replay bool, err error) {
	q := dbq.New(tx)
	p := dbq.InsertSSFEventParams{OrgID: org, ID: ids.NewV7(), TransmitterID: tid, Jti: set.JTI, EventType: set.EventType, IssuedAt: set.IssuedAt}
	if set.Subject.Format != "" {
		f := set.Subject.Format
		p.SubjectFormat = &f
	}
	switch {
	case set.EventType == TypeVerification:
		p.Outcome = OutcomeVerification
	case !handled(set.EventType):
		p.Outcome = OutcomeIgnored
	default:
		user, basis, err := matchUser(ctx, q, org, issuer, set.Subject)
		if err != nil {
			return false, err
		}
		p.Outcome = OutcomeUnmatched
		if !user.IsZero() {
			p.Outcome, p.UserID, p.MatchBasis = OutcomeAccepted, &user, &basis
		}
	}
	n, err := q.InsertSSFEvent(ctx, p)
	if err != nil || n == 0 {
		return n == 0 && err == nil, err
	}
	if err := q.SSFAccepted(ctx, org, tid); err != nil {
		return false, err
	}
	details := map[string]string{"event_type": ShortName(set.EventType), "outcome": p.Outcome, "event": p.ID.String()}
	if p.MatchBasis != nil {
		details["match_basis"] = *p.MatchBasis
		details["user"] = p.UserID.String()
	}
	entry, err := audit.Record(ctx, tx, audit.Event{
		Name: "signals.event_received", Actor: evdomain.Actor{Type: "ssf_transmitter", ID: tid.String()}, Outcome: audit.Success,
		Object: &audit.Object{Type: "ssf_event", ID: p.ID.String()}, Details: details,
	})
	if err != nil {
		return false, err
	}
	if p.Outcome != OutcomeAccepted {
		return false, nil
	}
	rec := Received{
		Org: org, Transmitter: tid, Event: p.ID, EventType: set.EventType, User: *p.UserID, MatchBasis: *p.MatchBasis,
		IssuedAt: set.IssuedAt,
	}
	if err := s.accepted(ctx, tx, rec, entry.ID); err != nil {
		return false, err
	}
	if s.sink != nil {
		return false, s.sink.Received(ctx, tx, rec)
	}
	return false, nil
}

// Match bases. Only BasisIssSub lets the identity playbook act (D46, D64).
const (
	// BasisIssSub: the subject's issuer is the transmitter's own issuer and
	// its subject is a person's linked OIDC identity.
	BasisIssSub = "iss_sub"
	// BasisForeignIssSub: an issuer and subject the transmitter names for
	// another issuer; the token's signer only vouches for its own issuer,
	// so the match is email-grade: a case only.
	BasisForeignIssSub = "foreign_iss_sub"
	// BasisEmail: an email exactly one active person has; a case only.
	BasisEmail = "email"
)

// matchUser finds the person an event is about (D37): by OIDC issuer and
// subject, or by an email that exactly one active person has. An issuer
// and subject count fully only when the subject's issuer is the
// transmitter's own issuer (D64). An opaque subject or any other format
// matches nobody.
func matchUser(ctx context.Context, q *dbq.Queries, org ids.OrgID, issuer string, sub setverify.Subject) (ids.UUID, string, error) {
	var (
		found []ids.UUID
		basis string
		err   error
	)
	switch sub.Format {
	case "iss_sub":
		found, err = q.SSFUserByIssSub(ctx, org, sub.Iss, sub.Sub)
		basis = BasisForeignIssSub
		if sub.Iss == issuer {
			basis = BasisIssSub
		}
	case "email":
		found, err = q.SSFUsersByEmail(ctx, org, td.NormalizeEmail(sub.Email))
		basis = BasisEmail
	}
	if err != nil || len(found) != 1 {
		return ids.UUID{}, "", err
	}
	return found[0], basis, nil
}

// tooMany answers 429 and counts the refusal.
func tooMany(w http.ResponseWriter, r *http.Request) {
	telemetry.RateLimited(r.Context(), telemetry.ScopeSignals)
	w.Header().Set("Retry-After", "60")
	writeError(w, http.StatusTooManyRequests, setverify.CodeInvalidRequest, "too many requests")
}
