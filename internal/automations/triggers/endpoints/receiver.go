// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package endpoints

import (
	"context"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/katocxl/pantherclaw/internal/automations/triggers"
	"github.com/katocxl/pantherclaw/internal/automations/triggers/inbound"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/telemetry"
	"github.com/katocxl/pantherclaw/internal/platform/ratelimit"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// The inbound endpoint (D21, D63 L7; HR-275, T-122):
// POST /v1/automations/events/{org}/{source}, outside Connect. In order:
// the per-address limit (240 a minute), the 64 KiB body bound, the
// Standard Webhooks headers, an ACTIVE source, the signature (current
// secret, or the previous one during its overlap), the timestamp (±5 min)
// — any of those three refused with one uniform 401 —, the source's own
// rate, the replay table (409), a JSON object with a declared type (422),
// then the audit record and the matching triggers (202). Bodies are never
// stored.
const (
	// EndpointPath is the route pattern.
	EndpointPath = "/v1/automations/events/{org}/{source}"
	// IPRateLimit is the per-address limit a minute.
	IPRateLimit = 240
	// RateWindow is the rate-limit window.
	RateWindow = time.Minute
)

// Receiver is the inbound endpoint's handler.
type Receiver struct {
	s      *Service
	byIP   *httpx.Limiter
	source ratelimit.Limiter
}

// Receiver returns the endpoint's handler. The per-address limit is this
// replica's; each source's own rate is counted in the shared limiter.
func (s *Service) Receiver() *Receiver {
	return &Receiver{
		s:      s,
		byIP:   httpx.NewLimiter(IPRateLimit, RateWindow, s.clock).WithClientIP(s.cfg.ClientIP),
		source: ratelimit.NewStore(s.pool),
	}
}

// Mount installs the endpoint on mux.
func (h *Receiver) Mount(mux *http.ServeMux) {
	mux.Handle(http.MethodPost+" "+EndpointPath, h)
}

type problem struct {
	Error string `json:"error"`
}

func reply(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Cache-Control", "no-store")
	if code == "" {
		w.WriteHeader(status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, problem{Error: code})
}

// Codes of refused requests.
const (
	CodeUnauthorized = "unauthorized"
	CodeRateLimited  = "rate_limited"
	CodeTooLarge     = "too_large"
	CodeHeaders      = "missing_webhook_headers"
	CodeReplay       = "replayed"
	CodeBody         = "invalid_body"
	CodeType         = "undeclared_type"
	CodeUnavailable  = "try_again_later"
)

// ServeHTTP verifies, records and fires one inbound event.
func (h *Receiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.byIP.AllowRequest(r) {
		telemetry.RateLimited(r.Context(), telemetry.ScopeInbound)
		w.Header().Set("Retry-After", "60")
		reply(w, http.StatusTooManyRequests, CodeRateLimited)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, inbound.MaxBody))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			reply(w, http.StatusRequestEntityTooLarge, CodeTooLarge)
			return
		}
		reply(w, http.StatusBadRequest, CodeBody)
		return
	}
	hdr, err := inbound.ReadHeaders(r.Header)
	if err != nil {
		reply(w, http.StatusBadRequest, CodeHeaders)
		return
	}
	org, err1 := ids.Parse[ids.Org](r.PathValue("org"))
	src, err2 := ids.ParseUUID(r.PathValue("source"))
	if err1 != nil || err2 != nil || org.IsZero() || src.IsZero() {
		reply(w, http.StatusUnauthorized, CodeUnauthorized)
		return
	}
	status, code := h.s.receive(r.Context(), h, org, src, hdr, body)
	if status == http.StatusTooManyRequests {
		telemetry.RateLimited(r.Context(), telemetry.ScopeInbound)
		w.Header().Set("Retry-After", "60")
	}
	reply(w, status, code)
}

// receiveActor records inbound events: the source itself.
func receiveActor(src ids.UUID) evdomain.Actor {
	return evdomain.Actor{Type: "automation_event_source", ID: src.String()}
}

// verified is what a request's verification found: the source's rate and
// types, the database time, and the secret generation that signed it.
type verified struct {
	rate  int
	types []string
	now   time.Time
	which string
}

// receive verifies, counts and records one inbound event in three steps,
// so the shared counter is never asked while a pooled connection is held
// (G0 M13 D28): the verification in a read-only tenant transaction, the
// source's rate in the counter's own short global transaction, then the
// receipt, audit record and triggers in a second tenant transaction,
// which checks again that the source is still active.
func (s *Service) receive(ctx context.Context, h *Receiver, org ids.OrgID, src ids.UUID, hdr inbound.Headers, body []byte) (int, string) {
	v, status, code, err := s.verify(ctx, org, src, hdr, body)
	if err == nil && status == 0 {
		var d ratelimit.Decision
		d, err = h.source.Take(ctx, scopeSource, org.String()+"/"+src.String(), RateWindow, 1, v.rate)
		switch {
		case err != nil:
			// The shared counter is unavailable: refuse (HR-376).
			s.log.ErrorContext(ctx, "automations.inbound_rate_unavailable", slog.String("source", src.String()), pclog.Err(err))
			return http.StatusTooManyRequests, CodeRateLimited
		case !d.Allowed:
			status, code = http.StatusTooManyRequests, CodeRateLimited
		}
		status, code, err = s.record(ctx, org, src, hdr, body, v, status, code)
	}
	if err != nil {
		s.log.ErrorContext(ctx, "automations.inbound_failed", slog.String("source", src.String()), pclog.Err(err))
		return http.StatusServiceUnavailable, CodeUnavailable
	}
	return status, code
}

// verify checks the source, the licence, the signature and the timestamp.
// A non-zero status refuses the request.
func (s *Service) verify(ctx context.Context, org ids.OrgID, src ids.UUID, hdr inbound.Headers, body []byte) (verified, int, string, error) {
	var v verified
	status, code := 0, ""
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		row, err := q.LoadEventSourceSecrets(ctx, org, src)
		if db.IsNoRows(err) || (err == nil && row.State != StateActive) {
			dummyVerify(hdr, body)
			status, code = http.StatusUnauthorized, CodeUnauthorized
			return nil
		} else if err != nil {
			return err
		}
		// A lapsed licence accepts nothing, with the same answer.
		if licensed := s.entitled(ctx) == nil; !licensed {
			dummyVerify(hdr, body)
			status, code = http.StatusUnauthorized, CodeUnauthorized
			return nil
		}
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		cur, err := s.envelope.Decrypt(ctx, field(org, sourcesTable, src, secretColumn), SecretPurpose, row.Secret)
		if err != nil {
			return err
		}
		which := "current"
		if inbound.VerifySignature([][]byte{cur}, hdr, body) != nil {
			ok := false
			if row.PrevSecret != nil && row.PrevUntil != nil && now.Before(*row.PrevUntil) {
				prev, err := s.envelope.Decrypt(ctx, field(org, sourcesTable, src, prevSecretColumn), SecretPurpose, row.PrevSecret)
				if err != nil {
					return err
				}
				ok = inbound.VerifySignature([][]byte{prev}, hdr, body) == nil
				which = "previous"
			}
			if !ok {
				status, code = http.StatusUnauthorized, CodeUnauthorized
				return nil
			}
		}
		if fresh := inbound.CheckTimestamp(hdr.Timestamp, now) == nil; !fresh {
			status, code = http.StatusUnauthorized, CodeUnauthorized
			return nil
		}
		v = verified{rate: int(row.RatePerMinute), types: row.Types, now: now, which: which}
		return nil
	}, db.ReadOnly())
	return v, status, code, err
}

// record keeps a counted request: over the rate, the owned failure (429);
// otherwise the receipt (409 on a replay), the body check, the audit
// record and the triggers (202). A source disabled since verify is
// refused like an unknown one.
func (s *Service) record(ctx context.Context, org ids.OrgID, src ids.UUID, hdr inbound.Headers, body []byte, v verified,
	status int, code string,
) (int, string, error) {
	if status == 0 {
		status = http.StatusAccepted
	}
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		row, err := q.LoadEventSourceSecrets(ctx, org, src)
		if db.IsNoRows(err) || (err == nil && row.State != StateActive) {
			status, code = http.StatusUnauthorized, CodeUnauthorized
			return nil
		} else if err != nil {
			return err
		}
		if status == http.StatusTooManyRequests {
			return s.rateLimited(ctx, tx, src, v.rate, v.now)
		}
		digest := inbound.Digest(body)
		ev, bodyCode := parseBody(body, v.types)
		typ := ev.Type
		if bodyCode != "" {
			typ = "invalid"
		}
		n, err := q.InsertEventReceipt(ctx, dbq.InsertEventReceiptParams{
			OrgID: org, SourceID: src, WebhookID: hdr.ID, Type: typ, BodySha256: digest[:],
		})
		if err != nil {
			return err
		}
		if n == 0 {
			status, code = http.StatusConflict, CodeReplay
			return nil
		}
		if bodyCode != "" {
			status, code = http.StatusUnprocessableEntity, bodyCode
			return nil
		}
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: "automation.event_received", Actor: receiveActor(src), Outcome: audit.Success,
			Object: &audit.Object{Type: "automation_event_source", ID: src.String()},
			Details: map[string]string{
				"source": src.String(), "type": ev.Type, "webhook_id": hdr.ID, "digest": hex.EncodeToString(digest[:]),
				"generation": v.which,
			},
		}); err != nil {
			return err
		}
		_, err = s.triggers.FireInbound(ctx, tx, triggers.InboundEvent{
			Source: src, Type: ev.Type, WebhookID: hdr.ID, Secret: v.which, Body: body, SentAt: time.Unix(hdr.Timestamp, 0).UTC(),
			ReceivedAt: v.now,
		})
		return err
	})
	return status, code, err
}

// scopeSource is the shared counter's scope of a source's own rate a
// minute (D21): counted in PostgreSQL, so it holds across every replica
// (G0 M13 D9, R-34, HR-376).
const scopeSource = "automation.source"

// FailureSourceRate is the owned failure of a source sending more than
// its rate (one per source and hour, HR-278).
const FailureSourceRate = "automation.source_rate_limited"

func (s *Service) rateLimited(ctx context.Context, tx db.TenantTx, src ids.UUID, rate int, now time.Time) error {
	if s.failures == nil {
		return nil
	}
	hour := now.UTC().Truncate(time.Hour)
	_, err := s.failures.Report(ctx, tx.Pgx(), reflexdomain.Failure{
		Org: tx.OrgID(), Kind: FailureSourceRate, DedupeKey: FailureSourceRate + ":" + src.String() + ":" + hour.Format(time.RFC3339),
		Summary:  fmt.Sprintf("Inbound event source %s sent more than its %d requests a minute; the excess was refused (429).", src, rate),
		NextStep: "Check what is sending to this source; raise its rate only by creating a new source if the volume is expected.",
	})
	return err
}

// parseBody reads the event type, or the code that refuses the body:
// CodeType for an undeclared type, CodeBody for anything else.
func parseBody(body []byte, types []string) (inbound.Event, string) {
	ev, err := inbound.ParseEvent(body, types)
	switch {
	case errors.Is(err, inbound.ErrType):
		return ev, CodeType
	case err != nil:
		return ev, CodeBody
	}
	return ev, ""
}

// dummyKey is verified against when there is no usable source, so an
// unknown, inactive or unlicensed source answers in the time a bad
// signature does (D87 L10).
var dummyKey = []byte("pantherclaw-automations-no-source-key")

// dummyVerify is a variable so tests can see the dummy path taken.
var dummyVerify = func(hdr inbound.Headers, body []byte) {
	_ = inbound.VerifySignature([][]byte{dummyKey}, hdr, body)
}
