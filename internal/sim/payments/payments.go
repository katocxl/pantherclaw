// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package payments is a simulated payments API for tests and demos
// (pantherclaw-sim payments). It refunds charges, reads refunds back one at
// a time or as a listing (by charge, or created since a time: the target
// log of G0 M7), requires an idempotency key and keeps it on the refund,
// detects replays, and can inject latency, declines, hangs, lost responses,
// slow settlement and redirects so that ALLOW, FAILED, UNKNOWN and every
// effect state can be exercised. Like a real target it can require a credential (the
// one PantherClaw holds in custody) or a PantherClaw action token, so a
// request that bypasses the gateway is refused (S11). Every response is
// marked SIMULATED; nothing here moves real money.
package payments

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json/v2"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// Faults configures fault injection. Rates are probabilities in [0, 1].
type Faults struct {
	Latency     time.Duration
	DeclineRate float64 // respond 402 card_declined (no effect)
	HangRate    float64 // never answer within the client's timeout, and refund nothing (unknown outcome, no effect)
	HangFor     time.Duration
	// LoseRate is the probability of refunding and then never answering:
	// an unknown outcome whose effect happened (G0 M7, S07).
	LoseRate float64
	// ShortRate is the probability of recording a refund one minor unit
	// short of what was asked and accepting it: the target's record then
	// disagrees with the request (G0 M7, a conflicting observation).
	ShortRate float64
	// SettleAfter keeps a new refund "pending" for this long before it is
	// "succeeded" (propagation pending, F483); zero settles at once.
	SettleAfter time.Duration
	// RedirectTo, when set, answers every refund with a 307 redirect to
	// it, which a client must not follow (S12).
	RedirectTo string
}

// Require is what a request must carry: the target's own checks.
type Require struct {
	// Token is the bearer token every request must carry, the credential
	// PantherClaw holds in custody (HR-061).
	Token string
	// ActionTokens, when set, verifies a PAP-Action token on every refund
	// (HR-188).
	ActionTokens *ActionVerifier
}

// Refund is one recorded refund.
type Refund struct {
	ID       string
	Charge   string
	Amount   money.Money
	Reason   string
	BodyHash [32]byte
	// Key is the idempotency key it was created with, which a reconciler
	// correlates with its transaction (HR-008).
	Key     string
	Created time.Time
	// Initial is the status the creating response reported, so that a
	// replay answers byte for byte the same.
	Initial string
}

// status returns the refund's status at now.
func (r Refund) status(now time.Time, settle time.Duration) string {
	if settle > 0 && now.Before(r.Created.Add(settle)) {
		return "pending"
	}
	return "succeeded"
}

// Server is the simulated payments API.
type Server struct {
	faults  Faults
	require Require
	log     *slog.Logger

	mu        sync.Mutex
	byKey     map[string]Refund
	byID      map[string]Refund
	order     []string // refund ids in creation order
	now       func() time.Time
	total     money.Decimal
	count     int
	replays   int
	refused   int
	redirects int
}

// New returns a simulator.
func New(f Faults, log *slog.Logger) *Server {
	if f.HangFor == 0 {
		f.HangFor = 30 * time.Second
	}
	return &Server{faults: f, log: log, byKey: map[string]Refund{}, byID: map[string]Refund{}, now: time.Now}
}

// WithClock replaces the simulator's clock (tests), and returns it.
func (s *Server) WithClock(now func() time.Time) *Server {
	s.now = now
	return s
}

// Refunds returns every refund in creation order.
func (s *Server) Refunds() []Refund {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Refund, len(s.order))
	for i, id := range s.order {
		out[i] = s.byID[id]
	}
	return out
}

// WithRequire makes the simulator require what r names, and returns it.
func (s *Server) WithRequire(r Require) *Server {
	s.require = r
	return s
}

type refundRequest struct {
	Charge   string `json:"charge"`
	Amount   string `json:"amount"`
	Currency string `json:"currency"`
	Reason   string `json:"reason"`
}

var (
	chargePattern = regexp.MustCompile(`^ch_[A-Za-z0-9]{1,64}$`)
	refundPattern = regexp.MustCompile(`^re_[A-Za-z0-9-]{1,64}$`)
	keyPattern    = regexp.MustCompile(`^[A-Za-z0-9._:-]{8,128}$`)
)

// pageSize is the most refunds one listing answers.
const pageSize = 100

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/refunds", s.refund)
	mux.HandleFunc("GET /v1/refunds", s.listRefunds)
	mux.HandleFunc("GET /v1/refunds/{id}", s.getRefund)
	mux.HandleFunc("GET /v1/stats", s.stats)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Simulated", "true")
		if r.URL.Path != "/v1/stats" && s.require.Token != "" &&
			subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+s.require.Token)) != 1 {
			s.refuse(w, http.StatusUnauthorized, "credential_required")
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// refuse answers a refused request and counts it.
func (s *Server) refuse(w http.ResponseWriter, status int, reason string) {
	s.mu.Lock()
	s.refused++
	s.mu.Unlock()
	writeJSON(w, status, map[string]string{"error": reason})
}

// getRefund reads one refund back (payments.refund.get).
func (s *Server) getRefund(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	ref, ok := s.byID[r.PathValue("id")]
	s.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "refund_not_found"})
		return
	}
	writeJSON(w, http.StatusOK, s.object(ref))
}

// amountText writes an amount with exactly its currency's minor-unit
// digits (30.00 USD), as a payments API reports it.
func amountText(m money.Money) string {
	if n, err := m.Currency.MinorUnits(); err == nil {
		if s, err := m.Amount.StringFixed(n); err == nil {
			return s
		}
	}
	return m.Amount.String()
}

// object is a refund as the API shows it.
func (s *Server) object(ref Refund) map[string]any {
	return map[string]any{
		"id": ref.ID, "charge": ref.Charge, "amount": amountText(ref.Amount), "currency": string(ref.Amount.Currency),
		"reason": ref.Reason, "status": ref.status(s.now(), s.faults.SettleAfter), "idempotency_key": ref.Key,
		"created": ref.Created.Unix(), "simulated": true,
	}
}

// listRefunds lists refunds in creation order (payments.refund.list and the
// target log payments.refund.recent): those of one charge, those created at
// or after created_gte (unix seconds), or both; starting_after continues
// after a refund id; at most 100 per page, with has_more.
func (s *Server) listRefunds(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	for k, v := range q {
		if len(v) != 1 || (k != "charge" && k != "created_gte" && k != "starting_after") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_query"})
			return
		}
	}
	charge, after := q.Get("charge"), q.Get("starting_after")
	var since int64 = -1
	if v := q.Get("created_gte"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_query"})
			return
		}
		since = n
	}
	if (charge == "" && since < 0) || (charge != "" && !chargePattern.MatchString(charge)) ||
		(after != "" && !refundPattern.MatchString(after)) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_query"})
		return
	}
	s.mu.Lock()
	var page []Refund
	more, started := false, after == ""
	for _, id := range s.order {
		ref := s.byID[id]
		if !started {
			started = id == after
			continue
		}
		if (charge != "" && ref.Charge != charge) || (since >= 0 && ref.Created.Unix() < since) {
			continue
		}
		if len(page) == pageSize {
			more = true
			break
		}
		page = append(page, ref)
	}
	s.mu.Unlock()
	data := make([]map[string]any, len(page))
	for i, ref := range page {
		data[i] = s.object(ref)
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": data, "has_more": more, "simulated": true})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, v)
}

func (s *Server) refund(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("Idempotency-Key")
	if !keyPattern.MatchString(key) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "idempotency_key_required"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unreadable_body"})
		return
	}
	var req refundRequest
	if err := json.Unmarshal(body, &req, json.RejectUnknownMembers(true)); err != nil || !chargePattern.MatchString(req.Charge) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	amount, err := money.ParseMoney(req.Amount, req.Currency)
	if err != nil || amount.Amount.Sign() <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_amount"})
		return
	}
	if v := s.require.ActionTokens; v != nil {
		want := Want{Operation: "payments.refund.create", TargetType: "payments.charge", TargetID: req.Charge}
		if err := v.Verify(r.Context(), r, body, want); err != nil {
			s.refuse(w, http.StatusForbidden, err.Error())
			return
		}
	}
	hash := sha256.Sum256(body)
	if s.faults.RedirectTo != "" {
		s.mu.Lock()
		s.redirects++
		s.mu.Unlock()
		w.Header().Set("Location", s.faults.RedirectTo)
		w.WriteHeader(http.StatusTemporaryRedirect)
		return
	}

	if s.faults.Latency > 0 {
		select {
		case <-time.After(s.faults.Latency):
		case <-r.Context().Done():
			return
		}
	}
	if chance(s.faults.HangRate) {
		s.hang(r)
	}

	status, resp, replayed := s.apply(key, req, amount, hash)
	if status == http.StatusOK && !replayed && chance(s.faults.LoseRate) {
		s.hang(r) // the refund happened; its answer never arrives
	}
	if replayed {
		w.Header().Set("Idempotent-Replayed", "true")
	}
	writeJSON(w, status, resp)
}

// hang waits for HangFor or the client to give up, then drops the
// connection without a response: an empty 200 would look like success to
// the caller.
func (s *Server) hang(r *http.Request) {
	select {
	case <-time.After(s.faults.HangFor):
	case <-r.Context().Done():
	}
	panic(http.ErrAbortHandler)
}

// apply records the refund under the lock and returns the response to
// write; the network write happens outside the lock.
func (s *Server) apply(key string, req refundRequest, amount money.Money, hash [32]byte) (status int, resp any, replayed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if prev, ok := s.byKey[key]; ok {
		if prev.BodyHash != hash {
			return http.StatusConflict, map[string]string{"error": "idempotency_key_reused_with_different_request"}, false
		}
		s.replays++
		return http.StatusOK, refundResponse{ID: prev.ID, Status: prev.Initial, Simulated: true}, true
	}
	if chance(s.faults.DeclineRate) {
		return http.StatusPaymentRequired, map[string]string{"error": "card_declined"}, false
	}
	if chance(s.faults.ShortRate) {
		amount = short(amount)
	}
	now := s.now()
	ref := Refund{
		ID: "re_" + ids.NewV7().String(), Charge: req.Charge, Amount: amount, Reason: req.Reason, BodyHash: hash,
		Key: key, Created: now,
	}
	ref.Initial = ref.status(now, s.faults.SettleAfter)
	s.byKey[key], s.byID[ref.ID] = ref, ref
	s.order = append(s.order, ref.ID)
	s.count++
	if t, err := s.total.Add(amount.Amount); err == nil {
		s.total = t
	}
	return http.StatusOK, refundResponse{ID: ref.ID, Status: ref.Initial, Simulated: true}, false
}

// Stats summarizes what the simulator has done.
type Stats struct {
	Refunds int    `json:"refunds"`
	Total   string `json:"total"`
	Replays int    `json:"replays"`
	// Refused counts requests refused for a missing or wrong credential or
	// action token; Redirects counts redirect answers.
	Refused   int `json:"refused"`
	Redirects int `json:"redirects"`
}

// Stats returns the current counters.
func (s *Server) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Stats{Refunds: s.count, Total: s.total.String(), Replays: s.replays, Refused: s.refused, Redirects: s.redirects}
}

func (s *Server) stats(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.Stats())
}

// chance returns true with probability p, using crypto/rand (math/rand is
// banned in this repository).
// short returns m less one minor unit of its currency, or m when that
// would leave nothing.
func short(m money.Money) money.Money {
	n, err := m.Currency.MinorUnits()
	if err != nil {
		return m
	}
	unit := "1"
	if n > 0 {
		unit = "0." + strings.Repeat("0", n-1) + "1"
	}
	d, err := money.Parse(unit)
	if err != nil {
		return m
	}
	out, err := m.Sub(money.Money{Amount: d, Currency: m.Currency})
	if err != nil || out.Amount.Sign() <= 0 {
		return m
	}
	return out
}

func chance(p float64) bool {
	if p <= 0 {
		return false
	}
	if p >= 1 {
		return true
	}
	var b [8]byte
	_, _ = rand.Read(b[:])
	return float64(binary.BigEndian.Uint64(b[:])>>11)/float64(1<<53) < p
}

// refundResponse has a fixed field order so replays are byte-identical.
type refundResponse struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	Simulated bool   `json:"simulated"`
}
