// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package siemforward is `pclaw siem forward` (founder decision FD8, D660;
// F950, HR-662, T-284): a receiver for PantherClaw's SIEM export that runs
// next to a SIEM agent which can only read files. It accepts a batch only
// when every configured signature scheme verifies it: the HMAC `v1,`
// signature with one of at most two secrets, and the Ed25519 `v1a,`
// signature with a key of the org's webhook JWKS, both over
// "webhook-id.webhook-timestamp.body". The timestamp must be inside the
// window and not before the forwarder started, and a webhook-id already
// written in the window is answered without being written again. Each OCSF
// event of a verified batch becomes one compact JSON line, synced to disk
// before the 2xx. An unverified body is never written, logged or echoed.
package siemforward

import (
	"context"
	"crypto/ed25519"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/katocxl/pantherclaw/internal/automations/triggers/inbound"
	ndomain "github.com/katocxl/pantherclaw/internal/notifications/domain"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/siem/ocsf"
)

// Limits and defaults (D660).
const (
	// DefaultListen is where the forwarder listens unless told otherwise:
	// loopback, so plain HTTP is allowed there.
	DefaultListen = "127.0.0.1:8471"
	// DefaultWindow and MaxWindow bound how far a batch's timestamp may be
	// from the forwarder's clock, either way.
	DefaultWindow = 5 * time.Minute
	MaxWindow     = 15 * time.Minute
	// MaxSecrets is the current secret and, while a rotation overlaps, the
	// previous one.
	MaxSecrets = 2
	// MaxBody is the exporter's largest batch body.
	MaxBody = ocsf.MaxBatchBytes
	// JWKSRefetchEvery bounds how often a `v1a,` signature that no known
	// key verifies refetches the JWKS.
	JWKSRefetchEvery = time.Minute
	// MaxBuffered bounds the body bytes held at once by all requests, read
	// but not yet written or refused, so unverified bodies can't pile up in
	// memory. It is charged as the bytes arrive, so a sender that stalls
	// holds only what it sent; a read that would pass it answers 503 busy,
	// which the exporter retries.
	MaxBuffered = 32 << 20
	// BodyReadTimeout bounds reading one body, so a stalled sender holds
	// its bytes for at most this long.
	BodyReadTimeout = 10 * time.Second
	// pruneEvery is how often forgotten webhook-ids are dropped.
	pruneEvery = time.Minute
)

// Outcomes, as logged and answered.
const (
	OutcomeWritten       = "written"
	OutcomeDuplicate     = "duplicate"
	OutcomeMalformed     = "malformed"
	OutcomeOutsideWindow = "outside_window"
	OutcomeBadSignature  = "bad_signature"
	OutcomeTooLarge      = "too_large"
	OutcomeWriteFailed   = "write_failed"
	OutcomeBusy          = "busy"
)

// answers maps an outcome to its status and fixed response text. Nothing a
// request carried is ever echoed.
var answers = map[string]struct {
	status int
	text   string
}{
	OutcomeWritten:       {http.StatusOK, "ok"},
	OutcomeDuplicate:     {http.StatusOK, "duplicate"},
	OutcomeMalformed:     {http.StatusBadRequest, "malformed batch"},
	OutcomeOutsideWindow: {http.StatusBadRequest, "timestamp outside the accepted window"},
	OutcomeBadSignature:  {http.StatusUnauthorized, "signature not verified"},
	OutcomeTooLarge:      {http.StatusRequestEntityTooLarge, "batch too large"},
	OutcomeWriteFailed:   {http.StatusServiceUnavailable, "write failed"},
	OutcomeBusy:          {http.StatusServiceUnavailable, "busy"},
}

// ErrNoScheme refuses a forwarder that would check no signature.
var ErrNoScheme = errors.New("no signature to check: give --secret-file (or set PCLAW_SIEM_SECRET) for HMAC, " +
	"or --jwks-url or --jwks-file for Ed25519")

// Config configures a Forwarder.
type Config struct {
	// Secrets are the HMAC signing secrets: the destination's current one
	// and, during a rotation overlap, the previous one. None: HMAC is not
	// checked.
	Secrets [][]byte
	// Keys verifies the `v1a,` signature. Nil: Ed25519 is not checked.
	Keys Keys
	// Window bounds a timestamp's distance from now (default DefaultWindow,
	// at most MaxWindow).
	Window time.Duration
	// Start is when the forwarder started: an earlier timestamp is refused,
	// because webhook-ids seen before it are not remembered. Zero: now.
	Start time.Time
	// Now is the clock (time.Now when nil).
	Now func() time.Time
	// Sink receives the lines of each verified batch.
	Sink Sink
	// Log receives one line per batch: its id, event count and outcome.
	Log *slog.Logger
}

// Forwarder is the http.Handler that verifies and writes batches.
type Forwarder struct {
	cfg Config
	// buffered is the body bytes requests hold now (MaxBuffered).
	buffered atomic.Int64
	// mu serializes the replay check and the write, so two copies of one
	// batch never both get written and lines of two batches never mix.
	mu     sync.Mutex
	seen   map[string]time.Time // webhook-id → until when it is remembered
	pruned time.Time
}

// New checks cfg and returns the forwarder.
func New(cfg Config) (*Forwarder, error) {
	switch {
	case len(cfg.Secrets) == 0 && cfg.Keys == nil:
		return nil, ErrNoScheme
	case len(cfg.Secrets) > MaxSecrets:
		return nil, fmt.Errorf("at most %d secrets (the current one and the previous one during a rotation)", MaxSecrets)
	case cfg.Window < 0 || cfg.Window > MaxWindow:
		return nil, fmt.Errorf("the window is at most %s", MaxWindow)
	case cfg.Sink == nil:
		return nil, errors.New("siemforward: no sink")
	}
	for _, s := range cfg.Secrets {
		if len(s) == 0 {
			return nil, errors.New("an empty secret")
		}
	}
	if cfg.Window == 0 {
		cfg.Window = DefaultWindow
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Start.IsZero() {
		cfg.Start = cfg.Now()
	}
	if cfg.Log == nil {
		cfg.Log = pclog.Discard()
	}
	return &Forwarder{cfg: cfg, seen: map[string]time.Time{}}, nil
}

// ServeHTTP takes one batch: headers, size, timestamp, signatures, replay,
// then the write. Every refusal comes before anything is written. The body
// must arrive within BodyReadTimeout, and its bytes count against
// MaxBuffered until the request ends: a read that would pass it answers
// 503 busy, before the signature is looked at.
func (f *Forwarder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h, err := inbound.ReadHeaders(r.Header)
	if err != nil {
		f.answer(ctx, w, "", -1, OutcomeMalformed, nil)
		return
	}
	if r.ContentLength > MaxBody {
		f.answer(ctx, w, h.ID, -1, OutcomeTooLarge, nil)
		return
	}
	// A server that can't set the deadline (a test recorder) still has
	// its own read timeout.
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(BodyReadTimeout))
	charged := &budgetBody{f: f, rc: r.Body}
	defer charged.release()
	body, err := io.ReadAll(http.MaxBytesReader(w, charged, MaxBody))
	if err != nil {
		var tooLarge *http.MaxBytesError
		switch {
		case errors.As(err, &tooLarge):
			f.answer(ctx, w, h.ID, -1, OutcomeTooLarge, nil)
		case errors.Is(err, errBusy):
			f.answer(ctx, w, h.ID, -1, OutcomeBusy, nil)
		default:
			f.answer(ctx, w, h.ID, -1, OutcomeMalformed, nil)
		}
		return
	}
	if !f.inWindow(h.Timestamp) {
		f.answer(ctx, w, h.ID, -1, OutcomeOutsideWindow, nil)
		return
	}
	if !f.verify(ctx, h, body) {
		f.answer(ctx, w, h.ID, -1, OutcomeBadSignature, nil)
		return
	}
	// Verified: from here on the body is PantherClaw's.
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.duplicateLocked(h.ID, h.Timestamp) {
		f.answer(ctx, w, h.ID, -1, OutcomeDuplicate, nil)
		return
	}
	lines, n, err := Lines(body)
	if err != nil {
		f.answer(ctx, w, h.ID, -1, OutcomeMalformed, nil)
		return
	}
	if err := f.cfg.Sink.Append(lines); err != nil {
		f.answer(ctx, w, h.ID, n, OutcomeWriteFailed, err)
		return
	}
	f.rememberLocked(h.ID, h.Timestamp)
	f.answer(ctx, w, h.ID, n, OutcomeWritten, nil)
}

// errBusy is a body read refused because it would pass MaxBuffered.
var errBusy = errors.New("siemforward: the bodies in hand already hold MaxBuffered bytes")

// budgetBody charges the bytes read from one request's body to the
// forwarder's shared count as they arrive, and refuses a read that would
// take the count past MaxBuffered. release gives them back.
type budgetBody struct {
	f       *Forwarder
	rc      io.ReadCloser
	charged int64
}

func (b *budgetBody) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	if n > 0 {
		if b.f.buffered.Add(int64(n)) > MaxBuffered {
			b.f.buffered.Add(-int64(n))
			return 0, errBusy
		}
		b.charged += int64(n)
	}
	return n, err
}

func (b *budgetBody) Close() error { return b.rc.Close() }

// release gives the request's bytes back once it is answered.
func (b *budgetBody) release() {
	b.f.buffered.Add(-b.charged)
	b.charged = 0
}

// answer writes the outcome's fixed status and text and logs the batch id
// (the webhook-id header, bounded printable ASCII), the event count when
// known and the outcome: never the body.
func (f *Forwarder) answer(ctx context.Context, w http.ResponseWriter, id string, events int, outcome string, err error) {
	a := answers[outcome]
	attrs := make([]slog.Attr, 0, 4)
	if id != "" {
		attrs = append(attrs, slog.String("batch", id))
	}
	if events >= 0 {
		attrs = append(attrs, slog.Int("events", events))
	}
	attrs = append(attrs, slog.String("outcome", outcome))
	level := slog.LevelInfo
	if a.status != http.StatusOK {
		level = slog.LevelWarn
	}
	if err != nil {
		attrs = append(attrs, pclog.Err(err)) // the sink's own error, never the body
	}
	f.cfg.Log.LogAttrs(ctx, level, "siem.forward.batch", attrs...)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(a.status)
	_, _ = io.WriteString(w, a.text+"\n")
}

// inWindow reports whether ts is within the window of now and not before
// the forwarder started.
func (f *Forwarder) inWindow(ts int64) bool {
	t := time.Unix(ts, 0)
	d := f.cfg.Now().Sub(t)
	return d <= f.cfg.Window && d >= -f.cfg.Window && !t.Before(f.cfg.Start)
}

// verify requires a valid signature for every configured scheme: HMAC
// first (compared in constant time), then Ed25519. A `v1a,` signature
// that no known key verifies refetches the JWKS when the source may (at
// most once a minute), then is checked once more. The refetch does not
// end with the request: a client that hangs up can't use up the minute's
// fetch and keep a rotated key out.
func (f *Forwarder) verify(ctx context.Context, h inbound.Headers, body []byte) bool {
	if len(f.cfg.Secrets) > 0 && inbound.VerifySignature(f.cfg.Secrets, h, body) != nil {
		return false
	}
	if f.cfg.Keys == nil {
		return true
	}
	if verifyV1a(f.cfg.Keys.Current(), h, body) {
		return true
	}
	return f.cfg.Keys.Refresh(context.WithoutCancel(ctx)) && verifyV1a(f.cfg.Keys.Current(), h, body)
}

// verifyV1a reports whether any `v1a,` entry of the header is a valid
// Ed25519 signature by any of keys.
func verifyV1a(keys []ed25519.PublicKey, h inbound.Headers, body []byte) bool {
	entries := strings.Fields(h.Signature)
	if len(entries) > inbound.MaxSignatures {
		return false
	}
	ok := false
	for _, e := range entries {
		if !strings.HasPrefix(e, "v1a,") {
			continue
		}
		for _, k := range keys {
			if ndomain.VerifyV1a(k, e, h.ID, h.Timestamp, body) {
				ok = true
			}
		}
	}
	return ok
}

// duplicateLocked reports whether id was written and is still remembered.
// A re-send of it (the exporter's retry carries a newer timestamp) keeps
// it remembered for as long as that re-send could pass the window.
func (f *Forwarder) duplicateLocked(id string, ts int64) bool {
	until, ok := f.seen[id]
	if !ok || f.cfg.Now().After(until) {
		return false
	}
	if u := f.until(ts); u.After(until) {
		f.seen[id] = u
	}
	return true
}

// rememberLocked records a written id until its timestamp leaves the
// window, dropping forgotten ids at most once a minute.
func (f *Forwarder) rememberLocked(id string, ts int64) {
	now := f.cfg.Now()
	if now.Sub(f.pruned) >= pruneEvery {
		for k, until := range f.seen {
			if now.After(until) {
				delete(f.seen, k)
			}
		}
		f.pruned = now
	}
	f.seen[id] = f.until(ts)
}

// until is how long a webhook-id with timestamp ts is remembered: past the
// last instant a request carrying ts passes the window.
func (f *Forwarder) until(ts int64) time.Time {
	return time.Unix(ts, 0).Add(f.cfg.Window + time.Second)
}

// batchBody is what Lines reads of an export batch (ocsf.Builder.Body).
type batchBody struct {
	Type string `json:"type"`
	Data struct {
		Events []jsontext.Value `json:"events"`
	} `json:"data"`
}

// Lines turns a verified batch body into its NDJSON: each OCSF event as one
// compact JSON object on its own line. It returns the lines and the event
// count, or an error when the body is not an export batch of objects.
func Lines(body []byte) ([]byte, int, error) {
	var b batchBody
	if err := json.Unmarshal(body, &b); err != nil {
		return nil, 0, errors.New("siemforward: not a JSON batch")
	}
	if b.Type != ocsf.BatchType || b.Data.Events == nil {
		return nil, 0, errors.New("siemforward: not an OCSF export batch")
	}
	out := make([]byte, 0, len(body))
	for _, e := range b.Data.Events {
		if e.Kind() != '{' {
			return nil, 0, errors.New("siemforward: an event is not a JSON object")
		}
		if err := e.Compact(); err != nil {
			return nil, 0, errors.New("siemforward: an event is not valid JSON")
		}
		out = append(out, e...)
		out = append(out, '\n')
	}
	return out, len(b.Data.Events), nil
}
