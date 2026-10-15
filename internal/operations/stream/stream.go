// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package stream serves the focused live stream of the Operations surface
// (G0 M10 D32; F215, founder decision F2; HR-256, T-112):
// GET /v1/operations/stream, text/event-stream.
//
// The bearer token is read from the Authorization header only; a request
// carrying anything that looks like a credential in its URL is refused.
// Each event's id is its feed sequence number, so Last-Event-ID (or the
// after parameter) resumes where the viewer left off. Only focus events are
// sent (live signals, alerts, incidents, containment), each filtered by the
// viewer's permissions; retries of one transaction are grouped into one
// event with a count. A heartbeat comment goes out every 15 seconds. The
// stream closes when the token expires and, within 30 seconds, when the
// session is revoked or the viewer loses the permission: the credential is
// authenticated again on every recheck.
package stream

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	"github.com/katocxl/pantherclaw/internal/reflex/feed"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Path is the stream's route on the API mux.
const Path = "/v1/operations/stream"

// PermOperations is the permission the stream needs (D4).
const PermOperations = td.PermOperationsRead

// Subject is one subject of an event (D1).
type Subject = reflexdomain.Subject

// Event is one feed event (D2).
type Event = feed.Event

// Feed reads an org's feed in sequence order.
type Feed interface {
	// After returns at most limit events of org with seq > after, ascending.
	After(ctx context.Context, org ids.OrgID, after int64, limit int) ([]Event, error)
	// Head returns the org's latest sequence number (0 when empty).
	Head(ctx context.Context, org ids.OrgID) (int64, error)
}

// Authenticator resolves a bearer credential to a caller with its current
// bindings (authn/app.Authenticator).
type Authenticator interface {
	Authenticate(ctx context.Context, bearer string) (tenancy.Caller, error)
}

// Scope is the set of agents whose events a viewer may see: All, or the
// listed agents.
type Scope struct {
	All    bool
	Agents map[ids.UUID]bool
}

// Scoper computes a viewer's agent scope (evidence.read where each agent
// lives, D8).
type Scoper interface {
	Scope(ctx context.Context, c tenancy.Caller) (Scope, error)
}

// Config tunes the stream; zero values take the D32 defaults.
type Config struct {
	Poll         time.Duration // feed poll interval (1 s)
	Heartbeat    time.Duration // heartbeat comment interval (15 s)
	Recheck      time.Duration // credential and permission recheck (30 s)
	MaxPerCaller int           // concurrent streams per principal (5)
	Batch        int           // events read per poll (500)
}

func (c Config) withDefaults() Config {
	if c.Poll <= 0 {
		c.Poll = time.Second
	}
	if c.Heartbeat <= 0 {
		c.Heartbeat = 15 * time.Second
	}
	if c.Recheck <= 0 {
		c.Recheck = 30 * time.Second
	}
	if c.MaxPerCaller <= 0 {
		c.MaxPerCaller = 5
	}
	if c.Batch <= 0 || c.Batch > 500 {
		c.Batch = 500
	}
	return c
}

// Handler serves the stream.
type Handler struct {
	feed   Feed
	auth   Authenticator
	scoper Scoper
	// expiry returns when an access token expires (false for credentials
	// without a fixed expiry, such as API keys, which the recheck covers).
	expiry func(bearer string) (time.Time, bool)
	clk    clock.Clock
	cfg    Config
	log    *slog.Logger

	mu     sync.Mutex
	active map[string]int
}

// New returns a Handler. expiry may be nil.
func New(feed Feed, auth Authenticator, scoper Scoper, expiry func(string) (time.Time, bool), clk clock.Clock,
	cfg Config, log *slog.Logger,
) (*Handler, error) {
	if feed == nil || auth == nil || scoper == nil {
		return nil, errors.New("stream: feed, authenticator and scoper are required")
	}
	if clk == nil {
		clk = clock.System{}
	}
	if log == nil {
		log = pclog.Discard()
	}
	if expiry == nil {
		expiry = func(string) (time.Time, bool) { return time.Time{}, false }
	}
	return &Handler{
		feed: feed, auth: auth, scoper: scoper, expiry: expiry, clk: clk, cfg: cfg.withDefaults(), log: log,
		active: map[string]int{},
	}, nil
}

// Mount adds the stream to mux.
func (h *Handler) Mount(mux *http.ServeMux) {
	mux.Handle("GET "+Path, h)
}

// credentialParams are query parameter names that would put a credential
// in a URL (logs, history, referrers): refused outright (F2).
var credentialParams = []string{"access_token", "token", "bearer", "authorization", "api_key", "key", "auth"}

// cursorOf reads the resume point: Last-Event-ID, else after, else none.
// Any other query parameter is refused.
func cursorOf(r *http.Request) (int64, bool, error) {
	q := r.URL.Query()
	for name := range q {
		if strings.EqualFold(name, "after") {
			continue
		}
		for _, c := range credentialParams {
			if strings.EqualFold(name, c) {
				return 0, false, errTokenInURL
			}
		}
		return 0, false, errBadParam
	}
	v := r.Header.Get("Last-Event-ID")
	if v == "" {
		v = q.Get("after")
	}
	if v == "" {
		return 0, false, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		return 0, false, errBadParam
	}
	return n, true, nil
}

var (
	errTokenInURL = errors.New("credentials are accepted in the Authorization header only")
	errBadParam   = errors.New("the only parameter is after, a sequence number")
)

func (h *Handler) acquire(principal string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.active[principal] >= h.cfg.MaxPerCaller {
		return false
	}
	h.active[principal]++
	return true
}

func (h *Handler) release(principal string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.active[principal]--; h.active[principal] <= 0 {
		delete(h.active, principal)
	}
}

// ServeHTTP serves one stream.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	after, resume, err := cursorOf(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || bearer == "" {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	ctx := r.Context()
	c, err := h.auth.Authenticate(ctx, bearer)
	if err != nil {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "invalid or expired credentials", http.StatusUnauthorized)
		return
	}
	if !c.CanAnywhere(PermOperations) {
		http.Error(w, "missing permission "+string(PermOperations), http.StatusForbidden)
		return
	}
	sc, err := h.scoper.Scope(ctx, c)
	if err != nil {
		h.log.ErrorContext(ctx, "operations.stream_scope", pclog.Err(err))
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	principal := c.Org.String() + "/" + c.Principal.String()
	if !h.acquire(principal) {
		w.Header().Set("Retry-After", "30")
		http.Error(w, "too many streams", http.StatusTooManyRequests)
		return
	}
	defer h.release(principal)
	if !resume {
		if after, err = h.feed.Head(ctx, c.Org); err != nil {
			h.log.ErrorContext(ctx, "operations.stream_head", pclog.Err(err))
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	s := &session{h: h, w: w, rc: http.NewResponseController(w), bearer: bearer, caller: c, scope: sc, cursor: after}
	if exp, ok := h.expiry(bearer); ok {
		s.expires = exp
	}
	hd := w.Header()
	hd.Set("Content-Type", "text/event-stream")
	hd.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	reason := s.run(ctx)
	h.log.InfoContext(ctx, "operations.stream_closed", slog.String("reason", reason))
}

// session is one open stream.
type session struct {
	h       *Handler
	w       http.ResponseWriter
	rc      *http.ResponseController
	bearer  string
	caller  tenancy.Caller
	scope   Scope
	cursor  int64
	expires time.Time
}

// Close reasons (logged; the client sees the stream end).
const (
	closedClient     = "client"
	closedExpired    = "token_expired"
	closedRevoked    = "credential_revoked"
	closedPermission = "permission_removed"
	closedWrite      = "write_failed"
	closedFeed       = "feed_failed"
)

func (s *session) run(ctx context.Context) string {
	cfg := s.h.cfg
	var expired <-chan time.Time
	if !s.expires.IsZero() {
		d := s.expires.Sub(s.h.clk.Now())
		if d <= 0 {
			return closedExpired
		}
		t := time.NewTimer(d)
		defer t.Stop()
		expired = t.C
	}
	poll := time.NewTicker(cfg.Poll)
	defer poll.Stop()
	beat := time.NewTicker(cfg.Heartbeat)
	defer beat.Stop()
	recheck := time.NewTicker(cfg.Recheck)
	defer recheck.Stop()
	if !s.write(": stream open\n\n") {
		return closedWrite
	}
	if reason := s.drain(ctx); reason != "" {
		return reason
	}
	for {
		select {
		case <-ctx.Done():
			return closedClient
		case <-expired:
			return closedExpired
		case <-recheck.C:
			if reason := s.recheck(ctx); reason != "" {
				return reason
			}
		case <-beat.C:
			// The id line moves the client's resume point past events it
			// was not shown, without dispatching anything.
			if !s.write(fmt.Sprintf("id: %d\n: heartbeat\n\n", s.cursor)) {
				return closedWrite
			}
		case <-poll.C:
			if reason := s.drain(ctx); reason != "" {
				return reason
			}
		}
	}
}

// recheck authenticates the credential again and reloads the viewer's
// scope: a revoked session, a disabled principal or a removed role closes
// the stream.
func (s *session) recheck(ctx context.Context) string {
	c, err := s.h.auth.Authenticate(ctx, s.bearer)
	if err != nil {
		return closedRevoked
	}
	if !c.CanAnywhere(PermOperations) || c.Org != s.caller.Org || c.Principal != s.caller.Principal {
		return closedPermission
	}
	sc, err := s.h.scoper.Scope(ctx, c)
	if err != nil {
		return closedFeed
	}
	s.caller, s.scope = c, sc
	return ""
}

// drain sends every focus event after the cursor that the viewer may see.
func (s *session) drain(ctx context.Context) string {
	for {
		evs, err := s.h.feed.After(ctx, s.caller.Org, s.cursor, s.h.cfg.Batch)
		if err != nil {
			if ctx.Err() != nil {
				return closedClient
			}
			s.h.log.ErrorContext(ctx, "operations.stream_feed", pclog.Err(err))
			return closedFeed
		}
		for _, g := range group(evs) {
			if !Focus(g.Event) || !Visible(s.caller, PermOperations, s.scope, g.Event) {
				continue
			}
			b, err := json.Marshal(wireOf(g))
			if err != nil {
				return closedWrite
			}
			if !s.write(fmt.Sprintf("id: %d\nevent: %s\ndata: %s\n\n", g.Seq, g.Kind, b)) {
				return closedWrite
			}
		}
		if n := len(evs); n > 0 {
			s.cursor = evs[n-1].Seq
		}
		if len(evs) < s.h.cfg.Batch {
			return ""
		}
	}
}

// write sends one frame, extending the write deadline first (the stream
// outlives the server's write timeout, like workloadrpc's wait stream).
func (s *session) write(frame string) bool {
	_ = s.rc.SetWriteDeadline(time.Now().Add(2 * s.h.cfg.Heartbeat))
	if _, err := fmt.Fprint(s.w, frame); err != nil {
		return false
	}
	return s.rc.Flush() == nil
}
