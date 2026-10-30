// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package externalchecks

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// InputVersion names the input format (D81).
const InputVersion = "pc.opa.v1"

// Why a check gave no answer (TestExternalCheck's error codes and the
// decision's detail).
const (
	UnavailableTimeout     = "TIMEOUT"
	UnavailableStatus      = "HTTP_STATUS"
	UnavailableBadAnswer   = "BAD_ANSWER"
	UnavailableUnreachable = "UNREACHABLE"
	UnavailableInFlight    = "TOO_MANY_IN_FLIGHT"
)

// maxAnswerBytes bounds an answer.
const maxAnswerBytes = 64 << 10

var _ pipeline.ExternalCheck = (*Service)(nil)

// UnavailableNotAllowed: the check's endpoint is no longer under the
// server's external_checks.allowed_prefixes, so it is not called (HR-438).
const UnavailableNotAllowed = "ENDPOINT_NOT_ALLOWED"

// CacheTTL is how long an org's active checks are served from memory; an
// activation or a disabling in this process drops the org's entry at once.
const CacheTTL = 5 * time.Second

// asker calls the checks: one egress client per check (its CA and
// timeout never change), and at most MaxInFlight calls per org in this
// process.
type asker struct {
	cfg     Config
	mu      sync.Mutex
	clients map[ids.UUID]*cachedClient
	flights map[ids.OrgID]*flight
}

func newAsker(cfg Config) *asker {
	return &asker{cfg: cfg, clients: map[ids.UUID]*cachedClient{}, flights: map[ids.OrgID]*flight{}}
}

// activeCache is each org's ACTIVE checks, read at most every CacheTTL.
type activeCache struct {
	mu   sync.Mutex
	orgs map[ids.OrgID]cachedChecks
	// warned and reported are the checks whose endpoint was found outside
	// the allowed prefixes in this process: each is logged once when read
	// and audited and alerted once when called.
	warned, reported map[ids.UUID]bool
}

type cachedChecks struct {
	checks []Check
	at     time.Time
}

func newActiveCache() *activeCache {
	return &activeCache{orgs: map[ids.OrgID]cachedChecks{}, warned: map[ids.UUID]bool{}, reported: map[ids.UUID]bool{}}
}

func (c *activeCache) get(org ids.OrgID, now time.Time) ([]Check, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.orgs[org]
	if !ok || now.Sub(e.at) > CacheTTL {
		delete(c.orgs, org)
		return nil, false
	}
	return e.checks, true
}

func (c *activeCache) put(org ids.OrgID, checks []Check, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for o, e := range c.orgs { // drop expired orgs while here
		if now.Sub(e.at) > CacheTTL {
			delete(c.orgs, o)
		}
	}
	c.orgs[org] = cachedChecks{checks: checks, at: now}
}

func (c *activeCache) drop(org ids.OrgID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.orgs, org)
}

// first reports whether id is in seen for the first time, and marks it.
func (c *activeCache) first(seen map[ids.UUID]bool, id ids.UUID) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if seen[id] {
		return false
	}
	seen[id] = true
	return true
}

// preloaded is the org's active checks, put on the context before the
// snapshot opened.
type preloaded struct {
	org    ids.OrgID
	checks []Check
	err    error
}

type preloadKey struct{}

// Preload implements pipeline.ExternalCheck: the org's ACTIVE checks from
// the cache, read in a short transaction of its own before the decision's
// snapshot holds a connection, and only on a miss. Without the external
// checks entitlement nothing is read. A read error is kept and Matching
// returns it (CANNOT_AUTHORIZE).
func (s *Service) Preload(ctx context.Context, org ids.OrgID) context.Context {
	checks, err := s.preload(ctx, org)
	return context.WithValue(ctx, preloadKey{}, preloaded{org: org, checks: checks, err: err})
}

func (s *Service) preload(ctx context.Context, org ids.OrgID) ([]Check, error) {
	if !s.entitled(ctx) {
		return nil, nil
	}
	now := time.Now()
	if checks, ok := s.cache.get(org, now); ok {
		return checks, nil
	}
	checks, err := s.active(ctx, org)
	if err != nil {
		return nil, err
	}
	s.cache.put(org, checks, now)
	for _, c := range checks {
		if CheckEndpoint(c.Endpoint, s.cfg.AllowedPrefixes) != nil && s.cache.first(s.cache.warned, c.ID) {
			s.log.WarnContext(ctx, "external_checks.endpoint_not_allowed", "org", org.String(), "check", c.ID.String(), "name", c.Name)
		}
	}
	return checks, nil
}

func (s *Service) active(ctx context.Context, org ids.OrgID) ([]Check, error) {
	var checks []Check
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListActiveExternalChecks(ctx, org)
		for _, r := range rows {
			checks = append(checks, Check{
				ID: r.ID, Name: r.Name, Endpoint: r.Endpoint, CAPEM: deref(r.CaPem), TimeoutMs: int(r.TimeoutMs),
				Operations: r.Operations, State: StateActive,
			})
		}
		return err
	}, db.ReadOnly())
	return checks, err
}

// errNotPreloaded: an evaluation reached the checks without Preload, which
// would read inside its snapshot; it is CANNOT_AUTHORIZE instead.
var errNotPreloaded = errors.New("externalchecks: the checks were not preloaded")

// Matching implements pipeline.ExternalCheck: the preloaded checks whose
// operations cover the operation, in name order. It never reads.
func (s *Service) Matching(ctx context.Context, org ids.OrgID, operation string) ([]pipeline.ExternalTarget, error) {
	pre, ok := ctx.Value(preloadKey{}).(preloaded)
	switch {
	case !ok || pre.org != org:
		return nil, errNotPreloaded
	case pre.err != nil:
		return nil, pre.err
	}
	var out []pipeline.ExternalTarget
	for _, c := range pre.checks {
		if c.Covers(operation) {
			out = append(out, pipeline.ExternalTarget{ID: c.ID, Name: c.Name})
		}
	}
	return out, nil
}

// Call implements pipeline.ExternalCheck: it asks each check, at once, with
// no database connection held. A check whose endpoint is no longer under
// the allowed prefixes is not called (ENDPOINT_NOT_ALLOWED, HR-438), and is
// audited and alerted once per process.
func (s *Service) Call(ctx context.Context, org ids.OrgID, calls []pipeline.ExternalCall) []pipeline.ExternalVerdict {
	checks, err := s.preload(ctx, org)
	out := make([]pipeline.ExternalVerdict, len(calls))
	byID := map[ids.UUID]Check{}
	for _, c := range checks {
		byID[c.ID] = c
	}
	var refused []Check
	var wg sync.WaitGroup
	for i, call := range calls {
		out[i] = pipeline.ExternalVerdict{CheckID: call.Check.ID, Check: call.Check.Name}
		c, ok := byID[call.Check.ID]
		switch {
		case err != nil || !ok:
			out[i].Unavailable = UnavailableUnreachable // disabled meanwhile, or unreadable
			continue
		case CheckEndpoint(c.Endpoint, s.cfg.AllowedPrefixes) != nil:
			out[i].Unavailable = UnavailableNotAllowed
			refused = append(refused, c)
			continue
		}
		body, err := Body(org, call.Input)
		if err != nil {
			out[i].Unavailable = UnavailableBadAnswer
			continue
		}
		wg.Go(func() {
			a := s.asker.ask(ctx, org, c, body)
			out[i].Decision, out[i].Reasons, out[i].Unavailable = a.Decision, a.Reasons, a.Unavailable
		})
	}
	wg.Wait()
	for _, c := range refused {
		s.notAllowed(ctx, org, c)
	}
	return out
}

// Answer is one check's answer: a decision with its UNTRUSTED reasons, or
// why there is none.
type Answer struct {
	Decision    string
	Reasons     []string
	Unavailable string
	Latency     time.Duration
}

// Body is the input posted to a check (D81). Disclosure-capable
// parameters are already lengths in in.Params (HR-439).
func Body(org ids.OrgID, in pipeline.ExternalInput) ([]byte, error) {
	type target struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	}
	type destination struct {
		Kind string `json:"kind"`
		ID   string `json:"id"`
	}
	type principal struct {
		Agent           string `json:"agent"`
		Instance        string `json:"instance"`
		Run             string `json:"run"`
		RepresentedUser string `json:"represented_user"`
	}
	type input struct {
		Version          string         `json:"version"`
		Org              string         `json:"org"`
		Operation        string         `json:"operation"`
		Access           string         `json:"access"`
		Target           target         `json:"target"`
		Destinations     []destination  `json:"destinations"`
		DestinationClass string         `json:"destination_class"`
		Principal        principal      `json:"principal"`
		Mode             string         `json:"mode"`
		Params           map[string]any `json:"params"`
	}
	dests := make([]destination, 0, len(in.Destinations))
	for _, d := range in.Destinations {
		dests = append(dests, destination{Kind: d.Kind, ID: d.ID})
	}
	params := in.Params
	if params == nil {
		params = map[string]any{}
	}
	return json.Marshal(struct {
		Input input `json:"input"`
	}{input{
		Version: InputVersion, Org: org.String(), Operation: in.Operation, Access: in.Access,
		Target: target{Type: in.Target.Type, ID: in.Target.ID}, Destinations: dests, DestinationClass: in.DestinationClass,
		Principal: principal{Agent: in.Agent, Instance: in.Instance, Run: in.Run, RepresentedUser: in.RepresentedUser},
		Mode:      in.Mode, Params: params,
	}}, json.Deterministic(true))
}

// ask posts body to one check. Beyond MaxInFlight calls in flight for the
// org it does not call at all.
func (a *asker) ask(ctx context.Context, org ids.OrgID, c Check, body []byte) Answer {
	release, ok := a.acquire(org)
	if !ok {
		return Answer{Unavailable: UnavailableInFlight}
	}
	defer release()
	client, err := a.client(c)
	if err != nil {
		return Answer{Unavailable: UnavailableUnreachable}
	}
	timeout := time.Duration(c.TimeoutMs) * time.Millisecond
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	ans := a.post(ctx, client, c.Endpoint, body)
	ans.Latency = time.Since(start)
	return ans
}

func (a *asker) post(ctx context.Context, client *http.Client, endpoint string, body []byte) Answer {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return Answer{Unavailable: UnavailableUnreachable}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return Answer{Unavailable: UnavailableTimeout}
		}
		return Answer{Unavailable: UnavailableUnreachable}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return Answer{Unavailable: UnavailableStatus}
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswerBytes+1))
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return Answer{Unavailable: UnavailableTimeout}
	case err != nil || len(raw) > maxAnswerBytes:
		return Answer{Unavailable: UnavailableBadAnswer}
	}
	return Parse(raw)
}

// Parse reads an answer: {"result": {"decision": "allow" | "deny" |
// "hold", "reasons": [...]}} with at most MaxReasons reasons of at most
// MaxReasonLen characters. Anything else is a bad answer (HR-437): never
// a guess, never an allow.
func Parse(raw []byte) Answer {
	var w struct {
		Result *struct {
			Decision *string  `json:"decision"`
			Reasons  []string `json:"reasons"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &w); err != nil || w.Result == nil || w.Result.Decision == nil {
		return Answer{Unavailable: UnavailableBadAnswer}
	}
	d := *w.Result.Decision
	if d != "allow" && d != "deny" && d != "hold" || len(w.Result.Reasons) > MaxReasons {
		return Answer{Unavailable: UnavailableBadAnswer}
	}
	reasons := make([]string, 0, len(w.Result.Reasons))
	for _, r := range w.Result.Reasons {
		if !utf8.ValidString(r) || utf8.RuneCountInString(r) > MaxReasonLen || strings.ContainsFunc(r, lineBreak) {
			return Answer{Unavailable: UnavailableBadAnswer}
		}
		// UNTRUSTED text for people: controls, format and bidi characters
		// are stripped as for any other untrusted text (HR-034, HR-102).
		reasons = append(reasons, apdomain.Clean("reason", r, MaxReasonLen).Text)
	}
	return Answer{Decision: d, Reasons: reasons}
}

// lineBreak reports a carriage return, line feed, line or paragraph
// separator: a reason is one line.
func lineBreak(r rune) bool { return r == 0x0a || r == 0x0d || r == 0x2028 || r == 0x2029 }

// flight is an org's in-flight calls in this process.
type flight struct {
	slots chan struct{}
	users int
}

// acquire takes one of the org's MaxInFlight slots in this process, or
// reports that none is free. The cap is per process: with several
// Authority replicas an org may have MaxInFlight calls in flight on each
// (the M19 shared limits will bound it across replicas). An org's entry is
// dropped once nothing uses it.
func (a *asker) acquire(org ids.OrgID) (release func(), ok bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	f, found := a.flights[org]
	if !found {
		f = &flight{slots: make(chan struct{}, MaxInFlight)}
		a.flights[org] = f
	}
	select {
	case f.slots <- struct{}{}:
	default:
		if f.users == 0 {
			delete(a.flights, org)
		}
		return nil, false
	}
	f.users++
	return func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		<-f.slots
		if f.users--; f.users == 0 {
			delete(a.flights, org)
		}
	}, true
}

// clientIdle is how long an unused check's client is kept.
const clientIdle = 10 * time.Minute

type cachedClient struct {
	client *http.Client
	used   time.Time
}

// client is the check's egress client: no redirects, the dial-time address
// guard, no proxy, no client certificate (HR-070..074), with the check's CA
// bundle (or the system roots) and its timeout. A client unused for
// clientIdle, or of a disabled check (evict), is dropped.
func (a *asker) client(c Check) (*http.Client, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	for id, cc := range a.clients {
		if now.Sub(cc.used) > clientIdle {
			delete(a.clients, id)
		}
	}
	if cc, ok := a.clients[c.ID]; ok {
		cc.used = now
		return cc.client, nil
	}
	ec := httpx.EgressConfig{Timeout: time.Duration(c.TimeoutMs) * time.Millisecond, AllowedPrefixes: a.cfg.AllowedAddrs, RootCAs: a.cfg.RootCAs}
	if c.CAPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(c.CAPEM)) {
			return nil, ErrCA
		}
		ec.RootCAs = pool
	}
	cl := httpx.NewEgressClient(ec)
	a.clients[c.ID] = &cachedClient{client: cl, used: now}
	return cl, nil
}

// evict drops a check's client (a disabled check).
func (a *asker) evict(id ids.UUID) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.clients, id)
}

// entitled reports whether the licence includes external checks; without
// it, no check is read for a decision.
func (s *Service) entitled(ctx context.Context) bool { return s.business(ctx) == nil }
