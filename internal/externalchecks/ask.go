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
	"sync"
	"time"
	"unicode/utf8"

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

// asker calls the checks: one egress client per check (its CA and
// timeout never change), and at most MaxInFlight calls per org.
type asker struct {
	cfg     Config
	mu      sync.Mutex
	clients map[ids.UUID]*http.Client
	flights map[ids.OrgID]chan struct{}
}

func newAsker(cfg Config) *asker {
	return &asker{cfg: cfg, clients: map[ids.UUID]*http.Client{}, flights: map[ids.OrgID]chan struct{}{}}
}

// preloaded is the org's active checks, read before the snapshot opened.
type preloaded struct {
	org    ids.OrgID
	checks []Check
	err    error
}

type preloadKey struct{}

// Preload implements pipeline.ExternalCheck: it reads the org's ACTIVE
// checks in its own short transaction, before the decision's snapshot
// holds a connection, so a burst of decisions never waits on the pool
// for a second one. A read error is kept and Ask returns it
// (CANNOT_AUTHORIZE).
func (s *Service) Preload(ctx context.Context, org ids.OrgID) context.Context {
	checks, err := s.active(ctx, org)
	return context.WithValue(ctx, preloadKey{}, preloaded{org: org, checks: checks, err: err})
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

// Ask implements pipeline.ExternalCheck: it asks each of the org's ACTIVE
// checks whose operations cover the action, in name order, from the
// preloaded list (read here when there is none).
func (s *Service) Ask(ctx context.Context, org ids.OrgID, in pipeline.ExternalInput) ([]pipeline.ExternalVerdict, error) {
	pre, ok := ctx.Value(preloadKey{}).(preloaded)
	if !ok || pre.org != org {
		pre.checks, pre.err = s.active(ctx, org)
	}
	if pre.err != nil {
		return nil, pre.err
	}
	var checks []Check
	for _, c := range pre.checks {
		if c.Covers(in.Operation) {
			checks = append(checks, c)
		}
	}
	if len(checks) == 0 {
		return nil, nil
	}
	body, err := Body(org, in)
	if err != nil {
		return nil, err
	}
	out := make([]pipeline.ExternalVerdict, len(checks))
	var wg sync.WaitGroup
	for i, c := range checks {
		wg.Go(func() {
			a := s.asker.ask(ctx, org, c, body)
			out[i] = pipeline.ExternalVerdict{Check: c.Name, Decision: a.Decision, Reasons: a.Reasons, Unavailable: a.Unavailable}
		})
	}
	wg.Wait()
	return out, nil
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
	slot := a.slot(org)
	select {
	case slot <- struct{}{}:
		defer func() { <-slot }()
	default:
		return Answer{Unavailable: UnavailableInFlight}
	}
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
	for _, r := range w.Result.Reasons {
		if !utf8.ValidString(r) || utf8.RuneCountInString(r) > MaxReasonLen {
			return Answer{Unavailable: UnavailableBadAnswer}
		}
	}
	return Answer{Decision: d, Reasons: w.Result.Reasons}
}

// slot is the org's in-flight semaphore.
func (a *asker) slot(org ids.OrgID) chan struct{} {
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.flights[org]
	if !ok {
		s = make(chan struct{}, MaxInFlight)
		a.flights[org] = s
	}
	return s
}

// client is the check's egress client: no redirects, the dial-time address
// guard, no proxy, no client certificate (HR-070..074), with the check's CA
// bundle (or the system roots) and its timeout.
func (a *asker) client(c Check) (*http.Client, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if cl, ok := a.clients[c.ID]; ok {
		return cl, nil
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
	a.clients[c.ID] = cl
	return cl, nil
}
