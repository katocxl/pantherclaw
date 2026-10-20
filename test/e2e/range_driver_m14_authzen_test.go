// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
)

// The range's authzen face (G0 M14 D29, RT-047, RT-048): the driver acts
// as a registered enforcement point in front of the payments simulator.
// It asks the AuthZEN decision endpoint about each request with the
// agent's credentials and, when allowed, forwards it to the simulator.

// rangePoints are the drivers' enforcement points, set up on first use.
var rangePoints sync.Map // *rangeDriver → *azPoint

func (d *rangeDriver) authzenPoint() *azPoint {
	if p, ok := rangePoints.Load(d); ok {
		return p.(*azPoint)
	}
	p := authzenPoint(d.t, d.s, "agent_held", d.s.simURL)
	rangePoints.Store(d, p)
	return p
}

// authzenRequest is the call's request.
func authzenRequest(w callWith, act ids.UUID) (azRequest, error) {
	if w.Method == "" || w.Path == "" {
		return azRequest{}, fmt.Errorf("face authzen needs a method and path")
	}
	var b []byte
	if len(w.Body) > 0 {
		b = []byte(w.Body)
		if w.Body.Kind() == '"' {
			var s string
			if err := json.Unmarshal(w.Body, &s); err != nil {
				return azRequest{}, err
			}
			b = []byte(s)
		}
	}
	return azRequest{Method: w.Method, Path: w.Path, Body: b, Action: act}, nil
}

// callAuthZEN asks about one call and, when allowed, sends it.
func (d *rangeDriver) callAuthZEN(_ string, w callWith, act ids.UUID) (domain.Observation, *callRec, error) {
	r, err := authzenRequest(w, act)
	if err != nil {
		return domain.Observation{}, nil, err
	}
	p := d.authzenPoint()
	a := p.evaluate(d.t, p.evaluation(d.t, r))
	if a.Decision {
		if err := d.forwardAllowed(r, a.Context.PantherClaw.ActionToken); err != nil {
			return domain.Observation{}, nil, err
		}
	}
	obs := azObserve(a)
	return obs, &callRec{act: act, txn: obs.TransactionID, obs: obs}, nil
}

// forwardAllowed sends an allowed request to the simulator as the
// enforcement point would.
func (d *rangeDriver) forwardAllowed(r azRequest, actionToken string) error {
	req, err := http.NewRequestWithContext(context.Background(), r.Method, d.s.simURL+r.Path, bytes.NewReader(r.Body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "agent-"+ids.NewV7().String())
	if actionToken != "" {
		req.Header.Set("PAP-Action", actionToken)
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("the simulator refused an allowed request: %d", resp.StatusCode)
	}
	return nil
}

// stealAuthZEN is an enforcement point misusing what it forwards: an
// agent's token with another key's proof (impersonation), an evaluation
// sent again verbatim (a replay to spend twice), or a nonce PantherClaw
// never issued.
func (d *rangeDriver) stealAuthZEN(mode string, w callWith) (domain.Observation, error) {
	r, err := authzenRequest(w, ids.NewV7())
	if err != nil {
		return domain.Observation{}, err
	}
	p := d.authzenPoint()
	switch mode {
	case "token_without_key":
		_, thief, _ := ed25519.GenerateKey(rand.Reader)
		r.Key, r.Token = thief, d.s.token
		return azObserve(p.evaluate(d.t, p.evaluation(d.t, r))), nil
	case "proof_replay":
		// The replay must follow an allow that spent, and spend nothing more.
		ev := p.evaluation(d.t, r)
		first := p.evaluate(d.t, ev)
		if !first.Decision {
			return domain.Observation{}, fmt.Errorf("proof_replay: the first evaluation was refused (%s); nothing to replay", first.Context.PantherClaw.Code)
		}
		if err := d.forwardAllowed(r, first.Context.PantherClaw.ActionToken); err != nil {
			return domain.Observation{}, err
		}
		refunds, spent := d.s.sim.Stats().Refunds, d.delegated()
		obs := azObserve(p.evaluate(d.t, ev))
		if d.s.sim.Stats().Refunds != refunds || d.delegated() != spent {
			return domain.Observation{}, fmt.Errorf("proof_replay: the replay spent again")
		}
		return obs, nil
	case "stale_nonce":
		live := p.nonce
		p.nonce = base64.RawURLEncoding.EncodeToString([]byte("stale-stale-stale-stale-stale-0"))
		obs := azObserve(p.evaluate(d.t, p.evaluation(d.t, r)))
		p.nonce = live
		return obs, nil
	case "other_instance":
		// The point names, as the subject, an agent other than the one
		// whose credentials it forwards.
		r.Agent = otherAgent(d.t, d.s).String()
		return azObserve(p.evaluate(d.t, p.evaluation(d.t, r))), nil
	}
	return domain.Observation{}, fmt.Errorf("agent.steal mode %q on face authzen", mode)
}

// azObserve reads a decision: true is ALLOW (an observing route too),
// false the outcome PantherClaw named, with its code.
func azObserve(a azAnswer) domain.Observation {
	pc := a.Context.PantherClaw
	obs := domain.Observation{TransactionID: pc.TransactionID, Reason: pc.Code, Code: pc.Code, Detail: "outcome " + pc.Outcome + ", coverage " + pc.Coverage}
	if pc.Code != "" {
		obs.Reasons = []string{pc.Code}
	}
	switch {
	case a.Decision:
		obs.Outcome = domain.OutcomeAllow
	case pc.Outcome == "hold":
		obs.Outcome = domain.OutcomeHold
	case pc.Outcome == "deny":
		obs.Outcome = domain.OutcomeDeny
	default:
		obs.Outcome = domain.OutcomeCannotAuthorize
	}
	if raw, err := json.Marshal(a); err == nil {
		obs.Response = capBytes(raw)
	}
	return obs
}

// delegated counts the org's DELEGATED attempts.
func (d *rangeDriver) delegated() string {
	return d.s.row(d.t, "SELECT count(*) FROM pc.execution_attempts WHERE org_id = $1 AND outcome = 'delegated'", d.s.org)
}
