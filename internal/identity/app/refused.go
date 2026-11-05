// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Limits of the refused-proof record (HR-850).
const (
	// RefusalWindow: at most one record per org, instance (or key) and
	// PAP-Error code per window; the refusals in between are counted.
	RefusalWindow = time.Minute
	// MaxRefusalRecordsPerOrg bounds the records one org writes per window
	// across all its keys, so a flood of made-up keys cannot grow the
	// ledger; the rest are counted on their own key.
	MaxRefusalRecordsPerOrg = 60
	// maxRefusalKeys bounds the limiter's memory.
	maxRefusalKeys = 10_000
)

// refusals is the in-process limiter of refused-proof records (HR-850).
type refusals struct {
	mu   sync.Mutex
	keys map[string]refusalSlot
	orgs map[ids.OrgID]refusalSlot
}

type refusalSlot struct {
	at time.Time
	n  int // suppressed since the last record (keys) or records this window (orgs)
}

// take reports whether a refusal of key in org may be recorded at now and,
// if so, how many refusals of key were suppressed since its last record.
func (r *refusals) take(org ids.OrgID, key string, now time.Time) (bool, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.keys == nil {
		r.keys, r.orgs = map[string]refusalSlot{}, map[ids.OrgID]refusalSlot{}
	}
	k := org.String() + "|" + key
	s, seen := r.keys[k]
	if seen && now.Sub(s.at) < RefusalWindow {
		s.n++
		r.keys[k] = s
		return false, 0
	}
	o := r.orgs[org]
	if now.Sub(o.at) >= RefusalWindow {
		o = refusalSlot{at: now}
	}
	if o.n >= MaxRefusalRecordsPerOrg {
		s.n++
		if !seen {
			s.at = now
		}
		r.keys[k] = s
		return false, 0
	}
	o.n++
	r.orgs[org] = o
	if len(r.keys) >= maxRefusalKeys {
		r.prune(now)
	}
	r.keys[k] = refusalSlot{at: now}
	return true, s.n
}

// prune drops the keys whose window ended with nothing suppressed, then,
// if the map is still full, every key older than an hour.
func (r *refusals) prune(now time.Time) {
	for k, s := range r.keys {
		if now.Sub(s.at) >= RefusalWindow && s.n == 0 {
			delete(r.keys, k)
		}
	}
	if len(r.keys) < maxRefusalKeys {
		return
	}
	for k, s := range r.keys {
		if now.Sub(s.at) >= time.Hour {
			delete(r.keys, k)
		}
	}
	for o, s := range r.orgs {
		if now.Sub(s.at) >= RefusalWindow {
			delete(r.orgs, o)
		}
	}
}

// RecordRefusedProof records a workload request the Authority refused
// because its PAP/1 credentials did not verify, as an identity event
// (HR-850): audit.security.workload_proof_refused with the PAP-Error code,
// the instance and agent when the workload token itself verifies, the
// thumbprint of the key the proof names, the gateway and how many refusals
// of the same key and code were suppressed since the last record. It never
// records the token or the proof. A refusal that is only about time
// (pap.Stale) and any error that is not a PAP-Error record nothing. At
// most one record per org, instance (or key) and code a minute, and at
// most MaxRefusalRecordsPerOrg per org a minute. The refusal itself is
// unchanged: recording happens after it, in its own transaction.
func (s *Service) RecordRefusedProof(ctx context.Context, org ids.OrgID, in IdentifyInput, gateway string, refusal error) error {
	var pe *pap.Error
	if !errors.As(refusal, &pe) || pap.Stale(refusal) {
		return nil
	}
	now := s.clk.Now()
	var inst *pap.Instance
	jkt := pap.ProofJKT(in.Proof)
	if in.Request.Token != "" {
		if v, err := s.TokenVerifier(); err == nil {
			if t, err := pap.VerifyToken(v, s.issuer, in.Request.Token, now); err == nil && t.Instance.Org == org {
				inst = &t.Instance
				if jkt == "" {
					jkt = t.JKT
				}
			}
		}
	}
	key := "key:" + jkt
	if inst != nil {
		key = "instance:" + inst.Instance.String()
	}
	ok, suppressed := s.refusals.take(org, key+"|"+string(pe.Code), now)
	if !ok {
		return nil
	}
	details := map[string]string{"pap_code": string(pe.Code), "suppressed": strconv.Itoa(suppressed)}
	if jkt != "" {
		details["jkt"] = jkt
	}
	if gateway != "" {
		details["gateway"] = gateway
	}
	ev := audit.Event{
		Name: auditkind.SecurityWorkloadProofRefused, Actor: evdomainSystem(), Outcome: audit.Denied, Details: details,
	}
	if gateway != "" {
		ev.Actor = evdomain.Actor{Type: "gateway", ID: gateway}
	}
	if inst != nil {
		details["instance"], details["agent"] = inst.Instance.String(), inst.Agent.String()
		ev.Object = &audit.Object{Type: "instance", ID: inst.Instance.String()}
	}
	return s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := audit.Record(ctx, tx, ev)
		return err
	})
}
