// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/anchor"
	"github.com/katocxl/pantherclaw/internal/evidence/anchor/anchortest"
	"github.com/katocxl/pantherclaw/internal/evidence/anchoring"
	"github.com/katocxl/pantherclaw/internal/evidence/checkpoints"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// stalledLog is a transparency log that holds every request until released,
// then answers 503.
type stalledLog struct {
	entered chan struct{}
	release chan struct{}
}

func (s *stalledLog) Do(req *http.Request) (*http.Response, error) {
	s.entered <- struct{}{}
	select {
	case <-s.release:
	case <-req.Context().Done():
		return nil, req.Context().Err()
	}
	return anchortest.Reply(http.StatusServiceUnavailable, nil), nil
}

// checkpointWorld chains w's org's ledger and signs a checkpoint, as the
// workers would.
func (w *world) checkpointWorld(reg *keys.Registry) {
	w.t.Helper()
	ctx := context.Background()
	for deadline := time.Now().Add(30 * time.Second); ; {
		if _, err := ledger.ChainAll(ctx, w.pool, w.org, 500); err != nil {
			w.t.Fatal(err)
		}
		var pending int
		if err := w.pool.InTenantTx(ctx, w.org, func(ctx context.Context, tx db.TenantTx) error {
			return tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM pc.ledger_entries) - (SELECT count(*) FROM pc.ledger_chain)`).Scan(&pending)
		}); err != nil {
			w.t.Fatal(err)
		}
		if pending == 0 {
			break
		}
		if time.Now().After(deadline) {
			w.t.Fatal("the entries were not chained within 30 seconds")
		}
		time.Sleep(50 * time.Millisecond)
	}
	cps := &checkpoints.Service{Pool: w.pool, Keys: reg, LogOrigin: "pc.test", Log: pclog.Discard()}
	if res, err := cps.Checkpoint(ctx, w.org); err != nil || !res.Signed {
		w.t.Fatalf("checkpoint: %+v, %v", res, err)
	}
}

// TestHR195_AnchoringFailureNeverAffectsAuthorize: while an anchor waits on
// a transparency log that does not answer, Authorize decides as before (the
// anchoring job holds no transaction or lock while it talks to the log);
// when the log fails, the anchor is FAILED and decisions are unchanged
// (design decision 20: authorization never waits for proof).
func TestHR195_AnchoringFailureNeverAffectsAuthorize(t *testing.T) {
	w := newWorld(t)
	w.refundable("ch_1", "ch_2", "ch_3")
	run := w.run(w.grant("500").ID, ids.UUID{})
	if r := w.authorize(w.request(run, ids.NewV7(), "ch_1", "10.00")); r.Decision != adomain.Allow {
		t.Fatalf("before anchoring: %s", r.Decision)
	}
	kek := filepath.Join(t.TempDir(), "kek")
	if err := keys.GenerateKEKFile(kek); err != nil {
		t.Fatal(err)
	}
	kp, err := keys.NewFileProvider([]string{kek})
	if err != nil {
		t.Fatal(err)
	}
	reg := keys.NewRegistry()
	if err := keystore.LoadSigningKeys(context.Background(), w.pool, kp, reg); err != nil {
		t.Fatal(err)
	}
	w.checkpointWorld(reg)

	log := &stalledLog{entered: make(chan struct{}, 1), release: make(chan struct{})}
	rekorKey := anchortest.NewRekor(t, "ecdsa")
	logKey, err := anchor.NewLog(anchortest.RekorOrigin, rekorKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	ca := anchortest.NewCA(t, anchortest.CertOpts{})
	verifier, err := anchor.NewTSAVerifier(ca.Chain)
	if err != nil {
		t.Fatal(err)
	}
	svc := &anchoring.Service{
		Pool: w.pool, Keys: reg, LogOrigin: "pc.test", Log: pclog.Discard(),
		Rekor: &anchor.RekorClient{URL: anchortest.RekorURL, HTTP: anchoring.HostOnly{Host: "rekor.test", Next: log}, Log: logKey},
		TSA: &anchor.TSAClient{
			URL: anchortest.TSAURL, HTTP: anchoring.HostOnly{Host: "tsa.test", Next: &anchortest.TSA{T: t, CA: ca}},
			Verifier: verifier,
		},
	}
	ctx := context.Background()
	created, err := svc.Create(ctx, svc.Period(time.Now()))
	if err != nil || created.ID.IsZero() {
		t.Fatalf("Create = %+v, %v", created, err)
	}
	done := make(chan anchoring.Result, 1)
	go func() {
		res, err := svc.Submit(ctx, created.ID)
		if err != nil {
			t.Error(err)
		}
		done <- res
	}()
	select {
	case <-log.entered:
	case <-time.After(30 * time.Second):
		t.Fatal("the anchor never reached the log")
	}
	// The log has the anchor and does not answer: decisions go on.
	if r := w.authorize(w.request(run, ids.NewV7(), "ch_2", "10.00")); r.Decision != adomain.Allow {
		t.Fatalf("while the log stalls: %s", r.Decision)
	}
	close(log.release)
	select {
	case res := <-done:
		if res.State != "FAILED" || res.Code != anchoring.CodeRekorFailed {
			t.Fatalf("Submit = %+v", res)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Submit did not return")
	}
	if r := w.authorize(w.request(run, ids.NewV7(), "ch_3", "10.00")); r.Decision != adomain.Allow {
		t.Fatalf("after the anchor failed: %s", r.Decision)
	}
}
