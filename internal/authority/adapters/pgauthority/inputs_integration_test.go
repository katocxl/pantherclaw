// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/recording"
	defpg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// keepInputs makes the world's Authority seal every evaluation's inputs
// with the org's evaluation_inputs DEK, as the server does.
func (w *world) keepInputs() *recording.Sealer {
	w.t.Helper()
	kek := filepath.Join(w.t.TempDir(), "kek")
	if err := keys.GenerateKEKFile(kek); err != nil {
		w.t.Fatal(err)
	}
	kp, err := keys.NewFileProvider([]string{kek})
	if err != nil {
		w.t.Fatal(err)
	}
	sealer := recording.NewSealer(pccrypto.NewEnvelope(keystore.NewCurrentCache(keystore.NewDEKStore(w.pool, kp), time.Minute, clock.System{})))
	w.auth.Inputs = sealer
	return sealer
}

// inputs reads the evaluation_inputs row of one evaluation, as pc_app.
func (w *world) inputs(txn ids.UUID, evaluation int) (recording.Sealed, bool) {
	w.t.Helper()
	var out recording.Sealed
	found := false
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		row, err := dbq.New(tx).GetEvaluationInputs(ctx, w.org, txn, int32(evaluation))
		if db.IsNoRows(err) {
			return nil
		}
		if err != nil {
			return err
		}
		found = true
		out = recording.Sealed{Format: int(row.FormatVersion), Pipeline: int(row.PipelineVersion), Inputs: row.Inputs, Truncated: row.Truncated}
		copy(out.Digest[:], row.InputsSha256)
		return nil
	}, db.ReadOnly()); err != nil {
		w.t.Fatal(err)
	}
	return out, found
}

// TestIntAuthorizeKeepsEachEvaluationsInputs: every evaluation, the
// tampering denial included, stores its sealed inputs with its receipt,
// and they replay to the same decision through the pipeline, read from the
// recording alone (G0 M7 design decision 11).
func TestIntAuthorizeKeepsEachEvaluationsInputs(t *testing.T) {
	w := newWorld(t)
	sealer := w.keepInputs()
	ctx := context.Background()
	w.refundable("ch_1")
	run := w.run(w.grant("500").ID, ids.UUID{})

	ok := w.authorize(w.request(run, ids.NewV7(), "ch_1", "30.00"))
	if ok.Decision != adomain.Allow {
		t.Fatalf("allow: %+v", ok)
	}
	row, found := w.inputs(ok.TransactionID, 1)
	if !found || row.Truncated || row.Format != recording.FormatVersion || row.Pipeline != pipeline.Version {
		t.Fatalf("inputs = %v %+v", found, row)
	}
	rec, err := sealer.Open(ctx, w.org, ok.TransactionID, 1, row)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Reads.Usage) != 1 || len(rec.Reads.Usage[0].Budgets) != 1 || len(rec.Reads.Facts) != 1 || rec.Reads.Policy == nil ||
		!rec.Reads.Policy.None || len(rec.Reads.Chains) != 1 {
		t.Fatalf("reads = %+v", rec.Reads)
	}

	// Replayed from the recording, with the definition loaded by its pin.
	store := &defpg.Store{Pool: w.pool}
	served := recording.Served{Definitions: map[string]*defs.Definition{}}
	for _, d := range rec.Reads.Definitions {
		def, _, err := store.Pinned(ctx, w.org, d.Pin)
		if err != nil {
			t.Fatal(err)
		}
		served.Definitions[d.Digest] = def
	}
	rd := recording.NewReader(w.org, rec, served)
	req, err := rd.Request()
	if err != nil {
		t.Fatal(err)
	}
	ev, err := (&pipeline.Pipeline{}).EvaluateWith(ctx, rd, req)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Decision != ok.Decision || ev.Basis.Digest() != ok.BasisDigest || ev.Decisive().Code != decisive(ok) || len(rd.Gaps()) > 0 {
		t.Fatalf("replay = %s %s %s, gaps %v; original %s %s %s", ev.Decision, ev.Decisive().Code, ev.Basis.Digest(), rd.Gaps(),
			ok.Decision, decisive(ok), ok.BasisDigest)
	}

	// An open transaction decided again once its fact arrives: each
	// evaluation keeps its own inputs, bound to its row.
	act := ids.NewV7()
	open := w.authorize(w.request(run, act, "ch_9", "10.00"))
	if open.Decision != adomain.CannotAuthorize || decisive(open) != fdomain.ReasonFactMissing {
		t.Fatalf("open: %s %s", open.Decision, decisive(open))
	}
	w.refundable("ch_9")
	if r := w.authorize(w.request(run, act, "ch_9", "10.00")); r.Decision != adomain.Allow || r.Evaluation != 2 {
		t.Fatalf("decided again: %s %d", r.Decision, r.Evaluation)
	}
	first, found1 := w.inputs(open.TransactionID, 1)
	second, found2 := w.inputs(open.TransactionID, 2)
	if !found1 || !found2 {
		t.Fatalf("inputs of evaluations 1 and 2: %v %v", found1, found2)
	}
	for evaluation, row := range map[int]recording.Sealed{1: first, 2: second} {
		r, err := sealer.Open(ctx, w.org, open.TransactionID, evaluation, row)
		if err != nil {
			t.Fatal(err)
		}
		if facts := r.Reads.Facts[0].Facts; (evaluation == 1) != (len(facts) == 0) {
			t.Fatalf("evaluation %d read facts %+v", evaluation, facts)
		}
	}
	if _, err := sealer.Open(ctx, w.org, open.TransactionID, 1, second); err == nil {
		t.Fatal("evaluation 2's inputs opened as evaluation 1's")
	}
}
