// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/evidence/bundle/bundletest"
	"github.com/katocxl/pantherclaw/internal/evidence/keydocs"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

func publishedKeys(t *testing.T) []keystore.PublishedKey {
	t.Helper()
	now := time.Now().UTC()
	r, err := keys.GenerateSigningKey(keys.PurposeReceipts)
	if err != nil {
		t.Fatal(err)
	}
	c, err := keys.GenerateSigningKey(keys.PurposeCheckpoints)
	if err != nil {
		t.Fatal(err)
	}
	a, _, err := keys.GenerateAltKey(keys.PurposeAnchors)
	if err != nil {
		t.Fatal(err)
	}
	return []keystore.PublishedKey{
		{KID: r.KID, Purpose: r.Purpose, Algorithm: keys.AlgEdDSA, Public: r.Public, State: keys.StateActive, Created: now, Changed: now},
		{KID: c.KID, Purpose: c.Purpose, Algorithm: keys.AlgEdDSA, Public: c.Public, State: keys.StateActive, Created: now, Changed: now},
		{KID: a.KID, Purpose: a.Purpose, Algorithm: keys.AlgES256, Public: a.Public, State: keys.StateActive, Created: now, Changed: now},
	}
}

// TestHR196_EvidenceTrustPinsTheDeploymentsKeysOnce: `evidence trust`
// fetches evidence-keys.json, prints every key's fingerprint and writes a
// trust file `pclaw verify` accepts; it never overwrites one, and refuses a
// document that is not evidence-keys.json.
func TestHR196_EvidenceTrustPinsTheDeploymentsKeysOnce(t *testing.T) {
	ks := publishedKeys(t)
	mux := http.NewServeMux()
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	keydocs.New(func(context.Context, []keys.Purpose) ([]keystore.PublishedKey, error) { return ks, nil },
		ts.URL, "pc.test", clock.System{}, nil).Mount(mux)
	dir := t.TempDir()
	env := envOf(map[string]string{"PANTHERCLAW_CONFIG_DIR": dir})
	out := filepath.Join(dir, "trust.json")

	code, stdout, errs := run(t, env, "evidence", "trust", "--out", out, "--server", ts.URL)
	if code != 0 {
		t.Fatalf("evidence trust = %d %s", code, errs)
	}
	for _, k := range ks {
		if !strings.Contains(stdout, k.KID) || !strings.Contains(stdout, fingerprint(k.Public)) {
			t.Errorf("output does not show %s and its fingerprint:\n%s", k.KID, stdout)
		}
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := bundle.ParseTrust(raw)
	if err != nil || trust.LogOrigin != "pc.test" || len(trust.Keys) != len(ks) {
		t.Fatalf("trust file %s: %v", raw, err)
	}
	if code, _, _ := run(t, env, "evidence", "trust", "--out", out, "--server", ts.URL); code == 0 {
		t.Fatal("an existing trust file was overwritten")
	}
	if code, _, errs := run(t, env, "evidence", "trust", "--out", filepath.Join(dir, "x.json")); code == 0 || !strings.Contains(errs, "--server") {
		t.Fatalf("without a server = %d %q", code, errs)
	}

	// A plain trust file served in its place is refused.
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(raw) }))
	t.Cleanup(fake.Close)
	if code, _, _ := run(t, env, "evidence", "trust", "--out", filepath.Join(dir, "y.json"), "--server", fake.URL); code == 0 {
		t.Fatal("a document that is not evidence-keys.json was pinned")
	}
	if _, err := os.Stat(filepath.Join(dir, "y.json")); err == nil {
		t.Fatal("a refused document was written")
	}
}

type recordEvidence struct {
	pantherclawv1connect.UnimplementedEvidenceServiceHandler
	req    *pantherclawv1.ExportBundleRequest
	bundle []byte
	replay *pantherclawv1.ReplayDecisionRequest
}

func (r *recordEvidence) ReplayDecision(_ context.Context, req *pantherclawv1.ReplayDecisionRequest) (*pantherclawv1.ReplayDecisionResponse, error) {
	r.replay = req
	out := &pantherclawv1.ReplayDecisionResponse{
		TransactionId: req.GetTransactionId(), Evaluation: 2, Complete: true, Reproduced: true,
		Decision: pantherclawv1.Decision_DECISION_ALLOW, OriginalDecision: pantherclawv1.Decision_DECISION_ALLOW,
	}
	if req.GetIncludeInputs() {
		out.Inputs = []byte(`{"format":1,"pipeline":1}`)
	}
	return out, nil
}

// TestHR197_EvidenceReplayAsksForTheEvaluationAndShowsTheOutcome: `pclaw
// evidence replay` sends the transaction, evaluation and policy version,
// prints the replay as JSON, and with --show-inputs embeds the recorded
// inputs as JSON beside it.
func TestHR197_EvidenceReplayAsksForTheEvaluationAndShowsTheOutcome(t *testing.T) {
	rec := &recordEvidence{}
	cs := connect.NewServer()
	pantherclawv1connect.RegisterEvidenceServiceHandler(cs, rec)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	env := envOf(map[string]string{"PANTHERCLAW_SERVER": ts.URL, "PANTHERCLAW_API_KEY": "pck_test_x"})
	const txn, policy = "0192aaaa-bbbb-7ccc-8ddd-000000000001", "0192aaaa-bbbb-7ccc-8ddd-000000000009"

	code, stdout, errs := run(t, env, "evidence", "replay", "--txn", txn, "--evaluation", "2", "--policy-version", policy)
	if code != 0 || !strings.Contains(stdout, `"reproduced": true`) || strings.Contains(stdout, `"inputs"`) {
		t.Fatalf("evidence replay = %d %s %s", code, stdout, errs)
	}
	if rec.replay.GetTransactionId() != txn || rec.replay.GetEvaluation() != 2 || rec.replay.GetPolicyVersionId() != policy ||
		rec.replay.GetIncludeInputs() {
		t.Fatalf("request = %v", rec.replay)
	}
	code, stdout, errs = run(t, env, "evidence", "replay", "--txn", txn, "--show-inputs")
	if code != 0 || !strings.Contains(stdout, `"replay": {`) || !strings.Contains(stdout, `"pipeline": 1`) || !rec.replay.GetIncludeInputs() {
		t.Fatalf("evidence replay --show-inputs = %d %s %s", code, stdout, errs)
	}
	for _, args := range [][]string{{}, {"--txn", txn, "--evaluation", "-1"}, {"--txn", txn, "extra"}} {
		if code, _, _ := run(t, env, append([]string{"evidence", "replay"}, args...)...); code == 0 {
			t.Errorf("evidence replay %v was accepted", args)
		}
	}
}

func (r *recordEvidence) ExportBundle(_ context.Context, req *pantherclawv1.ExportBundleRequest) (*pantherclawv1.ExportBundleResponse, error) {
	r.req = req
	return &pantherclawv1.ExportBundleResponse{Bundle: r.bundle, Entries: 3, CheckpointSize: 3}, nil
}

func TestEvidenceBundleAsksForTheSelectionAndWritesTheBundle(t *testing.T) {
	iss := bundletest.NewIssuer(t)
	iss.Append(2)
	saved := iss.Checkpoint()
	iss.Append(1)
	iss.Checkpoint()
	good := bundletest.Encode(t, iss.Bundle())
	rec := &recordEvidence{bundle: good}
	cs := connect.NewServer()
	pantherclawv1connect.RegisterEvidenceServiceHandler(cs, rec)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	env := envOf(map[string]string{"PANTHERCLAW_SERVER": ts.URL, "PANTHERCLAW_API_KEY": "pck_test_x"})
	dir := t.TempDir()

	const a, b = "0192aaaa-bbbb-7ccc-8ddd-000000000001", "0192aaaa-bbbb-7ccc-8ddd-000000000002"
	out := filepath.Join(dir, "bundle.json")
	if code, stdout, errs := run(t, env, "evidence", "bundle", "--txn", a, "--txn", b, "--out", out); code != 0 ||
		!strings.Contains(stdout, "checkpoint of size 3") {
		t.Fatalf("evidence bundle = %d %s %s", code, stdout, errs)
	}
	if ids := rec.req.GetTransactions().GetIds(); len(ids) != 2 || ids[0] != a || rec.req.GetConsistencyFrom() != 0 {
		t.Fatalf("request = %v", rec.req)
	}
	if got, _ := os.ReadFile(out); !bytes.Equal(got, good) {
		t.Fatal("the written bundle is not the server's")
	}

	prev := filepath.Join(dir, "saved.checkpoint")
	if err := os.WriteFile(prev, saved, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := run(t, env, "evidence", "bundle", "--from", "1", "--to", "3", "--previous", prev,
		"--out", filepath.Join(dir, "range.json")); code != 0 {
		t.Fatalf("range bundle = %d %s", code, errs)
	}
	if r := rec.req.GetRange(); r.GetFromSeq() != 1 || r.GetToSeq() != 3 || rec.req.GetConsistencyFrom() != 2 {
		t.Fatalf("range request = %v", rec.req)
	}

	for _, args := range [][]string{
		{"--out", filepath.Join(dir, "none.json")},
		{"--txn", a, "--from", "1", "--to", "2", "--out", filepath.Join(dir, "both.json")},
		{"--txn", a},
	} {
		if code, _, _ := run(t, env, append([]string{"evidence", "bundle"}, args...)...); code == 0 {
			t.Errorf("evidence bundle %v was accepted", args)
		}
	}
	if code, _, _ := run(t, env, "evidence", "bundle", "--txn", a, "--out", out); code == 0 {
		t.Fatal("an existing bundle file was overwritten")
	}
	rec.bundle = []byte(`{"format":"something else"}`)
	bad := filepath.Join(dir, "bad.json")
	if code, _, errs := run(t, env, "evidence", "bundle", "--txn", a, "--out", bad); code == 0 || !strings.Contains(errs, "invalid bundle") {
		t.Fatalf("an invalid bundle = %d %q", code, errs)
	}
	if _, err := os.Stat(bad); err == nil {
		t.Fatal("an invalid bundle was written")
	}
}
