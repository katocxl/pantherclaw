// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package anchoring_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/json/v2"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/anchor"
	"github.com/katocxl/pantherclaw/internal/evidence/anchor/anchortest"
	"github.com/katocxl/pantherclaw/internal/evidence/anchoring"
	evapp "github.com/katocxl/pantherclaw/internal/evidence/app"
	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/evidence/checkpoints"
	"github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/keydocs"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	"github.com/katocxl/pantherclaw/internal/evidence/merkle"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

const origin = "pc.test"

type fixture struct {
	d     *dbtest.DB
	p     *db.Pool
	reg   *keys.Registry
	orgs  []ids.OrgID
	rekor *anchortest.Rekor
	tsa   *anchortest.TSA
	svc   *anchoring.Service
}

// newFixture makes orgs, each with a few chained entries and a signed
// checkpoint, and an anchoring service talking to a local Rekor v2 log and
// timestamp authority (no network). The authority signs with the real
// clock, after the anchors key was created.
func newFixture(t *testing.T, orgs int) *fixture {
	t.Helper()
	d := dbtest.New(t)
	p := d.AppPool(t)
	path := filepath.Join(t.TempDir(), "kek")
	if err := keys.GenerateKEKFile(path); err != nil {
		t.Fatal(err)
	}
	kp, err := keys.NewFileProvider([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	reg := keys.NewRegistry()
	ctx := context.Background()
	if err := keystore.LoadSigningKeys(ctx, p, kp, reg); err != nil {
		t.Fatal(err)
	}
	f := &fixture{d: d, p: p, reg: reg, rekor: anchortest.NewRekor(t, "ecdsa")}
	cps := &checkpoints.Service{Pool: p, Keys: reg, LogOrigin: origin, Log: pclog.Discard()}
	for range orgs {
		org := ids.New[ids.Org]()
		f.orgs = append(f.orgs, org)
		f.exec(t, org, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'org')", org)
		f.grow(t, org, 3)
		if res, err := cps.Checkpoint(ctx, org); err != nil || !res.Signed {
			t.Fatalf("checkpoint: %+v, %v", res, err)
		}
	}
	f.tsa = &anchortest.TSA{T: t, CA: anchortest.NewCA(t, anchortest.CertOpts{Now: time.Now()})}
	// A minute ahead: the anchors key's validity starts at the database's
	// clock, which may run a little ahead of this one.
	f.tsa.Fault.GenTime = time.Now().UTC().Add(time.Minute)
	log, err := anchor.NewLog(anchortest.RekorOrigin, f.rekor.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := anchor.NewTSAVerifier(f.tsa.CA.Chain)
	if err != nil {
		t.Fatal(err)
	}
	f.svc = &anchoring.Service{
		Pool: p, Keys: reg, LogOrigin: origin, Log: pclog.Discard(),
		Rekor: &anchor.RekorClient{URL: anchortest.RekorURL, HTTP: anchoring.HostOnly{Host: "rekor.test", Next: f.rekor}, Log: log},
		TSA:   &anchor.TSAClient{URL: anchortest.TSAURL, HTTP: anchoring.HostOnly{Host: "tsa.test", Next: f.tsa}, Verifier: verifier},
	}
	return f
}

func (f *fixture) exec(t *testing.T, org ids.OrgID, sql string, args ...any) {
	t.Helper()
	if err := f.p.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// grow appends n entries to org's ledger and chains them.
func (f *fixture) grow(t *testing.T, org ids.OrgID, n int) {
	t.Helper()
	ctx := context.Background()
	if err := f.p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		for i := range n {
			body, err := domain.CanonicalBody(map[string]int{"i": i})
			if err != nil {
				return err
			}
			if _, err := ledger.Append(ctx, tx, "test.appended", domain.Actor{Type: "system", ID: "test"}, body); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// The chainer links only entries below the cluster's oldest running
	// transaction, which other tests on the shared cluster can hold back.
	for deadline := time.Now().Add(30 * time.Second); ; {
		if _, err := ledger.ChainAll(ctx, f.p, org, 500); err != nil {
			t.Fatal(err)
		}
		var entries, chained int
		if err := f.p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			return tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM pc.ledger_entries), (SELECT count(*) FROM pc.ledger_chain)`).Scan(&entries, &chained)
		}); err != nil {
			t.Fatal(err)
		}
		if entries == chained {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the entries were not chained within 30 seconds")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (f *fixture) anchor(t *testing.T, id ids.UUID) dbq.PcAnchor {
	t.Helper()
	var a dbq.PcAnchor
	if err := f.p.InGlobalTx(context.Background(), db.GlobalAnchors, func(ctx context.Context, tx db.GlobalTx) error {
		var err error
		a, err = dbq.New(tx).GetAnchor(ctx, id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return a
}

type leafRow struct {
	index int32
	nonce []byte
	size  int64
	note  []byte
}

func (f *fixture) leaf(t *testing.T, org ids.OrgID, anchorID ids.UUID) leafRow {
	t.Helper()
	var r leafRow
	if err := f.p.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, `SELECT l.leaf_index, l.nonce, l.checkpoint_size, c.note FROM pc.anchor_leaves l
			JOIN pc.checkpoints c ON c.org_id = l.org_id AND c.tree_size = l.checkpoint_size
			WHERE l.org_id = $1 AND l.anchor_id = $2`, org, anchorID).Scan(&r.index, &r.nonce, &r.size, &r.note)
	}); err != nil {
		t.Fatal(err)
	}
	return r
}

func (f *fixture) create(t *testing.T, period time.Time) anchoring.Created {
	t.Helper()
	c, err := f.svc.Create(context.Background(), period)
	if err != nil || c.Exists || c.ID.IsZero() {
		t.Fatalf("Create(%s) = %+v, %v", period, c, err)
	}
	return c
}

// TestHR195_AQuietOrgsLeafChangesEveryAnchorAndRevealsNothing: two anchors
// of two orgs whose checkpoints did not change: each org's leaf differs
// between the anchors (a fresh nonce), the leaves are in ascending order,
// and the global row holds nothing that names an org or its checkpoint:
// no org id, no checkpoint digest, no unblinded leaf. Each org's own row
// recomputes its leaf. A period is anchored once.
func TestHR195_AQuietOrgsLeafChangesEveryAnchorAndRevealsNothing(t *testing.T) {
	f := newFixture(t, 2)
	p1 := time.Now().UTC().Truncate(time.Hour).Add(-2 * time.Hour)
	first := f.create(t, p1)
	second := f.create(t, p1.Add(time.Hour))
	if again, err := f.svc.Create(context.Background(), p1); err != nil || !again.Exists {
		t.Fatalf("a second anchor for the same period: %+v, %v", again, err)
	}
	a1, a2 := f.anchor(t, first.ID), f.anchor(t, second.ID)
	for _, a := range []dbq.PcAnchor{a1, a2} {
		leaves, err := anchoring.Leaves(a.Leaves)
		if err != nil || len(leaves) != 2 || bytes.Compare(leaves[0], leaves[1]) >= 0 {
			t.Fatalf("anchor %s: %d leaves, not strictly ascending: %v", a.ID, len(leaves), err)
		}
		if a.State != "PENDING" || a.Kid == "" || a.RekorEntry != nil || a.TimestampToken != nil {
			t.Fatalf("a new anchor: %+v", a)
		}
		s, err := anchor.ParseStatement(a.Statement)
		if err != nil || s.Origin != origin || s.Size != 2 || !bytes.Equal(s.Root[:], a.Root) {
			t.Fatalf("statement %+v, %v", s, err)
		}
	}
	for _, org := range f.orgs {
		l1, l2 := f.leaf(t, org, first.ID), f.leaf(t, org, second.ID)
		if l1.size != l2.size || bytes.Equal(l1.nonce, l2.nonce) {
			t.Fatalf("org %s: checkpoint %d then %d, nonces equal %v", org, l1.size, l2.size, bytes.Equal(l1.nonce, l2.nonce))
		}
		leaves1, _ := anchoring.Leaves(a1.Leaves)
		leaves2, _ := anchoring.Leaves(a2.Leaves)
		leaf1, leaf2 := leaves1[l1.index], leaves2[l2.index]
		if bytes.Equal(leaf1, leaf2) {
			t.Fatalf("org %s: a quiet org's leaf did not change between anchors", org)
		}
		var n1 anchor.Nonce
		copy(n1[:], l1.nonce)
		if want := anchor.Leaf(n1, l1.note); !bytes.Equal(want[:], leaf1) {
			t.Fatalf("org %s: its row does not recompute its leaf", org)
		}
		digest := sha256.Sum256(l1.note)
		unblinded := merkle.LeafHash(l1.note)
		orgID := org.UUID()
		for _, a := range []dbq.PcAnchor{a1, a2} {
			for _, b := range [][]byte{a.Leaves, a.Statement, a.Signature, a.Root} {
				for _, secret := range [][]byte{orgID[:], []byte(org.String()), digest[:], unblinded[:], l1.note} {
					if bytes.Contains(b, secret) {
						t.Fatalf("the global anchor row reveals org %s or its checkpoint", org)
					}
				}
			}
		}
	}
}

// TestHR195_AnAnchorIsLoggedTimestampedAndVerifiedEndToEnd: the anchor's
// Rekor request is a well-formed hashedrekord v0.0.2 of the statement's
// digest, signed by the anchors key; its timestamp request is over the
// signature; both answers verify, so the anchor is ANCHORED. ExportBundle
// then carries the org's leaf, nonce, the anchor's leaves, the Rekor entry
// and the timestamp, and the offline verifier of `pclaw verify` passes
// every anchor check against the published keys and the log and authority
// a Sigstore trusted root would name.
func TestHR195_AnAnchorIsLoggedTimestampedAndVerifiedEndToEnd(t *testing.T) {
	f := newFixture(t, 2)
	ctx := context.Background()
	c := f.create(t, f.svc.Period(time.Now()))
	res, err := f.svc.Submit(ctx, c.ID)
	if err != nil || res.State != "ANCHORED" {
		t.Fatalf("Submit = %+v, %v", res, err)
	}
	a := f.anchor(t, c.ID)
	if a.State != "ANCHORED" || a.Attempts != 1 || a.AnchoredAt == nil || a.RekorEntry == nil || a.TimestampToken == nil {
		t.Fatalf("anchor: %+v", a)
	}
	var req struct {
		Req struct {
			Digest []byte `json:"digest"`
		} `json:"hashedRekordRequestV002"`
	}
	if err := json.Unmarshal(f.rekor.Request, &req); err != nil {
		t.Fatal(err)
	}
	if want := sha256.Sum256(a.Statement); !bytes.Equal(req.Req.Digest, want[:]) {
		t.Fatal("the Rekor request does not record the statement's digest")
	}
	var tsReq struct {
		Version int
		Imprint struct {
			Alg    struct{ Algorithm asn1.ObjectIdentifier }
			Hashed []byte
		}
		Nonce   *big.Int `asn1:"optional"`
		CertReq bool     `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(f.tsa.Request, &tsReq); err != nil {
		t.Fatal(err)
	}
	if want := sha256.Sum256(a.Signature); !bytes.Equal(tsReq.Imprint.Hashed, want[:]) || tsReq.Nonce == nil || !tsReq.CertReq {
		t.Fatal("the timestamp request is not over the statement's signature with a nonce")
	}
	// Submitting again changes nothing and calls nobody.
	if res, err := f.svc.Submit(ctx, c.ID); err != nil || res.State != "ANCHORED" || f.rekor.Calls != 1 || f.tsa.Calls != 1 {
		t.Fatalf("a second Submit: %+v, %v; calls %d, %d", res, err, f.rekor.Calls, f.tsa.Calls)
	}

	org := f.orgs[0]
	auditor := tenancy.WithCaller(ctx, tenancy.Caller{Subject: td.Subject{
		Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: ids.NewV7()},
		Bindings: []td.Binding{{Role: td.RoleAuditor, Scope: td.Scope{Type: td.ScopeOrg, ID: org.UUID()}}},
	}})
	svc := evapp.New(f.p, origin)
	// The org grows after the anchor: the bundle proves its latest
	// checkpoint extends the anchored one.
	f.grow(t, org, 2)
	cps := &checkpoints.Service{Pool: f.p, Keys: f.reg, LogOrigin: origin, Log: pclog.Discard()}
	if r, err := cps.Checkpoint(ctx, org); err != nil || !r.Signed {
		t.Fatalf("checkpoint: %+v, %v", r, err)
	}
	x, err := svc.ExportBundle(auditor, evapp.Selection{From: 1, To: 5}, 0)
	if err != nil || !x.Anchored || x.CheckpointSize != 5 {
		t.Fatalf("ExportBundle = %+v, %v", x, err)
	}
	b, err := bundle.Decode(x.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	if b.Anchor == nil || b.Anchor.Checkpoint != 3 || len(b.Checkpoints) != 2 || len(b.Anchor.Leaves) != 2 {
		t.Fatalf("bundle anchor %+v, %d checkpoints", b.Anchor, len(b.Checkpoints))
	}
	trust := f.trust(t)
	logKey, _ := anchor.NewLog(anchortest.RekorOrigin, f.rekor.PublicKey)
	tsaVerifier, _ := anchor.NewTSAVerifier(f.tsa.CA.Chain)
	report := bundle.Verify(b, bundle.Options{Trust: trust, Sigstore: &bundle.SigstoreRoot{
		Logs: []anchor.Log{logKey}, TSAs: []*anchor.TSAVerifier{tsaVerifier},
	}})
	if report.Failed() {
		t.Fatalf("the anchored bundle fails verification:\n%s", report.Text())
	}
	for _, name := range []string{"anchor.leaf", "anchor.root", "anchor.signature", "anchor.log", "anchor.timestamp", "checkpoint.consistency"} {
		if !passed(report, name) {
			t.Errorf("check %s did not pass:\n%s", name, report.Text())
		}
	}
	// Anchors are listed for the org with its leaf and checkpoint.
	page, err := svc.ListAnchors(auditor, 10, "")
	if err != nil || len(page.Items) != 1 || page.Items[0].State != "ANCHORED" || page.Items[0].CheckpointSize != 3 ||
		page.Items[0].Leaves != 2 || page.Items[0].ID != c.ID {
		t.Fatalf("ListAnchors = %+v, %v", page, err)
	}
	if cps, err := svc.ListCheckpoints(auditor, 1, ""); err != nil || cps.Integrity.AnchorState != "ANCHORED" || cps.Integrity.AnchorError != "" {
		t.Fatalf("integrity status: %+v, %v", cps.Integrity, err)
	}
	other := tenancy.WithCaller(ctx, tenancy.Caller{Subject: td.Subject{
		Org: ids.New[ids.Org](), Principal: td.PrincipalRef{Kind: td.KindUser, ID: ids.NewV7()},
		Bindings: []td.Binding{{Role: td.RoleAuditor}},
	}})
	if page, err := svc.ListAnchors(other, 10, ""); err != nil || len(page.Items) != 0 {
		t.Fatalf("another org sees %d anchors: %v", len(page.Items), err)
	}
}

func passed(r *bundle.Report, name string) bool {
	for _, c := range r.Checks {
		if c.Name == name && c.Status == bundle.Passed {
			return true
		}
	}
	return false
}

// trust pins the keys the deployment publishes in evidence-keys.json.
func (f *fixture) trust(t *testing.T) *bundle.Trust {
	t.Helper()
	mux := http.NewServeMux()
	keydocs.New(func(ctx context.Context, ps []keys.Purpose) ([]keystore.PublishedKey, error) {
		return keystore.PublishedKeys(ctx, f.p, ps)
	}, "https://pc.test", origin, clock.System{}, pclog.Discard()).Mount(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, keydocs.EvidenceKeysPath, nil))
	trust, err := bundle.ParseEvidenceKeys(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("evidence-keys.json: %v", err)
	}
	return trust
}

// auditEvents counts the platform audit's evidence.anchor_failed entries.
func (f *fixture) auditEvents(t *testing.T) int {
	t.Helper()
	var n int
	if err := f.p.InTenantTx(context.Background(), ids.PlatformOrg, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.evidence.anchor_failed'`).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestHR195_ABadInclusionProofOrTimestampLeavesTheAnchorFailed: a log answer
// whose inclusion proof or checkpoint does not verify, a timestamp over
// other data, and an unreachable authority each leave the anchor FAILED
// with its code, a backoff, an evidence.anchor_failed audit event and no
// response kept that did not verify. A verified log entry is kept, so the
// retry after a timestamp failure does not enter the statement again. The
// attempts are bounded.
func TestHR195_ABadInclusionProofOrTimestampLeavesTheAnchorFailed(t *testing.T) {
	f := newFixture(t, 1)
	ctx := context.Background()
	c := f.create(t, f.svc.Period(time.Now()))

	f.rekor.Mutate = func(_ *anchortest.Rekor, resp map[string]any) {
		hashes, _ := anchortest.ProofOf(resp)["hashes"].([]any)
		if len(hashes) > 0 {
			hashes[0] = anchortest.B64(bytes.Repeat([]byte{7}, 32))
		}
	}
	failed := func(want string, attempts int32) dbq.PcAnchor {
		t.Helper()
		res, err := f.svc.Submit(ctx, c.ID)
		if err != nil || res.State != "FAILED" || res.Code != want {
			t.Fatalf("Submit = %+v, %v; want FAILED %s", res, err, want)
		}
		a := f.anchor(t, c.ID)
		if a.State != "FAILED" || a.ErrorCode == nil || *a.ErrorCode != want || a.Attempts != attempts || !a.NextAt.After(time.Now()) ||
			a.TimestampToken != nil || a.AnchoredAt != nil {
			t.Fatalf("anchor after %s: %+v", want, a)
		}
		if n := f.auditEvents(t); n != int(attempts) {
			t.Fatalf("%d evidence.anchor_failed audit events after %d attempts", n, attempts)
		}
		return a
	}
	if a := failed(anchoring.CodeRekorInvalid, 1); a.RekorEntry != nil {
		t.Fatal("an entry whose inclusion proof does not verify was kept")
	}
	// The org's integrity status shows the failed anchor.
	org := f.orgs[0]
	reader := tenancy.WithCaller(ctx, tenancy.Caller{Subject: td.Subject{
		Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: ids.NewV7()},
		Bindings: []td.Binding{{Role: td.RoleDeveloper, Scope: td.Scope{Type: td.ScopeOrg, ID: org.UUID()}}},
	}})
	if p, err := evapp.New(f.p, origin).ListCheckpoints(reader, 1, ""); err != nil || p.Integrity.AnchorState != "FAILED" ||
		p.Integrity.AnchorError != anchoring.CodeRekorInvalid || p.Integrity.Failed {
		t.Fatalf("integrity status after a failed anchor: %+v, %v", p.Integrity, err)
	}
	// A checkpoint signed by another key than the configured one.
	other := anchortest.NewRekor(t, "ed25519")
	f.rekor.Mutate = func(r *anchortest.Rekor, resp map[string]any) {
		anchortest.Resign(t, resp, anchortest.CheckpointOf(t, resp), other.Signer)
	}
	if a := failed(anchoring.CodeRekorInvalid, 2); a.RekorEntry != nil {
		t.Fatal("an entry whose checkpoint does not verify was kept")
	}
	// The log answers well; the timestamp covers other data.
	f.rekor.Mutate = nil
	f.tsa.Fault.WrongImprint = true
	if a := failed(anchoring.CodeTimestampInvalid, 3); a.RekorEntry == nil {
		t.Fatal("the verified log entry was not kept")
	}
	calls := f.rekor.Calls
	// The authority cannot be reached (a host that is not configured).
	f.svc.TSA.HTTP = anchoring.HostOnly{Host: "elsewhere.test", Next: f.tsa}
	failed(anchoring.CodeTimestampFailed, 4)
	if f.rekor.Calls != calls {
		t.Fatal("a retry entered the statement in the log again")
	}
	// The authority recovers: the kept entry and a new timestamp anchor it.
	f.svc.TSA.HTTP = anchoring.HostOnly{Host: "tsa.test", Next: f.tsa}
	f.tsa.Fault.WrongImprint = false
	if res, err := f.svc.Submit(ctx, c.ID); err != nil || res.State != "ANCHORED" || f.rekor.Calls != calls {
		t.Fatalf("Submit after recovery = %+v, %v", res, err)
	}

	// Attempts are bounded: an anchor that keeps failing stops at
	// MaxAttempts, and the next period's anchor covers the orgs again.
	c2 := f.create(t, f.svc.Period(time.Now()).Add(-24*time.Hour))
	f.rekor.Status = http.StatusServiceUnavailable
	for i := range anchoring.MaxAttempts {
		if res, err := f.svc.Submit(ctx, c2.ID); err != nil || res.Code != anchoring.CodeRekorFailed {
			t.Fatalf("attempt %d: %+v, %v", i+1, res, err)
		}
	}
	before := f.rekor.Calls
	if res, err := f.svc.Submit(ctx, c2.ID); err != nil || res.State != "FAILED" || f.rekor.Calls != before {
		t.Fatalf("after %d attempts: %+v, %v; the log was called again", anchoring.MaxAttempts, res, err)
	}
	if a := f.anchor(t, c2.ID); a.Attempts != anchoring.MaxAttempts {
		t.Fatalf("attempts %d", a.Attempts)
	}
}

// TestHR195_TickAnchorsTheCurrentPeriodAndRetriesOnlyAfterTheBackoff: the
// worker's tick creates the current period's anchor once, submits it, and
// leaves a failed one alone until its backoff is over.
func TestHR195_TickAnchorsTheCurrentPeriodAndRetriesOnlyAfterTheBackoff(t *testing.T) {
	f := newFixture(t, 1)
	ctx := context.Background()
	f.tsa.Fault.Status = 2 // the authority refuses
	if err := f.svc.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	var anchors []ids.UUID
	if err := f.p.InGlobalTx(ctx, db.GlobalAnchors, func(ctx context.Context, tx db.GlobalTx) error {
		rows, err := tx.Query(ctx, "SELECT id FROM pc.anchors")
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id ids.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			anchors = append(anchors, id)
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	if len(anchors) != 1 {
		t.Fatalf("%d anchors after a tick", len(anchors))
	}
	if a := f.anchor(t, anchors[0]); a.State != "FAILED" || *a.ErrorCode != anchoring.CodeTimestampInvalid || a.Attempts != 1 {
		t.Fatalf("anchor after a refused timestamp: %+v", a)
	}
	calls := f.tsa.Calls
	f.tsa.Fault.Status = 0
	if err := f.svc.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if a := f.anchor(t, anchors[0]); a.State != "FAILED" || a.Attempts != 1 || f.tsa.Calls != calls {
		t.Fatalf("a tick within the backoff retried: %+v", a)
	}
}
