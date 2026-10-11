// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/adapters/pgauthority"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/recording"
	"github.com/katocxl/pantherclaw/internal/authority/replay"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/evidence/anchor"
	"github.com/katocxl/pantherclaw/internal/evidence/anchor/anchortest"
	"github.com/katocxl/pantherclaw/internal/evidence/anchoring"
	evapp "github.com/katocxl/pantherclaw/internal/evidence/app"
	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/evidence/checkpoints"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/merkle"
	"github.com/katocxl/pantherclaw/internal/evidence/note"
	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	"github.com/katocxl/pantherclaw/internal/evidence/packbuild"
	factspg "github.com/katocxl/pantherclaw/internal/facts/adapters/pgstore"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/pclaw"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	polpg "github.com/katocxl/pantherclaw/internal/policy/adapters/pgstore"
	policyapp "github.com/katocxl/pantherclaw/internal/policy/app"
	"github.com/katocxl/pantherclaw/internal/server"
	"github.com/katocxl/pantherclaw/internal/sim/payments"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	txapp "github.com/katocxl/pantherclaw/internal/transactions/app"
)

// The end-to-end tests of M7 track B (G0 M7 slice B11): the evidence of
// refunds made through the real gateway, checkpointed by the server's own
// workers with its own keys, exported, and checked by `pclaw verify`
// offline; tampering; decision replay; evidence packs.

// proof is what these tests act with: the server's signing keys, loaded with
// its KEK as its workers hold them; its evidence log origin; the trust file
// `pclaw evidence trust` pinned from the server's evidence-keys.json; and a
// client that queues jobs for the server's own workers.
type proof struct {
	s      *stack
	dir    string
	kp     keys.KeyProvider
	reg    *keys.Registry
	origin string
	trust  string
	jobs   *jobs.Client
}

func (s *stack) proof(t *testing.T) *proof {
	t.Helper()
	ctx := context.Background()
	kp, err := keys.NewFileProvider([]string{s.kek})
	if err != nil {
		t.Fatal(err)
	}
	reg := keys.NewRegistry()
	if err := keystore.LoadSigningKeys(ctx, s.pool, kp, reg); err != nil {
		t.Fatal(err)
	}
	insert, err := jobs.NewClient(s.pool, nil, jobs.Config{})
	if err != nil {
		t.Fatal(err)
	}
	p := &proof{s: s, dir: t.TempDir(), kp: kp, reg: reg, jobs: insert}
	// Trust on first use, as a user does: fetch evidence-keys.json once.
	p.trust = filepath.Join(p.dir, "trust.json")
	var out, errb bytes.Buffer
	if code := pclaw.Run(ctx, []string{"evidence", "trust", "--out", p.trust, "--server", s.apiURL}, &out, &errb, noEnv, pclaw.Options{}); code != 0 {
		t.Fatalf("pclaw evidence trust: %d %s %s", code, out.String(), errb.String())
	}
	raw, err := os.ReadFile(p.trust)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := bundle.ParseTrust(raw)
	if err != nil {
		t.Fatal(err)
	}
	p.origin = trust.LogOrigin
	return p
}

// offline is an HTTP client that fails the test on any request: pclaw
// verify must not make one.
type offline struct{ t *testing.T }

func (o offline) RoundTrip(r *http.Request) (*http.Response, error) {
	o.t.Errorf("pclaw verify made a network call to %s", r.URL.Redacted())
	return nil, errors.New("offline")
}

// verify runs `pclaw verify FILE --trust … --json` with flags, offline, and
// returns its exit code and report.
func (p *proof) verify(t *testing.T, file string, flags ...string) (int, *bundle.Report) {
	t.Helper()
	args := append([]string{"verify", file, "--trust", p.trust, "--json"}, flags...)
	var out, errb bytes.Buffer
	code := pclaw.Run(context.Background(), args, &out, &errb, noEnv, pclaw.Options{HTTPClient: &http.Client{Transport: offline{t}}})
	var r bundle.Report
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatalf("pclaw %v: %d %q %q", args, code, out.String(), errb.String())
	}
	if (code == 0) == r.Failed() || !strings.HasPrefix(r.Limits, bundle.Limits) {
		t.Fatalf("pclaw verify exit %d for a %s report with limits %q", code, r.Result, r.Limits)
	}
	return code, &r
}

// statuses returns the statuses of the checks named name, in order.
func statuses(r *bundle.Report, name string) []bundle.Status {
	var out []bundle.Status
	for _, c := range r.Checks {
		if c.Name == name {
			out = append(out, c.Status)
		}
	}
	return out
}

// all reports whether r has checks named name and every one is st.
func all(r *bundle.Report, name string, st bundle.Status) bool {
	got := statuses(r, name)
	return len(got) > 0 && !slices.ContainsFunc(got, func(s bundle.Status) bool { return s != st })
}

// some reports whether one check named name has status st.
func some(r *bundle.Report, name string, st bundle.Status) bool {
	return slices.Contains(statuses(r, name), st)
}

// receiptSeqs returns the chained positions of txn's receipts.
func (p *proof) receiptSeqs(t *testing.T, txn ids.UUID) map[string]int64 {
	t.Helper()
	out := map[string]int64{}
	for _, table := range []string{"decision_receipts", "execution_receipts", "effect_receipts"} {
		seq := p.s.row(t, `SELECT coalesce(max(c.seq), 0)::text FROM pc.`+table+` r
			JOIN pc.ledger_chain c ON c.org_id = r.org_id AND c.entry_id = r.ledger_entry_id WHERE r.transaction_id = $1`, txn)
		n, err := strconv.ParseInt(seq, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		out[table] = n
	}
	return out
}

// checkpointed asks the server's workers for checkpoints until one covers
// every receipt of txns (all of them chained), and returns the latest such
// checkpoint's size and signed note.
func (p *proof) checkpointed(t *testing.T, txns ...ids.UUID) (uint64, []byte) {
	t.Helper()
	ctx := context.Background()
	list := make([]string, len(txns))
	for i, x := range txns {
		list[i] = x.String()
	}
	for deadline := time.Now().Add(90 * time.Second); ; {
		var size int64
		var n []byte
		err := p.s.pool.InTenantTx(ctx, p.s.org, func(ctx context.Context, tx db.TenantTx) error {
			return tx.QueryRow(ctx, `WITH r AS (
					SELECT ledger_entry_id FROM pc.decision_receipts WHERE transaction_id = ANY($1::uuid[])
					UNION ALL SELECT ledger_entry_id FROM pc.execution_receipts WHERE transaction_id = ANY($1::uuid[])
					UNION ALL SELECT ledger_entry_id FROM pc.effect_receipts WHERE transaction_id = ANY($1::uuid[])),
				s AS (SELECT c.seq FROM r LEFT JOIN pc.ledger_chain c ON c.entry_id = r.ledger_entry_id)
				SELECT k.tree_size, k.note FROM pc.checkpoints k
				WHERE NOT EXISTS (SELECT 1 FROM s WHERE seq IS NULL) AND k.tree_size >= (SELECT max(seq) FROM s)
				ORDER BY k.tree_size DESC LIMIT 1`, list).Scan(&size, &n)
		})
		if err == nil {
			return uint64(size), n //nolint:gosec // G115: tree_size > 0
		}
		if !db.IsNoRows(err) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("no checkpoint covers the transactions within 90 seconds")
		}
		if _, err := p.jobs.Insert(ctx, checkpoints.CheckpointDispatchArgs{}, nil); err != nil {
			t.Fatal(err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// anchor anchors every org's latest checkpoint as the server's anchoring
// job does (blinded leaves, the statement signed by the server's anchors
// key), in a local fake Rekor v2 log with a local fake RFC 3161 authority
// (anchortest: nothing reaches Sigstore, which needs the founder's
// agreement), and writes the Sigstore trusted root that pins both.
func (p *proof) anchor(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	rekor := anchortest.NewRekor(t, "ed25519")
	ca := anchortest.NewCA(t, anchortest.CertOpts{Now: now})
	// The token is dated after the anchors key's not_before (the server
	// created it when it started).
	tsa := &anchortest.TSA{T: t, CA: ca, Fault: anchortest.TSAFault{GenTime: now.Add(time.Minute)}}
	log, err := anchor.NewLog(anchortest.RekorOrigin, rekor.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	tv, err := anchor.NewTSAVerifier(ca.Chain)
	if err != nil {
		t.Fatal(err)
	}
	svc := &anchoring.Service{
		Pool: p.s.pool, Keys: p.reg, LogOrigin: p.origin, Log: pclog.Discard(),
		Rekor: &anchor.RekorClient{URL: anchortest.RekorURL, HTTP: anchoring.HostOnly{Host: "rekor.test", Next: rekor}, Log: log},
		TSA:   &anchor.TSAClient{URL: anchortest.TSAURL, HTTP: anchoring.HostOnly{Host: "tsa.test", Next: tsa}, Verifier: tv},
	}
	created, err := svc.Create(ctx, svc.Period(now))
	if err != nil || created.ID.IsZero() {
		t.Fatalf("anchor: %+v, %v", created, err)
	}
	if res, err := svc.Submit(ctx, created.ID); err != nil || res.State != "ANCHORED" {
		t.Fatalf("anchor submit: %+v, %v", res, err)
	}
	root, err := json.Marshal(map[string]any{
		"mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
		"tlogs": []any{map[string]any{
			"baseUrl": "https://" + anchortest.RekorOrigin, "hashAlgorithm": "SHA2_256",
			"publicKey": map[string]any{"rawBytes": rekor.PublicKey, "keyDetails": "PKIX_ED25519"},
		}},
		"timestampAuthorities": []any{map[string]any{
			"certChain": map[string]any{"certificates": []any{
				map[string]any{"rawBytes": ca.Cert.Raw}, map[string]any{"rawBytes": ca.Root.Raw},
			}},
			"validFor": map[string]any{"start": now.Add(-24 * time.Hour).Format(time.RFC3339)},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return writeFile(t, p.dir, "trusted_root.json", root)
}

// export builds a verify bundle as the caller of ctx through ExportBundle
// and writes it to name.
func (p *proof) export(t *testing.T, ctx context.Context, name string, sel evapp.Selection, from uint64) (string, evapp.Export) {
	t.Helper()
	x, err := evapp.New(p.s.pool, p.origin).ExportBundle(ctx, sel, from)
	if err != nil {
		t.Fatal(err)
	}
	return writeFile(t, p.dir, name, x.Bundle), x
}

// refunded makes a refund through the gateway and waits for the verifier's
// effect receipt in state.
func (s *stack) refunded(t *testing.T, amount, state string) ids.UUID {
	t.Helper()
	code, r := s.refund(t, ids.NewV7(), amount)
	if code != http.StatusOK || r.Outcome != "ACCEPTED" {
		t.Fatalf("refund %s: %d %+v", amount, code, r)
	}
	s.eventually(t, state, "SELECT state FROM pc.effect_receipts WHERE transaction_id = $1 ORDER BY seq DESC LIMIT 1", r.TransactionID)
	return mustUUID(t, r.TransactionID)
}

// TestE2E_M7_VerifyBundleOffline: a refund through the gateway is decided,
// executed and verified; the server's workers chain and checkpoint its
// receipts with the server's own keys; its checkpoint is anchored (a local
// fake Rekor v2 log and RFC 3161 authority); ExportBundle gives an auditor
// its bundle, and `pclaw verify` passes it offline against the keys pinned
// with `pclaw evidence trust`: three receipt signatures, chain links,
// inclusion, the checkpoint, the anchor leaf, root and signature, the log
// entry and the timestamp. Without the Sigstore trusted root, the log
// entry and the timestamp are not available, never passed (HR-196, PN-007.4).
func TestE2E_M7_VerifyBundleOffline(t *testing.T) {
	s := start(t, options{budget: "1000.00"})
	p := s.proof(t)
	txn := s.refunded(t, "30.00", "CONFIRMED")
	p.checkpointed(t, txn)
	sigstore := p.anchor(t)

	auditor := s.person(t, "verify-auditor", td.RoleAuditor).ctx
	file, x := p.export(t, auditor, "bundle.json", evapp.Selection{Transactions: []ids.UUID{txn}}, 0)
	if !x.Anchored || x.Receipts < 3 || x.Entries < 3 {
		t.Fatalf("export: %d receipts, %d entries, anchored %v", x.Receipts, x.Entries, x.Anchored)
	}
	code, r := p.verify(t, file, "--sigstore-trusted-root", sigstore)
	if code != 0 {
		t.Fatalf("pclaw verify exit %d:\n%+v", code, r.Checks)
	}
	for _, name := range []string{
		"bundle.origin", "checkpoint.signature", "entry.link", "entry.inclusion", "receipt.signature", "receipt.ledger",
		"anchor.leaf", "anchor.root", "anchor.signature", "anchor.log", "anchor.timestamp",
	} {
		if !all(r, name, bundle.Passed) {
			t.Errorf("check %s: %v", name, statuses(r, name))
		}
	}
	var kinds []string
	for _, c := range r.Checks {
		if c.Name == "receipt.signature" {
			kinds = append(kinds, strings.Fields(c.Subject)[0])
		}
	}
	for _, kind := range []string{"pap-decision", "pap-execution", "pap-effect"} {
		if !slices.Contains(kinds, kind) {
			t.Errorf("no %s receipt checked: %v", kind, kinds)
		}
	}

	// Without the Sigstore trusted root nothing about the log can be
	// checked: not available, and the rest still passes.
	code, r = p.verify(t, file)
	if code != 0 || !all(r, "anchor.log", bundle.NotAvailable) || !all(r, "anchor.timestamp", bundle.NotAvailable) ||
		!all(r, "anchor.leaf", bundle.Passed) {
		t.Fatalf("without the trusted root: exit %d\n%+v", code, r.Checks)
	}
}

// resign is an insider with the database and the deployment's real
// checkpoints key. From an honest bundle of the whole ledger it rewrites
// the body of the entry at seq, recomputes every later chain link and the
// tree, and signs a checkpoint of the rewritten tree with the real key. It
// returns the forged bundle (no anchor, no earlier checkpoint) and the
// forger's own consistency proof from size from to the rewritten tree.
func (p *proof) resign(t *testing.T, honest *bundle.Bundle, seq int64, from uint64) (*bundle.Bundle, bundle.Consistency) {
	t.Helper()
	ctx := context.Background()
	org := ids.MustParse[ids.Org](honest.Org)
	entries := slices.Clone(honest.Entries)
	body, err := evdomain.CanonicalBody(map[string]string{"decision": "DENY", "rewritten": "by an insider"})
	if err != nil {
		t.Fatal(err)
	}
	prev, tiles := evdomain.GenesisHash, merkle.NewMemoryTiles()
	for i := range entries {
		e := &entries[i]
		if e.Seq != int64(i)+1 || e.Removed != nil {
			t.Fatalf("the honest bundle is not the whole ledger: seq %d at %d", e.Seq, i)
		}
		if e.Seq == seq {
			e.Body = jsontext.Value(body)
		}
		if e.Seq >= seq {
			id, err := ids.ParseUUID(e.ID)
			if err != nil {
				t.Fatal(err)
			}
			ts, err := time.Parse("2006-01-02T15:04:05.000000Z", e.TS)
			if err != nil {
				t.Fatal(err)
			}
			l, err := evdomain.Next(e.Seq-1, prev, evdomain.Entry{Org: org, ID: id, Kind: e.Kind, Actor: e.Actor, OccurredAt: ts, Body: []byte(e.Body)})
			if err != nil {
				t.Fatal(err)
			}
			e.PrevHash, e.EntryHash = l.PrevHash, l.EntryHash
		}
		prev = e.EntryHash
		if err := tiles.Append(ctx, merkle.LeafHash(e.EntryHash)); err != nil {
			t.Fatal(err)
		}
	}
	size := uint64(len(entries))
	root, err := merkle.Root(ctx, tiles, size)
	if err != nil {
		t.Fatal(err)
	}
	ks := p.reg.Keys(keys.PurposeCheckpoints)
	if len(ks) == 0 || ks[0].State != keys.StateActive {
		t.Fatal("no active checkpoints key")
	}
	signer, err := note.NewEd25519Signer(honest.Origin, ks[0].Private.Reveal())
	if err != nil {
		t.Fatal(err)
	}
	cp, err := note.SignCheckpoint(note.Checkpoint{Origin: honest.Origin, Size: size, Root: root}, signer)
	if err != nil {
		t.Fatal(err)
	}
	forged := &bundle.Bundle{
		Format: honest.Format, Org: honest.Org, Origin: honest.Origin, Receipts: honest.Receipts, Entries: entries,
		Checkpoints: []string{string(cp)},
	}
	hashes := func(hs []merkle.Hash) [][]byte {
		out := make([][]byte, len(hs))
		for i, h := range hs {
			out[i] = slices.Clone(h[:])
		}
		return out
	}
	for _, e := range entries {
		proofOf, err := merkle.InclusionProof(ctx, tiles, uint64(e.Seq)-1, size) //nolint:gosec // G115: seq ≥ 1
		if err != nil {
			t.Fatal(err)
		}
		forged.Inclusion = append(forged.Inclusion, bundle.Inclusion{Seq: e.Seq, Size: size, Proof: hashes(proofOf)})
	}
	cons, err := merkle.ConsistencyProof(ctx, tiles, from, size)
	if err != nil {
		t.Fatal(err)
	}
	return forged, bundle.Consistency{From: from, To: size, Proof: hashes(cons)}
}

// noteOf returns the bundle's checkpoint note of size.
func noteOf(t *testing.T, b *bundle.Bundle, size uint64) string {
	t.Helper()
	for _, n := range b.Checkpoints {
		if lines := strings.SplitN(n, "\n", 3); len(lines) == 3 && lines[1] == strconv.FormatUint(size, 10) {
			return n
		}
	}
	t.Fatalf("the bundle has no checkpoint of size %d", size)
	return ""
}

// integrity queues the server's daily verification of the org and waits
// until the org's evidence integrity reads want (state, failure code and
// position, or "OK" once a verification succeeded).
func (p *proof) integrity(t *testing.T, want string) {
	t.Helper()
	// The verification is unique per org while one is queued or running: an
	// earlier job River has not marked completed yet would swallow this
	// insert, and nothing would verify after a reset. Insert until a new job
	// is queued.
	deadline := time.Now().Add(30 * time.Second)
	for {
		res, err := p.jobs.Insert(context.Background(), checkpoints.VerifyOrgArgs{Org: p.s.org}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !res.UniqueSkippedAsDuplicate {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("an earlier verification job did not finish within 30 seconds")
		}
		time.Sleep(50 * time.Millisecond)
	}
	p.s.eventually(t, want, `SELECT CASE WHEN state = 'OK' AND verified_at IS NOT NULL THEN 'OK'
		ELSE state || ' ' || coalesce(failure_code, '') || ' ' || coalesce(failed_seq::text, '') END FROM pc.evidence_integrity`)
}

// TestE2E_M7_TamperDetected: the BUILD_GUIDE M7 tests "tampering detected
// (row edit, deletion, re-signing without a witness)" against a running
// server (T-029, T-073, HR-194, HR-196).
//   - A history rewritten from a chained row and re-signed with the
//     deployment's real checkpoints key passes `pclaw verify` on its own (a
//     signature proves who signed, not that nothing was rewritten); against
//     the checkpoint the user saved earlier (--previous), or against the
//     anchored root, it fails.
//   - A chained row edited in the database fails `pclaw verify` (its link no
//     longer matches) and the server's daily integrity job (CHAIN_LINK at
//     its position, audited); put back from a backup and reset, the org
//     verifies again.
//   - A chained row deleted from the chain is found by the integrity job;
//     the exported evidence then shows a receipt that no chained entry
//     records.
func TestE2E_M7_TamperDetected(t *testing.T) {
	s := start(t, options{budget: "1000.00"})
	p := s.proof(t)
	ctx := context.Background()
	first := s.refunded(t, "30.00", "CONFIRMED")
	savedSize, saved := p.checkpointed(t, first)
	savedFile := writeFile(t, p.dir, "saved.note", saved)
	sigstore := p.anchor(t)
	second := s.refunded(t, "20.00", "CONFIRMED")
	size, _ := p.checkpointed(t, second)
	if size <= savedSize {
		t.Fatalf("checkpoints of size %d then %d", savedSize, size)
	}
	auditor := s.person(t, "tamper-auditor", td.RoleAuditor).ctx

	// The honest ledger verifies, with the saved checkpoint as a witness and
	// with its anchored root.
	honestFile, x := p.export(t, auditor, "honest.json", evapp.Selection{From: 1, To: int64(size)}, savedSize) //nolint:gosec // G115
	code, r := p.verify(t, honestFile, "--previous", savedFile, "--sigstore-trusted-root", sigstore)
	if code != 0 || !all(r, "witness.previous", bundle.Passed) || !all(r, "anchor.log", bundle.Passed) || !x.Anchored {
		t.Fatalf("the honest ledger: exit %d\n%+v", code, r.Checks)
	}
	raw, err := os.ReadFile(honestFile)
	if err != nil {
		t.Fatal(err)
	}
	honest, err := bundle.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}

	// Re-signing without a witness: rewrite the first refund's decision
	// entry and every link after it, and sign the rewritten tree with the
	// real key.
	seqs := p.receiptSeqs(t, first)
	anchored := honest.Anchor.Checkpoint
	if seqs["decision_receipts"] < 1 || uint64(seqs["decision_receipts"]) > savedSize || anchored < savedSize { //nolint:gosec // G115
		t.Fatalf("decision at seq %d, saved %d, anchored %d", seqs["decision_receipts"], savedSize, anchored)
	}
	forged, forgersProof := p.resign(t, honest, seqs["decision_receipts"], anchored)
	forgedFile := writeFile(t, p.dir, "forged.json", bundletestEncode(t, forged))
	code, r = p.verify(t, forgedFile, "--sigstore-trusted-root", sigstore)
	if code != 0 || !all(r, "witness.previous", bundle.NotAvailable) || !all(r, "anchor", bundle.NotAvailable) ||
		!all(r, "checkpoint.signature", bundle.Passed) {
		t.Fatalf("on its own the re-signed history should pass (that is what witnesses are for): exit %d\n%+v", code, r.Checks)
	}
	code, r = p.verify(t, forgedFile, "--previous", savedFile)
	if code != 1 || !all(r, "witness.previous", bundle.Failed) {
		t.Fatalf("against the saved checkpoint: exit %d\n%+v", code, r.Checks)
	}
	// Against the anchored root: the anchor commits to the real checkpoint,
	// which the rewritten tree does not extend, whatever proof the forger
	// adds; leaving the real checkpoint out breaks the anchor instead.
	withAnchor := *forged
	withAnchor.Anchor = honest.Anchor
	withAnchor.Checkpoints = []string{noteOf(t, honest, anchored), forged.Checkpoints[0]}
	withAnchor.Consistency = []bundle.Consistency{forgersProof}
	code, r = p.verify(t, writeFile(t, p.dir, "forged-anchor.json", bundletestEncode(t, &withAnchor)), "--sigstore-trusted-root", sigstore)
	if code != 1 || !all(r, "anchor.leaf", bundle.Passed) || !all(r, "anchor.log", bundle.Passed) || !some(r, "checkpoint.consistency", bundle.Failed) {
		t.Fatalf("against the anchored root: exit %d\n%+v", code, r.Checks)
	}
	withAnchor.Checkpoints, withAnchor.Consistency = forged.Checkpoints, nil
	code, r = p.verify(t, writeFile(t, p.dir, "forged-anchor-only.json", bundletestEncode(t, &withAnchor)), "--sigstore-trusted-root", sigstore)
	if code != 1 || !some(r, "anchor.leaf", bundle.Failed) {
		t.Fatalf("an anchor without its checkpoint: exit %d\n%+v", code, r.Checks)
	}

	// A row edit: the second refund's execution entry now says it failed.
	execSeq := p.receiptSeqs(t, second)["execution_receipts"]
	var entry ids.UUID
	var original []byte
	s.db.AdminQueryRow(t, `SELECT e.id, e.body FROM pc.ledger_chain c JOIN pc.ledger_entries e ON e.org_id = c.org_id AND e.id = c.entry_id
		WHERE c.org_id = $1 AND c.seq = $2`, []any{s.org, execSeq}, &entry, &original)
	s.db.AdminExec(t, "UPDATE pc.ledger_entries SET body = $3 WHERE org_id = $1 AND id = $2", s.org, entry, []byte(`{"outcome":"failed"}`))
	edited, _ := p.export(t, auditor, "edited.json", evapp.Selection{Transactions: []ids.UUID{second}}, 0)
	code, r = p.verify(t, edited)
	if code != 1 || !slices.ContainsFunc(r.Checks, func(c bundle.Check) bool {
		return c.Name == "entry.link" && c.Status == bundle.Failed && c.Subject == "seq "+strconv.FormatInt(execSeq, 10)
	}) {
		t.Fatalf("an edited row: exit %d\n%+v", code, r.Checks)
	}
	p.integrity(t, "FAILED CHAIN_LINK "+strconv.FormatInt(execSeq, 10))
	if n := s.row(t, "SELECT count(*)::text FROM pc.ledger_entries WHERE kind = 'audit.security.evidence_integrity_failed'"); n != "1" {
		t.Fatalf("%s integrity failures audited", n)
	}
	s.eventually(t, "1", "SELECT count(*)::text FROM pc.notifications WHERE type = 'security.evidence_integrity_failed'")

	// Put back from the backup, the operator resets the org, and the daily
	// job verifies the whole chain again.
	s.db.AdminExec(t, "UPDATE pc.ledger_entries SET body = $3 WHERE org_id = $1 AND id = $2", s.org, entry, original)
	var out, errb bytes.Buffer
	if code := server.Run(ctx, []string{
		"evidence", "integrity", "reset", "--config", s.serverCfg, "--org", s.org.String(),
		"--reason", "restored the edited execution entry from the backup", "--confirm",
	}, &out, &errb, noEnv); code != 0 {
		t.Fatalf("evidence integrity reset: %d %s %s", code, out.String(), errb.String())
	}
	p.integrity(t, "OK")

	// A deletion: the first refund's decision entry is cut out of the chain.
	s.db.AdminExec(t, "DELETE FROM pc.ledger_chain WHERE org_id = $1 AND seq = $2", s.org, seqs["decision_receipts"])
	p.integrity(t, "FAILED CHAIN_LINK "+strconv.FormatInt(seqs["decision_receipts"], 10))
	cut, _ := p.export(t, auditor, "cut.json", evapp.Selection{Transactions: []ids.UUID{first}}, 0)
	_, r = p.verify(t, cut)
	if !slices.ContainsFunc(r.Checks, func(c bundle.Check) bool {
		return c.Name == "receipt.ledger" && c.Status == bundle.NotAvailable && strings.HasPrefix(c.Subject, "pap-decision")
	}) {
		t.Fatalf("the cut decision's receipt:\n%+v", r.Checks)
	}
}

// bundletestEncode encodes b as canonical JSON.
func bundletestEncode(t *testing.T, b *bundle.Bundle) []byte {
	t.Helper()
	out, err := bundle.Encode(b)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// replayer is the server's replay wiring (internal/server/wiring_replay.go)
// over its database and KEK: read ports only.
func (p *proof) replayer() *evapp.Service {
	pool := p.s.pool
	return evapp.New(pool, p.origin).WithReplay(&replay.Engine{
		Source: &pgauthority.ReplaySource{Pool: pool, Definitions: &defspg.Store{Pool: pool}, FactStore: &factspg.Store{Pool: pool}},
		Inputs: recording.NewSealer(pccrypto.NewEnvelope(keystore.NewDEKStore(pool, p.kp))),
	}, nil)
}

// draftPolicy stores bundle as a new policy version that nobody publishes:
// a proposed policy (F505).
func (s *stack) draftPolicy(t *testing.T, bundle string) ids.UUID {
	t.Helper()
	v := &policyapp.Versions{
		Store: &polpg.Store{Pool: s.pool}, Facts: &factspg.Store{Pool: s.pool}, Definitions: &defspg.Store{Pool: s.pool},
		Authz: grantsapp.SubjectAuthorizer{}, Limits: celenv.DefaultLimits,
	}
	draft, err := v.Create(s.person(t, "proposing-author", td.RolePolicyAuthor).ctx, []byte(bundle))
	if err != nil {
		t.Fatal(err)
	}
	return draft.ID
}

// counts returns the rows of the tables a decision or a dispatch writes.
func (s *stack) counts(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, table := range []string{
		"transactions", "decision_receipts", "evaluation_inputs", "permits", "reservations", "dedupe_claims",
		"execution_attempts", "execution_receipts", "effect_receipts", "reconciliation_tasks", "approval_requests",
	} {
		out[table] = s.row(t, "SELECT count(*)::text FROM pc."+table)
	}
	return out
}

// TestE2E_M7_ReplayNeverDispatches: a refund decided and dispatched through
// the gateway is replayed from its sealed inputs: unchanged, it reproduces
// the decision; under a proposed policy version that forbids it (a draft,
// never published), it is denied and the difference names the rule. The
// replays write no decision, receipt, permit or reservation, and neither
// the gateway nor the target sees a call (HR-197, T-074, F504–F508).
func TestE2E_M7_ReplayNeverDispatches(t *testing.T) {
	s := start(t, options{budget: "1000.00"})
	p := s.proof(t)
	txn := s.refunded(t, "30.00", "CONFIRMED")
	draft := s.draftPolicy(t, `{"id": "dev-holds", "rules": [{"id": "no-large-refunds", "kind": "FORBID",
		"summary": "no refunds over 20", "operations": ["payments.refund.create"],
		"when": "action.params.amount > money(\"20\", \"USD\")", "reason": "REFUND_TOO_LARGE"}]}`)

	before, gw, dispatches, refunds := s.counts(t), s.gwCalls.Load(), s.simCalls.Load(), s.sim.Stats().Refunds
	svc := p.replayer()
	auditor := s.person(t, "replay-auditor", td.RoleAuditor).ctx
	same, err := svc.ReplayDecision(auditor, txn, 0, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if o := same.Outcome; !o.Complete || !o.Reproduced || o.Decision != adomain.Allow || o.Proposed {
		t.Fatalf("unchanged replay: %+v", o)
	}
	proposed, err := svc.ReplayDecision(auditor, txn, 0, &draft, false)
	if err != nil {
		t.Fatal(err)
	}
	if o := proposed.Outcome; !o.Complete || !o.Proposed || o.Decision != adomain.Deny || o.Reason != "REFUND_TOO_LARGE" || o.Reproduced ||
		!slices.ContainsFunc(o.Differences, func(d replay.Difference) bool { return slices.Contains(d.Rules, "no-large-refunds") }) {
		t.Fatalf("replay under the proposed policy: %+v", o)
	}

	after := s.counts(t)
	for table, n := range before {
		if after[table] != n {
			t.Errorf("%s: %s rows before the replays, %s after", table, n, after[table])
		}
	}
	if s.gwCalls.Load() != gw || s.simCalls.Load() != dispatches || s.sim.Stats().Refunds != refunds {
		t.Fatalf("the replays reached the gateway (%d → %d calls) or the target (%d → %d dispatches, %d → %d refunds)",
			gw, s.gwCalls.Load(), dispatches, s.simCalls.Load(), refunds, s.sim.Stats().Refunds)
	}
	if got := s.row(t, "SELECT count(*)::text FROM pc.permits WHERE transaction_id = $1", txn); got != "1" {
		t.Fatalf("the replayed transaction has %s permits", got)
	}
}

// teamEdition is a Team licence (evidence packs, PN-007): the e2e server
// runs Community.
type teamEdition struct{}

func (teamEdition) Current(context.Context) (billing.Entitlements, error) {
	en := billing.CommunityEntitlements()
	en.Edition = billing.Team
	return en, nil
}

// boundAuditor is an Auditor of the org whose binding is also stored: a
// pack's builder reads its creator's permissions from the database when it
// runs (F515).
func (s *stack) boundAuditor(t *testing.T, name string) context.Context {
	t.Helper()
	id := ids.NewV7()
	s.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)", s.org, id, name)
	s.exec(t, `INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by) VALUES ($1, $2, $3, $4, 'ORG', 'test')`,
		s.org, ids.NewV7(), string(td.RoleAuditor), id)
	return tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: s.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: id},
		Bindings: []td.Binding{{Role: td.RoleAuditor, Scope: td.Scope{Type: td.ScopeOrg, ID: s.org.UUID()}}},
	}, Credential: tapp.CredAccessToken})
}

// TestE2E_M7_EvidencePack: in one run, through the gateway, a refund the
// target records a cent short (CONFLICTING), one whose answer never comes
// (UNKNOWN), one that is confirmed, and one the grant denies. An auditor's
// pack of the run holds each with its effect state, the unknown and the
// conflicting ones included, its gaps with their reasons (not anchored),
// and the fixed sentence; `pclaw verify` checks the pack offline and
// reports the gaps as not available; a pack changed to call the unknown
// refund confirmed fails (HR-196, T-077, F527–F532).
func TestE2E_M7_EvidencePack(t *testing.T) {
	s := start(t, options{budget: "1000.00", faults: payments.Faults{ShortRate: 1}, timeout: 2 * time.Second})
	p := s.proof(t)
	ctx := context.Background()
	conflicting := s.refunded(t, "30.00", "CONFLICTING")
	s.sim.SetFaults(payments.Faults{HangRate: 1, HangFor: time.Minute})
	code, r := s.refund(t, ids.NewV7(), "20.00")
	if code != http.StatusGatewayTimeout || r.Outcome != "UNKNOWN" {
		t.Fatalf("the unanswered refund: %d %+v", code, r)
	}
	unknown := mustUUID(t, r.TransactionID)
	s.sim.SetFaults(payments.Faults{})
	confirmed := s.refunded(t, "10.00", "CONFIRMED")
	code, r = s.refund(t, ids.NewV7(), "125.00")
	if code != http.StatusForbidden || r.Decision != "DENY" {
		t.Fatalf("the refund over the grant: %d %+v", code, r)
	}
	denied := mustUUID(t, r.TransactionID)
	p.checkpointed(t, conflicting, unknown, confirmed)

	var queued []ids.UUID
	svc := evapp.New(s.pool, p.origin).WithPacks(func(_ context.Context, _ db.TenantTx, _ ids.OrgID, id ids.UUID) error {
		queued = append(queued, id)
		return nil
	}, teamEdition{})
	builder := &packbuild.Service{
		Pool: s.pool, Keys: p.reg, LogOrigin: p.origin, Explorer: &txapp.Explorer{Pool: s.pool}, Bundles: evapp.New(s.pool, p.origin),
		Log: pclog.Discard(),
	}
	auditor := s.boundAuditor(t, "pack-auditor")
	pk, err := svc.CreateEvidencePack(auditor, evapp.PackRequest{Kind: pack.ScopeRun, Run: mustUUID(t, s.run), Include: pack.Include{
		Receipts: true, Versions: true, Approvals: true, Containment: true,
	}})
	if err != nil || !slices.Contains(queued, pk.ID) {
		t.Fatalf("create: %+v %v, queued %v", pk, err, queued)
	}
	if err := builder.Build(ctx, s.org, pk.ID); err != nil {
		t.Fatal(err)
	}
	d, err := svc.DownloadEvidencePack(auditor, pk.ID)
	if err != nil {
		t.Fatal(err)
	}
	files, err := pack.Read(d.Content)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := pack.ParseJWS(string(files[pack.ManifestPath]))
	if err != nil {
		t.Fatal(err)
	}
	m, err := pack.DecodeManifest(signed.Payload)
	if err != nil {
		t.Fatal(err)
	}
	effects := map[string]string{}
	for _, tx := range m.Transactions {
		effects[tx.ID] = tx.Effect
	}
	want := map[ids.UUID]string{conflicting: "CONFLICTING", unknown: "UNKNOWN", confirmed: "CONFIRMED", denied: ""}
	for id, st := range want {
		if got, ok := effects[id.String()]; !ok || got != st {
			t.Errorf("transaction %s: effect %q (listed %v), want %q", id, got, ok, st)
		}
	}
	if len(m.Transactions) != len(want) || m.EffectStates["UNKNOWN"] != 1 || m.EffectStates["CONFLICTING"] != 1 || m.EffectStates["CONFIRMED"] != 1 {
		t.Fatalf("pack transactions %d, effect states %v", len(m.Transactions), m.EffectStates)
	}
	if m.Statement != pack.Statement || m.Checkpoint == nil || len(m.Gaps) == 0 ||
		!slices.ContainsFunc(m.Gaps, func(g pack.Gap) bool { return g.Reason == pack.GapNotAnchored }) ||
		slices.ContainsFunc(m.Gaps, func(g pack.Gap) bool { return g.Reason == "" || g.Subject == "" }) {
		t.Fatalf("pack manifest: statement %q, checkpoint %+v, gaps %+v", m.Statement, m.Checkpoint, m.Gaps)
	}
	if n := s.row(t, "SELECT count(*)::text FROM pc.ledger_entries WHERE kind = 'audit.evidence.pack_downloaded'"); n != "1" {
		t.Fatalf("%s pack downloads audited", n)
	}

	file := writeFile(t, p.dir, "pack.zip", d.Content)
	code, rep := p.verify(t, file)
	if code != 0 || !all(rep, "pack.signature", bundle.Passed) || !all(rep, "pack.gap", bundle.NotAvailable) ||
		len(statuses(rep, "pack.gap")) != len(m.Gaps) || !some(rep, "receipt.signature", bundle.Passed) {
		t.Fatalf("pclaw verify of the pack: exit %d\n%+v", code, rep.Checks)
	}

	// The unknown refund's file changed to say it was confirmed: the pack
	// no longer matches its signed manifest.
	path := "transactions/" + unknown.String() + ".json"
	var rest []pack.File
	for name, data := range files {
		if name == path {
			if !bytes.Contains(data, []byte(`"UNKNOWN"`)) {
				t.Fatalf("the unknown refund's file: %s", data)
			}
			data = bytes.Replace(data, []byte(`"UNKNOWN"`), []byte(`"CONFIRMED"`), 1)
		}
		if name != pack.ManifestPath {
			rest = append(rest, pack.File{Path: name, Data: data})
		}
	}
	changed, err := pack.Write(rest, string(files[pack.ManifestPath]), nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if code, rep := p.verify(t, writeFile(t, p.dir, "changed.zip", changed)); code != 1 {
		t.Fatalf("a changed pack: exit %d\n%+v", code, rep.Checks)
	}
}
