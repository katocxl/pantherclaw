// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/rpcauth"
	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/adapters/evidencerpc"
	evapp "github.com/katocxl/pantherclaw/internal/evidence/app"
	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/evidence/keydocs"
	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	"github.com/katocxl/pantherclaw/internal/evidence/packbuild"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/rpc"
	"github.com/katocxl/pantherclaw/internal/platform/rpc/protoperms"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	txapp "github.com/katocxl/pantherclaw/internal/transactions/app"
)

// edition is the licence's edition, changeable by the test.
type edition struct{ ed billing.Edition }

func (e *edition) Current(context.Context) (billing.Entitlements, error) {
	en := billing.CommunityEntitlements()
	en.Edition = e.ed
	return en, nil
}

// packWorld builds packs over the world's database: the use cases with an
// enqueuer that records the job, and the builder with the deployment's
// keys.
type packWorld struct {
	*world
	reg     *keys.Registry
	svc     *evapp.Service
	builder *packbuild.Service
	queued  []ids.UUID
	edition *edition
}

func (w *world) packs(ed billing.Edition) *packWorld {
	w.t.Helper()
	kek := filepath.Join(w.t.TempDir(), "kek")
	if err := keys.GenerateKEKFile(kek); err != nil {
		w.t.Fatal(err)
	}
	kp, err := keys.NewFileProvider([]string{kek})
	if err != nil {
		w.t.Fatal(err)
	}
	reg := keys.NewRegistry()
	if err := keystore.LoadSigningKeys(context.Background(), w.pool, kp, reg); err != nil {
		w.t.Fatal(err)
	}
	p := &packWorld{world: w, reg: reg, edition: &edition{ed}}
	p.svc = evapp.New(w.pool, "pc.test").WithPacks(func(_ context.Context, _ db.TenantTx, _ ids.OrgID, id ids.UUID) error {
		p.queued = append(p.queued, id)
		return nil
	}, p.edition)
	p.builder = &packbuild.Service{
		Pool: w.pool, Keys: reg, LogOrigin: "pc.test", Explorer: &txapp.Explorer{Pool: w.pool}, Bundles: evapp.New(w.pool, "pc.test"),
		Log: pclog.Discard(),
	}
	return p
}

// team adds a team to the world's org.
func (p *packWorld) team(slug string) td.Scope {
	p.t.Helper()
	id := ids.NewV7()
	exec(p.t, p.pool, p.org, "INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, $3, $3)", p.org, id, slug)
	return td.Scope{Type: td.ScopeTeam, ID: id}
}

// person is a user of the world's org bound to role at scope (the org or a
// team), as a caller. The pack's builder reads the same binding.
func (p *packWorld) person(name string, role td.RoleName, scope td.Scope) context.Context {
	p.t.Helper()
	id := ids.NewV7()
	exec(p.t, p.pool, p.org, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)", p.org, id, name)
	if scope.Type == td.ScopeTeam {
		exec(p.t, p.pool, p.org, `INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, team_id, created_by)
			VALUES ($1, $2, $3, $4, 'TEAM', $5, 'test')`, p.org, ids.NewV7(), string(role), id, scope.ID)
	} else {
		exec(p.t, p.pool, p.org, `INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by)
			VALUES ($1, $2, $3, $4, 'ORG', 'test')`, p.org, ids.NewV7(), string(role), id)
	}
	return tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: p.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: id}, Bindings: []td.Binding{{Role: role, Scope: scope}},
	}})
}

// create asks for a pack and builds it.
func (p *packWorld) create(ctx context.Context, req evapp.PackRequest) evapp.Pack {
	p.t.Helper()
	pk, err := p.svc.CreateEvidencePack(ctx, req)
	if err != nil {
		p.t.Fatal(err)
	}
	if pk.State != "BUILDING" || !slices.Contains(p.queued, pk.ID) {
		p.t.Fatalf("a new pack: %+v, queued %v", pk, p.queued)
	}
	if err := p.builder.Build(context.Background(), p.org, pk.ID); err != nil {
		p.t.Fatal(err)
	}
	got, err := p.svc.GetEvidencePack(ctx, pk.ID)
	if err != nil || got.State != "READY" {
		p.t.Fatalf("after the build: %+v, %v", got, err)
	}
	return got
}

func (p *packWorld) download(ctx context.Context, id ids.UUID) []byte {
	p.t.Helper()
	d, err := p.svc.DownloadEvidencePack(ctx, id)
	if err != nil {
		p.t.Fatal(err)
	}
	return d.Content
}

// trust pins the keys the deployment publishes.
func (p *packWorld) trust() *bundle.Trust {
	p.t.Helper()
	mux := http.NewServeMux()
	keydocs.New(func(ctx context.Context, ps []keys.Purpose) ([]keystore.PublishedKey, error) {
		return keystore.PublishedKeys(ctx, p.pool, ps)
	}, "https://pc.test", "pc.test", clock.System{}, pclog.Discard()).Mount(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, keydocs.EvidenceKeysPath, nil))
	published, err := bundle.ParseEvidenceKeys(rec.Body.Bytes())
	if err != nil {
		p.t.Fatal(err)
	}
	// The world's Authority signs receipts with a key of its own registry.
	receipts, ok := p.auth.Receipts.(*jws.Signer)
	if !ok {
		p.t.Fatal("the world's receipt signer is not a JWS signer")
	}
	published.Keys = append(published.Keys, bundle.TrustedKey{
		KID: receipts.KeyID(), Purpose: bundle.PurposeReceipts, Algorithm: bundle.AlgEdDSA, PublicKey: receipts.Public(),
		NotBefore: time.Now().Add(-time.Hour), State: bundle.StateActive,
	})
	raw, err := json.Marshal(published)
	if err != nil {
		p.t.Fatal(err)
	}
	trust, err := bundle.ParseTrust(raw)
	if err != nil {
		p.t.Fatal(err)
	}
	return trust
}

func manifestOf(t *testing.T, raw []byte) *pack.Manifest {
	t.Helper()
	files, err := pack.Read(raw)
	if err != nil {
		t.Fatal(err)
	}
	s, err := pack.ParseJWS(string(files[pack.ManifestPath]))
	if err != nil {
		t.Fatal(err)
	}
	m, err := pack.DecodeManifest(s.Payload)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func hasGap(m *pack.Manifest, reason string) bool {
	return slices.ContainsFunc(m.Gaps, func(g pack.Gap) bool { return g.Reason == reason })
}

// TestHR196_APackHoldsEveryEffectStateOfItsScope: a pack of a run holds
// each of its transactions with its decision, execution and effect state
// side by side, the unknown, conflicting and pending ones included (F528),
// one file per transaction listed with its digest, the versions the
// decisions applied (F527), the approval that held one (F171), its gaps
// (not checkpointed, not anchored), the fixed sentence, and it verifies
// offline against the published keys.
func TestHR196_APackHoldsEveryEffectStateOfItsScope(t *testing.T) {
	w := newWorld(t)
	w.auth.PermitTTL = time.Hour
	w.refundable("ch_1")
	s := w.verifier()
	run := w.run(w.grant("500").ID, ids.UUID{})
	confirmed := w.recorded(run, "ch_1", "10.00", finalize.Accepted, "re_1")
	l := w.lease(s, confirmed.TransactionID)
	if _, err := s.Report(context.Background(), w.org, w.gwID, txapp.Report{
		Task: l.Task, Secret: l.Secret, HTTPStatus: 200, Found: true,
		Fields: refund("succeeded", "10.00"),
	}); err != nil {
		t.Fatal(err)
	}
	conflicting := w.recorded(run, "ch_1", "11.00", finalize.Accepted, "re_2")
	l = w.lease(s, conflicting.TransactionID)
	if _, err := s.Report(context.Background(), w.org, w.gwID, txapp.Report{
		Task: l.Task, Secret: l.Secret, HTTPStatus: 200, Found: true,
		Fields: refund("succeeded", "99.00"),
	}); err != nil {
		t.Fatal(err)
	}
	pending := w.recorded(run, "ch_1", "12.00", finalize.Accepted, "re_3")
	l = w.lease(s, pending.TransactionID)
	if _, err := s.Report(context.Background(), w.org, w.gwID, txapp.Report{
		Task: l.Task, Secret: l.Secret, HTTPStatus: 200, Found: true,
		Fields: refund("pending", "12.00"),
	}); err != nil {
		t.Fatal(err)
	}
	unknown := w.recorded(run, "ch_1", "13.00", finalize.Unknown, "")
	denied := w.authorize(w.request(run, ids.NewV7(), "ch_1", "700.00"))

	p := w.packs(billing.Team)
	org := td.Scope{Type: td.ScopeOrg, ID: w.org.UUID()}
	auditor := p.person("auditor", td.RoleAuditor, org)
	pk := p.create(auditor, evapp.PackRequest{Kind: pack.ScopeRun, Run: run, Include: pack.Include{
		Receipts: true, Versions: true, Approvals: true, Containment: true,
	}})
	raw := p.download(auditor, pk.ID)
	m := manifestOf(t, raw)
	states := map[string]string{}
	for _, tx := range m.Transactions {
		states[tx.ID] = tx.Effect
	}
	want := map[ids.UUID]string{
		confirmed.TransactionID: "CONFIRMED", conflicting.TransactionID: "CONFLICTING", pending.TransactionID: "PROPAGATION_PENDING",
		unknown.TransactionID: "UNKNOWN", denied.TransactionID: "",
	}
	for id, st := range want {
		got, ok := states[id.String()]
		if !ok || got != st {
			t.Errorf("transaction %s: effect %q (listed %v), want %q", id, got, ok, st)
		}
	}
	if len(m.Transactions) != len(want) || m.EffectStates["UNKNOWN"] != 1 || m.EffectStates["CONFLICTING"] != 1 {
		t.Fatalf("manifest transactions %d, effect states %v", len(m.Transactions), m.EffectStates)
	}
	if m.Statement != pack.Statement || m.Versions == nil || len(m.Versions.Definitions) == 0 || len(m.Versions.Levels) == 0 ||
		!hasGap(m, pack.GapNotCheckpointed) || !hasGap(m, pack.GapNotAnchored) || len(m.Filters) == 0 {
		t.Fatalf("manifest: %+v", m)
	}
	files, _ := pack.Read(raw)
	for id := range want {
		if _, ok := files["transactions/"+id.String()+".json"]; !ok {
			t.Errorf("no file for %s", id)
		}
	}
	trust := p.trust()
	report := bundle.VerifyPack(raw, bundle.Options{Trust: trust})
	if report.Failed() {
		t.Fatalf("the pack does not verify:\n%s", report.Text())
	}
	var txn map[string]any
	unknownPath := "transactions/" + unknown.TransactionID.String() + ".json"
	if err := json.Unmarshal(files[unknownPath], &txn); err != nil || txn["effect_state"] != "UNKNOWN" || txn["decisions"] == nil {
		t.Fatalf("the unknown refund's file: %v, %v", txn, err)
	}
	// A changed pack fails its manifest: the unknown refund's file says it
	// was confirmed.
	var rest []pack.File
	for path, data := range files {
		if path == unknownPath {
			data = bytes.Replace(data, []byte(`"UNKNOWN"`), []byte(`"CONFIRMED"`), 1)
		}
		if path != pack.ManifestPath {
			rest = append(rest, pack.File{Path: path, Data: data})
		}
	}
	changed, err := pack.Write(rest, string(files[pack.ManifestPath]), nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if r := bundle.VerifyPack(changed, bundle.Options{Trust: trust}); !r.Failed() {
		t.Fatal("a changed pack verifies")
	}

	// Once the workers chained and checkpointed the org, a new pack holds
	// the latest checkpoint and the inclusion proof of every receipt.
	w.checkpointWorld(p.reg)
	raw = p.download(auditor, p.create(auditor, evapp.PackRequest{Kind: pack.ScopeRun, Run: run, Include: pack.Include{Receipts: true}}).ID)
	m = manifestOf(t, raw)
	if m.Checkpoint == nil || m.Checkpoint.Size == 0 || hasGap(m, pack.GapNotCheckpointed) || !hasGap(m, pack.GapNotAnchored) {
		t.Fatalf("a checkpointed pack: checkpoint %+v, gaps %+v", m.Checkpoint, m.Gaps)
	}
	report = bundle.VerifyPack(raw, bundle.Options{Trust: p.trust()})
	if report.Failed() || !slices.ContainsFunc(report.Checks, func(c bundle.Check) bool {
		return c.Name == "entry.inclusion" && c.Status == bundle.Passed
	}) {
		t.Fatalf("the checkpointed pack:\n%s", report.Text())
	}
}

// TestHR196_APackHoldsNothingOutsideItsCreatorsPermissions: a pack of a
// time range made by an auditor of another team holds none of the
// transactions, says how many it left out and why, and which filter
// applied (F515); the same request by an auditor of the agent's team holds
// them all. The creator's permissions are read when the pack is built.
func TestHR196_APackHoldsNothingOutsideItsCreatorsPermissions(t *testing.T) {
	w := newWorld(t)
	w.refundable("ch_1")
	run := w.run(w.grant("500").ID, ids.UUID{})
	for _, amount := range []string{"10.00", "11.00", "12.00"} {
		w.authorize(w.request(run, ids.NewV7(), "ch_1", amount))
	}
	p := w.packs(billing.Team)
	from, to := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	req := evapp.PackRequest{Kind: pack.ScopeTimeRange, From: &from, To: &to, Include: pack.Include{Receipts: true}}

	outsider := p.person("outsider", td.RoleAuditor, p.team("elsewhere"))
	m := manifestOf(t, p.download(outsider, p.create(outsider, req).ID))
	if len(m.Transactions) != 0 || len(m.Items) != 0 || !slices.ContainsFunc(m.Gaps, func(g pack.Gap) bool {
		return g.Reason == pack.GapOutsidePermission && g.Subject == "transactions"
	}) {
		t.Fatalf("an outsider's pack: %+v", m)
	}
	insider := p.person("insider", td.RoleAuditor, td.Scope{Type: td.ScopeTeam, ID: w.teamOfAgent()})
	m = manifestOf(t, p.download(insider, p.create(insider, req).ID))
	if len(m.Transactions) != 3 || hasGap(m, pack.GapOutsidePermission) {
		t.Fatalf("an insider's pack: %d transactions, gaps %+v", len(m.Transactions), m.Gaps)
	}
}

// TestHR196_PacksThroughTheRPC: served as the API serves EvidenceService
// (the permission interceptor and protovalidate included), a person with
// evidence.export creates a pack, reads its metadata and downloads it as a
// stream whose bytes match the stated SHA-256 and verify; a service
// account is refused (evidence.export is human only) and another org's
// pack is not found.
func TestHR196_PacksThroughTheRPC(t *testing.T) {
	w := newWorld(t)
	w.refundable("ch_1")
	run := w.run(w.grant("500").ID, ids.UUID{})
	w.authorize(w.request(run, ids.NewV7(), "ch_1", "10.00"))
	p := w.packs(billing.Team)
	org := td.Scope{Type: td.ScopeOrg, ID: w.org.UUID()}
	auditorCtx := p.person("rpc-auditor", td.RoleAuditor, org)
	auditorCaller, _ := tapp.CallerFrom(auditorCtx)

	declared, err := protoperms.Declared(filepath.Join("..", "..", "..", "..", "proto"))
	if err != nil {
		t.Fatal(err)
	}
	perms := map[string]td.Permission{}
	for proc, perm := range declared {
		perms[proc] = td.Permission(perm)
	}
	who := callers{
		"auditor": auditorCaller,
		"robot": tapp.Caller{Subject: td.Subject{
			Org: w.org, Principal: td.PrincipalRef{Kind: td.KindServiceAccount, ID: w.billing}, Bindings: []td.Binding{{Role: td.RoleAuditor, Scope: org}},
		}},
	}
	s, err := rpc.NewServer(rpc.Options{Authenticate: rpcauth.New(who, perms, nil)})
	if err != nil {
		t.Fatal(err)
	}
	pantherclawv1connect.RegisterEvidenceServiceHandler(s, evidencerpc.New(p.svc))
	mux := http.NewServeMux()
	rpc.Mount(mux, s)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	client := func(bearer string) pantherclawv1connect.EvidenceServiceClient {
		return pantherclawv1connect.NewEvidenceServiceClient(connect.NewClient(connecthttp.NewTransport(&http.Client{
			Timeout: 30 * time.Second, Transport: bearerRT{bearer},
		}, ts.URL)))
	}
	ctx := context.Background()
	req := &pantherclawv1.CreateEvidencePackRequest{
		Scope:   &pantherclawv1.CreateEvidencePackRequest_RunId{RunId: run.String()},
		Include: &pantherclawv1.PackContents{Receipts: true, Versions: true},
	}
	_, err = client("robot").CreateEvidencePack(ctx, req)
	replayCode(t, "a service account", err, connect.CodePermissionDenied)
	created, err := client("auditor").CreateEvidencePack(ctx, req)
	if err != nil || created.GetPack().GetState() != pantherclawv1.EvidencePackState_EVIDENCE_PACK_STATE_BUILDING {
		t.Fatalf("CreateEvidencePack = %v, %v", created, err)
	}
	id, _ := ids.ParseUUID(created.GetPack().GetId())
	if err := p.builder.Build(ctx, w.org, id); err != nil {
		t.Fatal(err)
	}
	got, err := client("auditor").GetEvidencePack(ctx, &pantherclawv1.GetEvidencePackRequest{Id: id.String()})
	if err != nil || got.GetPack().GetState() != pantherclawv1.EvidencePackState_EVIDENCE_PACK_STATE_READY || got.GetPack().GetManifest() == "" {
		t.Fatalf("GetEvidencePack = %v, %v", got, err)
	}
	stream, err := client("auditor").DownloadEvidencePack(ctx, &pantherclawv1.DownloadEvidencePackRequest{Id: id.String()})
	if err != nil {
		t.Fatal(err)
	}
	var content []byte
	var sum []byte
	for {
		m, err := stream.Receive()
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		content, sum = append(content, m.GetChunk()...), m.GetContentSha256()
	}
	_ = stream.Close()
	if s := sha256.Sum256(content); !bytes.Equal(s[:], sum) || !bytes.Equal(s[:], got.GetPack().GetContentSha256()) {
		t.Fatal("the streamed content does not match its SHA-256")
	}
	if r := bundle.VerifyPack(content, bundle.Options{Trust: p.trust()}); r.Failed() {
		t.Fatalf("the downloaded pack:\n%s", r.Text())
	}
	list, err := client("auditor").ListEvidencePacks(ctx, &pantherclawv1.ListEvidencePacksRequest{})
	if err != nil || len(list.GetPacks()) != 1 {
		t.Fatalf("ListEvidencePacks = %v, %v", list, err)
	}
	_, err = client("auditor").GetEvidencePack(ctx, &pantherclawv1.GetEvidencePackRequest{Id: ids.NewV7().String()})
	replayCode(t, "an unknown pack", err, connect.CodeNotFound)
}

// TestHR196_PacksAreTeamEditionHumanOnlyAndScopedToTheirOrg: packs need a
// Team licence and evidence.export (human only); another org's run, pack
// or download is not found (T-037); a pack's content goes only to its
// creator or an org-wide exporter, and every download is audited.
func TestHR196_PacksAreTeamEditionHumanOnlyAndScopedToTheirOrg(t *testing.T) {
	w := newWorld(t)
	w.refundable("ch_1")
	run := w.run(w.grant("500").ID, ids.UUID{})
	w.authorize(w.request(run, ids.NewV7(), "ch_1", "10.00"))
	org := td.Scope{Type: td.ScopeOrg, ID: w.org.UUID()}
	req := evapp.PackRequest{Kind: pack.ScopeRun, Run: run, Include: pack.Include{Receipts: true}}

	p := w.packs(billing.Community)
	auditor := p.person("auditor", td.RoleAuditor, org)
	if _, err := p.svc.CreateEvidencePack(auditor, req); !errors.Is(err, evapp.ErrPacksEdition) {
		t.Fatalf("Community: %v", err)
	}
	p.edition.ed = billing.Team
	sa := tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: w.org, Principal: td.PrincipalRef{Kind: td.KindServiceAccount, ID: w.billing},
		Bindings: []td.Binding{{Role: td.RoleAuditor, Scope: org}},
	}})
	if _, err := p.svc.CreateEvidencePack(sa, req); pcerr.CodeOf(err) != pcerr.PermissionDenied {
		t.Fatalf("a service account: %v", err)
	}
	developer := p.person("developer", td.RoleDeveloper, org)
	if _, err := p.svc.CreateEvidencePack(developer, req); pcerr.CodeOf(err) != pcerr.PermissionDenied {
		t.Fatalf("without evidence.export: %v", err)
	}
	if _, err := p.svc.CreateEvidencePack(auditor, evapp.PackRequest{Kind: pack.ScopeRun, Run: ids.NewV7(), Include: req.Include}); !errors.Is(err, evapp.ErrRunNotFound) {
		t.Fatalf("an unknown run: %v", err)
	}
	pk := p.create(auditor, req)
	before := w.count("SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.evidence.pack_downloaded'")
	p.download(auditor, pk.ID)
	if after := w.count("SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.evidence.pack_downloaded'"); after != before+1 {
		t.Fatalf("downloads audited: %d then %d", before, after)
	}
	if n := w.count("SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.evidence.pack_created'"); n != 1 {
		t.Fatalf("creations audited: %d", n)
	}
	// Another team's exporter neither sees nor downloads it.
	teamAuditor := p.person("team-auditor", td.RoleAuditor, td.Scope{Type: td.ScopeTeam, ID: w.teamOfAgent()})
	if _, err := p.svc.GetEvidencePack(teamAuditor, pk.ID); !errors.Is(err, evapp.ErrPackNotFound) {
		t.Fatalf("a team auditor reads an org auditor's pack: %v", err)
	}
	if _, err := p.svc.DownloadEvidencePack(teamAuditor, pk.ID); !errors.Is(err, evapp.ErrPackNotFound) {
		t.Fatalf("a team auditor downloads an org auditor's pack: %v", err)
	}
	// Another org.
	stranger := ids.New[ids.Org]()
	exec(t, w.pool, stranger, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'globex')", stranger)
	intruder := tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: stranger, Principal: td.PrincipalRef{Kind: td.KindUser, ID: ids.NewV7()},
		Bindings: []td.Binding{{Role: td.RoleAuditor, Scope: td.Scope{Type: td.ScopeOrg, ID: stranger.UUID()}}},
	}})
	if _, err := p.svc.GetEvidencePack(intruder, pk.ID); !errors.Is(err, evapp.ErrPackNotFound) {
		t.Fatalf("another org's pack: %v", err)
	}
	if _, err := p.svc.DownloadEvidencePack(intruder, pk.ID); !errors.Is(err, evapp.ErrPackNotFound) {
		t.Fatalf("another org's download: %v", err)
	}
	// Expiry: 7 days after ready the content goes.
	w.db.AdminExec(t, "UPDATE pc.evidence_packs SET ready_at = ready_at - interval '8 days', expires_at = expires_at - interval '8 days' WHERE id = $1", pk.ID)
	if _, err := p.svc.DownloadEvidencePack(auditor, pk.ID); !errors.Is(err, evapp.ErrPackExpired) {
		t.Fatalf("an expired pack: %v", err)
	}
	if err := p.builder.Expire(context.Background(), w.org); err != nil {
		t.Fatal(err)
	}
	var state string
	var content []byte
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		r, err := dbq.New(tx).GetEvidencePackContent(ctx, w.org, pk.ID)
		state, content = r.State, r.Content
		return err
	}); err != nil || state != "EXPIRED" || content != nil {
		t.Fatalf("after expiry: %s, %d bytes, %v", state, len(content), err)
	}
}
