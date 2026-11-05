// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	credapp "github.com/katocxl/pantherclaw/internal/credentials/app"
	creddomain "github.com/katocxl/pantherclaw/internal/credentials/domain"
	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	defsapp "github.com/katocxl/pantherclaw/internal/definitions/app"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/trust"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/redteam/app"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
	"github.com/katocxl/pantherclaw/internal/sim/google"
	"github.com/katocxl/pantherclaw/internal/sim/linear"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// M31 range capabilities (G0 M31): agents working through pc.gmail,
// pc.google-workspace and pc.linear against their simulators. Harness
// only: on a live range they would send mail and share files.
const (
	capGmailSend   app.Capability = "gmail.send"
	capDriveShare  app.Capability = "drive.share"
	capLinearIssue app.Capability = "linear.issue"
)

func m31Capabilities() map[app.Capability]bool {
	return map[app.Capability]bool{capGmailSend: true, capDriveShare: true, capLinearIssue: true}
}

// needsM31 reports whether a scenario works through an M31 package.
func needsM31(sc domain.Scenario) bool {
	return requires(sc, string(capGmailSend)) || requires(sc, string(capDriveShare)) || requires(sc, string(capLinearIssue))
}

// The simulated identities: the mailbox the service account acts as, a
// mailbox of the same domain it does not act as, and a Linear key (test
// values, not real ones).
const (
	googleAccount = "pc-agent@simulated-project.iam.gserviceaccount.com"
	otherMailbox  = "other.user@example.test"
	linearKey     = "lin_api_" + "SimulatedE2EKey0123456789abcdefghijklmno"
)

var (
	seededGmail           = regexp.MustCompile(`seeded gmail connection ([0-9a-f-]{36}) `)
	seededGoogleWorkspace = regexp.MustCompile(`seeded google-workspace connection ([0-9a-f-]{36}) `)
	seededLinear          = regexp.MustCompile(`seeded linear connection ([0-9a-f-]{36}) `)
)

// googleSim is the Google simulator of a stack, the service account it
// accepts and the seeded connections "gmail" and "google-workspace".
type googleSim struct {
	sim          *google.Server
	url          string
	key          []byte
	gmail, drive ids.UUID
}

func startGoogleSim(t *testing.T) *googleSim {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	s := google.New(&google.Account{ClientEmail: googleAccount, Key: &k.PublicKey}, google.Faults{}, pclog.Discard())
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return &googleSim{sim: s, url: srv.URL, key: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})}
}

func (g *googleSim) seeded(t *testing.T, out string) {
	t.Helper()
	m, w := seededGmail.FindStringSubmatch(out), seededGoogleWorkspace.FindStringSubmatch(out)
	if m == nil || w == nil {
		t.Fatalf("dev seed output %q", out)
	}
	g.gmail, g.drive = mustUUID(t, m[1]), mustUUID(t, w[1])
}

// linearSim is the Linear simulator of a stack and the seeded connection
// "linear".
type linearSim struct {
	sim  *linear.Server
	url  string
	conn ids.UUID
}

func startLinearSim(t *testing.T) *linearSim {
	t.Helper()
	s := linear.New(linearKey, linear.Faults{}, pclog.Discard())
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return &linearSim{sim: s, url: srv.URL}
}

func (l *linearSim) seeded(t *testing.T, out string) {
	t.Helper()
	m := seededLinear.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("dev seed output %q", out)
	}
	l.conn = mustUUID(t, m[1])
}

// sealGoogle seals the simulator's service account for conn, acting as
// subject with scopes, as pclaw seal --google-service-account does, and
// returns the configuration version the gateway must reach.
func (s *stack) sealGoogle(t *testing.T, conn ids.UUID, subject string, scopes ...string) int64 {
	t.Helper()
	plain, err := creddomain.GoogleServiceAccount{
		V: 1, ClientEmail: googleAccount, PrivateKey: s.google.key, TokenURI: s.google.url + "/token", Subject: subject, Scopes: scopes,
	}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	id := ids.NewV7()
	s.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)", s.org.UUID(), id, "google-admin-"+conn.String())
	admin := tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: s.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: id},
		Bindings: []td.Binding{{Role: td.RoleGatewayAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: s.org.UUID()}}},
	}, Credential: tapp.CredAccessToken})
	svc := credapp.New(s.pool, nil)
	k, err := svc.GetSealingKey(admin, conn)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := pccrypto.ParseSealPublicKey(k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	k.Binding.Kind = creddomain.KindGoogleServiceAccount
	sealed, err := pccrypto.Seal(pub, k.Binding.Info(), creddomain.AAD, plain)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PutCredential(admin, credapp.PutInput{
		Connection: conn, BrokerKey: mustUUID(t, k.Binding.BrokerKey), Version: k.Binding.Version, Sealed: sealed,
		AllowedHosts: k.Binding.AllowedHosts, Header: k.Binding.Header, Scheme: k.Binding.Scheme, Kind: creddomain.KindGoogleServiceAccount,
	}); err != nil {
		t.Fatal(err)
	}
	return s.configVersion(t, k.Gateway)
}

// sealGoogleConnections seals the service account for "gmail" (gmail.send)
// and "google-workspace" (drive), each acting as the simulated mailbox.
func (s *stack) sealGoogleConnections(t *testing.T) {
	t.Helper()
	s.waitConfig(t, s.sealGoogle(t, s.google.gmail, google.Mailbox, "https://www.googleapis.com/auth/gmail.send"))
	s.waitConfig(t, s.sealGoogle(t, s.google.drive, google.Mailbox, "https://www.googleapis.com/auth/drive"))
}

// sha256Hex is the lowercase hex sha256 of b.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// setupM31Connectors gives the scenario's agent one grant over what it
// requires: Gmail sends as the credential's mailbox and as another one
// (the subject check, not the grant, refuses that one), Drive shares of the
// simulated file, and Linear issues in the simulated team. The org owns
// the simulated Workspace domain. Fixtures: mailbox, other_mailbox,
// drive_file, own_domain, linear_team.
func (d *rangeDriver) setupM31Connectors() {
	var ops []string
	targets := map[string]any{}
	if d.fix == nil {
		d.fix = app.Fixture{}
	}
	if requires(d.sc, string(capGmailSend)) {
		ops = append(ops, "gmail.message.send")
		targets["gmail_mailbox"] = map[string]any{"ids": []string{google.Mailbox, otherMailbox}}
		d.fix["mailbox"], d.fix["other_mailbox"] = google.Mailbox, otherMailbox
	}
	if requires(d.sc, string(capDriveShare)) {
		ops = append(ops, "drive.permission.create")
		targets["drive_file"] = map[string]any{"ids": []string{google.FileID}}
		d.fix["drive_file"], d.fix["own_domain"] = google.FileID, google.Domain
		d.s.exec(d.t, "INSERT INTO pc.owned_accounts (org_id, id, kind, value, added_by) VALUES ($1, $2, 'email_domain', $3, 'e2e')",
			d.s.org.UUID(), ids.NewV7(), google.Domain)
	}
	if requires(d.sc, string(capLinearIssue)) {
		ops = append(ops, "linear.issue.create")
		targets["linear_team"] = map[string]any{"ids": []string{linear.TeamID}}
		d.fix["linear_team"] = linear.TeamID
	}
	if len(ops) == 0 {
		return
	}
	b, err := json.Marshal(map[string]any{"operations": ops, "targets": targets})
	if err != nil {
		d.t.Fatal(err)
	}
	d.ownGrant(string(b), "")
}

// m31Call has the scenario's agent call an M31 tool over MCP.
func (d *rangeDriver) m31Call(t *testing.T, conn, tool string, args map[string]any) domain.Observation {
	t.Helper()
	b, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	obs, _, err := d.callOnce(callWith{Face: "mcp", Connection: conn, Tool: tool, Args: b}, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	return obs
}

// The OpenAPI spec the range drafts a package from: one read.
const m31Spec = `{
  "openapi": "3.1.0",
  "servers": [{"url": "https://api.acme.test/v1"}],
  "paths": {"/widgets/{widgetId}": {"get": {"operationId": "getWidget",
    "parameters": [{"name": "widgetId", "in": "path", "required": true, "schema": {"type": "string", "pattern": "^w-[0-9]{1,8}$"}}],
    "responses": {"200": {"description": "ok"}}}}}
}`

// packageImport drafts acme.widgets from m31Spec with pclaw package draft
// openapi, has a person review it (remove review_required) when reviewed,
// signs targets listing that file with an org package key the org
// registered (pclaw package sign refuses a draft, so the harness signs the
// draft's bytes itself) and imports it (G0 M31 D953, HR-720).
func (d *rangeDriver) packageImport(reviewed bool) (domain.Observation, error) {
	t, s := d.t, d.s
	dir := t.TempDir()
	spec := writeFile(t, dir, "spec.json", []byte(m31Spec))
	out := filepath.Join(dir, "draft.yaml")
	d.importSeq++
	version := "0.1." + itoa(int64(d.importSeq))
	runPclaw(t, noEnv, "package", "draft", "openapi", spec, "--name", "acme.widgets", "--version", version, "--out", out)
	raw, err := os.ReadFile(out)
	if err != nil {
		return domain.Observation{}, err
	}
	if reviewed {
		raw = withoutReviewRequired(raw)
	}
	ctx := t.Context()
	store := &defspg.Store{Pool: s.pool}
	if d.importKey == nil {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return domain.Observation{}, err
		}
		if err := store.RegisterSigningKey(ctx, s.org, defsapp.SigningKey{
			ID: ids.NewV7(), KID: trust.OrgKID(pub), Name: "range", Public: pub, State: defsapp.KeyActive, CreatedBy: "e2e",
		}, nil); err != nil {
			return domain.Observation{}, err
		}
		d.importKey = priv
	}
	signer, err := jws.NewSigner(trust.OrgKID(d.importKey.Public().(ed25519.PublicKey)), d.importKey)
	if err != nil {
		return domain.Observation{}, err
	}
	doc, err := trust.Sign(trust.Targets{
		Version: int64(d.importSeq), Expires: time.Now().UTC().Truncate(time.Second).AddDate(0, 0, 30).Format(time.RFC3339),
		Targets: map[string]trust.Target{trust.Key("acme.widgets", version): trustTarget(raw)},
	}, signer)
	if err != nil {
		return domain.Observation{}, err
	}
	im := &defsapp.Importer{Repo: store, Keys: store, Clock: clock.System{}}
	if _, err := im.Import(ctx, s.org, "acme.widgets", version, doc, raw, nil); err != nil {
		reason := ""
		if errors.Is(err, manifest.ErrDraftNotReviewed) {
			reason = "DRAFT_NOT_REVIEWED"
		}
		return domain.Observation{Outcome: domain.OutcomeRefused, Reason: reason, Reasons: []string{reason}, Detail: err.Error()}, nil
	}
	return domain.Observation{Outcome: domain.OutcomeAllow}, nil
}

// withoutReviewRequired removes a draft's review_required block, as the
// person who reviewed it does.
func withoutReviewRequired(raw []byte) []byte {
	var out []string
	skipping := false
	for line := range strings.Lines(string(raw)) {
		switch {
		case strings.HasPrefix(line, "review_required:"):
			skipping = true
			continue
		case skipping && (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "-")):
			continue
		}
		skipping = false
		out = append(out, line)
	}
	return []byte(strings.Join(out, ""))
}

// trustTarget is a targets entry for raw, without decoding it.
func trustTarget(raw []byte) trust.Target {
	return trust.Target{Length: int64(len(raw)), Hashes: map[string]string{"sha256": sha256Hex(raw)}}
}

// m31Step runs package.import; ok is false for any other kind.
func (d *rangeDriver) m31Step(st domain.Step) (domain.Observation, bool, error) {
	if st.Do != "package.import" {
		return domain.Observation{}, false, nil
	}
	var w struct {
		File string `json:"file"`
	}
	if err := json.Unmarshal(st.With, &w); err != nil {
		return domain.Observation{}, true, err
	}
	obs, err := d.packageImport(w.File == "reviewed")
	return obs, true, err
}

// TestE2E_M31_ConnectorBreadth is the M31 exit scenario on the real stack
// (G0 M31). A drafted package is never imported until a person reviews it
// (HR-720). An agent sends Gmail through pc.gmail with a Google service
// account only the gateway holds, which mints a token for the sealed
// mailbox per dispatch (HR-721); a subject with a line break is refused
// before any decision (HR-724); a send as another mailbox is refused before
// anything is minted (D956a). A Drive share to anyone holds for a person,
// one inside the org's own domain goes through (HR-725). A Linear issue is
// created with the package's fixed GraphQL document (HR-723).
//
// Covers: F1005, F1007, F1008, F1010, F1011, F1017
func TestE2E_M31_ConnectorBreadth(t *testing.T) {
	p := inProcessIdP(t)
	s := start(t, options{budget: "1000.00", people: &p, google: true, linear: true})
	d := newRangeDriver(t)
	d.s, d.people = s, &m2Stack{url: s.apiURL, cfg: s.serverCfg, idp: p}
	d.sc = domain.Scenario{ID: "M31-EXIT", Requires: []string{string(capGmailSend), string(capDriveShare), string(capLinearIssue)}}
	d.setupM31Connectors()

	if obs, err := d.packageImport(false); err != nil || obs.Outcome != domain.OutcomeRefused || obs.Reason != "DRAFT_NOT_REVIEWED" {
		t.Fatalf("draft import: %+v %v", obs, err)
	}
	if obs, err := d.packageImport(true); err != nil || obs.Outcome != domain.OutcomeAllow {
		t.Fatalf("reviewed import: %+v %v", obs, err)
	}

	send := map[string]any{"mailbox": google.Mailbox, "to": []string{"bob@example.test"}, "subject": "Retries fixed", "text": "Deployed in the e2e build."}
	if obs := d.m31Call(t, "gmail", "gmail_send_message", send); obs.Outcome != domain.OutcomeAllow {
		t.Fatalf("gmail send: %+v", obs)
	}
	st := s.google.sim.Stats()
	if len(st.Sent) != 1 || st.Sent[0].Mailbox != google.Mailbox || !slices.Equal(st.Sent[0].To, []string{"bob@example.test"}) ||
		len(st.Grants) != 1 || st.Grants[0].Subject != google.Mailbox {
		t.Fatalf("sent %+v, grants %+v", st.Sent, st.Grants)
	}
	injected := map[string]any{"mailbox": google.Mailbox, "to": []string{"bob@example.test"}, "subject": "Hi\nBcc: eve@attacker.example", "text": "x"}
	if obs := d.m31Call(t, "gmail", "gmail_send_message", injected); obs.Outcome == domain.OutcomeAllow {
		t.Fatalf("a header injection: %+v", obs)
	}
	other := map[string]any{"mailbox": otherMailbox, "to": []string{"bob@example.test"}, "subject": "As someone else", "text": "x"}
	if obs := d.m31Call(t, "gmail", "gmail_send_message", other); obs.Outcome == domain.OutcomeAllow {
		t.Fatalf("a send as another mailbox: %+v", obs)
	}
	if st := s.google.sim.Stats(); len(st.Sent) != 1 || st.TokensIssued != 1 {
		t.Fatalf("after the refusals: %d sent, %d tokens", len(st.Sent), st.TokensIssued)
	}

	share := func(args map[string]any) domain.Observation {
		args["file_id"] = google.FileID
		return d.m31Call(t, "google-workspace", "drive_share_file", args)
	}
	if obs := share(map[string]any{"type": "anyone", "role": "reader"}); obs.Outcome != domain.OutcomeHold || !slices.Contains(obs.Reasons, "SHARE_PUBLIC") {
		t.Fatalf("a public share: %+v", obs)
	}
	if obs := share(map[string]any{"type": "user", "role": "reader", "email_address": "eve@attacker.example"}); obs.Outcome != domain.OutcomeHold ||
		!slices.Contains(obs.Reasons, "SHARE_ACCOUNT_NOT_OWNED") {
		t.Fatalf("a share outside: %+v", obs)
	}
	if obs := share(map[string]any{"type": "user", "role": "reader", "email_address": "bob@example.test"}); obs.Outcome != domain.OutcomeAllow {
		t.Fatalf("an internal share: %+v", obs)
	}
	if ps := s.google.sim.Stats().Permissions; len(ps) != 1 || ps[0].EmailAddress != "bob@example.test" {
		t.Fatalf("permissions %+v", ps)
	}

	if obs := d.m31Call(t, "linear", "linear_create_issue", map[string]any{"team_id": linear.TeamID, "title": "Retries"}); obs.Outcome != domain.OutcomeAllow {
		t.Fatalf("linear create: %+v", obs)
	}
	if n := s.linear.sim.Stats()["issueCreate"]; n != 1 {
		t.Fatalf("issueCreate %d", n)
	}
}
