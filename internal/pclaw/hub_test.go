// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"crypto/ed25519"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/hub/domain"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/rootkey"
)

// Covers: F846

// hubSite is a Hub directory signed with a development key.
type hubSite struct {
	t      *testing.T
	dir    string
	signer *jws.Signer
	pub    string // the .pub.json file
}

func newHubSite(t *testing.T) *hubSite {
	t.Helper()
	priv, kid, err := rootkey.Generate(rootkey.PurposeDevHub)
	if err != nil {
		t.Fatal(err)
	}
	s, err := jws.NewSigner(kid, priv)
	if err != nil {
		t.Fatal(err)
	}
	pubKey, _ := priv.Public().(ed25519.PublicKey)
	b, err := json.Marshal(struct {
		Keys []jws.JWK `json:"keys"`
	}{Keys: []jws.JWK{jws.PublicJWK(pubKey, kid)}})
	if err != nil {
		t.Fatal(err)
	}
	h := &hubSite{t: t, dir: t.TempDir(), signer: s, pub: filepath.Join(t.TempDir(), "hub-dev.pub.json")}
	if err := os.WriteFile(h.pub, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(h.dir, "items"), 0o750); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *hubSite) item(name, version string, kind domain.Kind, body any) ([]byte, domain.Entry) {
	h.t.Helper()
	b, err := json.Marshal(body, json.Deterministic(true))
	if err != nil {
		h.t.Fatal(err)
	}
	raw, err := json.Marshal(domain.Item{Spec: domain.ItemSpec, Name: name, Version: version, Kind: kind, Body: jsontext.Value(b)}, json.Deterministic(true))
	if err != nil {
		h.t.Fatal(err)
	}
	e := domain.Entry{Name: name, Version: version, Kind: kind, SHA256: domain.Digest(raw), Size: int64(len(raw)), Title: "Title of " + name, Summary: "A summary"}
	if err := os.WriteFile(filepath.Join(h.dir, "items", e.SHA256+".json"), raw, 0o600); err != nil {
		h.t.Fatal(err)
	}
	return raw, e
}

func (h *hubSite) sign(version uint64, entries ...domain.Entry) {
	h.t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	doc, err := domain.Sign(domain.Index{
		Version: version, IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.AddDate(0, 0, 30).Format(time.RFC3339), Items: entries,
	}, h.signer)
	if err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.dir, "index.jws"), []byte(doc), 0o600); err != nil {
		h.t.Fatal(err)
	}
}

func (h *hubSite) rule(version string) domain.Entry {
	_, e := h.item("pc.detect.watch", version, domain.KindDetectionRule, domain.DetectionRuleBody{Content: "id: org.watch " + version})
	return e
}

type fakeHub struct {
	pantherclawv1connect.UnimplementedHubServiceHandler
	got      *pantherclawv1.InstallHubItemRequest
	installs []*pantherclawv1.HubInstall
}

func (f *fakeHub) InstallHubItem(_ context.Context, r *pantherclawv1.InstallHubItemRequest) (*pantherclawv1.InstallHubItemResponse, error) {
	f.got = r
	return &pantherclawv1.InstallHubItemResponse{Install: &pantherclawv1.HubInstall{Name: "installed-marker"}}, nil
}

func (f *fakeHub) ListHubInstalls(context.Context, *pantherclawv1.ListHubInstallsRequest) (*pantherclawv1.ListHubInstallsResponse, error) {
	return &pantherclawv1.ListHubInstallsResponse{Installs: f.installs}, nil
}

func (f *fakeHub) GetHubState(context.Context, *pantherclawv1.GetHubStateRequest) (*pantherclawv1.GetHubStateResponse, error) {
	return &pantherclawv1.GetHubStateResponse{Present: true, IndexVersion: 3}, nil
}

func hubEnv(t *testing.T, h *hubSite, f *fakeHub) Env {
	t.Helper()
	m := map[string]string{"PANTHERCLAW_CONFIG_DIR": t.TempDir(), envHubDevKey: h.pub}
	if f != nil {
		cs := connect.NewServer()
		pantherclawv1connect.RegisterHubServiceHandler(cs, f)
		mux := http.NewServeMux()
		connecthttp.Mount(mux, cs)
		ts := httptest.NewServer(mux)
		t.Cleanup(ts.Close)
		m["PANTHERCLAW_SERVER"], m["PANTHERCLAW_API_KEY"] = ts.URL, "pck_test_x"
	}
	return envOf(m)
}

func TestHubSearchShowAndUpdate(t *testing.T) {
	h := newHubSite(t)
	_, cx := h.item("pc.range.cx", "1.0.0", domain.KindRangeScenario, domain.RangeScenarioBody{FileName: "CX-90001-x.yaml", Scenario: "id: CX-90001\n"})
	old, latest := h.rule("1.0.0"), h.rule("1.2.0")
	h.sign(2, old, latest, cx)
	f := &fakeHub{installs: []*pantherclawv1.HubInstall{{
		Name: old.Name, Version: "1.0.0", Status: pantherclawv1.HubInstallStatus_HUB_INSTALL_STATUS_INSTALLED, ResultKind: "custom_rule", ResultRef: "r1",
	}}}
	env := hubEnv(t, h, f)

	code, out, errs := run(t, env, "hub", "search", "WATCH", "--source", h.dir)
	if code != 0 || !strings.Contains(out, "pc.detect.watch@1.2.0") || strings.Contains(out, "pc.range.cx") {
		t.Fatalf("search = %d\n%s\n%s", code, out, errs)
	}
	code, out, _ = run(t, env, "hub", "search", "--kind", "range_scenario", "--source", h.dir)
	if code != 0 || !strings.Contains(out, "pc.range.cx") || strings.Contains(out, "pc.detect.watch") {
		t.Fatalf("search by kind = %d\n%s", code, out)
	}
	if code, _, errs := run(t, env, "hub", "search", "--kind", "script", "--source", h.dir); code == 0 || !strings.Contains(errs, "unknown kind") {
		t.Fatalf("closed kinds: %d %s", code, errs)
	}
	// The latest version unless one is named.
	if code, out, _ := run(t, env, "hub", "show", "pc.detect.watch", "--source", h.dir); code != 0 || !strings.Contains(out, "org.watch 1.2.0") {
		t.Fatalf("show = %d\n%s", code, out)
	}
	if code, out, _ := run(t, env, "hub", "show", "pc.detect.watch@1.0.0", "--source", h.dir); code != 0 || !strings.Contains(out, "org.watch 1.0.0") {
		t.Fatalf("show = %d\n%s", code, out)
	}
	code, out, errs = run(t, env, "hub", "update", "--source", h.dir)
	if code != 0 || !strings.Contains(out, "index version 2") || !strings.Contains(out, "update available: pc.detect.watch 1.0.0 -> 1.2.0") {
		t.Fatalf("update = %d\n%s\n%s", code, out, errs)
	}
	code, out, errs = run(t, env, "hub", "status")
	if code != 0 || !strings.Contains(out, "this machine: index version 2") || !strings.Contains(out, "this org: index version 3") ||
		!strings.Contains(out, "update available: pc.detect.watch") {
		t.Fatalf("status = %d\n%s\n%s", code, out, errs)
	}
}

// TestHR562_CLIRefusesARollback holds whichever way the older index arrives:
// through the same source or through another one.
func TestHR562_CLIRefusesARollback(t *testing.T) {
	h := newHubSite(t)
	env := hubEnv(t, h, nil)
	e := h.rule("1.0.0")
	h.sign(5, e)
	if code, _, errs := run(t, env, "hub", "search", "--source", h.dir); code != 0 {
		t.Fatal(errs)
	}
	h.sign(4, e)
	if code, _, errs := run(t, env, "hub", "search", "--source", h.dir); code == 0 || !strings.Contains(errs, "HUB_ROLLBACK") {
		t.Fatalf("older index = %d %s", code, errs)
	}
	h.sign(5, e, h.rule("1.1.0"))
	if code, _, errs := run(t, env, "hub", "search", "--source", h.dir); code == 0 || !strings.Contains(errs, "HUB_ROLLBACK") {
		t.Fatalf("same version, other content = %d %s", code, errs)
	}
	h.sign(4, e)
	ts := httptest.NewServer(http.FileServer(http.Dir(h.dir)))
	defer ts.Close()
	if code, _, errs := run(t, env, "hub", "search", "--source", ts.URL); code == 0 || !strings.Contains(errs, "HUB_ROLLBACK") {
		t.Fatalf("older index from a mirror = %d %s", code, errs)
	}
	h.sign(6, e)
	if code, _, errs := run(t, env, "hub", "search", "--source", h.dir); code != 0 {
		t.Fatal(errs)
	}
	// A state file that cannot be read never counts as no state.
	st := filepath.Join(mustHubDir(t, env), "state.json")
	if err := os.WriteFile(st, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := run(t, env, "hub", "search", "--source", h.dir); code == 0 {
		t.Fatal("a damaged state file reset the rollback check")
	}
}

func mustHubDir(t *testing.T, env Env) string {
	t.Helper()
	d, err := hubDir(env)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestHubInstall(t *testing.T) {
	h := newHubSite(t)
	f := &fakeHub{}
	env := hubEnv(t, h, f)
	raw, e := h.item("pc.coding.x", "1.0.0", domain.KindDetectionRule, domain.DetectionRuleBody{Content: "id: org.x"})
	h.sign(1, e)

	code, out, errs := run(t, env, "hub", "install", "pc.coding.x", "--dry-run", "--source", h.dir)
	if code != 0 || f.got != nil || !strings.Contains(out, "inert draft") {
		t.Fatalf("dry run = %d %v\n%s\n%s", code, f.got, out, errs)
	}
	code, out, errs = run(t, env, "hub", "install", "pc.coding.x", "--set", "environment=production", "--source", h.dir)
	if code != 0 || !strings.Contains(out, "installed-marker") {
		t.Fatalf("install = %d\n%s\n%s", code, out, errs)
	}
	if string(f.got.GetItem()) != string(raw) || f.got.GetParams()["environment"] != "production" || !strings.Contains(f.got.GetIndexJws(), ".") {
		t.Fatalf("request %v", f.got)
	}
	if code, _, errs := run(t, env, "hub", "install", "pc.coding.x", "--set", "bad", "--source", h.dir); code == 0 || !strings.Contains(errs, "K=V") {
		t.Fatalf("bad --set = %d %s", code, errs)
	}

	// A mirror that swaps an item's bytes is caught here, before any RPC.
	f.got = nil
	p := filepath.Join(h.dir, "items", e.SHA256+".json")
	if err := os.WriteFile(p, []byte(`{"tampered":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	fresh := hubEnv(t, h, f)
	if code, _, errs := run(t, fresh, "hub", "install", "pc.coding.x", "--source", h.dir); code == 0 || !strings.Contains(errs, "HUB_DIGEST") || f.got != nil {
		t.Fatalf("tampered = %d %s", code, errs)
	}
	// A cached item is no way around that either.
	cached := filepath.Join(mustHubDir(t, env), "cache", "items", e.SHA256+".json")
	if err := os.WriteFile(cached, []byte(`{"tampered":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := run(t, env, "hub", "install", "pc.coding.x", "--source", h.dir); code == 0 || !strings.Contains(errs, "HUB_DIGEST") {
		t.Fatalf("tampered cache = %d %s", code, errs)
	}
}

func TestHubInstallRefusesARequestThatWouldNotFit(t *testing.T) {
	h := newHubSite(t)
	f := &fakeHub{}
	env := hubEnv(t, h, f)
	_, e := h.item("pc.big", "1.0.0", domain.KindDetectionRule, domain.DetectionRuleBody{Content: strings.Repeat("x", domain.MaxItemBytes-200)})
	h.sign(1, e)
	if code, _, errs := run(t, env, "hub", "install", "pc.big", "--set", "x="+strings.Repeat("v", domain.MaxIndexBytes), "--source", h.dir); code == 0 || !strings.Contains(errs, "one request takes") || f.got != nil {
		t.Fatalf("oversized = %d %s", code, errs)
	}
	if code, out, errs := run(t, env, "hub", "install", "pc.big", "--source", h.dir); code != 0 || !strings.Contains(out, "installed-marker") {
		t.Fatalf("largest item = %d\n%s\n%s", code, out, errs)
	}
}

// TestHubScenarioStaysLocal: a range scenario never reaches a server.
func TestHubScenarioStaysLocal(t *testing.T) {
	h := newHubSite(t)
	f := &fakeHub{}
	env := hubEnv(t, h, f)
	_, e := h.item("pc.range.cx", "1.0.0", domain.KindRangeScenario, domain.RangeScenarioBody{FileName: "CX-90001-x.yaml", Scenario: "id: CX-90001\n"})
	h.sign(1, e)
	dir := filepath.Join(t.TempDir(), "scenarios")
	if code, out, _ := run(t, env, "hub", "install", "pc.range.cx", "--scenario-dir", dir, "--dry-run", "--source", h.dir); code != 0 || !strings.Contains(out, "would write") {
		t.Fatalf("dry run = %d %s", code, out)
	}
	path := filepath.Join(dir, "CX-90001-x.yaml")
	if _, err := os.Stat(path); err == nil {
		t.Fatal("a dry run wrote the file")
	}
	if code, _, errs := run(t, env, "hub", "install", "pc.range.cx", "--scenario-dir", dir, "--source", h.dir); code != 0 {
		t.Fatal(errs)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "id: CX-90001\n" { //nolint:gosec // G304: test path
		t.Fatalf("%q %v", b, err)
	}
	if code, out, _ := run(t, env, "hub", "install", "pc.range.cx", "--scenario-dir", dir, "--source", h.dir); code != 0 || !strings.Contains(out, "already there") {
		t.Fatalf("again = %d %s", code, out)
	}
	if err := os.WriteFile(path, []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := run(t, env, "hub", "install", "pc.range.cx", "--scenario-dir", dir, "--source", h.dir); code == 0 || !strings.Contains(errs, "other content") {
		t.Fatalf("overwrite = %d %s", code, errs)
	}
	if f.got != nil {
		t.Fatal("the scenario went to the server")
	}
}

func TestHubSourceRules(t *testing.T) {
	h := newHubSite(t)
	e := h.rule("1.0.0")
	h.sign(1, e)
	a := &app{http: &http.Client{}, env: envOf(nil), stderr: new(strings.Builder)}
	for _, bad := range []string{"http://hub.example.test/", "ftp://127.0.0.1/", "https://u:p@hub.example.test/", "https://hub.example.test/?x=1"} {
		if _, err := a.hubSource(bad); err == nil {
			t.Errorf("source %q accepted", bad)
		}
	}
	for _, good := range []string{"https://hub.example.test/x", "http://127.0.0.1:9/", "http://localhost:9", "http://[::1]:9/"} {
		if _, err := a.hubSource(good); err != nil {
			t.Errorf("source %q: %v", good, err)
		}
	}
	if s, err := a.hubSource(""); err != nil || s.base == nil || s.base.Scheme != "https" || s.local {
		t.Errorf("default source %+v %v", s, err)
	}

	// No cross-host redirect.
	other := httptest.NewServer(http.FileServer(http.Dir(h.dir)))
	defer other.Close()
	mirror := httptest.NewServer(http.RedirectHandler(other.URL+"/index.jws", http.StatusFound))
	defer mirror.Close()
	env := hubEnv(t, h, nil)
	if code, _, errs := run(t, env, "hub", "search", "--source", mirror.URL); code == 0 || !strings.Contains(errs, "another host") {
		t.Fatalf("cross-host redirect = %d %s", code, errs)
	}
}

func TestHubDevKeyAppliesToLocalSourcesOnly(t *testing.T) {
	h := newHubSite(t)
	h.sign(1, h.rule("1.0.0"))
	env := hubEnv(t, h, nil)
	a := &app{env: env, stderr: new(strings.Builder)}
	roots, err := a.hubRoots(true)
	if err != nil || len(roots) != 1 {
		t.Fatalf("local roots %v %v", roots, err)
	}
	roots, err = a.hubRoots(false)
	if err != nil || len(roots) != 0 {
		t.Fatalf("remote roots %v %v", roots, err)
	}
	// Without the key a local source has no root at all.
	noKey := envOf(map[string]string{"PANTHERCLAW_CONFIG_DIR": t.TempDir()})
	if code, _, errs := run(t, noKey, "hub", "search", "--source", h.dir); code == 0 || !strings.Contains(errs, "HUB_NO_ROOT") {
		t.Fatalf("no root = %d %s", code, errs)
	}
}
