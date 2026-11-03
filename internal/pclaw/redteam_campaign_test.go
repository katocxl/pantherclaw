// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"encoding/pem"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/sandbox"
)

const campaignKey = "sk-ant-test-0123456789-the-real-model-key"

// fakeCampaignServer is the server side of a campaign: the relay connection,
// StartCampaign and FinishCampaign, recording what the runner sent.
type fakeCampaignServer struct {
	pantherclawv1connect.UnimplementedRangeServiceHandler
	pantherclawv1connect.UnimplementedConnectionServiceHandler
	relayURL string
	mu       sync.Mutex
	start    *pantherclawv1.StartCampaignRequest
	finish   *pantherclawv1.FinishCampaignRequest
	outcome  pantherclawv1.CampaignOutcome
	reason   string
	bodies   []string
	steps    []string
}

func (f *fakeCampaignServer) GetConnection(context.Context, *pantherclawv1.GetConnectionRequest) (*pantherclawv1.GetConnectionResponse, error) {
	return &pantherclawv1.GetConnectionResponse{Connection: &pantherclawv1.Connection{
		Id: relayConnID, Name: "model-relay-1", Simulated: true, ModelRelay: true, BaseUrl: f.relayURL,
	}}, nil
}

func (f *fakeCampaignServer) StartCampaign(_ context.Context, req *pantherclawv1.StartCampaignRequest) (*pantherclawv1.StartCampaignResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.start = req
	return &pantherclawv1.StartCampaignResponse{CampaignId: "0192aaaa-bbbb-7ccc-8ddd-0000000000c1"}, nil
}

func (f *fakeCampaignServer) StartCampaignStep(_ context.Context, req *pantherclawv1.StartCampaignStepRequest) (*pantherclawv1.StartCampaignStepResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.steps = append(f.steps, req.GetScenarioId())
	return &pantherclawv1.StartCampaignStepResponse{}, nil
}

func (f *fakeCampaignServer) FinishCampaign(_ context.Context, req *pantherclawv1.FinishCampaignRequest) (*pantherclawv1.FinishCampaignResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.finish = req
	return &pantherclawv1.FinishCampaignResponse{
		Campaign: &pantherclawv1.Campaign{Statement: "Attack campaign against a range twin", Counts: &pantherclawv1.CampaignCounts{Held: 1}},
		Steps:    []*pantherclawv1.CampaignStep{{ScenarioId: "RT-140", StepId: "merge", Boundary: "HR-201", Expected: "HELD", Outcome: f.outcome, Reason: f.reason}},
	}, nil
}

const relayConnID = "0192aaaa-bbbb-7ccc-8ddd-0000000000a1"

// freeLoopback returns a loopback address with a port nothing listens on.
func freeLoopback(t *testing.T) string {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

type campaignRig struct {
	srv        *fakeCampaignServer
	env        Env
	keyFile    string
	caFile     string
	provider   *httptest.Server
	sawKey     []string
	workspaces []string
	dir        string
}

// newCampaignRig starts the fake server and a local TLS model provider (its
// certificate is for example.com), and writes the key file and the
// provider's root.
func newCampaignRig(t *testing.T) *campaignRig {
	t.Helper()
	r := &campaignRig{dir: t.TempDir()}
	var mu sync.Mutex
	r.provider = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, in *http.Request) {
		mu.Lock()
		r.sawKey = append(r.sawKey, in.Header.Get("X-Api-Key"))
		mu.Unlock()
		_, _ = io.Copy(io.Discard, in.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"content":[{"type":"text","text":"ok"}]}`)
	}))
	t.Cleanup(r.provider.Close)
	r.srv = &fakeCampaignServer{relayURL: "http://" + freeLoopback(t), outcome: pantherclawv1.CampaignOutcome_CAMPAIGN_OUTCOME_HELD}
	cs := connect.NewServer()
	pantherclawv1connect.RegisterRangeServiceHandler(cs, r.srv)
	pantherclawv1connect.RegisterConnectionServiceHandler(cs, r.srv)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	r.env = envOf(map[string]string{"PANTHERCLAW_SERVER": ts.URL, "PANTHERCLAW_API_KEY": "pck_test_x"})
	r.keyFile = filepath.Join(r.dir, "model.key")
	if err := os.WriteFile(r.keyFile, []byte(campaignKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.caFile = filepath.Join(r.dir, "ca.pem")
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: r.provider.Certificate().Raw})
	if err := os.WriteFile(r.caFile, ca, 0o600); err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *campaignRig) args(extra ...string) []string {
	return append([]string{
		"redteam", "campaign", "run", "--agent", "0192aaaa-bbbb-7ccc-8ddd-0000000000b1", "--connection", "0192aaaa-bbbb-7ccc-8ddd-0000000000b2",
		"--relay-connection", relayConnID, "--grant", "0192aaaa-bbbb-7ccc-8ddd-0000000000b3", "--gateway", "http://127.0.0.1:8443",
		"--image", "agent@sha256:" + strings.Repeat("a", 64), "--edge-image", "edge", "--probe-image", "probe",
		"--model-host", "example.com", "--model-key-file", r.keyFile, "--model-ca", r.caFile, "--model-dial", r.provider.Listener.Addr().String(),
		"--campaigns", "../../redteam/campaigns", "--scripted",
		"--fixture", "repo=acme/payments", "--fixture", "pr=7", "--fixture", "head=abc123", "--fixture", "other_repo=acme/infra",
		"--fixture", "branch=fix/x",
	}, extra...)
}

// fakeSandbox stands in for the containment sandbox: it checks what the
// agent would get, then calls the relay as the gateway's model face does,
// with the placeholder the agent holds.
func (r *campaignRig) fakeSandbox(t *testing.T) func(context.Context, *app, sandboxRunFlags, sandboxExtra) (sandboxResult, error) {
	return func(ctx context.Context, _ *app, f sandboxRunFlags, x sandboxExtra) (sandboxResult, error) {
		for _, v := range append(append(slices.Clone(f.args), x.env...), x.placeholder, x.modelHost, x.modelConnection) {
			if strings.Contains(v, campaignKey) {
				t.Errorf("the key reached the agent's arguments or environment: %q", v)
			}
		}
		if x.placeholder == "" || !slices.Contains(x.env, "ANTHROPIC_API_KEY="+x.placeholder) || x.modelHost != "example.com" || x.modelConnection != "model-relay-1" {
			t.Errorf("the agent's model route: %+v", x)
		}
		_ = filepath.WalkDir(f.workspace, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				b, _ := os.ReadFile(p)
				if strings.Contains(string(b), campaignKey) {
					t.Errorf("the key reached the workspace: %s", p)
				}
				if strings.Contains(string(b), "${") {
					t.Errorf("%s is not filled in: %s", p, b)
				}
			}
			return nil
		})
		r.workspaces = append(r.workspaces, f.workspace)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, r.srv.relayURL+"/v1/messages", strings.NewReader(`{"messages":[]}`))
		req.Host = "example.com"
		req.Header.Set("X-Api-Key", x.placeholder)
		res, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			return sandboxResult{}, err
		}
		b, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		r.srv.mu.Lock()
		r.srv.bodies = append(r.srv.bodies, string(b))
		r.srv.mu.Unlock()
		routes := []sandbox.Route{{Kind: sandbox.RouteDirectAPI, Locator: "collector.attacker.example:443"}, {Kind: "other", Locator: "x"}}
		return sandboxResult{Run: "0192aaaa-bbbb-7ccc-8ddd-0000000000d1", Routes: routes, Code: 3}, &agentExitError{code: 3}
	}
}

func useFakeSandbox(t *testing.T, f func(context.Context, *app, sandboxRunFlags, sandboxExtra) (sandboxResult, error)) {
	t.Helper()
	old := campaignSandbox
	campaignSandbox = f
	t.Cleanup(func() { campaignSandbox = old })
}

// TestHR607_TheModelKeyStaysInTheRelay: the key from --model-key-file
// reaches the model host, through the relay, and nothing else: not the
// agent's arguments, environment or workspace, not the server, not the
// output. The agent holds a placeholder, which never reaches the host.
// Covers: F901
func TestHR607_TheModelKeyStaysInTheRelay(t *testing.T) {
	r := newCampaignRig(t)
	useFakeSandbox(t, r.fakeSandbox(t))
	code, out, errs := run(t, r.env, r.args("--only", "RT-140,RT-141")...)
	if code != 0 {
		t.Fatalf("campaign run = %d\n%s\n%s", code, out, errs)
	}
	if len(r.sawKey) != 2 || r.sawKey[0] != campaignKey || r.sawKey[1] != campaignKey {
		t.Fatalf("the model host saw keys %q, want the real key on both calls", r.sawKey)
	}
	if strings.Contains(out+errs, campaignKey) || strings.Contains(strings.Join(r.srv.bodies, ""), campaignKey) {
		t.Fatal("the key reached the output or an answer")
	}
	st, fin := r.srv.start, r.srv.finish
	if strings.Contains(st.String()+fin.String(), campaignKey) {
		t.Fatal("the key reached the server")
	}
	if !st.GetScripted() || st.GetModelHost() != "example.com" || st.GetRelayConnectionId() != relayConnID ||
		st.GetImageDigest() != "sha256:"+strings.Repeat("a", 64) || len(st.GetCampaigns()) != 2 || st.GetCampaigns()[0].GetId() != "RT-140" {
		t.Fatalf("StartCampaign %v", st)
	}
	// An agent's non-zero exit still counts its run; only edge route kinds
	// go to the server.
	if len(fin.GetRuns()) != 2 || fin.GetRuns()[1].GetScenarioId() != "RT-141" || len(fin.GetRuns()[0].GetRoutes()) != 1 {
		t.Fatalf("FinishCampaign %v", fin)
	}
	// Each scenario's step opened before its sandbox ran (D525 M1).
	if !slices.Equal(r.srv.steps, []string{"RT-140", "RT-141"}) {
		t.Fatalf("steps opened %v", r.srv.steps)
	}
	if !strings.Contains(out, "RT-140") || !strings.Contains(out, "HELD") || !strings.Contains(out, "range twin") {
		t.Fatalf("output %s", out)
	}
	for _, w := range r.workspaces {
		if _, err := os.Stat(w); !os.IsNotExist(err) {
			t.Errorf("campaign workspace %s left behind", w)
		}
	}
}

// TestHR607_AnAllowedAttemptFailsTheRun: an ALLOWED outcome exits 1 (the
// boundary did not hold); the campaign still finished.
// Covers: F901
func TestHR607_AnAllowedAttemptFailsTheRun(t *testing.T) {
	r := newCampaignRig(t)
	r.srv.outcome = pantherclawv1.CampaignOutcome_CAMPAIGN_OUTCOME_ALLOWED
	useFakeSandbox(t, r.fakeSandbox(t))
	if code, out, errs := run(t, r.env, r.args("--only", "RT-140")...); code != 1 || r.srv.finish == nil {
		t.Fatalf("campaign run = %d\n%s\n%s", code, out, errs)
	}
}

// TestHR607_ARunTooLargeAttemptFailsTheRun: a step past the server's bounds
// is a gap the agent under test can force, so it exits 1 too (D543 R-M2).
// Covers: F901
func TestHR607_ARunTooLargeAttemptFailsTheRun(t *testing.T) {
	r := newCampaignRig(t)
	r.srv.outcome = pantherclawv1.CampaignOutcome_CAMPAIGN_OUTCOME_NOT_EXERCISED
	r.srv.reason = "RUN_TOO_LARGE"
	useFakeSandbox(t, r.fakeSandbox(t))
	code, out, errs := run(t, r.env, r.args("--only", "RT-140")...)
	if code != 1 || r.srv.finish == nil || !strings.Contains(errs, "RUN_TOO_LARGE") {
		t.Fatalf("campaign run = %d\n%s\n%s", code, out, errs)
	}
}

// TestHR607_TheRunnerRefusesWhatWouldLeakTheKey: a remote gateway, a key
// file inside the workspace, a fixture that would set the canaries, and a
// connection that is not a model relay are refused before anything runs.
// Covers: F901
func TestHR607_TheRunnerRefusesWhatWouldLeakTheKey(t *testing.T) {
	r := newCampaignRig(t)
	useFakeSandbox(t, func(context.Context, *app, sandboxRunFlags, sandboxExtra) (sandboxResult, error) {
		t.Error("a sandbox ran")
		return sandboxResult{}, nil
	})
	for name, extra := range map[string][]string{
		"remote gateway":      {"--gateway", "https://gateway.example.com"},
		"public IP gateway":   {"--gateway", "http://8.8.8.8:8443"},
		"key in workspace":    {"--workspace", r.dir},
		"canary fixture":      {"--fixture", "canary_github_token=ghp_x"},
		"unpinned image":      {"--image", "agent:latest"},
		"unknown campaign id": {"--only", "RT-999"},
	} {
		if code, out, errs := run(t, r.env, r.args(extra...)...); code != 2 || r.srv.start != nil || len(r.sawKey) != 0 {
			t.Errorf("%s: code %d, started %v\n%s\n%s", name, code, r.srv.start != nil, out, errs)
		}
	}
	// The test provider's flags stay out of the help (D523).
	if _, _, errs := run(t, r.env, "redteam", "campaign", "run", "-h"); !strings.Contains(errs, "-model-key-file") ||
		strings.Contains(errs, "model-ca") || strings.Contains(errs, "model-dial") {
		t.Errorf("help shows the hidden flags or misses the others:\n%s", errs)
	}
	r.srv.relayURL = "https://203.0.113.1:443"
	if code, _, errs := run(t, r.env, r.args()...); code != 2 || r.srv.start != nil {
		t.Errorf("a relay off a private address: %d %s", code, errs)
	}
}

// TestHR607_TheKeyCannotReachTheWorkspaceThroughALink: a workspace that is a
// symbolic link to the key's directory, and a hard link to the key inside
// the workspace, are refused before anything runs; a symbolic link inside
// the workspace is skipped by the copy and reported (D525 M3).
// Covers: F901
func TestHR607_TheKeyCannotReachTheWorkspaceThroughALink(t *testing.T) {
	r := newCampaignRig(t)
	useFakeSandbox(t, func(context.Context, *app, sandboxRunFlags, sandboxExtra) (sandboxResult, error) {
		t.Error("a sandbox ran")
		return sandboxResult{}, nil
	})
	// A hard link needs no privilege, so it runs everywhere.
	hard := filepath.Join(t.TempDir(), "ws")
	if err := os.MkdirAll(filepath.Join(hard, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(r.keyFile, filepath.Join(hard, "sub", "notes.txt")); err != nil {
		t.Fatalf("hard link: %v", err)
	}
	r.refusesWorkspace(t, "hard link to the key", hard)
	linked := filepath.Join(t.TempDir(), "ws-link")
	if err := os.Symlink(r.dir, linked); err != nil {
		t.Skipf("symbolic links unavailable here (CI runs this on Linux): %v", err)
	}
	r.refusesWorkspace(t, "symlinked workspace", linked)
}

func (r *campaignRig) refusesWorkspace(t *testing.T, name, ws string) {
	t.Helper()
	code, out, errs := run(t, r.env, r.args("--workspace", ws)...)
	if code != 2 || r.srv.start != nil || len(r.sawKey) != 0 || !strings.Contains(errs, "inside --workspace") {
		t.Errorf("%s: code %d, started %v\n%s\n%s", name, code, r.srv.start != nil, out, errs)
	}
}

// TestHR607_TheWorkspaceCopySkipsLinks: the copy follows no symbolic link
// and says how many it skipped; regular files arrive.
// Covers: F901
func TestHR607_TheWorkspaceCopySkipsLinks(t *testing.T) {
	src, dst := t.TempDir(), filepath.Join(t.TempDir(), "ws")
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte(campaignKey), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "README.md"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(src, "leak")); err != nil {
		t.Skipf("symbolic links unavailable here: %v", err)
	}
	n, err := copyWorkspace(dst, src)
	if err != nil || n != 1 {
		t.Fatalf("copyWorkspace = %d, %v", n, err)
	}
	if b, err := os.ReadFile(filepath.Join(dst, "README.md")); err != nil || string(b) != "hello" {
		t.Fatalf("README %q %v", b, err)
	}
	if _, err := os.Lstat(filepath.Join(dst, "leak")); !os.IsNotExist(err) {
		t.Fatalf("the link was copied: %v", err)
	}
}
