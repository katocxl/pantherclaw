// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bytes"
	"context"
	"encoding/base64"
	binenc "encoding/binary"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// The extension ids the M33 host tests configure and refuse.
const (
	extOK    = "abcdefghijklmnopabcdefghijklmnop"
	extOther = "ponmlkjihgfedcbaponmlkjihgfedcba"
)

// browserHookFake is the gateway's /hook/{connection} face for the browser
// tools: it allows browser_navigate, holds browser_takeover, denies
// browser_submit and stalls on browser_download.
type browserHookFake struct {
	*httptest.Server
	mu   sync.Mutex
	reqs []*http.Request
	body []map[string]any
}

func newBrowserHookFake(t *testing.T) *browserHookFake {
	t.Helper()
	f := &browserHookFake{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &req)
		req["path"] = r.URL.Path
		f.mu.Lock()
		f.reqs, f.body = append(f.reqs, r), append(f.body, req)
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch req["tool"] {
		case "browser_navigate":
			_, _ = io.WriteString(w, `{"decision":"allow","reason":"allowed","transaction_id":"t-1"}`)
		case "browser_takeover":
			_, _ = io.WriteString(w, `{"decision":"deny","held":true,"code":"BROWSER_TAKEOVER","reason":"held for a person","transaction_id":"t-2"}`)
		case "browser_download":
			time.Sleep(500 * time.Millisecond)
			_, _ = io.WriteString(w, `{"decision":"allow","reason":"too late"}`)
		default:
			_, _ = io.WriteString(w, `{"decision":"deny","code":"BROWSER_SECRET_FIELD","reason":"a person submits this form"}`)
		}
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *browserHookFake) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.reqs)
}

// frame is one Chrome native message: a uint32 little-endian length and
// the JSON.
func frame(t *testing.T, v any) []byte {
	t.Helper()
	b, ok := v.([]byte)
	if !ok {
		var err error
		if b, err = json.Marshal(v); err != nil {
			t.Fatal(err)
		}
	}
	var n [4]byte
	binenc.LittleEndian.PutUint32(n[:], uint32(len(b)))
	return append(n[:], b...)
}

// replies reads every framed reply, keyed by its id.
func replies(t *testing.T, out []byte) map[string]map[string]any {
	t.Helper()
	got := map[string]map[string]any{}
	r := bytes.NewReader(out)
	for r.Len() > 0 {
		var n uint32
		if err := binenc.Read(r, binenc.LittleEndian, &n); err != nil {
			t.Fatalf("frame length: %v", err)
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(r, b); err != nil {
			t.Fatalf("frame body: %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("reply %q: %v", b, err)
		}
		got[m["id"].(string)] = m
	}
	return got
}

// syncBuf is a buffer the host's goroutines write and the test reads.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) Bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.b.Bytes())
}

func (s *syncBuf) String() string { return string(s.Bytes()) }

func (s *syncBuf) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.b.Reset()
}

// testBrowserHost returns a host's state for gateway, with a workload
// token in memory (ten minutes left) so it signs without the server.
func testBrowserHost(t *testing.T, gateway string) (*browserHostState, *syncBuf, *syncBuf) {
	t.Helper()
	keyFile, _, run := proxyFiles(t)
	enc := base64.RawURLEncoding.EncodeToString
	tok := enc([]byte(`{"alg":"EdDSA"}`)) + "." + enc([]byte(`{"exp":`+itoa(time.Now().Add(10*time.Minute).Unix())+`}`)) + ".sig"
	out, errb := &syncBuf{}, &syncBuf{}
	a := &app{stdout: out, stderr: errb, env: envOf(nil), http: &http.Client{}}
	h := &browserHostState{a: a, out: out, token: tok, cfg: browserHostConfig{
		Gateway: gateway, Connection: "browser", KeyFile: keyFile, Run: run, ExtensionIDs: []string{extOK},
	}}
	return h, out, errb
}

// serveFrames runs the host on in with stdin kept open (as Chrome keeps
// the port open) until want replies are written, then closes stdin and
// waits for the host to exit. It returns the replies.
func serveFrames(t *testing.T, h *browserHostState, out *syncBuf, in []byte, want int) map[string]map[string]any {
	t.Helper()
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- h.serve(context.Background(), pr) }()
	go func() { _, _ = pw.Write(in) }()
	deadline := time.Now().Add(10 * time.Second)
	for len(replies(t, out.Bytes())) < want && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	_ = pw.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the host did not exit on stdin EOF")
	}
	return replies(t, out.Bytes())
}

func decideMsg(id, tool, action string, input any) map[string]any {
	m := map[string]any{"v": 1, "id": id, "type": "decide", "tool": tool, "input": input}
	if action != "" {
		m["action_id"] = action
	}
	return m
}

// hostConfigFile writes a host configuration file with mode.
func hostConfigFile(t *testing.T, mode os.FileMode) string {
	t.Helper()
	keyFile, _, run := proxyFiles(t)
	b, _ := json.Marshal(browserHostConfig{Gateway: "http://127.0.0.1:1", Connection: "browser", KeyFile: keyFile, Run: run, ExtensionIDs: []string{extOK}})
	p := filepath.Join(t.TempDir(), "host-config.json")
	if err := writeFileMode(p, b, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func runHost(t *testing.T, stdin []byte, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Run(context.Background(), append([]string{"browser", "host"}, args...), &out, &errb, envOf(nil), Options{Stdin: bytes.NewReader(stdin)})
	return code, out.String(), errb.String()
}

// TestHR753_TheHostServesOnlyAConfiguredExtension: Chrome starts the host
// with the caller's origin; a configured chrome-extension://<id>/ is
// served until stdin ends (exit 0), and any other origin, or none, exits 1
// with nothing on stdout.
func TestHR753_TheHostServesOnlyAConfiguredExtension(t *testing.T) {
	cfg := hostConfigFile(t, 0o600)
	if code, out, errs := runHost(t, nil, "--config", cfg, "chrome-extension://"+extOK+"/", "--parent-window=0"); code != 0 || out != "" {
		t.Fatalf("configured origin, empty stdin = %d %q %q", code, out, errs)
	}
	for name, args := range map[string][]string{
		"other extension": {"--config", cfg, "chrome-extension://" + extOther + "/"},
		"no slash":        {"--config", cfg, "chrome-extension://" + extOK},
		"no origin":       {"--config", cfg},
	} {
		stdin := frame(t, map[string]any{"v": 1, "id": ids.NewV7().String(), "type": "status"})
		code, out, errs := runHost(t, stdin, args...)
		if code != 1 || out != "" || !strings.Contains(errs, "not a configured extension") {
			t.Errorf("%s = %d %q %q", name, code, out, errs)
		}
	}
	if code, out, _ := runHost(t, nil, "chrome-extension://"+extOK+"/"); code == 0 || out != "" {
		t.Errorf("no --config = %d %q", code, out)
	}
}

// TestHR753_TheHostRefusesAConfigurationOthersCanRead: on unix a host
// configuration group or others can read is refused (it names the key
// file); a 0600 one is read.
func TestHR753_TheHostRefusesAConfigurationOthersCanRead(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix file modes")
	}
	if _, err := readBrowserHostConfig(hostConfigFile(t, 0o600)); err != nil {
		t.Fatalf("0600: %v", err)
	}
	for _, mode := range []os.FileMode{0o640, 0o604} {
		if _, err := readBrowserHostConfig(hostConfigFile(t, mode)); err == nil || !strings.Contains(err.Error(), "chmod 600") {
			t.Errorf("%o: %v", mode, err)
		}
		code, out, _ := runHost(t, nil, "--config", hostConfigFile(t, mode), "chrome-extension://"+extOK+"/")
		if code != 1 || out != "" {
			t.Errorf("%o: run = %d %q", mode, code, out)
		}
	}
}

// TestHR753_EachDecideIsOneSignedHookCall: a decide message becomes one
// PAP/1 hook call on the configured connection with its tool, its input
// as sent and the action id as PC-Action-Id; the gateway's allow, hold and
// deny come back as they were answered, and a hold is a deny with held.
func TestHR753_EachDecideIsOneSignedHookCall(t *testing.T) {
	f := newBrowserHookFake(t)
	h, out, _ := testBrowserHost(t, f.URL)
	act := ids.NewV7().String()
	nav, held, deny := ids.NewV7().String(), ids.NewV7().String(), ids.NewV7().String()
	in := append(frame(t, decideMsg(nav, "browser_navigate", act, map[string]any{"url": "https://docs.example.com/a", "call": "c-1"})),
		frame(t, decideMsg(held, "browser_takeover", "", map[string]any{"page_url": "https://docs.example.com/", "minutes": 10, "call": "c-2"}))...)
	in = append(in, frame(t, decideMsg(deny, "browser_submit", "", map[string]any{"url": "https://docs.example.com/f", "secret_fields": true, "call": "c-3"}))...)
	got := serveFrames(t, h, out, in, 3)
	if r := got[nav]; r["decision"] != "allow" || r["held"] != false || r["transaction_id"] != "t-1" || r["v"] != float64(1) {
		t.Errorf("allow reply %v", r)
	}
	if r := got[held]; r["decision"] != "deny" || r["held"] != true || r["code"] != "BROWSER_TAKEOVER" || r["transaction_id"] != "t-2" {
		t.Errorf("held reply %v", r)
	}
	if r := got[deny]; r["decision"] != "deny" || r["held"] != false || r["code"] != "BROWSER_SECRET_FIELD" {
		t.Errorf("deny reply %v", r)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.reqs) != 3 {
		t.Fatalf("%d hook calls, want 3", len(f.reqs))
	}
	for i, b := range f.body {
		r := f.reqs[i]
		if b["path"] != "/hook/browser" || r.Header.Get("PAP-Run-Id") != h.cfg.Run || r.Header.Get("PAP-Proof") == "" ||
			!strings.HasPrefix(r.Header.Get("Authorization"), "PAP ") || r.Header.Get("Origin") != "" {
			t.Errorf("call %d: %v %v", i, b, r.Header)
		}
		input, _ := b["input"].(map[string]any)
		switch b["tool"] {
		case "browser_navigate":
			if r.Header.Get(headerActionID) != act || input["url"] != "https://docs.example.com/a" || input["call"] != "c-1" {
				t.Errorf("navigate call %v %v", b, r.Header)
			}
		default:
			if r.Header.Get(headerActionID) != "" {
				t.Errorf("%v: an action id that was not sent", b["tool"])
			}
		}
	}
}

// TestHR753_AnyErrorIsADenyWithCannotDecide: a tool that is not a browser
// tool, an input over 64 KiB or not an object, an action id that is not a
// UUID, an unreachable gateway and a call past the deadline are each a
// deny with CANNOT_DECIDE; the first four never reach the gateway.
func TestHR753_AnyErrorIsADenyWithCannotDecide(t *testing.T) {
	f := newBrowserHookFake(t)
	h, out, _ := testBrowserHost(t, f.URL)
	old := browserHostDeadline
	browserHostDeadline = 100 * time.Millisecond
	t.Cleanup(func() { browserHostDeadline = old })
	big := map[string]any{"url": "https://docs.example.com/", "call": "c", "pad": strings.Repeat("x", 64<<10)}
	cases := map[string]map[string]any{
		"shell tool":    decideMsg(ids.NewV7().String(), "shell", "", map[string]any{"command": "ls"}),
		"big input":     decideMsg(ids.NewV7().String(), "browser_navigate", "", big),
		"array input":   decideMsg(ids.NewV7().String(), "browser_navigate", "", []any{1}),
		"bad action id": decideMsg(ids.NewV7().String(), "browser_navigate", "not-a-uuid", map[string]any{"url": "https://docs.example.com/"}),
	}
	var in []byte
	for _, m := range cases {
		in = append(in, frame(t, m)...)
	}
	got := serveFrames(t, h, out, in, len(cases))
	for name, m := range cases {
		if r := got[m["id"].(string)]; r["decision"] != "deny" || r["code"] != browserCannotDecide || !strings.Contains(r["reason"].(string), "cannot decide") {
			t.Errorf("%s: %v", name, r)
		}
	}
	if n := f.calls(); n != 0 {
		t.Errorf("%d calls reached the gateway", n)
	}
	// The gateway stalls past the deadline.
	out.Reset()
	slow := ids.NewV7().String()
	if r := serveFrames(t, h, out, frame(t, decideMsg(slow, "browser_download", "", map[string]any{"url": "https://docs.example.com/f.zip"})), 1)[slow]; r["decision"] != "deny" ||
		r["code"] != browserCannotDecide || !strings.Contains(r["reason"].(string), "deadline") {
		t.Errorf("past the deadline: %v", r)
	}
	// Nothing listens at the gateway.
	down := httptest.NewServer(http.NotFoundHandler())
	down.Close()
	h2, out2, _ := testBrowserHost(t, down.URL)
	gone := ids.NewV7().String()
	if r := serveFrames(t, h2, out2, frame(t, decideMsg(gone, "browser_navigate", "", map[string]any{"url": "https://docs.example.com/"})), 1)[gone]; r["decision"] != "deny" || r["code"] != browserCannotDecide {
		t.Errorf("unreachable: %v", r)
	}
}

// TestHR753_TheHostBoundsItsChannelAndNeverLogsInput: a malformed message
// or one without a valid id is ignored with a line on stderr and no reply;
// a message over 1 MiB closes the host, so nothing after it is answered;
// the input's content never reaches stderr.
func TestHR753_TheHostBoundsItsChannelAndNeverLogsInput(t *testing.T) {
	f := newBrowserHookFake(t)
	h, out, errb := testBrowserHost(t, f.URL)
	const secret = "hunter2-do-not-log"
	ok := ids.NewV7().String()
	in := frame(t, []byte(`{"v":1,"id":`))
	in = append(in, frame(t, map[string]any{"v": 2, "id": ids.NewV7().String(), "type": "status"})...)
	in = append(in, frame(t, decideMsg("not-an-id", "browser_navigate", "", map[string]any{"url": "https://x.example.com/?q=" + secret}))...)
	in = append(in, frame(t, map[string]any{"v": 1, "id": ids.NewV7().String(), "type": "other", "input": secret})...)
	in = append(in, frame(t, decideMsg(ok, "browser_navigate", "", map[string]any{"url": "https://docs.example.com/?q=" + secret, "call": "c"}))...)
	got := serveFrames(t, h, out, in, 1)
	if len(got) != 1 || got[ok]["decision"] != "allow" {
		t.Fatalf("replies %v, want only the valid decide", got)
	}
	errs := errb.String()
	if strings.Count(errs, "ignored") != 4 || strings.Contains(errs, secret) {
		t.Errorf("stderr %q", errs)
	}
	if f.calls() != 1 {
		t.Errorf("%d hook calls, want 1", f.calls())
	}

	// A length over 1 MiB closes the host while stdin stays open, and the
	// message after it is not answered.
	out.Reset()
	var n [4]byte
	binenc.LittleEndian.PutUint32(n[:], browserHostMaxIn+1)
	after := ids.NewV7().String()
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })
	go func() {
		_, _ = pw.Write(n[:])
		_, _ = pw.Write(frame(t, decideMsg(after, "browser_navigate", "", map[string]any{"url": "https://docs.example.com/"})))
	}()
	done := make(chan error, 1)
	go func() { done <- h.serve(context.Background(), pr) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("an oversized message did not close the host")
	}
	if len(out.Bytes()) != 0 || !strings.Contains(errb.String(), "over 1 MiB") || f.calls() != 1 {
		t.Errorf("after an oversized message: out %q, stderr %q, %d calls", out.Bytes(), errb.String(), f.calls())
	}
}

// TestHR753_StatusSaysWhetherTheHostCanSign: status is ok with a readable
// key file, a run and a token at hand, and not ok when the key file
// cannot be read.
func TestHR753_StatusSaysWhetherTheHostCanSign(t *testing.T) {
	h, out, _ := testBrowserHost(t, "http://127.0.0.1:1")
	id := ids.NewV7().String()
	if r := serveFrames(t, h, out, frame(t, map[string]any{"v": 1, "id": id, "type": "status"}), 1)[id]; r["ok"] != true || r["connection"] != "browser" || r["run"] != h.cfg.Run {
		t.Errorf("status %v", r)
	}
	out.Reset()
	h.cfg.KeyFile = filepath.Join(t.TempDir(), "missing.json")
	if r := serveFrames(t, h, out, frame(t, map[string]any{"v": 1, "id": id, "type": "status"}), 1)[id]; r["ok"] != false || !strings.Contains(r["reason"].(string), "key file") {
		t.Errorf("status without a key file %v", r)
	}
}

// installRecorder replaces the registration with one that records what
// would be registered.
type installRecorder struct {
	dir      string
	browsers []string
	system   bool
	manifest []byte
}

func recordInstall(t *testing.T) *installRecorder {
	t.Helper()
	r := &installRecorder{}
	old := registerBrowserHostFn
	registerBrowserHostFn = func(dir string, browsers []string, system bool, manifest []byte) ([]string, error) {
		r.dir, r.browsers, r.system, r.manifest = dir, browsers, system, manifest
		return []string{filepath.Join(dir, browserHostName+".json")}, nil
	}
	t.Cleanup(func() { registerBrowserHostFn = old })
	cfg := t.TempDir()
	t.Setenv("AppData", cfg)
	t.Setenv("XDG_CONFIG_HOME", cfg)
	t.Setenv("HOME", cfg)
	return r
}

// TestHR753_InstallHostWritesAPrivateConfigurationAndOnlyTheGivenIDs:
// install-host writes the configuration (0600 on unix), a wrapper that
// starts `pclaw browser host --config` with it, and a manifest whose
// allowed origins are exactly the given extension ids.
func TestHR753_InstallHostWritesAPrivateConfigurationAndOnlyTheGivenIDs(t *testing.T) {
	r := recordInstall(t)
	keyFile, _, run := proxyFiles(t)
	code, out, errs := runArgs(t, "browser", "install-host", "--gateway", "https://gw.example.test", "--connection", "browser",
		"--key-file", keyFile, "--extension-id", extOK, "--extension-id", extOther, "--run", run, "--browser", "chrome")
	if code != 0 {
		t.Fatalf("install-host = %d %q %q", code, out, errs)
	}
	cfgPath := filepath.Join(r.dir, "host-config.json")
	cfg, err := readBrowserHostConfig(cfgPath)
	if err != nil || cfg.Gateway != "https://gw.example.test" || cfg.Connection != "browser" || cfg.Run != run ||
		!slices.Equal(cfg.ExtensionIDs, []string{extOK, extOther}) || !filepath.IsAbs(cfg.KeyFile) {
		t.Fatalf("configuration %+v, %v", cfg, err)
	}
	if fi, _ := os.Stat(cfgPath); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("configuration mode %o", fi.Mode().Perm())
	}
	var m browserHostManifest
	if err := json.Unmarshal(r.manifest, &m); err != nil {
		t.Fatal(err)
	}
	if m.Name != browserHostName || m.Type != "stdio" ||
		!slices.Equal(m.AllowedOrigins, []string{"chrome-extension://" + extOK + "/", "chrome-extension://" + extOther + "/"}) ||
		!slices.Equal(r.browsers, []string{"chrome"}) || r.system {
		t.Fatalf("manifest %+v, browsers %v system %v", m, r.browsers, r.system)
	}
	w, err := os.ReadFile(m.Path)
	if err != nil {
		t.Fatal(err)
	}
	exe, _ := os.Executable()
	exe, _ = filepath.Abs(exe)
	want := `exec "` + exe + `" browser host --config "` + cfgPath + `" "$@"`
	if runtime.GOOS == "windows" {
		want = `@"` + exe + `" browser host --config "` + cfgPath + `" %*`
	}
	if !strings.Contains(string(w), want) {
		t.Errorf("wrapper %q, want %q", w, want)
	}
}

// TestHR753_InstallHostRefusesBadInput: an extension id that is not one,
// an http gateway that is not localhost, a run that is not a UUID, an
// unknown browser and a missing key file are refused, and nothing is
// registered.
func TestHR753_InstallHostRefusesBadInput(t *testing.T) {
	r := recordInstall(t)
	keyFile, _, _ := proxyFiles(t)
	base := []string{"browser", "install-host", "--connection", "browser"}
	for name, args := range map[string][]string{
		"bad id":       {"--gateway", "https://gw.example.test", "--key-file", keyFile, "--extension-id", "not-an-id"},
		"http gateway": {"--gateway", "http://gw.example.test", "--key-file", keyFile, "--extension-id", extOK},
		"bad run":      {"--gateway", "https://gw.example.test", "--key-file", keyFile, "--extension-id", extOK, "--run", "r1"},
		"bad browser":  {"--gateway", "https://gw.example.test", "--key-file", keyFile, "--extension-id", extOK, "--browser", "firefox"},
		"no key file":  {"--gateway", "https://gw.example.test", "--key-file", filepath.Join(t.TempDir(), "none"), "--extension-id", extOK},
		"no id":        {"--gateway", "https://gw.example.test", "--key-file", keyFile},
	} {
		if code, _, _ := runArgs(t, append(slices.Clone(base), args...)...); code == 0 {
			t.Errorf("%s accepted", name)
		}
	}
	if r.manifest != nil {
		t.Errorf("registered %s", r.manifest)
	}
}

func runArgs(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	return run(t, envOf(nil), args...)
}

// browserSitesFake is a BrowserService.
type browserSitesFake struct {
	pantherclawv1connect.UnimplementedBrowserServiceHandler
	sites []*pb.BrowserSite
	add   *pb.AddBrowserSiteRequest
	rm    *pb.RemoveBrowserSiteRequest
}

func (f *browserSitesFake) ListBrowserSites(context.Context, *pb.ListBrowserSitesRequest) (*pb.ListBrowserSitesResponse, error) {
	return &pb.ListBrowserSitesResponse{Sites: f.sites}, nil
}

func (f *browserSitesFake) AddBrowserSite(_ context.Context, req *pb.AddBrowserSiteRequest) (*pb.AddBrowserSiteResponse, error) {
	f.add = req
	return &pb.AddBrowserSiteResponse{ProtectedChangeId: "pch-1"}, nil
}

func (f *browserSitesFake) RemoveBrowserSite(_ context.Context, req *pb.RemoveBrowserSiteRequest) (*pb.RemoveBrowserSiteResponse, error) {
	f.rm = req
	return &pb.RemoveBrowserSiteResponse{}, nil
}

func browserServer(t *testing.T, f *browserSitesFake) Env {
	t.Helper()
	cs := connect.NewServer()
	pantherclawv1connect.RegisterBrowserServiceHandler(cs, f)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return envOf(map[string]string{"PANTHERCLAW_SERVER": ts.URL, "PANTHERCLAW_API_KEY": "pck_test_x"})
}

// TestHR755_ThePolicyGeneratorOnlyWritesTwoFiles: the generator writes
// chrome-policy.json and chrome-policy.reg and nothing else: the extension
// force-installed and pinned, incognito (1) and guest mode off, and the
// managed configuration with the host name and the click rules of the
// sites that have selectors.
func TestHR755_ThePolicyGeneratorOnlyWritesTwoFiles(t *testing.T) {
	env := browserServer(t, &browserSitesFake{sites: []*pb.BrowserSite{
		{Host: "docs.example.com", IncludeSubdomains: true, ClickSelectors: []string{"button.buy", `a[href="/delete"]`}},
		{Host: "plain.example.com"},
	}})
	dir := filepath.Join(t.TempDir(), "out")
	code, out, errs := run(t, env, "browser", "policy", "generate", "--extension-id", extOK, "--update-url", "https://ext.example.test/update.xml", "--out", dir)
	if code != 0 || !strings.Contains(out, "Nothing is installed") {
		t.Fatalf("generate = %d %q %q", code, out, errs)
	}
	entries, _ := os.ReadDir(dir)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if !slices.Equal(names, []string{"chrome-policy.json", "chrome-policy.reg"}) {
		t.Fatalf("wrote %v", names)
	}
	var p struct {
		Settings  map[string]chromeInstall `json:"ExtensionSettings"`
		Incognito int                      `json:"IncognitoModeAvailability"`
		Guest     *bool                    `json:"BrowserGuestModeEnabled"`
		Third     struct {
			Extensions map[string]chromeExtensionPolicy `json:"extensions"`
		} `json:"3rdparty"`
	}
	b, _ := os.ReadFile(filepath.Join(dir, "chrome-policy.json"))
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	inst := p.Settings[extOK]
	ext := p.Third.Extensions[extOK]
	if len(p.Settings) != 1 || inst.InstallationMode != "force_installed" || inst.ToolbarPin != "force_pinned" ||
		inst.UpdateURL != "https://ext.example.test/update.xml" || p.Incognito != 1 || p.Guest == nil || *p.Guest ||
		ext.HostName != browserHostName || len(ext.ClickRules) != 1 || ext.ClickRules[0].Host != "docs.example.com" ||
		!ext.ClickRules[0].IncludeSubdomains || len(ext.ClickRules[0].Selectors) != 2 {
		t.Fatalf("policy %s", b)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "chrome-policy.reg"))
	if len(raw) < 2 || raw[0] != 0xFF || raw[1] != 0xFE {
		t.Fatalf("reg without a UTF-16LE BOM")
	}
	u := make([]uint16, 0, len(raw)/2)
	for i := 2; i+1 < len(raw); i += 2 {
		u = append(u, uint16(raw[i])|uint16(raw[i+1])<<8)
	}
	reg := string(utf16.Decode(u))
	for _, want := range []string{
		`[HKEY_LOCAL_MACHINE\Software\Policies\Google\Chrome]`,
		`"IncognitoModeAvailability"=dword:00000001`, `"BrowserGuestModeEnabled"=dword:00000000`,
		`\3rdparty\extensions\` + extOK + `\policy]`, `"host_name"="dev.pantherclaw.browser"`,
		`\"installation_mode\":\"force_installed\"`, `\"toolbar_pin\":\"force_pinned\"`, `a[href=\\\"/delete\\\"]`,
	} {
		if !strings.Contains(reg, want) {
			t.Errorf("reg lacks %q:\n%s", want, reg)
		}
	}
}

// TestHR755_ThePolicyGeneratorRefusesBadInput: an id that is not one, an
// update URL that is not https and a bad host name are refused before
// anything is written.
func TestHR755_ThePolicyGeneratorRefusesBadInput(t *testing.T) {
	env := browserServer(t, &browserSitesFake{})
	for name, args := range map[string][]string{
		"bad id":      {"--extension-id", "x", "--update-url", "https://ext.example.test/u.xml"},
		"http update": {"--extension-id", extOK, "--update-url", "http://ext.example.test/u.xml"},
		"bad host":    {"--extension-id", extOK, "--update-url", "https://ext.example.test/u.xml", "--host-name", "Bad Name"},
	} {
		dir := filepath.Join(t.TempDir(), "out")
		code, _, _ := run(t, env, append([]string{"browser", "policy", "generate", "--out", dir}, args...)...)
		if _, err := os.Stat(dir); code == 0 || err == nil {
			t.Errorf("%s: %d, out dir written: %v", name, code, err == nil)
		}
	}
}

// TestHR749_SiteCommandsSendTheirFlags: `pclaw browser sites add` sends
// the host, subdomains, compare, selectors, note and reason, and says a
// second person confirms it; remove sends the id and reason; an extra
// argument is refused.
func TestHR749_SiteCommandsSendTheirFlags(t *testing.T) {
	f := &browserSitesFake{}
	env := browserServer(t, f)
	code, _, errs := run(t, env, "browser", "sites", "add", "--host", "docs.example.com", "--subdomains", "--compare",
		"--selector", "button.buy", "--selector", "a.del", "--note", "n", "--reason", "r")
	if code != 0 || !strings.Contains(errs, "second person") || f.add.GetHost() != "docs.example.com" || !f.add.GetIncludeSubdomains() ||
		!f.add.GetCompare() || !slices.Equal(f.add.GetClickSelectors(), []string{"button.buy", "a.del"}) || f.add.GetNote() != "n" || f.add.GetReason() != "r" {
		t.Fatalf("add = %d %q, sent %v", code, errs, f.add)
	}
	if code, _, errs := run(t, env, "browser", "sites", "remove", "s1", "--reason", "gone"); code != 0 || f.rm.GetId() != "s1" || f.rm.GetReason() != "gone" {
		t.Fatalf("remove = %d %q, sent %v", code, errs, f.rm)
	}
	f.add = nil
	if code, _, _ := run(t, env, "browser", "sites", "add", "--host", "docs.example.com", "extra"); code == 0 || f.add != nil {
		t.Fatalf("extra argument = %d, sent %v", code, f.add)
	}
}
