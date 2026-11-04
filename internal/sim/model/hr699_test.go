// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package model

import (
	"bufio"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	"github.com/katocxl/pantherclaw/internal/gateway/simcheck"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/sim/payments"
)

func egressClient(t *testing.T, base string) *egress.Client {
	t.Helper()
	cl, err := egress.NewClient(base, 5*time.Second, 0, []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
	if err != nil {
		t.Fatal(err)
	}
	return cl
}

// TestHR699_TheFakeModelAnswersOnlyAsASimulator: the fake model answers the
// simulator handshake as kind "model", so the gateway verifies a simulated
// model connection to it, and every answer, reply, stream, error or refusal,
// carries Simulated: true; every reply and error text starts SIMULATED
// (G0 M29 D826).
//
// Covers: F985, HR-699
func TestHR699_TheFakeModelAnswersOnlyAsASimulator(t *testing.T) {
	f := newFixture(t)
	base := f.url + "/v1"
	if err := simcheck.New().VerifyKind(t.Context(), "conn", base, Kind, egressClient(t, f.url)); err != nil {
		t.Fatalf("the gateway's check refused the fake model: %v", err)
	}
	if err := simcheck.New().Verify(t.Context(), "conn", base, egressClient(t, f.url)); err != nil {
		t.Fatalf("the gateway's plain check refused the fake model: %v", err)
	}
	none := []string{"Anthropic-Version", anthropicVersion}
	for name, tc := range map[string]struct {
		method, path, body string
		hdr                []string
		text               bool // the answer carries text that must say SIMULATED
	}{
		"messages":        {"POST", "/v1/messages", `{"model":"m","max_tokens":5,"messages":[]}`, anthropicHdr(), true},
		"messages stream": {"POST", "/v1/messages", `{"model":"m","max_tokens":5,"stream":true,"messages":[]}`, anthropicHdr(), true},
		"messages tool":   {"POST", "/v1/messages", `{"model":"sim-tool","max_tokens":5,"messages":[]}`, anthropicHdr(), true},
		"messages error":  {"POST", "/v1/messages", `{"model":"sim-error","max_tokens":5,"messages":[]}`, anthropicHdr(), true},
		"messages 400":    {"POST", "/v1/messages", `{"model":"m","messages":[]}`, anthropicHdr(), true},
		"messages 401":    {"POST", "/v1/messages", `{}`, none, true},
		"count tokens":    {"POST", "/v1/messages/count_tokens", `{"model":"m","messages":[]}`, anthropicHdr(), false},
		"models a":        {"GET", "/v1/models", "", anthropicHdr(), true},
		"model a":         {"GET", "/v1/models/x", "", anthropicHdr(), true},
		"models o":        {"GET", "/v1/models", "", openaiHdr(), false},
		"chat":            {"POST", "/v1/chat/completions", `{"model":"m","messages":[]}`, openaiHdr(), true},
		"chat stream":     {"POST", "/v1/chat/completions", `{"model":"m","stream":true,"messages":[]}`, openaiHdr(), true},
		"chat tool":       {"POST", "/v1/chat/completions", `{"model":"sim-tool","messages":[]}`, openaiHdr(), true},
		"chat error":      {"POST", "/v1/chat/completions", `{"model":"sim-error","messages":[]}`, openaiHdr(), true},
		"chat 401":        {"POST", "/v1/chat/completions", `{}`, nil, true},
		"responses":       {"POST", "/v1/responses", `{"model":"m","input":"x"}`, openaiHdr(), true},
		"responses strm":  {"POST", "/v1/responses", `{"model":"m","stream":true,"input":"x"}`, openaiHdr(), true},
		"responses error": {"POST", "/v1/responses", `{"model":"sim-error","input":"x"}`, openaiHdr(), true},
		"unknown route":   {"GET", "/v1/files", "", openaiHdr(), true},
		"stats":           {"GET", "/__sim/stats", "", nil, false},
	} {
		res := f.do(tc.method, tc.path, tc.body, tc.hdr...)
		raw, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if res.Header.Get("Simulated") != "true" {
			t.Errorf("%s: no Simulated: true", name)
		}
		if tc.text && !regexp.MustCompile(`"(text|message|display_name|content)":"SIMULATED`).Match(raw) {
			t.Errorf("%s: no text starting SIMULATED: %s", name, raw)
		}
		stream := strings.HasPrefix(res.Header.Get("Content-Type"), "text/event-stream")
		if stream {
			evs, err := readSSE(t, strings.NewReader(string(raw)))
			if err != nil || !strings.HasPrefix(text(t, evs), "SIMULATED") {
				t.Errorf("%s: the streamed text does not start SIMULATED: %v", name, err)
			}
		} else if tc.text && regexp.MustCompile(`"(text|message|display_name|content)":"[^S]`).Match(raw) {
			t.Errorf("%s: a text not starting SIMULATED: %s", name, raw)
		}
	}
}

// baseURLLine is a line that sets a connection base URL; realProvider is a
// real provider's API as a URL (an agent host, a bare name, is fine).
var (
	baseURLLine  = regexp.MustCompile(`(?i)base[_-]?url`)
	realProvider = regexp.MustCompile(`https://api\.(anthropic|openai)\.com`)
)

// realBaseURL reports whether a line uses a real model provider as a
// connection base URL.
func realBaseURL(line string) bool {
	return baseURLLine.MatchString(line) && realProvider.MatchString(line)
}

// TestHR699_NoTestUsesARealProviderAsABaseURL: no file under test/, redteam/
// or any testdata directory points a connection's base URL at
// https://api.anthropic.com or https://api.openai.com; tests, scenarios and
// fixtures use the fake model (G0 M29 D804, D826). An agent host (the bare
// name an agent dials through the edge) is fine.
//
// Covers: F985, HR-699, T-319
func TestHR699_NoTestUsesARealProviderAsABaseURL(t *testing.T) {
	for line, want := range map[string]bool{
		`base_url: https://api.anthropic.com/v1`:                        true,
		`	BaseURL: "https://api.openai.com/v1",`:                        true,
		`pclaw connections create --base-url https://api.openai.com/v1`: true,
		`OPENAI_BASE_URL=https://api.openai.com/v1`:                     true,
		`base_url: http://127.0.0.1:9103/v1`:                            false,
		`agent_hosts: [api.anthropic.com, api.openai.com]`:              false,
		`curl https://api.anthropic.com/v1/messages`:                    false,
	} {
		if realBaseURL(line) != want {
			t.Fatalf("realBaseURL(%q) != %v", line, want)
		}
	}
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repository root not found at %s: %v", root, err)
	}
	scanned := 0
	scan := func(dir string) {
		err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			fh, err := os.Open(p)
			if err != nil {
				return err
			}
			defer func() { _ = fh.Close() }()
			scanned++
			sc := bufio.NewScanner(fh)
			sc.Buffer(nil, 16<<20)
			for n := 1; sc.Scan(); n++ {
				if realBaseURL(sc.Text()) {
					rel, _ := filepath.Rel(root, p)
					t.Errorf("%s:%d uses a real model provider as a base URL", filepath.ToSlash(rel), n)
				}
			}
			return nil
		})
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			t.Fatal(err)
		}
	}
	scan(filepath.Join(root, "test"))
	scan(filepath.Join(root, "redteam"))
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return err
		}
		switch d.Name() {
		case ".git", "node_modules", ".claude":
			return filepath.SkipDir
		case "testdata":
			if rel, _ := filepath.Rel(root, p); !strings.HasPrefix(filepath.ToSlash(rel), "test/") && !strings.HasPrefix(filepath.ToSlash(rel), "redteam/") {
				scan(p)
			}
			return filepath.SkipDir
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned == 0 {
		t.Fatal("no file scanned")
	}
}

// TestT319_ASimulatedModelConnectionNeverReachesARealProvider: the gateway's
// simulator check, which every simulated connection passes before a request
// is sent, refuses a real provider's host before dialing it and refuses a
// target that answers as another simulator, so a test's model call reaches
// the fake model or nothing (G0 M29 D826).
//
// Covers: F985, HR-699, T-319
func TestT319_ASimulatedModelConnectionNeverReachesARealProvider(t *testing.T) {
	for _, base := range []string{"https://api.anthropic.com/v1", "https://api.openai.com/v1", "https://8.8.8.8/v1"} {
		if _, err := simcheck.LocalLiteral(base); !errors.Is(err, simcheck.ErrUnverified) {
			t.Errorf("%s passed the literal check: %v", base, err)
		}
		if err := simcheck.New().VerifyKind(t.Context(), "conn", base, Kind, egressClient(t, "http://127.0.0.1:1")); !errors.Is(err, simcheck.ErrUnverified) {
			t.Errorf("%s passed the check: %v", base, err)
		}
	}
	other := httptest.NewServer(payments.New(payments.Faults{}, pclog.Discard()).Handler())
	defer other.Close()
	if err := simcheck.New().VerifyKind(t.Context(), "conn", other.URL+"/v1", Kind, egressClient(t, other.URL)); !errors.Is(err, simcheck.ErrUnverified) {
		t.Fatalf("a payments simulator passed as the fake model: %v", err)
	}
	notSim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"simulator":"pantherclaw-sim","kind":"model","nonce":"x"}`)
	}))
	defer notSim.Close()
	if err := simcheck.New().VerifyKind(t.Context(), "conn", notSim.URL+"/v1", Kind, egressClient(t, notSim.URL)); !errors.Is(err, simcheck.ErrUnverified) {
		t.Fatalf("a server that is not a simulator passed: %v", err)
	}
	f := newFixture(t)
	if err := simcheck.New().VerifyKind(t.Context(), "conn", f.url+"/v1", Kind, egressClient(t, f.url)); err != nil {
		t.Fatalf("the fake model failed the check: %v", err)
	}
}
