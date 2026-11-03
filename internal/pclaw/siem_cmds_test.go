// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	ndomain "github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/siem/ocsf"
)

// lockedBuffer is a stdout or stderr read while the command runs.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

var (
	fwdSecret   = []byte("pclaw-siem-forward-test-secret-0123456789")
	fwdListenRe = regexp.MustCompile(`"event":"siem.forward.listening".*?"addr":"([^"]+)"`)
)

const fwdMarker = "FWD-BODY-MARKER-91c2"

// fwdBatch is an export batch of two events, each carrying the marker, and
// the NDJSON it should become.
func fwdBatch(t *testing.T, id string) ([]byte, string) {
	t.Helper()
	var b ocsf.Builder
	var want strings.Builder
	for i := range 2 {
		enc := []byte(`{"class_uid":2004,"message":"` + fwdMarker + `","metadata":{"uid":"` + id + "-" + strconv.Itoa(i) + `"}}`)
		if ok, err := b.Add(enc); !ok || err != nil {
			t.Fatalf("add: %v %v", ok, err)
		}
		want.Write(enc)
		want.WriteByte('\n')
	}
	body, err := b.Body(id, 0, 2)
	if err != nil {
		t.Fatal(err)
	}
	return body, want.String()
}

// startForward runs `pclaw siem forward` until the test ends and returns
// the address it listens on.
func startForward(t *testing.T, env map[string]string, args ...string) (string, *lockedBuffer, *lockedBuffer, func() int) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	stdout, stderr := &lockedBuffer{}, &lockedBuffer{}
	code := make(chan int, 1)
	go func() {
		code <- Run(ctx, append([]string{"siem", "forward", "--listen", "127.0.0.1:0"}, args...), stdout, stderr, envOf(env), Options{})
	}()
	var once sync.Once
	exit := -1
	stop := func() int {
		once.Do(func() {
			cancel()
			select {
			case exit = <-code:
			case <-time.After(15 * time.Second):
				t.Error("siem forward did not stop")
			}
		})
		return exit
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if m := fwdListenRe.FindStringSubmatch(stderr.String()); m != nil {
			t.Cleanup(func() { stop() })
			return m[1], stdout, stderr, stop
		}
		select {
		case c := <-code:
			cancel()
			t.Fatalf("siem forward exited %d: %s", c, stderr.String())
		default:
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("siem forward is not listening: %s", stderr.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// postBatch posts body to the forwarder with the given webhook-signature
// at timestamp ts.
func postBatch(t *testing.T, addr, id string, ts int64, sig string, body []byte) int {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+addr+"/", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("webhook-id", id)
	req.Header.Set("webhook-timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("webhook-signature", sig)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// TestF950_ForwardsVerifiedBatchesToStdout: with the secret in
// PCLAW_SIEM_SECRET and `--out -`, a signed batch comes out on stdout as
// one line per event; a forged one is refused; stderr carries only the
// log, never a body or the secret.
// Covers: F950
func TestF950_ForwardsVerifiedBatchesToStdout(t *testing.T) {
	shown := ndomain.FormatSecret(fwdSecret)
	addr, stdout, stderr, stop := startForward(t, map[string]string{"PCLAW_SIEM_SECRET": shown}, "--out", "-")
	body, want := fwdBatch(t, "cli-1")
	// One second ahead: the forwarder refuses a timestamp from before it
	// started, and timestamps are whole seconds.
	ts := time.Now().Unix() + 1
	if code := postBatch(t, addr, "cli-1", ts, ndomain.Signatures([][]byte{fwdSecret}, "cli-1", ts, body), body); code != http.StatusOK {
		t.Fatalf("signed = %d: %s", code, stderr.String())
	}
	if code := postBatch(t, addr, "cli-2", ts, ndomain.Signatures([][]byte{[]byte("another-secret-0123456789abcdef")}, "cli-2", ts, body), body); code != http.StatusUnauthorized {
		t.Errorf("forged = %d", code)
	}
	if c := stop(); c != 0 {
		t.Errorf("exit %d: %s", c, stderr.String())
	}
	if got := stdout.String(); got != want {
		t.Errorf("stdout %q, want %q", got, want)
	}
	logs := stderr.String()
	for _, leak := range []string{fwdMarker, shown, strings.TrimPrefix(shown, ndomain.SecretPrefix)} {
		if strings.Contains(logs, leak) {
			t.Errorf("stderr holds %q: %s", leak, logs)
		}
	}
	if !strings.Contains(logs, `"outcome":"written"`) || !strings.Contains(logs, `"outcome":"bad_signature"`) {
		t.Errorf("stderr %s", logs)
	}
}

// TestF950_FileModeAppendsWithBothSchemes: with two secret files (a
// rotation) and a JWKS file, a batch carrying the HMAC and Ed25519
// signatures is appended to an existing file, which keeps what it held
// (siemforward's TestHR662_NewOutputFileIsOwnerOnly checks how a new file
// is created).
// Covers: F950
func TestF950_FileModeAppendsWithBothSchemes(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	doc, err := json.Marshal(map[string][]jws.JWK{"keys": {jws.PublicJWK(pub, keys.KIDFor(keys.PurposeWebhooks, pub))}})
	if err != nil {
		t.Fatal(err)
	}
	old := []byte("the-previous-secret-0123456789abcdef")
	out := filepath.Join(dir, "ocsf.json")
	if err := os.WriteFile(out, []byte("{\"earlier\":true}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	addr, _, stderr, stop := startForward(t, nil, "--out", out,
		"--secret-file", write("new.secret", []byte(ndomain.FormatSecret(fwdSecret)+"\n")),
		"--secret-file", write("old.secret", []byte(ndomain.FormatSecret(old))),
		"--jwks-file", write("jwks.json", doc), "--window", "2m")
	body, want := fwdBatch(t, "file-1")
	ts := time.Now().Unix() + 1
	hmacOnly := ndomain.Signatures([][]byte{fwdSecret}, "file-1", ts, body)
	if code := postBatch(t, addr, "file-1", ts, hmacOnly, body); code != http.StatusUnauthorized {
		t.Errorf("HMAC only = %d", code)
	}
	both := ndomain.Signatures([][]byte{old}, "file-1", ts, body) + " " + ndomain.V1a(ed25519.Sign(priv, ndomain.SignedContent("file-1", ts, body)))
	if code := postBatch(t, addr, "file-1", ts, both, body); code != http.StatusOK {
		t.Fatalf("old secret and key = %d: %s", code, stderr.String())
	}
	if c := stop(); c != 0 {
		t.Errorf("exit %d: %s", c, stderr.String())
	}
	got, err := os.ReadFile(out)
	if err != nil || string(got) != "{\"earlier\":true}\n"+want {
		t.Errorf("file %q, %v", got, err)
	}
}

// TestHR662_ForwarderRefusesUnsafeStarts: no signature to check, a
// non-loopback listener without TLS, more than two secrets, a secret both
// in a file and the environment, an http JWKS URL, an empty JWKS file or a
// window over 15 minutes stops it before it listens or creates the output
// file. A secret is never taken as an argument, and an error never repeats
// one.
// Covers: F950
func TestHR662_ForwarderRefusesUnsafeStarts(t *testing.T) {
	dir := t.TempDir()
	secretFile := filepath.Join(dir, "s")
	if err := os.WriteFile(secretFile, []byte(ndomain.FormatSecret(fwdSecret)), 0o600); err != nil {
		t.Fatal(err)
	}
	badSecret := filepath.Join(dir, "bad")
	if err := os.WriteFile(badSecret, []byte("whsec_hunter2 not base64"), 0o600); err != nil {
		t.Fatal(err)
	}
	emptyJWKS := filepath.Join(dir, "jwks.json")
	if err := os.WriteFile(emptyJWKS, []byte(`{"keys":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "never.json")
	envSecret := map[string]string{"PCLAW_SIEM_SECRET": ndomain.FormatSecret(fwdSecret)}
	for name, c := range map[string]struct {
		env  map[string]string
		args []string
		want string
	}{
		"no scheme":            {nil, nil, "no signature to check"},
		"non-loopback":         {envSecret, []string{"--listen", "0.0.0.0:0"}, "--tls-cert"},
		"every interface":      {envSecret, []string{"--listen", ":8471"}, "--tls-cert"},
		"cert without key":     {envSecret, []string{"--tls-cert", secretFile}, "go together"},
		"three secret files":   {nil, []string{"--secret-file", secretFile, "--secret-file", secretFile, "--secret-file", secretFile}, "at most 2"},
		"file and environment": {envSecret, []string{"--secret-file", secretFile}, "not both"},
		"bad secret":           {nil, []string{"--secret-file", badSecret}, "not a signing secret"},
		"http jwks":            {nil, []string{"--jwks-url", "http://pc.example.com/.well-known/pantherclaw/orgs/x/webhook-jwks.json"}, "https"},
		"empty jwks file":      {nil, []string{"--jwks-file", emptyJWKS}, "no webhooks Ed25519 key"},
		"jwks url and file":    {nil, []string{"--jwks-url", "https://pc.example.com/j", "--jwks-file", emptyJWKS}, "not both"},
		"window too long":      {envSecret, []string{"--window", "16m"}, "at most 15m"},
		"window zero":          {envSecret, []string{"--window", "0s"}, "--window"},
		"secret as argument":   {nil, []string{"--secret", ndomain.FormatSecret(fwdSecret)}, "not defined"},
		"secret as positional": {envSecret, []string{ndomain.FormatSecret(fwdSecret)}, "usage"},
	} {
		var stdout, stderr bytes.Buffer
		code := Run(t.Context(), append([]string{"siem", "forward", "--out", out}, c.args...), &stdout, &stderr, envOf(c.env), Options{})
		errs := stderr.String()
		if code == 0 || !strings.Contains(errs, c.want) {
			t.Errorf("%s: code %d, stderr %q", name, code, errs)
		}
		for _, leak := range []string{ndomain.FormatSecret(fwdSecret), "hunter2"} {
			if strings.Contains(errs, leak) || strings.Contains(stdout.String(), leak) {
				t.Errorf("%s: output repeats a secret: %q", name, errs)
			}
		}
		if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s: the output file was created", name)
		}
	}
	var stdout, stderr bytes.Buffer
	if code := Run(t.Context(), []string{"siem", "forward"}, &stdout, &stderr, envOf(envSecret), Options{}); code != 2 {
		t.Errorf("no --out = %d", code)
	}
}

// TestF950_JWKSURLIsFetchedThroughPclawsClient: --jwks-url is fetched at
// start, with pclaw's own client (no redirects), and a fetch that fails
// stops the start.
// Covers: F950
func TestF950_JWKSURLIsFetchedThroughPclawsClient(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	doc, err := json.Marshal(map[string][]jws.JWK{"keys": {jws.PublicJWK(pub, keys.KIDFor(keys.PurposeWebhooks, pub))}})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	fetched := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/moved" {
			http.Redirect(w, r, "/jwks", http.StatusFound)
			return
		}
		mu.Lock()
		fetched++
		mu.Unlock()
		_, _ = w.Write(doc)
	}))
	t.Cleanup(srv.Close)
	client := srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	var stdout, stderr bytes.Buffer
	if code := Run(t.Context(), []string{"siem", "forward", "--out", "-", "--listen", "127.0.0.1:0", "--jwks-url", srv.URL + "/moved"},
		&stdout, &stderr, envOf(nil), Options{HTTPClient: client}); code == 0 || !strings.Contains(stderr.String(), "status 302") {
		t.Errorf("a redirect was followed: code %d, %s", code, stderr.String())
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan int, 1)
	errs := &lockedBuffer{}
	go func() {
		done <- Run(ctx, []string{"siem", "forward", "--out", "-", "--listen", "127.0.0.1:0", "--jwks-url", srv.URL + "/jwks"},
			&stdout, errs, envOf(nil), Options{HTTPClient: client})
	}()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(errs.String(), "siem.forward.listening") {
		if time.Now().After(deadline) {
			t.Fatalf("not listening: %s", errs.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if c := <-done; c != 0 {
		t.Errorf("exit %d", c)
	}
	mu.Lock()
	defer mu.Unlock()
	if fetched != 1 {
		t.Errorf("%d fetches at start", fetched)
	}
}

// TestHR662_ForwarderStopSignals: an interrupt and SIGTERM (a service
// manager's stop; on Windows also a console close, logoff or shutdown)
// both end the forwarder's context, so it lets batches in flight finish
// instead of dying mid-write.
// Covers: F950
func TestHR662_ForwarderStopSignals(t *testing.T) {
	if !slices.Contains(siemForwardStop, os.Interrupt) || !slices.Contains(siemForwardStop, os.Signal(syscall.SIGTERM)) {
		t.Errorf("stop signals %v", siemForwardStop)
	}
}
