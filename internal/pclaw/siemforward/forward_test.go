// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package siemforward

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	ndomain "github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/siem/ocsf"
)

// samples is the packs' golden OCSF directory: the layout a SIEM agent
// reading the forwarder's file expects, one event per line.
const samples = "../../../integrations/siem/samples"

// marker sits in every test body: it must never reach a log or an answer.
const marker = "BODY-MARKER-7f3c"

var (
	secretA = []byte("forwarder-secret-a-0123456789abcdef")
	secretB = []byte("forwarder-secret-b-0123456789abcdef")
	secretC = []byte("forwarder-secret-c-0123456789abcdef")
	keyA    = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	keyB    = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
)

func pub(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

// jwksDoc is an org's webhook JWKS as the server serves it.
func jwksDoc(t *testing.T, ks ...ed25519.PrivateKey) []byte {
	t.Helper()
	set := struct {
		Keys []jws.JWK `json:"keys"`
	}{}
	for _, k := range ks {
		set.Keys = append(set.Keys, jws.PublicJWK(pub(k), keys.KIDFor(keys.PurposeWebhooks, pub(k))))
	}
	b, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// testClock is a settable clock shared with the server goroutine.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// syncBuffer is a log destination read while the server writes.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type fixture struct {
	t     *testing.T
	clock *testClock
	out   string
	logs  *syncBuffer
	fwd   *Forwarder
	srv   *httptest.Server
}

// newFixture serves a forwarder writing to a file in a temp directory. Its
// clock starts a minute after the forwarder did.
func newFixture(t *testing.T, cfg Config) *fixture {
	t.Helper()
	return newFixtureAt(t, cfg, &testClock{now: time.Unix(1_793_534_400, 0)})
}

// newFixtureAt is newFixture on the given clock.
func newFixtureAt(t *testing.T, cfg Config, clk *testClock) *fixture {
	t.Helper()
	f := &fixture{t: t, clock: clk, out: filepath.Join(t.TempDir(), "ocsf.json"), logs: &syncBuffer{}}
	if cfg.Sink == nil {
		sink, err := OpenFile(f.out)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = sink.Close() })
		cfg.Sink = sink
	}
	cfg.Now = f.clock.Now
	if cfg.Start.IsZero() {
		cfg.Start = f.clock.Now().Add(-time.Minute)
	}
	cfg.Log = pclog.New(f.logs, pclog.Options{})
	fwd, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.fwd = fwd
	f.srv = httptest.NewServer(fwd)
	t.Cleanup(f.srv.Close)
	return f
}

// sig is a webhook-signature header: the v1 signatures of secrets and the
// v1a signature of each key, as the exporter sends them.
func sig(secrets [][]byte, privs []ed25519.PrivateKey, id string, ts int64, body []byte) string {
	parts := []string{}
	if len(secrets) > 0 {
		parts = append(parts, ndomain.Signatures(secrets, id, ts, body))
	}
	for _, k := range privs {
		parts = append(parts, ndomain.V1a(ed25519.Sign(k, ndomain.SignedContent(id, ts, body))))
	}
	return strings.Join(parts, " ")
}

// post sends one batch and returns the status and the answer.
func (f *fixture) post(id string, ts int64, signature string, body []byte) (int, string) {
	f.t.Helper()
	req, err := http.NewRequestWithContext(f.t.Context(), http.MethodPost, f.srv.URL+"/ingest", bytes.NewReader(body))
	if err != nil {
		f.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if id != "" {
		req.Header.Set("webhook-id", id)
	}
	req.Header.Set("webhook-timestamp", strconv.FormatInt(ts, 10))
	if signature != "" {
		req.Header.Set("webhook-signature", signature)
	}
	resp, err := f.srv.Client().Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// signed posts body signed with secrets and keys at the clock's now.
func (f *fixture) signed(id string, body []byte, secrets [][]byte, privs ...ed25519.PrivateKey) (int, string) {
	f.t.Helper()
	ts := f.clock.Now().Unix()
	return f.post(id, ts, sig(secrets, privs, id, ts, body), body)
}

func (f *fixture) written() string {
	f.t.Helper()
	b, err := os.ReadFile(f.out)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		f.t.Fatal(err)
	}
	return string(b)
}

// noLeak checks the logs never hold the body.
func (f *fixture) noLeak() {
	f.t.Helper()
	if strings.Contains(f.logs.String(), marker) {
		f.t.Errorf("a body reached the log: %s", f.logs.String())
	}
}

// batch is an export batch of n events, each carrying the marker.
func batch(t *testing.T, id string, n int) ([]byte, string) {
	t.Helper()
	var b ocsf.Builder
	var want strings.Builder
	for i := range n {
		enc := []byte(`{"class_uid":2004,"message":"` + marker + `","metadata":{"uid":"` + id + "-" + strconv.Itoa(i) + `"}}`)
		if ok, err := b.Add(enc); !ok || err != nil {
			t.Fatalf("add: %v %v", ok, err)
		}
		want.Write(enc)
		want.WriteByte('\n')
	}
	body, err := b.Body(id, 1, int64(n))
	if err != nil {
		t.Fatal(err)
	}
	return body, want.String()
}

// sampleBatch is the packs' golden batch and the lines its samples make.
func sampleBatch(t *testing.T) ([]byte, string) {
	t.Helper()
	norm := func(b []byte) []byte { return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")) }
	body, err := os.ReadFile(filepath.Join(samples, "batch", "batch.json"))
	if err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(samples, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("samples: %v", err)
	}
	var want strings.Builder
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		want.Write(norm(b))
	}
	return bytes.TrimSuffix(norm(body), []byte("\n")), want.String()
}

const batchID = "0192f944-0000-7000-8000-0000000000f1"

// TestHR662_HMACBatchIsWrittenOneEventPerLine: the packs' golden batch,
// HMAC-signed, becomes exactly the golden sample files, one event per
// line, the layout Wazuh's JSON decoder and a custom text log read. The
// log names the batch, the count and the outcome, and the answer echoes
// nothing.
// Covers: F950
func TestHR662_HMACBatchIsWrittenOneEventPerLine(t *testing.T) {
	f := newFixture(t, Config{Secrets: [][]byte{secretA}})
	body, want := sampleBatch(t)
	code, answer := f.signed(batchID, body, [][]byte{secretA})
	if code != http.StatusOK || answer != "ok\n" {
		t.Fatalf("answer %d %q", code, answer)
	}
	if got := f.written(); got != want {
		t.Errorf("written:\n%s\nwant the samples:\n%s", got, want)
	}
	logs := f.logs.String()
	if !strings.Contains(logs, `"batch":"`+batchID+`"`) || !strings.Contains(logs, `"events":17`) || !strings.Contains(logs, `"outcome":"written"`) {
		t.Errorf("log %s", logs)
	}
	if strings.Contains(logs, "class_uid") || strings.Contains(logs, "pc.authority.self_issue") {
		t.Errorf("the log holds batch content: %s", logs)
	}
}

// TestHR662_Ed25519BatchIsWritten: with only a JWKS configured, a `v1a,`
// signature by a webhooks key of the org's JWKS is enough; a batch with
// only the HMAC signature is not.
// Covers: F950
func TestHR662_Ed25519BatchIsWritten(t *testing.T) {
	ks, err := ParseJWKS(jwksDoc(t, keyA))
	if err != nil || len(ks) != 1 {
		t.Fatalf("jwks: %v %d", err, len(ks))
	}
	f := newFixture(t, Config{Keys: StaticKeys(ks)})
	body, want := batch(t, "b-1", 3)
	if code, _ := f.signed("b-1", body, [][]byte{secretA}); code != http.StatusUnauthorized {
		t.Fatalf("HMAC only = %d", code)
	}
	if code, _ := f.signed("b-1", body, nil, keyA); code != http.StatusOK {
		t.Fatalf("v1a = %d", code)
	}
	if got := f.written(); got != want {
		t.Errorf("written %q", got)
	}
	f.noLeak()
}

// TestHR662_EveryConfiguredSchemeMustVerify: with HMAC and a JWKS both
// configured, one valid signature is not enough: each scheme must have its
// own.
// Covers: F950
func TestHR662_EveryConfiguredSchemeMustVerify(t *testing.T) {
	f := newFixture(t, Config{Secrets: [][]byte{secretA}, Keys: StaticKeys{pub(keyA)}})
	body, want := batch(t, "b-2", 2)
	for name, c := range map[string]struct {
		secrets [][]byte
		privs   []ed25519.PrivateKey
	}{
		"hmac only":            {[][]byte{secretA}, nil},
		"v1a only":             {nil, []ed25519.PrivateKey{keyA}},
		"hmac and another key": {[][]byte{secretA}, []ed25519.PrivateKey{keyB}},
		"another secret, key":  {[][]byte{secretB}, []ed25519.PrivateKey{keyA}},
	} {
		if code, answer := f.signed("b-2", body, c.secrets, c.privs...); code != http.StatusUnauthorized || strings.Contains(answer, marker) {
			t.Errorf("%s = %d %q", name, code, answer)
		}
	}
	if f.written() != "" {
		t.Fatalf("a batch missing a scheme was written: %q", f.written())
	}
	if code, _ := f.signed("b-2", body, [][]byte{secretA}, keyA); code != http.StatusOK {
		t.Fatalf("both = %d", code)
	}
	if got := f.written(); got != want {
		t.Errorf("written %q", got)
	}
	f.noLeak()
}

// TestHR662_EitherSecretOfARotationVerifies: during a rotation overlap the
// forwarder holds both secrets; a batch signed by the new one, the old one
// or both is written, one signed by neither is not.
// Covers: F950
func TestHR662_EitherSecretOfARotationVerifies(t *testing.T) {
	f := newFixture(t, Config{Secrets: [][]byte{secretB, secretA}})
	n := 0
	for name, secrets := range map[string][][]byte{
		"new": {secretB}, "old": {secretA}, "both": {secretB, secretA},
	} {
		n++
		id := "rot-" + name
		body, _ := batch(t, id, 1)
		if code, _ := f.signed(id, body, secrets); code != http.StatusOK {
			t.Errorf("%s = %d", name, code)
		}
	}
	body, _ := batch(t, "rot-other", 1)
	if code, _ := f.signed("rot-other", body, [][]byte{secretC}); code != http.StatusUnauthorized {
		t.Errorf("a third secret = %d", code)
	}
	if got := strings.Count(f.written(), "\n"); got != n {
		t.Errorf("%d lines, want %d", got, n)
	}
	if _, err := New(Config{Secrets: [][]byte{secretA, secretB, secretC}, Sink: NewWriterSink(io.Discard)}); err == nil {
		t.Error("three secrets accepted")
	}
}

// TestHR662_WrongSignatureIsRefusedAndNeverWritten: a signature by another
// secret, over another id or timestamp, over a changed body, or missing,
// gets 401 or 400 and nothing of the body is written, logged or answered.
// Covers: F950
func TestHR662_WrongSignatureIsRefusedAndNeverWritten(t *testing.T) {
	f := newFixture(t, Config{Secrets: [][]byte{secretA}})
	body, _ := batch(t, "b-3", 2)
	ts := f.clock.Now().Unix()
	tampered := bytes.Replace(body, []byte(marker), []byte("BODY-MARKER-0000"), 1)
	for name, c := range map[string]struct {
		sig  string
		body []byte
		want int
	}{
		"other secret":    {sig([][]byte{secretB}, nil, "b-3", ts, body), body, http.StatusUnauthorized},
		"other id":        {sig([][]byte{secretA}, nil, "b-4", ts, body), body, http.StatusUnauthorized},
		"other timestamp": {sig([][]byte{secretA}, nil, "b-3", ts-1, body), body, http.StatusUnauthorized},
		"changed body":    {sig([][]byte{secretA}, nil, "b-3", ts, body), tampered, http.StatusUnauthorized},
		"not base64":      {"v1,!!!!", body, http.StatusUnauthorized},
		"v1a for hmac":    {sig(nil, []ed25519.PrivateKey{keyA}, "b-3", ts, body), body, http.StatusUnauthorized},
		"missing":         {"", body, http.StatusBadRequest},
	} {
		code, answer := f.post("b-3", ts, c.sig, c.body)
		if code != c.want || strings.Contains(answer, marker) || strings.Contains(answer, "BODY-MARKER") {
			t.Errorf("%s = %d %q", name, code, answer)
		}
	}
	if code, _ := f.post("", ts, sig([][]byte{secretA}, nil, "", ts, body), body); code != http.StatusBadRequest {
		t.Errorf("no webhook-id = %d", code)
	}
	if f.written() != "" {
		t.Errorf("written %q", f.written())
	}
	if strings.Contains(f.logs.String(), "BODY-MARKER") || !strings.Contains(f.logs.String(), `"outcome":"bad_signature"`) {
		t.Errorf("log %s", f.logs.String())
	}
}

// TestHR662_TimestampOutsideTheWindowIsRefused: a timestamp further than
// the window from now, past or future, is 400 even when signed; the edges
// of the window are inside.
// Covers: F950
func TestHR662_TimestampOutsideTheWindowIsRefused(t *testing.T) {
	for _, window := range []time.Duration{0, time.Minute, MaxWindow} {
		f := newFixture(t, Config{Secrets: [][]byte{secretA}, Window: window, Start: time.Unix(1, 0)})
		w := window
		if w == 0 {
			w = DefaultWindow
		}
		now := f.clock.Now().Unix()
		secs := int64(w / time.Second)
		for i, c := range []struct {
			ts   int64
			want int
		}{
			{now - secs - 1, http.StatusBadRequest},
			{now + secs + 1, http.StatusBadRequest},
			{now - secs, http.StatusOK},
			{now + secs, http.StatusOK},
		} {
			id := "w-" + strconv.Itoa(i)
			body, _ := batch(t, id, 1)
			code, _ := f.post(id, c.ts, sig([][]byte{secretA}, nil, id, c.ts, body), body)
			if code != c.want {
				t.Errorf("window %s, offset %d = %d, want %d", w, c.ts-now, code, c.want)
			}
		}
		if got := strings.Count(f.written(), "\n"); got != 2 {
			t.Errorf("window %s: %d lines", w, got)
		}
		if !strings.Contains(f.logs.String(), `"outcome":"outside_window"`) {
			t.Errorf("log %s", f.logs.String())
		}
	}
	for _, w := range []time.Duration{-time.Second, MaxWindow + time.Second} {
		if _, err := New(Config{Secrets: [][]byte{secretA}, Window: w, Sink: NewWriterSink(io.Discard)}); err == nil {
			t.Errorf("window %s accepted", w)
		}
	}
}

// TestHR662_TimestampBeforeStartIsRefused: inside the window but signed
// before the forwarder started, a batch is refused: ids seen before the
// start are not remembered, so it could be a replay.
// Covers: F950
func TestHR662_TimestampBeforeStartIsRefused(t *testing.T) {
	clk := time.Unix(1_793_534_400, 0)
	f := newFixture(t, Config{Secrets: [][]byte{secretA}, Start: clk})
	for i, c := range []struct {
		ts   int64
		want int
	}{{clk.Unix() - 1, http.StatusBadRequest}, {clk.Unix() - 60, http.StatusBadRequest}, {clk.Unix(), http.StatusOK}} {
		id := "s-" + strconv.Itoa(i)
		body, _ := batch(t, id, 1)
		if code, _ := f.post(id, c.ts, sig([][]byte{secretA}, nil, id, c.ts, body), body); code != c.want {
			t.Errorf("%d s before the start = %d, want %d", clk.Unix()-c.ts, code, c.want)
		}
	}
	if got := strings.Count(f.written(), "\n"); got != 1 {
		t.Errorf("%d lines", got)
	}
}

// TestHR662_ReplayIsAnsweredWithoutWriting: the same request again, or the
// exporter's re-send of the batch with a newer timestamp, is answered 200
// and not written again for as long as it could pass the window.
// Covers: F950
func TestHR662_ReplayIsAnsweredWithoutWriting(t *testing.T) {
	f := newFixture(t, Config{Secrets: [][]byte{secretA}})
	body, want := batch(t, "r-1", 2)
	ts1 := f.clock.Now().Unix()
	first := sig([][]byte{secretA}, nil, "r-1", ts1, body)
	if code, _ := f.post("r-1", ts1, first, body); code != http.StatusOK {
		t.Fatalf("first = %d", code)
	}
	if code, answer := f.post("r-1", ts1, first, body); code != http.StatusOK || answer != "duplicate\n" {
		t.Fatalf("replay = %d %q", code, answer)
	}
	// The exporter re-sends after a lost answer: same id, a newer timestamp.
	f.clock.add(4 * time.Minute)
	ts2 := f.clock.Now().Unix()
	second := sig([][]byte{secretA}, nil, "r-1", ts2, body)
	if code, answer := f.post("r-1", ts2, second, body); code != http.StatusOK || answer != "duplicate\n" {
		t.Fatalf("re-send = %d %q", code, answer)
	}
	// Past the first timestamp's window the re-send can still pass, so it
	// is still remembered.
	f.clock.add(3 * time.Minute)
	if code, answer := f.post("r-1", ts2, second, body); code != http.StatusOK || answer != "duplicate\n" {
		t.Fatalf("replay of the re-send = %d %q", code, answer)
	}
	if got := f.written(); got != want {
		t.Errorf("written %q, want once %q", got, want)
	}
	if !strings.Contains(f.logs.String(), `"outcome":"duplicate"`) {
		t.Errorf("log %s", f.logs.String())
	}
	// Once no request carrying it can pass the window, the id is forgotten:
	// a later delivery of the batch is written again (at least once; SIEMs
	// drop duplicates by metadata.uid).
	f.clock.add(10 * time.Minute)
	if code, answer := f.signed("r-1", body, [][]byte{secretA}); code != http.StatusOK || answer != "ok\n" {
		t.Fatalf("after the window = %d %q", code, answer)
	}
	if got := f.written(); got != want+want {
		t.Errorf("written %q", got)
	}
}

// TestHR662_OversizedBodyIs413: a body over the exporter's batch limit is
// refused 413, with or without a Content-Length, and nothing is written.
// Through the server Serve runs, a declared oversize is refused by
// httpx.LimitBody before the forwarder sees it, so it logs no batch line;
// a chunked one is refused by the forwarder and logged too_large.
// Covers: F950
func TestHR662_OversizedBodyIs413(t *testing.T) {
	f := newFixture(t, Config{Secrets: [][]byte{secretA}})
	big := bytes.Repeat([]byte("x"), MaxBody+1)
	ts := f.clock.Now().Unix()
	srv, err := newServer(f.fwd, ServeConfig{Listen: "127.0.0.1:0"}, pclog.Discard())
	if err != nil {
		t.Fatal(err)
	}
	bigReq := func(id string) *http.Request {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", bytes.NewReader(big))
		r.Header.Set("webhook-id", id)
		r.Header.Set("webhook-timestamp", strconv.FormatInt(ts, 10))
		r.Header.Set("webhook-signature", sig([][]byte{secretA}, nil, id, ts, big))
		return r
	}
	// With a Content-Length it is refused before the body is read (called
	// in process: a client still sending a refused body may see the reset).
	rec := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rec, bigReq("big-0"))
	if rec.Code != http.StatusRequestEntityTooLarge || rec.Body.String() != "request body too large\n" {
		t.Errorf("with Content-Length, through the server = %d %q", rec.Code, rec.Body.String())
	}
	if strings.Contains(f.logs.String(), "siem.forward.batch") {
		t.Errorf("a declared oversize reached the forwarder: %s", f.logs.String())
	}
	// The forwarder refuses it as well, should it ever be served without
	// the limit in front.
	rec = httptest.NewRecorder()
	f.fwd.ServeHTTP(rec, bigReq("big-1"))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("with Content-Length, the forwarder alone = %d", rec.Code)
	}
	prod := httptest.NewServer(srv.Handler)
	t.Cleanup(prod.Close)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, prod.URL, io.MultiReader(bytes.NewReader(big)))
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = -1 // chunked
	req.Header.Set("webhook-id", "big-2")
	req.Header.Set("webhook-timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("webhook-signature", sig([][]byte{secretA}, nil, "big-2", ts, big))
	resp, err := prod.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("chunked = %d", resp.StatusCode)
	}
	if f.written() != "" || !strings.Contains(f.logs.String(), `"batch":"big-2"`) || !strings.Contains(f.logs.String(), `"outcome":"too_large"`) {
		t.Errorf("written %d bytes, log %s", len(f.written()), f.logs.String())
	}
	if MaxBody != ocsf.MaxBatchBytes {
		t.Errorf("the limit %d is not the exporter's %d", MaxBody, ocsf.MaxBatchBytes)
	}
}

// TestHR662_BodyBudgetSpentIs503: when the bodies in hand already hold
// nearly MaxBuffered bytes, a read that would pass it answers 503 busy
// before the signature is looked at, writes nothing and keeps none of its
// bytes. Once the budget is free again the batch is taken, and every
// request gives its bytes back when it is answered.
// Covers: F950
func TestHR662_BodyBudgetSpentIs503(t *testing.T) {
	f := newFixture(t, Config{Secrets: [][]byte{secretA}})
	const inHand = MaxBuffered - 10 // other requests' bodies
	f.fwd.buffered.Store(inHand)
	body, want := batch(t, "busy-1", 1)
	ts := f.clock.Now().Unix()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set("webhook-id", "busy-1")
	req.Header.Set("webhook-timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("webhook-signature", sig([][]byte{secretA}, nil, "busy-1", ts, body))
	rec := httptest.NewRecorder()
	f.fwd.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable || rec.Body.String() != "busy\n" {
		t.Errorf("over the budget = %d %q", rec.Code, rec.Body.String())
	}
	if got := f.fwd.buffered.Load(); got != inHand {
		t.Errorf("after the refusal %d bytes are counted, want %d", got, inHand)
	}
	if !strings.Contains(f.logs.String(), `"outcome":"busy"`) || f.written() != "" {
		t.Errorf("written %q, log %s", f.written(), f.logs.String())
	}
	f.fwd.buffered.Add(-inHand) // the other requests were answered
	if code, _ := f.signed("busy-1", body, [][]byte{secretA}); code != http.StatusOK || f.written() != want {
		t.Errorf("with the budget free = %d, written %q", code, f.written())
	}
	if got := f.fwd.buffered.Load(); got != 0 {
		t.Errorf("%d bytes still counted after the answer", got)
	}
	f.noLeak()
}

// TestHR662_StalledBodiesDontBlockASignedBatch: many senders that each
// send headers and one body byte, then stall, hold one byte of the budget
// each, not a place in a queue: a correctly signed batch is still
// written. After BodyReadTimeout each stalled body is given up, its
// connection answered or closed and its byte given back.
// Covers: F950
func TestHR662_StalledBodiesDontBlockASignedBatch(t *testing.T) {
	out := filepath.Join(t.TempDir(), "ocsf.json")
	sink, err := OpenFile(out)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sink.Close() })
	fwd, err := New(Config{Secrets: [][]byte{secretA}, Sink: sink, Start: time.Now().Add(-time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	addrc, done := make(chan string, 1), make(chan error, 1)
	go func() {
		done <- Serve(ctx, fwd, ServeConfig{Listen: "127.0.0.1:0", Ready: func(a string) { addrc <- a }})
	}()
	t.Cleanup(func() { cancel(); <-done })
	var addr string
	select {
	case addr = <-addrc:
	case err := <-done:
		t.Fatalf("Serve: %v", err)
	}
	const stalled = 40
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	var dialer net.Dialer
	conns := make([]net.Conn, 0, stalled)
	for i := range stalled {
		c, err := dialer.DialContext(t.Context(), "tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		conns = append(conns, c)
		head := "POST / HTTP/1.1\r\nHost: forwarder\r\nwebhook-id: stall-" + strconv.Itoa(i) + "\r\nwebhook-timestamp: " + ts +
			"\r\nwebhook-signature: v1,AAAA\r\nContent-Length: 1000\r\n\r\nx"
		if _, err := io.WriteString(c, head); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	for fwd.buffered.Load() != stalled {
		if time.Now().After(deadline) {
			t.Fatalf("%d stalled bytes counted, want %d", fwd.buffered.Load(), stalled)
		}
		time.Sleep(10 * time.Millisecond)
	}
	body, want := batch(t, "real-1", 2)
	now := time.Now().Unix()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+addr+"/", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("webhook-id", "real-1")
	req.Header.Set("webhook-timestamp", strconv.FormatInt(now, 10))
	req.Header.Set("webhook-signature", sig([][]byte{secretA}, nil, "real-1", now, body))
	client := &http.Client{Transport: &http.Transport{}, Timeout: 10 * time.Second}
	t.Cleanup(client.CloseIdleConnections)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("a signed batch beside %d stalled senders = %d", stalled, resp.StatusCode)
	}
	if got, _ := os.ReadFile(out); string(got) != want {
		t.Errorf("written %q", got)
	}
	// Each stalled body is given up after BodyReadTimeout: the sender gets
	// an answer or a closed connection, never a wait without end.
	for i, c := range conns {
		if err := c.SetReadDeadline(time.Now().Add(BodyReadTimeout + 10*time.Second)); err != nil {
			t.Fatal(err)
		}
		_, err := io.ReadAll(c)
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatalf("stalled sender %d still held after %s", i, BodyReadTimeout)
		}
	}
	deadline = time.Now().Add(10 * time.Second)
	for fwd.buffered.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("%d bytes still counted after the stalled bodies were given up", fwd.buffered.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// failingFile writes part of what it is given and then fails, or fails to
// sync, as a full disk or an I/O error would.
type failingFile struct {
	*os.File
	partial, noSync bool
}

func (f *failingFile) Write(p []byte) (int, error) {
	if f.partial {
		n, _ := f.File.Write(p[:len(p)/2])
		return n, errors.New("no space left on device")
	}
	return f.File.Write(p)
}

func (f *failingFile) Sync() error {
	if f.noSync {
		return errors.New("input/output error")
	}
	return f.File.Sync()
}

// TestHR662_WriteFailureIs503AndLeavesNoPartialLine: a write that fails
// part way answers 503, the file is cut back to the last whole batch, and
// the id is not remembered, so the exporter's retry is written. A sync that
// fails after a whole write keeps the lines (agents tailing the file would
// read it again from the start were it cut back), answers 503 and stops
// the sink: every later batch gets 503 and nothing more is written.
// Covers: F950
func TestHR662_WriteFailureIs503AndLeavesNoPartialLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ocsf.json")
	osf, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = osf.Close() })
	ff := &failingFile{File: osf}
	f := newFixture(t, Config{Secrets: [][]byte{secretA}, Sink: &FileSink{f: ff}})
	f.out = path
	first, want := batch(t, "wf-1", 2)
	if code, _ := f.signed("wf-1", first, [][]byte{secretA}); code != http.StatusOK {
		t.Fatalf("first = %d", code)
	}
	second, more := batch(t, "wf-2", 3)
	ff.partial = true
	if code, answer := f.signed("wf-2", second, [][]byte{secretA}); code != http.StatusServiceUnavailable || answer != "write failed\n" {
		t.Errorf("partial = %d %q", code, answer)
	}
	if got := f.written(); got != want {
		t.Errorf("partial: the file holds %q, want only the first batch %q", got, want)
	}
	ff.partial = false
	if code, _ := f.signed("wf-2", second, [][]byte{secretA}); code != http.StatusOK {
		t.Fatalf("retry = %d", code)
	}
	want += more
	if got := f.written(); got != want {
		t.Errorf("after the retry the file holds %q, want %q", got, want)
	}
	third, kept := batch(t, "wf-3", 2)
	ff.noSync = true
	if code, answer := f.signed("wf-3", third, [][]byte{secretA}); code != http.StatusServiceUnavailable || answer != "write failed\n" {
		t.Errorf("sync = %d %q", code, answer)
	}
	want += kept
	if got := f.written(); got != want {
		t.Errorf("sync: the file holds %q, want the whole lines kept %q", got, want)
	}
	ff.noSync = false
	fourth, _ := batch(t, "wf-4", 1)
	for id, body := range map[string][]byte{"wf-3": third, "wf-4": fourth} {
		if code, answer := f.signed(id, body, [][]byte{secretA}); code != http.StatusServiceUnavailable || answer != "write failed\n" {
			t.Errorf("%s after the failed sync = %d %q", id, code, answer)
		}
	}
	if got := f.written(); got != want {
		t.Errorf("the stopped sink wrote: the file holds %q, want %q", got, want)
	}
	logs := f.logs.String()
	if !strings.Contains(logs, `"outcome":"write_failed"`) || !strings.Contains(logs, "no space left") || !strings.Contains(logs, "could not be synced") {
		t.Errorf("log %s", logs)
	}
	f.noLeak()
}

// partialWriter is a stream that takes half of a write and then fails, as
// a full disk under a redirected stdout would; with none set it takes
// nothing.
type partialWriter struct {
	bytes.Buffer
	calls int
	none  bool
}

func (w *partialWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.none {
		return 0, errors.New("broken pipe")
	}
	n, _ := w.Buffer.Write(p[:len(p)/2])
	return n, errors.New("no space left on device")
}

// TestHR662_StdoutStopsAfterAPartialWrite: `--out -` can't cut a stream
// back, so after a write that took part of a batch every later batch gets
// 503 and nothing more is written: the next batch is never glued to the
// fragment. A write that took nothing leaves the stream usable.
// Covers: F950
func TestHR662_StdoutStopsAfterAPartialWrite(t *testing.T) {
	pw := &partialWriter{none: true}
	f := newFixture(t, Config{Secrets: [][]byte{secretA}, Sink: NewWriterSink(pw)})
	first, _ := batch(t, "sp-1", 3) // half of three lines ends inside one
	if code, _ := f.signed("sp-1", first, [][]byte{secretA}); code != http.StatusServiceUnavailable || pw.Len() != 0 {
		t.Fatalf("nothing taken = %d, %d bytes", code, pw.Len())
	}
	pw.none = false
	if code, answer := f.signed("sp-1", first, [][]byte{secretA}); code != http.StatusServiceUnavailable || answer != "write failed\n" {
		t.Fatalf("partial = %d %q", code, answer)
	}
	fragment, calls := pw.String(), pw.calls
	if fragment == "" || strings.HasSuffix(fragment, "\n") {
		t.Fatalf("the probe wrote no fragment: %q", fragment)
	}
	second, _ := batch(t, "sp-2", 1)
	for id, body := range map[string][]byte{"sp-1": first, "sp-2": second} {
		if code, answer := f.signed(id, body, [][]byte{secretA}); code != http.StatusServiceUnavailable || answer != "write failed\n" {
			t.Errorf("%s after the partial write = %d %q", id, code, answer)
		}
	}
	if pw.String() != fragment || pw.calls != calls {
		t.Errorf("the stopped sink wrote again: %d calls, %q", pw.calls-calls, pw.String())
	}
	if !strings.Contains(f.logs.String(), "partial line") {
		t.Errorf("log %s", f.logs.String())
	}
	f.noLeak()
}

// TestHR662_MalformedRequestsAreRefused: verified but not an export batch,
// headers missing or malformed, or not a POST: nothing is written.
// Covers: F950
func TestHR662_MalformedRequestsAreRefused(t *testing.T) {
	f := newFixture(t, Config{Secrets: [][]byte{secretA}})
	for name, body := range map[string]string{
		"not json":       `{"type":` + marker,
		"other type":     `{"type":"pantherclaw.other","data":{"events":[{"m":"` + marker + `"}]}}`,
		"no events":      `{"type":"pantherclaw.ocsf.batch","data":{}}`,
		"event a string": `{"type":"pantherclaw.ocsf.batch","data":{"events":["` + marker + `"]}}`,
		"duplicate name": `{"type":"pantherclaw.ocsf.batch","type":"pantherclaw.ocsf.batch","data":{"events":[]}}`,
	} {
		id := "m-" + strings.ReplaceAll(name, " ", "-")
		if code, answer := f.signed(id, []byte(body), [][]byte{secretA}); code != http.StatusBadRequest || strings.Contains(answer, marker) {
			t.Errorf("%s = %d %q", name, code, answer)
		}
	}
	ts := f.clock.Now().Unix()
	body, _ := batch(t, "m-h", 1)
	for name, h := range map[string]map[string]string{
		"timestamp not a number": {"webhook-timestamp": "soon"},
		"id with a space":        {"webhook-id": "m h"},
	} {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, f.srv.URL, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("webhook-id", "m-h")
		req.Header.Set("webhook-timestamp", strconv.FormatInt(ts, 10))
		req.Header.Set("webhook-signature", sig([][]byte{secretA}, nil, "m-h", ts, body))
		for k, v := range h {
			req.Header.Set(k, v)
		}
		resp, err := f.srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s = %d", name, resp.StatusCode)
		}
	}
	get, err := http.NewRequestWithContext(t.Context(), http.MethodGet, f.srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := f.srv.Client().Do(get)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET = %d", resp.StatusCode)
	}
	if f.written() != "" {
		t.Errorf("written %q", f.written())
	}
	f.noLeak()
}

// TestHR662_JWKSRefetchedAtMostOnceAMinute: after the org rotates its
// key, a signature by the new key refetches the JWKS once and is written;
// another unknown key within the minute fetches nothing, and after a
// minute it may fetch again. The URL must be https.
// Covers: F950
func TestHR662_JWKSRefetchedAtMostOnceAMinute(t *testing.T) {
	var mu sync.Mutex
	doc, fetches := jwksDoc(t, keyA), 0
	jwks := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		fetches++
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write(doc)
	}))
	t.Cleanup(jwks.Close)
	count := func() int { mu.Lock(); defer mu.Unlock(); return fetches }
	clk := &testClock{now: time.Unix(1_793_534_400, 0)}
	src, err := NewJWKSURL(t.Context(), jwks.URL+"/.well-known/pantherclaw/orgs/o/webhook-jwks.json", jwks.Client(), clk.Now, nil)
	if err != nil || count() != 1 || len(src.Current()) != 1 {
		t.Fatalf("first fetch: %v, %d fetches", err, count())
	}
	f := newFixtureAt(t, Config{Keys: src}, clk) // one clock for both
	body, _ := batch(t, "k-1", 1)
	// Within the minute of the first fetch, a key it does not know fetches nothing.
	if code, _ := f.post("k-1", clk.Now().Unix(), sig(nil, []ed25519.PrivateKey{keyB}, "k-1", clk.Now().Unix(), body), body); code != http.StatusUnauthorized ||
		count() != 1 {
		t.Fatalf("unknown key at once = %d, %d fetches", code, count())
	}
	mu.Lock()
	doc = jwksDoc(t, keyB, keyA) // the org rotated: B ACTIVE, A RETIRING
	mu.Unlock()
	clk.add(JWKSRefetchEvery)
	ts := clk.Now().Unix()
	if code, _ := f.post("k-1", ts, sig(nil, []ed25519.PrivateKey{keyB}, "k-1", ts, body), body); code != http.StatusOK || count() != 2 {
		t.Fatalf("rotated key = %d, %d fetches", code, count())
	}
	body2, _ := batch(t, "k-2", 1)
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))
	for range 3 {
		if code, _ := f.post("k-2", ts, sig(nil, []ed25519.PrivateKey{other}, "k-2", ts, body2), body2); code != http.StatusUnauthorized {
			t.Fatalf("unknown key = %d", code)
		}
	}
	if count() != 2 {
		t.Errorf("%d fetches within the minute", count())
	}
	// The retiring key still verifies without a fetch.
	if code, _ := f.post("k-2", ts, sig(nil, []ed25519.PrivateKey{keyA}, "k-2", ts, body2), body2); code != http.StatusOK || count() != 2 {
		t.Errorf("retiring key = %d, %d fetches", code, count())
	}
	for _, bad := range []string{"http://pc.example.com/jwks.json", "https://user:pw@pc.example.com/jwks.json", "pc.example.com/jwks.json", "https:///jwks"} {
		if err := CheckJWKSURL(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := NewJWKSURL(t.Context(), "http://"+strings.TrimPrefix(jwks.URL, "https://"), jwks.Client(), nil, nil); err == nil {
		t.Error("an http JWKS URL was fetched")
	}
}

// TestHR662_CanceledRequestStillLoadsARotatedKey: a client that hangs up
// while its batch triggers the refetch does not use up the minute's
// fetch: the fetch runs to the end, the rotated key is loaded, and the
// exporter's next batch signed by it verifies without another fetch.
// Covers: F950
func TestHR662_CanceledRequestStillLoadsARotatedKey(t *testing.T) {
	var mu sync.Mutex
	doc, fetches := jwksDoc(t, keyA), 0
	jwks := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		fetches++
		_, _ = w.Write(doc)
	}))
	t.Cleanup(jwks.Close)
	count := func() int { mu.Lock(); defer mu.Unlock(); return fetches }
	clk := &testClock{now: time.Unix(1_793_534_400, 0)}
	src, err := NewJWKSURL(t.Context(), jwks.URL+"/jwks.json", jwks.Client(), clk.Now, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := newFixtureAt(t, Config{Keys: src}, clk)
	mu.Lock()
	doc = jwksDoc(t, keyB, keyA) // the org rotated
	mu.Unlock()
	clk.add(JWKSRefetchEvery)
	ts := clk.Now().Unix()
	body, want := batch(t, "c-1", 1)
	gone, cancel := context.WithCancel(t.Context())
	cancel() // the client has hung up
	req := httptest.NewRequestWithContext(gone, http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set("webhook-id", "c-1")
	req.Header.Set("webhook-timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("webhook-signature", sig(nil, []ed25519.PrivateKey{keyB}, "c-1", ts, body))
	rec := httptest.NewRecorder()
	f.fwd.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || count() != 2 || len(src.Current()) != 2 {
		t.Fatalf("a canceled request = %d: %d fetches, %d keys", rec.Code, count(), len(src.Current()))
	}
	body2, want2 := batch(t, "c-2", 1)
	if code, _ := f.post("c-2", ts, sig(nil, []ed25519.PrivateKey{keyB}, "c-2", ts, body2), body2); code != http.StatusOK || count() != 2 {
		t.Errorf("the next batch by the rotated key = %d, %d fetches", code, count())
	}
	if got := f.written(); got != want+want2 {
		t.Errorf("written %q", got)
	}
	// Refresh itself ignores a canceled context once the minute is up.
	clk.add(JWKSRefetchEvery)
	if !src.Refresh(gone) || count() != 3 {
		t.Errorf("Refresh on a canceled context: %d fetches", count())
	}
}

// TestParseJWKS_KeepsOnlyWebhooksKeys: a key whose kid is not its own
// webhooks kid, or that is not Ed25519, is skipped.
func TestParseJWKS_KeepsOnlyWebhooksKeys(t *testing.T) {
	good := jws.PublicJWK(pub(keyA), keys.KIDFor(keys.PurposeWebhooks, pub(keyA)))
	wrongKid := jws.PublicJWK(pub(keyB), keys.KIDFor(keys.PurposeWebhooks, pub(keyA)))
	permits := jws.PublicJWK(pub(keyB), keys.KIDFor(keys.PurposePermits, pub(keyB)))
	rsa := jws.JWK{Kty: "RSA", Kid: "r"}
	doc, err := json.Marshal(map[string][]jws.JWK{"keys": {good, wrongKid, permits, rsa}})
	if err != nil {
		t.Fatal(err)
	}
	ks, err := ParseJWKS(doc)
	if err != nil || len(ks) != 1 || !ks[0].Equal(pub(keyA)) {
		t.Errorf("keys %v, %v", ks, err)
	}
	if _, err := ParseJWKS([]byte("[")); err == nil {
		t.Error("not JSON accepted")
	}
}

// TestParseSecret: the secret as PantherClaw shows it, with or without the
// prefix and surrounding whitespace; an error never repeats the value.
func TestParseSecret(t *testing.T) {
	shown := ndomain.FormatSecret(secretA)
	for _, in := range []string{shown, shown + "\n", strings.TrimPrefix(shown, ndomain.SecretPrefix)} {
		if s, err := ParseSecret(in); err != nil || !bytes.Equal(s, secretA) {
			t.Errorf("ParseSecret(%q) = %q, %v", in, s, err)
		}
	}
	for _, bad := range []string{"", "whsec_", "whsec_not base64 at all!", "c2VjcmV0 c2VjcmV0"} {
		if _, err := ParseSecret(bad); err == nil || strings.Contains(err.Error(), "base64 at all") || strings.Contains(err.Error(), "c2VjcmV0") {
			t.Errorf("ParseSecret(%q) = %v", bad, err)
		}
	}
}

// TestHR662_NoSchemeNoForwarder: a forwarder that would check no signature
// is refused.
// Covers: F950
func TestHR662_NoSchemeNoForwarder(t *testing.T) {
	if _, err := New(Config{Sink: NewWriterSink(io.Discard)}); !errors.Is(err, ErrNoScheme) {
		t.Errorf("New = %v", err)
	}
	if _, err := New(Config{Secrets: [][]byte{{}}, Sink: NewWriterSink(io.Discard)}); err == nil {
		t.Error("an empty secret accepted")
	}
}

// TestHR662_NonLoopbackListenerNeedsTLS: plain HTTP is served on loopback
// only; any other address, every interface included, needs TLS.
// Covers: F950
func TestHR662_NonLoopbackListenerNeedsTLS(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:8471": true, "[::1]:8471": true, "localhost:8471": true,
		"0.0.0.0:8471": false, ":8471": false, "10.0.0.5:8471": false, "[::]:8471": false, "siem.example.net:8471": false, "8471": false,
	} {
		if Loopback(addr) != want {
			t.Errorf("Loopback(%q) = %v", addr, !want)
		}
		if want {
			continue
		}
		if err := Serve(t.Context(), http.NotFoundHandler(), ServeConfig{Listen: addr}); !errors.Is(err, ErrNeedsTLS) {
			t.Errorf("Serve(%q) = %v", addr, err)
		}
	}
}

// TestHR662_ServesHTTPSAndStops: over TLS 1.3 the forwarder takes a batch
// through the hardened server, and stops when its context ends.
// Covers: F950
func TestHR662_ServesHTTPSAndStops(t *testing.T) {
	// httptest's certificate is for 127.0.0.1; borrow it.
	tlsSrv := httptest.NewUnstartedServer(http.NotFoundHandler())
	tlsSrv.StartTLS()
	cert, leaf := tlsSrv.TLS.Certificates[0], tlsSrv.Certificate()
	tlsSrv.Close()
	out := filepath.Join(t.TempDir(), "ocsf.json")
	sink, err := OpenFile(out)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sink.Close() })
	// Started a minute ago: a timestamp in the second it started (whole
	// seconds) would be refused as possibly before it.
	fwd, err := New(Config{Secrets: [][]byte{secretA}, Sink: sink, Start: time.Now().Add(-time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	addrc, done := make(chan string, 1), make(chan error, 1)
	go func() {
		done <- Serve(ctx, fwd, ServeConfig{
			Listen: "127.0.0.1:0", TLS: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}},
			Ready: func(a string) { addrc <- a },
		})
	}()
	var addr string
	select {
	case addr = <-addrc:
	case err := <-done:
		t.Fatalf("Serve: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	body, want := batch(t, "tls-1", 2)
	ts := time.Now().Unix()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+addr+"/", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("webhook-id", "tls-1")
	req.Header.Set("webhook-timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("webhook-signature", sig([][]byte{secretA}, nil, "tls-1", ts, body))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.TLS == nil || resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("status %d, tls %v", resp.StatusCode, resp.TLS)
	}
	if got, _ := os.ReadFile(out); string(got) != want {
		t.Errorf("written %q", got)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve after cancel: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Serve did not stop")
	}
}

// blockingSink holds each Append until released, as a slow disk would.
type blockingSink struct {
	Sink
	entered, release chan struct{}
}

func (b *blockingSink) Append(p []byte) error {
	b.entered <- struct{}{}
	<-b.release
	return b.Sink.Append(p)
}

// TestHR662_StopLetsBatchesInFlightFinish: told to stop (an interrupt or
// SIGTERM ends the context) while a batch is being written, the forwarder
// finishes it, answers it 200 and only then returns, so a service manager's
// stop leaves no partial line.
// Covers: F950
func TestHR662_StopLetsBatchesInFlightFinish(t *testing.T) {
	out := filepath.Join(t.TempDir(), "ocsf.json")
	fsink, err := OpenFile(out)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fsink.Close() })
	bs := &blockingSink{Sink: fsink, entered: make(chan struct{}, 1), release: make(chan struct{})}
	fwd, err := New(Config{Secrets: [][]byte{secretA}, Sink: bs, Start: time.Now().Add(-time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	addrc, done := make(chan string, 1), make(chan error, 1)
	go func() {
		done <- Serve(ctx, fwd, ServeConfig{Listen: "127.0.0.1:0", Ready: func(a string) { addrc <- a }})
	}()
	var addr string
	select {
	case addr = <-addrc:
	case err := <-done:
		t.Fatalf("Serve: %v", err)
	}
	body, want := batch(t, "drain-1", 3)
	ts := time.Now().Unix()
	client := &http.Client{Transport: &http.Transport{}}
	t.Cleanup(client.CloseIdleConnections)
	type result struct {
		code int
		err  error
	}
	resc := make(chan result, 1)
	go func() {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+addr+"/", bytes.NewReader(body))
		if err != nil {
			resc <- result{err: err}
			return
		}
		req.Header.Set("webhook-id", "drain-1")
		req.Header.Set("webhook-timestamp", strconv.FormatInt(ts, 10))
		req.Header.Set("webhook-signature", sig([][]byte{secretA}, nil, "drain-1", ts, body))
		resp, err := client.Do(req)
		if err != nil {
			resc <- result{err: err}
			return
		}
		_ = resp.Body.Close()
		resc <- result{code: resp.StatusCode}
	}()
	select {
	case <-bs.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the batch never reached the sink")
	}
	cancel()
	select {
	case err := <-done:
		t.Fatalf("Serve returned with a batch in flight: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	close(bs.release)
	select {
	case r := <-resc:
		if r.err != nil || r.code != http.StatusOK {
			t.Errorf("the batch in flight = %d, %v", r.code, r.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the batch in flight got no answer")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve after the drain: %v", err)
		}
	case <-time.After(ShutdownGrace):
		t.Fatal("Serve did not stop")
	}
	if got, _ := os.ReadFile(out); string(got) != want {
		t.Errorf("written %q, want %q", got, want)
	}
}

// TestHR662_OpenEndsAPartialLastLine: a file left ending in part of a line
// (the forwarder killed, or the power lost, mid-write) gets a newline when
// it is opened, so the fragment stays a line of its own and the next
// batch's first event is whole. A file ending in a newline, or empty, is
// left as it is.
// Covers: F950
func TestHR662_OpenEndsAPartialLastLine(t *testing.T) {
	_, lines := batch(t, "nl-1", 2)
	for name, tc := range map[string]struct{ before, after string }{
		"fragment": {`{"class_uid":2004,"mess`, "{\"class_uid\":2004,\"mess\n"},
		"whole":    {"{}\n", "{}\n"},
		"empty":    {"", ""},
	} {
		path := filepath.Join(t.TempDir(), "ocsf.json")
		if err := os.WriteFile(path, []byte(tc.before), 0o600); err != nil {
			t.Fatal(err)
		}
		s, err := OpenFile(path)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got, _ := os.ReadFile(path); string(got) != tc.after {
			t.Errorf("%s: opened, the file holds %q, want %q", name, got, tc.after)
		}
		if err := s.Append([]byte(lines)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got, _ := os.ReadFile(path); string(got) != tc.after+lines {
			t.Errorf("%s: after a batch the file holds %q", name, got)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

// TestHR662_NewOutputFileIsOwnerOnly: the file the forwarder creates is
// its user's alone: mode 0600, or on Windows a protected access list (no
// entry inherited from the folder) allowing only that user, SYSTEM and
// Administrators.
// Covers: F950
func TestHR662_NewOutputFileIsOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ocsf.json")
	s, err := OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.Append([]byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	ownerOnly(t, path)
}

// TestLines_CompactsEachEvent: an event spread over lines becomes one
// compact line.
func TestLines_CompactsEachEvent(t *testing.T) {
	body := []byte("{\"type\":\"pantherclaw.ocsf.batch\",\"data\":{\"batch\":\"x\",\"events\":[{\n \"a\": 1,\n \"b\": \"two\\nlines\"\n}, {}]}}")
	lines, n, err := Lines(body)
	if err != nil || n != 2 || string(lines) != "{\"a\":1,\"b\":\"two\\nlines\"}\n{}\n" {
		t.Errorf("Lines = %q, %d, %v", lines, n, err)
	}
	if lines, n, err := Lines([]byte(`{"type":"pantherclaw.ocsf.batch","data":{"events":[]}}`)); err != nil || n != 0 || len(lines) != 0 {
		t.Errorf("empty batch = %q, %d, %v", lines, n, err)
	}
}
