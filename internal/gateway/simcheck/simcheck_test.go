// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package simcheck

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/sim/payments"
)

func client(t *testing.T, base string) *egress.Client {
	t.Helper()
	cl, err := egress.NewClient(base, 5*time.Second, 0, []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
	if err != nil {
		t.Fatal(err)
	}
	return cl
}

func TestVerifyAcceptsASimulatorAndCaches(t *testing.T) {
	var hits atomic.Int32
	sim := payments.New(payments.Faults{}, pclog.Discard()).Handler()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("the handshake carried a credential")
		}
		sim.ServeHTTP(w, r)
	}))
	defer ts.Close()
	c := New()
	now := time.Now()
	c.now = func() time.Time { return now }
	cl := client(t, ts.URL)
	for range 3 {
		if err := c.Verify(t.Context(), "conn", ts.URL, cl); err != nil {
			t.Fatal(err)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("%d handshakes, want 1 within the TTL", hits.Load())
	}
	now = now.Add(TTL + time.Second)
	if err := c.Verify(t.Context(), "conn", ts.URL, cl); err != nil || hits.Load() != 2 {
		t.Fatalf("no re-check after the TTL: %v %d", err, hits.Load())
	}
}

func TestVerifyRefusesWhatIsNotASimulator(t *testing.T) {
	good := payments.New(payments.Faults{}, pclog.Discard()).Handler()
	for name, h := range map[string]http.Handler{
		"plain 404":         http.NotFoundHandler(),
		"200 without proof": http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("{}")) }),
		"no header": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec := httptest.NewRecorder()
			good.ServeHTTP(rec, r)
			_, _ = w.Write(rec.Body.Bytes())
		}),
		"wrong nonce": http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Simulated", "true")
			_, _ = w.Write([]byte(`{"simulator":"pantherclaw-sim","kind":"mcp","nonce":"00000000000000000000000000000000"}`))
		}),
		"wrong kind": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Simulated", "true")
			_, _ = w.Write([]byte(`{"simulator":"pantherclaw-sim","kind":"bank","nonce":"` + r.URL.Query().Get("nonce") + `"}`))
		}),
	} {
		ts := httptest.NewServer(h)
		err := New().Verify(t.Context(), "c", ts.URL, client(t, ts.URL))
		if !errors.Is(err, ErrUnverified) {
			t.Errorf("%s: %v", name, err)
		}
		ts.Close()
	}
}

func TestVerifyRefusesAnUnreachableTarget(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	url := ts.URL
	cl := client(t, url)
	ts.Close()
	if err := New().Verify(t.Context(), "c", url, cl); !errors.Is(err, ErrUnverified) {
		t.Fatal(err)
	}
}

func TestHR221_TheGatewayRechecksTheLiteral(t *testing.T) {
	ts := httptest.NewServer(payments.New(payments.Faults{}, pclog.Discard()).Handler())
	defer ts.Close()
	cl := client(t, ts.URL)
	c := New()
	if err := c.Verify(t.Context(), "c", ts.URL, cl); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		"https://api.stripe.com", "http://localhost:8080", "http://example.com", "http://8.8.8.8", "http://[2001:db8::1]",
		"http://169.254.169.254", "http://0.0.0.0", "http://user@127.0.0.1", "ftp://127.0.0.1", "http://[fe80::1%25eth0]",
		"http://127.0.0.1.nip.io", "http://2130706433", "", "://",
	} {
		if err := c.Verify(t.Context(), "c", bad, cl); !errors.Is(err, ErrUnverified) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	for _, good := range []string{"http://127.0.0.1:1", "http://[::1]:1", "http://10.1.2.3", "http://172.16.0.1", "http://172.31.255.255", "http://192.168.1.1", "http://[fd00::1]", "https://[::ffff:127.0.0.1]"} {
		if _, err := LocalLiteral(good); err != nil {
			t.Errorf("%q: %v", good, err)
		}
	}
	for _, bad := range []string{"http://172.32.0.1", "http://11.0.0.1", "http://[fe00::1]", "http://192.169.0.1"} {
		if _, err := LocalLiteral(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	// A verified connection whose literal changed is not served from the cache.
	if err := c.Verify(t.Context(), "c", "https://api.stripe.com", cl); err == nil {
		t.Fatal("cached success reused for another base URL")
	}
}
