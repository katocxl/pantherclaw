// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package externalchecks

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR437_BadAnswersAreUnavailable: a missing result or decision, an
// unknown decision, bad JSON and too many or too long reasons are never an
// answer.
// Covers: F366
func TestHR437_BadAnswersAreUnavailable(t *testing.T) {
	bad := []string{
		``, `null`, `{}`, `{"result": null}`, `{"result": {}}`, `{"result": {"decision": "maybe"}}`,
		`{"result": {"decision": true}}`, `{"result": {"decision": "allow", "reasons": ["a","b","c","d","e","f"]}}`,
		`{"result": {"decision": "deny", "reasons": ["` + strings.Repeat("x", MaxReasonLen+1) + `"]}}`,
		`{"result": {"decision": "allow"}`, `{"result": {"decision": "allow", "decision": "deny"}}`,
	}
	for _, raw := range bad {
		if a := Parse([]byte(raw)); a.Decision != "" || a.Unavailable != UnavailableBadAnswer {
			t.Errorf("%q: %+v, want BAD_ANSWER", raw, a)
		}
	}
	for _, d := range []string{"allow", "deny", "hold"} {
		if a := Parse([]byte(`{"result": {"decision": "` + d + `", "reasons": ["r"]}, "decision_id": "x"}`)); a.Decision != d || a.Unavailable != "" {
			t.Errorf("%s: %+v", d, a)
		}
	}
}

// TestHR437_TimeoutStatusAndInFlightCapAreUnavailable: an answer later
// than the check's timeout, a non-2xx status and a call beyond the org's
// in-flight cap give no decision.
// Covers: F366
func TestHR437_TimeoutStatusAndInFlightCapAreUnavailable(t *testing.T) {
	slow := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
		_, _ = w.Write([]byte(`{"result": {"decision": "allow"}}`))
	}))
	defer slow.Close()
	failing := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"result": {"decision": "allow"}}`, http.StatusInternalServerError)
	}))
	defer failing.Close()
	a := testAsker(slow)
	org := ids.New[ids.Org]()
	check := Check{ID: ids.NewV7(), Name: "slow", Endpoint: slow.URL, TimeoutMs: MinTimeoutMs}
	if got := a.ask(context.Background(), org, check, []byte(`{}`)); got.Unavailable != UnavailableTimeout {
		t.Errorf("slow: %+v, want TIMEOUT", got)
	}
	f := testAsker(failing)
	if got := f.ask(context.Background(), org, Check{ID: ids.NewV7(), Endpoint: failing.URL, TimeoutMs: MaxTimeoutMs}, []byte(`{}`)); got.Unavailable != UnavailableStatus {
		t.Errorf("500: %+v, want HTTP_STATUS", got)
	}
	slot := a.slot(org)
	for range MaxInFlight {
		slot <- struct{}{}
	}
	if got := a.ask(context.Background(), org, check, []byte(`{}`)); got.Unavailable != UnavailableInFlight {
		t.Errorf("over the cap: %+v, want TOO_MANY_IN_FLIGHT", got)
	}
	if got := a.ask(context.Background(), ids.New[ids.Org](), Check{ID: ids.NewV7(), Endpoint: failing.URL, TimeoutMs: 50}, []byte(`{}`)); got.Unavailable == UnavailableInFlight {
		t.Error("another org's calls count against this org's cap")
	}
}

func testAsker(srv *httptest.Server) *asker {
	return newAsker(Config{
		RootCAs:      poolOf(srv),
		AllowedAddrs: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")},
	})
}

// TestHR438_EndpointsAreAllowListedHTTPS: http, credentials, fragments,
// metadata services and anything outside the configured prefixes are
// refused; a prefix never matches a longer host.
// Covers: F366
func TestHR438_EndpointsAreAllowListedHTTPS(t *testing.T) {
	allowed := []string{"https://opa.example.com", "https://policy.example.org/v1/data/"}
	ok := []string{"https://opa.example.com/v1/data/pc", "https://opa.example.com", "https://policy.example.org/v1/data/pc/decision"}
	refused := []string{
		"http://opa.example.com/v1", "https://user:pw@opa.example.com/v1", "https://opa.example.com/v1#x",
		"https://opa.example.com.evil.test/v1", "https://other.example.com/v1", "https://policy.example.org/v2/data/x",
		"https://169.254.169.254/latest", "https://metadata.google.internal/x",
	}
	for _, u := range ok {
		if err := CheckEndpoint(u, allowed); err != nil {
			t.Errorf("%s refused: %v", u, err)
		}
	}
	for _, u := range refused {
		if err := CheckEndpoint(u, allowed); err == nil {
			t.Errorf("%s allowed", u)
		}
	}
	if err := CheckEndpoint("https://opa.example.com/v1", nil); err == nil {
		t.Error("no allowed prefixes: an endpoint passed")
	}
	if err := CheckEndpoint("https://169.254.169.254/x", []string{"https://169.254.169.254"}); err == nil {
		t.Error("a metadata address passed because a prefix allowed it")
	}
}

// TestHR439_BodyCarriesTheMeaningOnly: the input holds the action's
// meaning and the params the pipeline passed, in the pc.opa.v1 shape.
// Covers: F366
func TestHR439_BodyCarriesTheMeaningOnly(t *testing.T) {
	org := ids.New[ids.Org]()
	b, err := Body(org, pipeline.ExternalInput{
		Operation: "slack.message.post", Access: "write", DestinationClass: "public", Mode: "enforce",
		Params: map[string]any{"text": map[string]any{"bytes": 12}, "channel": "C1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{`"version":"pc.opa.v1"`, `"org":"` + org.String() + `"`, `"text":{"bytes":12}`, `"destination_class":"public"`, `"principal":{`} {
		if !strings.Contains(s, want) {
			t.Errorf("body %s lacks %s", s, want)
		}
	}
}

// TestCovers matches exact operations and prefixes ending in *.
func TestCovers(t *testing.T) {
	ops := []string{"stripe.refund.create", "slack.*"}
	for op, want := range map[string]bool{"stripe.refund.create": true, "slack.message.post": true, "stripe.refund": false, "github.pr.merge": false} {
		if Covers(ops, op) != want {
			t.Errorf("%s: want %v", op, want)
		}
	}
	if !Covers([]string{"*"}, "anything.at.all") {
		t.Error("* covers every operation")
	}
}

// TestNewCheckValidation applies the name, timeout and operation rules.
func TestNewCheckValidation(t *testing.T) {
	good := NewCheck{Name: "opa", Endpoint: "https://opa.example.com", Operations: []string{"stripe.*"}}
	in, err := good.validate()
	if err != nil || in.TimeoutMs != DefaultTimeoutMs {
		t.Fatalf("%+v %v", in, err)
	}
	for name, c := range map[string]NewCheck{
		"name":      {Name: "OPA", Operations: []string{"a.b"}},
		"slow":      {Name: "opa", TimeoutMs: 1001, Operations: []string{"a.b"}},
		"fast":      {Name: "opa", TimeoutMs: 49, Operations: []string{"a.b"}},
		"none":      {Name: "opa"},
		"pattern":   {Name: "opa", Operations: []string{"a*b"}},
		"duplicate": {Name: "opa", Operations: []string{"a.b", "a.b"}},
		"ca":        {Name: "opa", Operations: []string{"a.b"}, CAPEM: "not a certificate"},
	} {
		if _, err := c.validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func poolOf(srv *httptest.Server) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(srv.Certificate())
	return p
}
