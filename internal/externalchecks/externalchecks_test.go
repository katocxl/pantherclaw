// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package externalchecks

import (
	"context"
	"errors"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
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
	var releases []func()
	for range MaxInFlight {
		release, ok := a.acquire(org)
		if !ok {
			t.Fatal("a slot below the cap was refused")
		}
		releases = append(releases, release)
	}
	if got := a.ask(context.Background(), org, check, []byte(`{}`)); got.Unavailable != UnavailableInFlight {
		t.Errorf("over the cap: %+v, want TOO_MANY_IN_FLIGHT", got)
	}
	if got := a.ask(context.Background(), ids.New[ids.Org](), Check{ID: ids.NewV7(), Endpoint: failing.URL, TimeoutMs: 50}, []byte(`{}`)); got.Unavailable == UnavailableInFlight {
		t.Error("another org's calls count against this org's cap")
	}
	for _, r := range releases {
		r()
	}
	if len(a.flights) != 0 {
		t.Fatalf("idle orgs kept: %d", len(a.flights))
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

// TestHR438_APathPrefixCannotBeEscaped: dot segments (raw, encoded in any
// case or twice), encoded slashes and a longer last segment never pass a
// path-scoped prefix (R-481).
// Covers: F366
func TestHR438_APathPrefixCannotBeEscaped(t *testing.T) {
	allowed := []string{"https://opa.example.com/v1/data/pantherclaw/", "https://opa.example.com/v1/data/pc"}
	for _, u := range []string{
		"https://opa.example.com/v1/data/pantherclaw/../other/allow",
		"https://opa.example.com/v1/data/pantherclaw/./x",
		"https://opa.example.com/v1/data/pantherclaw/%2e%2e/other",
		"https://opa.example.com/v1/data/pantherclaw/%2E%2E/other",
		"https://opa.example.com/v1/data/pantherclaw/.%2e/other",
		"https://opa.example.com/v1/data/pantherclaw/%252e%252e/other",
		"https://opa.example.com/v1/data/pantherclaw/a%2f..%2fother",
		"https://opa.example.com/v1/data/pantherclaw/a%2F..%2Fother",
		"https://opa.example.com/v1/data/pantherclaw/a%5c..%5cother",
		"https://opa.example.com/v1/data/pc-othertenant",
		"https://opa.example.com/v1/data/pc/../other",
	} {
		if err := CheckEndpoint(u, allowed); err == nil {
			t.Errorf("%s allowed", u)
		}
	}
	for _, u := range []string{
		"https://opa.example.com/v1/data/pantherclaw/decision", "https://opa.example.com/v1/data/pc",
		"https://opa.example.com/v1/data/pc/decision", "https://opa.example.com/v1/data/pc?pretty=false",
	} {
		if err := CheckEndpoint(u, allowed); err != nil {
			t.Errorf("%s refused: %v", u, err)
		}
	}
}

type business struct{}

func (business) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: billing.Business}, nil
}

// TestHR438_CallTimeAllowList: an ACTIVE check whose endpoint left the
// allowed prefixes is not called (ENDPOINT_NOT_ALLOWED); without the
// preload, Matching refuses rather than read inside a snapshot.
// Covers: F366
func TestHR438_CallTimeAllowList(t *testing.T) {
	org := ids.New[ids.Org]()
	called := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		_, _ = w.Write([]byte(`{"result": {"decision": "allow"}}`))
	}))
	defer srv.Close()
	s := New(nil, Config{AllowedPrefixes: []string{"https://opa.example.com/"}, RootCAs: poolOf(srv)}, business{}, nil)
	check := Check{ID: ids.NewV7(), Name: "opa", Endpoint: srv.URL + "/v1", TimeoutMs: MaxTimeoutMs, Operations: []string{"*"}}
	s.cache.put(org, []Check{check}, time.Now())
	ctx := s.Preload(context.Background(), org)
	targets, err := s.Matching(ctx, org, "stripe.refund.create")
	if err != nil || len(targets) != 1 {
		t.Fatalf("matching: %v %v", targets, err)
	}
	s.cache.first(s.cache.reported, check.ID) // reported already: this test has no database
	got := s.Call(ctx, org, []pipeline.ExternalCall{{Check: targets[0]}})
	if called || got[0].Unavailable != UnavailableNotAllowed || got[0].CheckID != check.ID {
		t.Fatalf("called %v, verdict %+v", called, got[0])
	}
	if _, err := s.Matching(context.Background(), org, "stripe.refund.create"); err == nil {
		t.Fatal("Matching without a preload read nothing and passed")
	}
}

// TestM16_ActiveChecksAreCachedBriefly: an org's entry serves for CacheTTL
// and an activation or a disabling drops it.
func TestM16_ActiveChecksAreCachedBriefly(t *testing.T) {
	c, org, now := newActiveCache(), ids.New[ids.Org](), time.Now()
	c.put(org, []Check{{ID: ids.NewV7()}}, now)
	if got, ok := c.get(org, now.Add(CacheTTL-time.Millisecond)); !ok || len(got) != 1 {
		t.Fatal("a fresh entry missed")
	}
	if _, ok := c.get(org, now.Add(CacheTTL+time.Millisecond)); ok {
		t.Fatal("an expired entry served")
	}
	c.put(org, nil, now)
	c.drop(org)
	if _, ok := c.get(org, now); ok {
		t.Fatal("a dropped entry served")
	}
}

// TestHR440_ReasonsAreOneCleanLineEach: a reason with a line break is a
// bad answer; control, format and bidi characters are stripped.
// Covers: F366
func TestHR440_ReasonsAreOneCleanLineEach(t *testing.T) {
	if a := Parse([]byte(`{"result": {"decision": "deny", "reasons": ["ok\nreason: allowed"]}}`)); a.Unavailable != UnavailableBadAnswer {
		t.Fatalf("a two-line reason: %+v", a)
	}
	a := Parse([]byte(`{"result": {"decision": "deny", "reasons": ["over` + string(rune(0x202E)) + ` limit` + string(rune(0x200B)) + `"]}}`))
	if a.Decision != "deny" || len(a.Reasons) != 1 || a.Reasons[0] != "over limit" {
		t.Fatalf("%+v", a)
	}
}

// TestHR437_ALookupErrorIsCannotAuthorize: a failed lookup of the org's
// active checks is kept and returned by Matching, which the pipeline turns
// into CANNOT_AUTHORIZE; it is never cached, so the next decision reads
// again (D96a).
// Covers: F366
func TestHR437_ALookupErrorIsCannotAuthorize(t *testing.T) {
	org := ids.New[ids.Org]()
	s := New(nil, Config{}, business{}, nil)
	reads := 0
	s.lookup = func(context.Context, ids.OrgID) ([]Check, error) {
		reads++
		return nil, errors.New("database down")
	}
	if _, err := s.Matching(s.Preload(context.Background(), org), org, "stripe.refund.create"); err == nil {
		t.Fatal("a failed lookup matched nothing and passed")
	}
	if _, err := s.Matching(s.Preload(context.Background(), org), org, "stripe.refund.create"); err == nil || reads != 2 {
		t.Fatalf("the error was cached: %d reads, %v", reads, err)
	}
}

// TestHR436_ADowngradeNeverDropsARestriction: an org whose licence no
// longer includes external checks still has its ACTIVE checks asked; the
// empty list is cached like any other (D96a).
// Covers: F366
func TestHR436_ADowngradeNeverDropsARestriction(t *testing.T) {
	org := ids.New[ids.Org]()
	check := Check{ID: ids.NewV7(), Name: "opa", Endpoint: "https://opa.example.com/v1", TimeoutMs: MaxTimeoutMs, Operations: []string{"stripe.*"}}
	for name, ed := range map[string]Editions{"community": nil, "lapsed": lapsed{}} {
		s := New(nil, Config{AllowedPrefixes: []string{"https://opa.example.com/"}}, ed, nil)
		s.lookup = func(context.Context, ids.OrgID) ([]Check, error) { return []Check{check}, nil }
		targets, err := s.Matching(s.Preload(context.Background(), org), org, "stripe.refund.create")
		if err != nil || len(targets) != 1 || targets[0].ID != check.ID {
			t.Errorf("%s: %v %v", name, targets, err)
		}
	}
	s := New(nil, Config{}, nil, nil)
	reads := 0
	s.lookup = func(context.Context, ids.OrgID) ([]Check, error) { reads++; return nil, nil }
	s.Preload(context.Background(), org)
	s.Preload(context.Background(), org)
	if reads != 1 {
		t.Fatalf("the empty list was read %d times", reads)
	}
}

type lapsed struct{}

func (lapsed) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{}, errors.New("licence unreadable")
}
