// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

package verifier_test

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/sdk/go/internal/vectors"
	"github.com/katocxl/pantherclaw/sdk/go/pap"
	"github.com/katocxl/pantherclaw/sdk/go/verifier"
)

type tokenCase struct {
	Name       string `json:"name"`
	Token      string `json:"token"`
	Body       string `json:"body"`
	Operation  string `json:"operation"`
	TargetType string `json:"target_type"`
	TargetID   string `json:"target_id"`
	Issuer     string `json:"issuer"`
	Audience   string `json:"audience"`
	Now        int64  `json:"now"`
	Store      string `json:"store"`
	Twice      bool   `json:"twice"`
	ThenValid  bool   `json:"then_valid"`
	Expect     string `json:"expect"`
}

type tokenFile struct {
	JWKS  jsontext.Value `json:"jwks"`
	Cases []tokenCase    `json:"cases"`
}

// keys serves the vectors' JWKS and counts the fetches.
type keys struct {
	srv     *httptest.Server
	fetches atomic.Int32
}

func load(t *testing.T) (tokenFile, *keys) {
	t.Helper()
	var f tokenFile
	vectors.Load(t, "action_tokens.json", &f)
	k := &keys{}
	k.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		k.fetches.Add(1)
		_, _ = w.Write(f.JWKS)
	}))
	t.Cleanup(k.srv.Close)
	return f, k
}

type failing struct{}

func (failing) Use(context.Context, verifier.Spend) (bool, error) {
	return false, errors.New("unreachable")
}
func (failing) Shared() bool { return true }

func (c tokenCase) verifier(t *testing.T, k *keys, store verifier.ReplayStore) *verifier.Verifier {
	t.Helper()
	if store == nil {
		// A store that began recording before any vector's token.
		store = verifier.NewMemoryStore(0, time.Unix(c.Now-3600, 0))
	}
	if c.Store == "unavailable" {
		store = failing{}
	}
	v, err := verifier.New(verifier.Config{
		JWKSURL: k.srv.URL, Issuer: c.Issuer, Audience: c.Audience, Store: store, Now: func() time.Time { return time.Unix(c.Now, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func (c tokenCase) match(cl verifier.Claims) bool {
	return cl.PAP.Op == c.Operation && cl.PAP.Target.Type == c.TargetType && cl.PAP.Target.ID == c.TargetID
}

// TestHR202_ConformanceActionTokens: every refusal code of the shared
// vectors, the same answers PantherClaw's payments simulator gives
// (internal/conformance/gen runs it over the same file).
func TestHR202_ConformanceActionTokens(t *testing.T) {
	f, k := load(t)
	valid := f.Cases[0]
	for _, c := range f.Cases {
		v := c.verifier(t, k, nil)
		_, err := v.Verify(context.Background(), c.Token, []byte(c.Body), c.match)
		if c.Twice {
			if err != nil {
				t.Fatalf("%s: first presentation: %v", c.Name, err)
			}
			_, err = v.Verify(context.Background(), c.Token, []byte(c.Body), c.match)
		}
		got := string(verifier.CodeOf(err))
		if got == "" {
			got = "ok"
		}
		if got != c.Expect {
			t.Errorf("%s: %s (%v), want %s", c.Name, got, err, c.Expect)
		}
		if c.ThenValid {
			// Verify before insert: the refusal left the token unspent.
			if _, err := v.Verify(context.Background(), c.Token, []byte(valid.Body), valid.match); err != nil {
				t.Errorf("%s: the valid request after the refusal: %v", c.Name, err)
			}
		}
	}
}

// route is a refunds handler behind the middleware; ran counts its runs.
func route(t *testing.T, c tokenCase, k *keys, store verifier.ReplayStore, ran *int) http.Handler {
	t.Helper()
	v := c.verifier(t, k, store)
	match := func(r *http.Request, cl verifier.Claims) bool {
		return r.Method == http.MethodPost && r.URL.Path == "/v1/refunds" && c.match(cl)
	}
	return v.Middleware(match, 0, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := verifier.FromContext(r.Context()); !ok {
			t.Error("the handler ran without verified claims")
		}
		*ran++
		w.WriteHeader(http.StatusCreated)
	}))
}

func post(h http.Handler, token, body string) (int, string) {
	r := httptest.NewRequest(http.MethodPost, "/v1/refunds", strings.NewReader(body))
	if token != "" {
		r.Header.Set(pap.HeaderAction, token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code, w.Body.String()
}

// TestHR202_RefusesBeforeTheHandlerRuns: every refusal answers with its
// status and code before the handler runs; the token itself runs once.
func TestHR202_RefusesBeforeTheHandlerRuns(t *testing.T) {
	f, k := load(t)
	for _, c := range f.Cases {
		ran := 0
		h := route(t, c, k, nil, &ran)
		status, body := post(h, c.Token, c.Body)
		if c.Twice {
			status, body = post(h, c.Token, c.Body)
		}
		want := map[string]int{"ok": http.StatusCreated, "replayed": http.StatusConflict, "store_unavailable": http.StatusServiceUnavailable}[c.Expect]
		if want == 0 {
			want = http.StatusUnauthorized
		}
		runs := map[bool]int{true: 1, false: 0}[c.Expect == "ok" || c.Twice]
		if status != want || ran != runs || (c.Expect != "ok" && !strings.Contains(body, `"code":"`+c.Expect+`"`)) {
			t.Errorf("%s: HTTP %d %s, handler ran %d times", c.Name, status, body, ran)
		}
	}
}

// TestHR202_StoresRefuseWhatTheyCannotRecord: a full memory store, one
// that began recording after the token was issued (a restart), and an
// unreachable store all give 503, never a run; entries are kept until exp
// plus the skew.
func TestHR202_StoresRefuseWhatTheyCannotRecord(t *testing.T) {
	f, k := load(t)
	c := f.Cases[0]
	ran := 0
	iat := time.Unix(c.Now-10, 0)
	full := verifier.NewMemoryStore(1, iat.Add(-time.Minute))
	if ok, err := full.Use(context.Background(), verifier.Spend{ID: "other", IssuedAt: iat, Now: iat, Until: iat.Add(65 * time.Second)}); !ok || err != nil {
		t.Fatal(ok, err)
	}
	for name, store := range map[string]verifier.ReplayStore{
		"full":      full,
		"restarted": verifier.NewMemoryStore(0, iat.Add(time.Minute)),
		"down":      failing{},
	} {
		if status, _ := post(route(t, c, k, store, &ran), c.Token, c.Body); status != http.StatusServiceUnavailable || ran != 0 {
			t.Errorf("%s store: HTTP %d, handler ran %d times", name, status, ran)
		}
	}
	m := verifier.NewMemoryStore(1, iat.Add(-time.Minute))
	until := iat.Add(65 * time.Second)
	if ok, _ := m.Use(context.Background(), verifier.Spend{ID: "a", IssuedAt: iat, Now: iat, Until: until}); !ok {
		t.Fatal("first use refused")
	}
	if _, err := m.Use(context.Background(), verifier.Spend{ID: "b", IssuedAt: iat, Now: until, Until: until.Add(time.Minute)}); !errors.Is(err, verifier.ErrStoreFull) {
		t.Fatalf("an entry was evicted at its keeping time: %v", err)
	}
	if ok, err := m.Use(context.Background(), verifier.Spend{ID: "b", IssuedAt: iat, Now: until.Add(time.Second), Until: until.Add(time.Minute)}); !ok || err != nil {
		t.Fatalf("after the keeping time: %v %v", ok, err)
	}
}

// TestHR202_UnknownKeysRefetchAtMostOnceAMinute: a token under a kid the
// JWKS does not hold refetches it, but not more than once a minute.
func TestHR202_UnknownKeysRefetchAtMostOnceAMinute(t *testing.T) {
	f, k := load(t)
	var stranger tokenCase
	for _, c := range f.Cases {
		if strings.Contains(c.Name, "not in the JWKS") {
			stranger = c
		}
	}
	now := stranger.Now
	v, err := verifier.New(verifier.Config{
		JWKSURL: k.srv.URL, Issuer: stranger.Issuer, Audience: stranger.Audience, Store: &verifier.MemoryStore{},
		Now: func() time.Time { return time.Unix(now, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	for range 5 {
		_, _ = v.Verify(context.Background(), stranger.Token, []byte(stranger.Body), stranger.match)
	}
	if k.fetches.Load() != 1 {
		t.Fatalf("%d fetches within a second", k.fetches.Load())
	}
	now += 61
	_, _ = v.Verify(context.Background(), stranger.Token, []byte(stranger.Body), stranger.match)
	if k.fetches.Load() != 2 {
		t.Fatalf("%d fetches after a minute", k.fetches.Load())
	}
}

// TestHR024_TheTargetVerifierMakesACooperativeRouteVerifiable: behind the
// middleware a request reaches the target only with the token PantherClaw
// minted for exactly its bytes, so an agent that skips PantherClaw (its SDK
// hook or the gateway) changes nothing there; a body one byte off is
// refused; and a verifier on the memory store declares itself
// single-replica, so it cannot back an enforced claim for more replicas.
func TestHR024_TheTargetVerifierMakesACooperativeRouteVerifiable(t *testing.T) {
	f, k := load(t)
	c := f.Cases[0]
	ran := 0
	h := route(t, c, k, nil, &ran)
	if s, _ := post(h, "", c.Body); s != http.StatusUnauthorized || ran != 0 {
		t.Fatal("a request that skipped PantherClaw ran")
	}
	if s, _ := post(h, c.Token, c.Body+" "); s != http.StatusUnauthorized || ran != 0 {
		t.Fatal("a body one byte off ran")
	}
	if s, _ := post(h, c.Token, c.Body); s != http.StatusCreated || ran != 1 {
		t.Fatal("PantherClaw's token was refused")
	}
	if !c.verifier(t, k, verifier.NewMemoryStore(0, time.Time{})).SingleReplica() || c.verifier(t, k, &verifier.SQLStore{DB: openFake(t)}).SingleReplica() {
		t.Fatal("the replica declaration is wrong")
	}
}

// TestT081_ReplicasSharingAStoreSpendATokenOnce: a token spent at one
// replica is refused (409) at another that shares the SQL replay store.
func TestT081_ReplicasSharingAStoreSpendATokenOnce(t *testing.T) {
	f, k := load(t)
	c := f.Cases[0]
	db := openFake(t)
	ran := 0
	a := route(t, c, k, &verifier.SQLStore{DB: db}, &ran)
	b := route(t, c, k, &verifier.SQLStore{DB: db, Dialect: verifier.SQLite}, &ran)
	if s, _ := post(a, c.Token, c.Body); s != http.StatusCreated {
		t.Fatalf("the first replica: HTTP %d", s)
	}
	if s, _ := post(b, c.Token, c.Body); s != http.StatusConflict || ran != 1 {
		t.Fatalf("the second replica: HTTP %d, handler ran %d times", s, ran)
	}
	if n, err := (&verifier.SQLStore{DB: db}).Purge(context.Background(), time.Unix(c.Now+3600, 0)); err != nil || n != 1 {
		t.Fatalf("purge: %d %v", n, err)
	}
}

// TestHR202_ARestartRefusesTokensItMayHaveSpent: a memory store refuses
// tokens issued before it began recording plus the skew, since one issued
// by an Authority clock a little ahead may have been spent before a
// restart; a store with no start time begins at its first use.
func TestHR202_ARestartRefusesTokensItMayHaveSpent(t *testing.T) {
	started := time.Unix(1_791_201_600, 0)
	m := verifier.NewMemoryStore(0, started)
	spend := func(s *verifier.MemoryStore, iat time.Time) error {
		_, err := s.Use(context.Background(), verifier.Spend{Audience: "a", ID: iat.String(), IssuedAt: iat, Now: started.Add(time.Minute), Until: iat.Add(65 * time.Second)})
		return err
	}
	for _, d := range []time.Duration{-time.Minute, -verifier.Skew, 0, verifier.Skew - time.Second} {
		if err := spend(m, started.Add(d)); !errors.Is(err, verifier.ErrStoreRestarted) {
			t.Errorf("issued %v after the start: %v", d, err)
		}
	}
	if err := spend(m, started.Add(verifier.Skew)); err != nil {
		t.Errorf("issued %v after the start: %v", verifier.Skew, err)
	}
	var zero verifier.MemoryStore
	if _, err := zero.Use(context.Background(), verifier.Spend{ID: "x", IssuedAt: started, Now: started, Until: started.Add(time.Minute)}); !errors.Is(err, verifier.ErrStoreRestarted) {
		t.Errorf("a store without a start time accepted a token issued before its first use: %v", err)
	}
}

// TestHR202_TheReplayStoreKeysByAudienceAndID: one store can serve several
// targets; a jti is spent once per audience.
func TestHR202_TheReplayStoreKeysByAudienceAndID(t *testing.T) {
	iat := time.Unix(1_791_201_600, 0)
	m := verifier.NewMemoryStore(0, iat.Add(-time.Hour))
	use := func(aud string) bool {
		ok, err := m.Use(context.Background(), verifier.Spend{Audience: aud, ID: "jti", IssuedAt: iat, Now: iat, Until: iat.Add(time.Minute)})
		return ok && err == nil
	}
	if !use("a") || !use("b") || use("a") {
		t.Fatal("the store does not key by audience and id")
	}
}

// TestHR202_TheJWKSComesOverTLSWithoutRedirects: a JWKS URL in clear text
// to another machine is refused, and a redirect is never followed, so the
// keys cannot come from anyone on the way.
func TestHR202_TheJWKSComesOverTLSWithoutRedirects(t *testing.T) {
	f, k := load(t)
	c := f.Cases[0]
	for _, u := range []string{"http://pantherclaw.example.test/jwks.json", "http://10.0.0.1/jwks.json", "https://user@pantherclaw.example.test/jwks.json"} {
		if _, err := verifier.New(verifier.Config{JWKSURL: u, Issuer: c.Issuer, Audience: c.Audience, Store: failing{}}); err == nil {
			t.Errorf("%s accepted", u)
		}
	}
	redirect := httptest.NewServer(http.RedirectHandler(k.srv.URL, http.StatusFound))
	t.Cleanup(redirect.Close)
	v, err := verifier.New(verifier.Config{
		JWKSURL: redirect.URL, Issuer: c.Issuer, Audience: c.Audience, Store: verifier.NewMemoryStore(0, time.Unix(c.Now-3600, 0)),
		Client: &http.Client{}, Now: func() time.Time { return time.Unix(c.Now, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = v.Verify(context.Background(), c.Token, []byte(c.Body), c.match)
	if verifier.CodeOf(err) != verifier.StoreUnavailable || k.fetches.Load() != 0 {
		t.Fatalf("%v; the redirect was followed %d times", err, k.fetches.Load())
	}
}

// TestHR202_OneJWKSFetchAtATime: verifications that find the keys stale
// share one fetch.
func TestHR202_OneJWKSFetchAtATime(t *testing.T) {
	f, _ := load(t)
	c := f.Cases[0]
	var fetches atomic.Int32
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		time.Sleep(100 * time.Millisecond)
		_, _ = w.Write(f.JWKS)
	}))
	t.Cleanup(slow.Close)
	v, err := verifier.New(verifier.Config{
		JWKSURL: slow.URL, Issuer: c.Issuer, Audience: c.Audience, Store: verifier.NewMemoryStore(0, time.Unix(c.Now-3600, 0)),
		Now: func() time.Time { return time.Unix(c.Now, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 8)
	for range 8 {
		go func() {
			_, err := v.Verify(context.Background(), c.Token, []byte(c.Body), func(verifier.Claims) bool { return false })
			done <- err
		}()
	}
	for range 8 {
		if err := <-done; verifier.CodeOf(err) != verifier.OperationMismatch {
			t.Errorf("%v", err)
		}
	}
	if fetches.Load() != 1 {
		t.Fatalf("%d fetches", fetches.Load())
	}
}
