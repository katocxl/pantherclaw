// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package cimd_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/idaccess/adapters/cimd"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
)

// TestHR628_ClientDocumentsAreCheckedAsDraft00Says (G0 M26 D402, D408.2;
// HR-628): a client id is an https URL with a path and no dot segments,
// query, fragment or userinfo; its document's client_id is exactly that
// URL, it names no secret and no client authentication but none, and its
// redirect URIs are https or http loopback without fragments.
// Covers: F913
func TestHR628_ClientDocumentsAreCheckedAsDraft00Says(t *testing.T) {
	for _, u := range []string{
		"http://c.example/app", "https://c.example", "https://c.example/", "https://c.example/a/../b", "https://c.example/a/./b",
		"https://c.example/a/..", "https://c.example/%2e%2e/b", "https://c.example/app?x=1", "https://c.example/app#f",
		"https://u:p@c.example/app",
	} {
		if cimd.ValidClientID(u) {
			t.Errorf("%s accepted", u)
		}
	}
	if !cimd.ValidClientID("https://c.example/oauth/client.json") || !cimd.ValidClientID("https://c.example:8443/c") {
		t.Fatal("a valid client id refused")
	}
	const id = "https://c.example/client.json"
	ok := `{"client_id":"` + id + `","client_name":"Editor","redirect_uris":["https://c.example/cb","http://127.0.0.1:3333/cb"],"token_endpoint_auth_method":"none"}`
	md, err := cimd.Parse([]byte(ok), id)
	if err != nil || md.Name != "Editor" || len(md.RedirectURIs) != 2 {
		t.Fatalf("a valid document: %+v %v", md, err)
	}
	for name, doc := range map[string]string{
		"another client_id":   `{"client_id":"https://c.example/other.json","redirect_uris":["https://c.example/cb"]}`,
		"no client_id":        `{"redirect_uris":["https://c.example/cb"]}`,
		"a client secret":     `{"client_id":"` + id + `","client_secret":"s","redirect_uris":["https://c.example/cb"]}`,
		"a secret expiry":     `{"client_id":"` + id + `","client_secret_expires_at":0,"redirect_uris":["https://c.example/cb"]}`,
		"client_secret_basic": `{"client_id":"` + id + `","token_endpoint_auth_method":"client_secret_basic","redirect_uris":["https://c.example/cb"]}`,
		"private_key_jwt":     `{"client_id":"` + id + `","token_endpoint_auth_method":"private_key_jwt","redirect_uris":["https://c.example/cb"]}`,
		"no redirect URIs":    `{"client_id":"` + id + `"}`,
		"an http redirect":    `{"client_id":"` + id + `","redirect_uris":["http://c.example/cb"]}`,
		"a fragment":          `{"client_id":"` + id + `","redirect_uris":["https://c.example/cb#x"]}`,
		"a custom scheme":     `{"client_id":"` + id + `","redirect_uris":["javascript:alert(1)"]}`,
		"not an object":       `[]`,
	} {
		if _, err := cimd.Parse([]byte(doc), id); !errors.Is(err, cimd.ErrDocument) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

type fixedClock struct{ now *time.Time }

func (c fixedClock) Now() time.Time { return *c.now }

var _ clock.Clock = fixedClock{}

// TestClientDocumentsAreSizeCappedAndCachedOnlyWhenValid (§4.4, §6.6).
func TestClientDocumentsAreSizeCappedAndCachedOnlyWhenValid(t *testing.T) {
	var hits atomic.Int32
	body, cc := "", "max-age=600"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", cc)
		_, _ = w.Write([]byte(strings.ReplaceAll(body, "SELF", "https://"+r.Host+r.URL.Path)))
	}))
	defer srv.Close()
	now := time.Unix(1_800_000_000, 0)
	rd := &cimd.Reader{Client: srv.Client(), CheckURL: func(string) error { return nil }, Clock: fixedClock{&now}}
	id := srv.URL + "/client.json"
	ctx := context.Background()

	body = `{"client_id":"SELF","redirect_uris":"oops"}`
	if _, err := rd.Fetch(ctx, id); err == nil {
		t.Fatal("an invalid document accepted")
	}
	body = `{"client_id":"SELF","redirect_uris":["https://c.example/cb"]}`
	if _, err := rd.Fetch(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := rd.Fetch(ctx, id); err != nil || hits.Load() != 2 {
		t.Fatalf("the invalid document was cached, or the valid one was not: %d reads", hits.Load())
	}
	now = now.Add(time.Hour + time.Second) // max-age 600 is within the hour cap; past it
	if _, err := rd.Fetch(ctx, id); err != nil || hits.Load() != 3 {
		t.Fatalf("not read again after expiry: %d", hits.Load())
	}

	cc = "no-store"
	id2 := srv.URL + "/other.json"
	for range 2 {
		if _, err := rd.Fetch(ctx, id2); err != nil {
			t.Fatal(err)
		}
	}
	if hits.Load() != 5 {
		t.Fatalf("a no-store document was cached: %d", hits.Load())
	}

	body = `{"client_id":"SELF","redirect_uris":["https://c.example/cb"],"pad":"` + strings.Repeat("x", cimd.MaxDocument) + `"}`
	if _, err := rd.Fetch(ctx, srv.URL+"/big.json"); !errors.Is(err, cimd.ErrDocument) {
		t.Fatalf("an oversized document: %v", err)
	}
}
