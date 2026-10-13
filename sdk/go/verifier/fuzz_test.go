// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

package verifier_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/sdk/go/internal/vectors"
	"github.com/katocxl/pantherclaw/sdk/go/verifier"
)

// FuzzActionTokenVerifier: whatever token and body arrive, the verifier
// never panics, and only the token PantherClaw minted, with its exact
// body, verifies.
func FuzzActionTokenVerifier(f *testing.F) {
	var file tokenFile
	vectors.Load(f, "action_tokens.json", &file)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(file.JWKS) }))
	f.Cleanup(srv.Close)
	good := file.Cases[0]
	for _, c := range file.Cases {
		f.Add(c.Token, c.Body)
	}
	f.Fuzz(func(t *testing.T, token, body string) {
		v, err := verifier.New(verifier.Config{
			JWKSURL: srv.URL, Issuer: good.Issuer, Audience: good.Audience, Store: verifier.NewMemoryStore(0, time.Unix(good.Now-3600, 0)),
			Now: func() time.Time { return time.Unix(good.Now, 0) },
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = v.Verify(context.Background(), token, []byte(body), good.match)
		if err == nil && (body != good.Body || !sameToken(token, good.Token, file.Cases)) {
			t.Fatalf("a token PantherClaw did not mint for this body verified: %q %q", token, body)
		}
	})
}

// sameToken reports whether token is one of the tokens the vectors expect
// to verify for the minted body.
func sameToken(token, minted string, cases []tokenCase) bool {
	if token == minted {
		return true
	}
	for _, c := range cases {
		if c.Expect == "ok" && c.Token == token {
			return true
		}
	}
	return false
}
