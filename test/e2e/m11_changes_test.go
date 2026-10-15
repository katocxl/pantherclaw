// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/authn/webauthntest"
)

// changeRequestURL finds the change request a publish that loosens the
// policy printed (M11.1 D6, D11).
var changeRequestURL = regexp.MustCompile(`/policy-changes/([0-9a-f-]{36})`)

// keyHolder is a person signed in in a browser with a security key on
// their account, as the policy changes page needs (HR-231).
type keyHolder struct {
	b   *browser
	key *webauthntest.Authenticator
}

// signInWithKey signs a person who already joined the org in and adds a
// virtual security key to their account.
func signInWithKey(t *testing.T, s *stack, people *m2Stack, subject, email string) keyHolder {
	t.Helper()
	b := newBrowser(people)
	b.signIn(t, s.org.String(), subject, email, true)
	key, err := webauthntest.New(s.apiURL, "localhost", webauthntest.ES256)
	if err != nil {
		t.Fatal(err)
	}
	code, body := b.post(t, "/account/keys/registration-options", map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("registration options: %d %v", code, body)
	}
	resp, err := key.Register(body["options"])
	if err != nil {
		t.Fatal(err)
	}
	if code, body = b.post(t, "/account/keys", map[string]any{"ceremony": body["ceremony"], "name": "Desk key", "response": jsontext.Value(resp)}); code != http.StatusOK {
		t.Fatalf("add key: %d %v", code, body)
	}
	return keyHolder{b: b, key: key}
}

// confirmChange confirms a change request on its page with the person's
// key, as the page's script does, and returns the request's state.
func (k keyHolder) confirmChange(t *testing.T, id string) string {
	t.Helper()
	path := "/policy-changes/" + id
	if code, page := k.b.page(t, path); code != http.StatusOK {
		t.Fatalf("change request page: %d %s", code, page)
	}
	code, body := k.b.post(t, path+"/confirm-options", map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("confirm options: %d %v", code, body)
	}
	resp, err := k.key.Assert(body["options"])
	if err != nil {
		t.Fatal(err)
	}
	code, out := k.b.post(t, path+"/confirm", map[string]any{"ceremony": body["ceremony"], "response": jsontext.Value(resp)})
	if code != http.StatusOK {
		t.Fatalf("confirm: %d %v", code, out)
	}
	var state string
	if err := json.Unmarshal(out["state"], &state); err != nil {
		t.Fatal(err)
	}
	return state
}

// repoRuleIDOf is a template's per-repository rule id, as pclaw makes it
// (repoRuleID): the base, the repository as a slug and 6 hex of its hash.
func repoRuleIDOf(base, repo string) string {
	slug := []byte(strings.ToLower(repo))
	for i, c := range slug {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			slug[i] = '-'
		}
	}
	sum := sha256.Sum256([]byte(repo))
	id := base + "--" + string(slug)
	if hash := "-" + hex.EncodeToString(sum[:])[:6]; len(id)+len(hash) > 64 {
		id = id[:64-len(hash)] + hash
	} else {
		id += hash
	}
	return id
}
