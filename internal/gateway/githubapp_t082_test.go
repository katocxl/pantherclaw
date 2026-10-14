// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"bytes"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/katocxl/pantherclaw/internal/sim/github"
)

// lockedBuffer is a log sink the gateway's goroutines share.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestT082_InstallationTokensStayWithinTheirAction is T-082 (installation
// token over-scope or leakage) against the gateway and the GitHub
// simulator. A token is never minted for a repository outside the action
// or the installation, nor with more permissions than the operation
// declares; one is never used for two actions; and its value never reaches
// the agent's answer, the execution record or the gateway's log, even at
// debug level.
func TestT082_InstallationTokensStayWithinTheirAction(t *testing.T) {
	t.Run("a repository outside the installation", func(t *testing.T) {
		w := newGitHubWorld(t)
		h := setup(t, withGitHubApp(t, w))
		r := h.do(t, http.MethodGet, "/payments/repos/acme/ledger/contents/README.md", "", nil)
		if r.code < 400 {
			t.Fatalf("a repository the App is not installed on: %d %s", r.code, r.body)
		}
		for _, req := range w.sim.Requests() {
			if req.User == "alice" {
				continue // the world's own setup
			}
			if !strings.HasSuffix(req.Path, "/access_tokens") {
				t.Fatalf("sent without a token for the repository: %+v", req)
			}
		}
		for _, tok := range w.sim.Tokens() {
			if slices.ContainsFunc(tok.Repos, func(r string) bool { return r != "acme/ledger" }) {
				t.Fatalf("a token for another repository: %+v", tok)
			}
		}
	})

	t.Run("a permission the operation does not declare", func(t *testing.T) {
		w := newGitHubWorld(t)
		h := setup(t, withGitHubApp(t, w))
		w.sim.SetFaults(github.Faults{WiderGrant: true})
		r := h.do(t, http.MethodPut, "/payments/repos/acme/payments/pulls/1/merge", `{"sha":"`+w.head+`"}`, nil)
		if r.refusal.Error != "credential_scope_mismatch" {
			t.Fatalf("a wider grant for a merge: %d %+v", r.code, r.refusal)
		}
		if p, _ := w.sim.PullRequest("acme/payments", 1); p.Merged {
			t.Fatal("merged with a wider token")
		}
		for _, tok := range w.sim.Tokens() {
			if !tok.Revoked || tok.Uses != 0 {
				t.Fatalf("the wider token %+v", tok)
			}
		}
	})

	t.Run("one token per action, never in an answer, a record or a log", func(t *testing.T) {
		w := newGitHubWorld(t)
		var logs lockedBuffer
		h := setup(t, withGitHubApp(t, w), func(h *harness) {
			h.log = slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
		})
		var answers []string
		for range 2 {
			r := h.do(t, http.MethodGet, "/payments/repos/acme/payments/contents/README.md", "", nil)
			if r.code != http.StatusOK {
				t.Fatalf("read = %d %+v", r.code, r.refusal)
			}
			answers = append(answers, r.body)
		}
		r := h.do(t, http.MethodPut, "/payments/repos/acme/payments/pulls/1/merge", `{"sha":"`+w.head+`"}`, nil)
		if r.code != http.StatusOK {
			t.Fatalf("merge = %d %+v", r.code, r.refusal)
		}
		answers = append(answers, r.body)

		tokens := w.sim.Tokens()
		if len(tokens) != 3 {
			t.Fatalf("%d tokens for 3 actions", len(tokens))
		}
		for _, tok := range tokens {
			if !tok.Revoked || tok.Uses != 1 || !slices.Equal(tok.Repos, []string{"acme/payments"}) {
				t.Fatalf("token %+v", tok)
			}
		}
		used := map[string]bool{}
		for _, req := range w.sim.Requests() {
			if !strings.HasPrefix(req.Path, "/repos/") || req.User == "alice" {
				continue
			}
			if used[req.Token] {
				t.Fatalf("a token used for two actions: %+v", req)
			}
			used[req.Token] = true
			want := map[string]string{"contents": "read", "metadata": "read"}
			if req.Method == http.MethodPut {
				want["contents"] = "write"
			}
			if !maps.Equal(req.Permissions, want) {
				t.Fatalf("%s %s went out with %v", req.Method, req.Path, req.Permissions)
			}
		}
		for i, a := range answers {
			if strings.Contains(a, "ghs_") {
				t.Fatalf("answer %d carries a token", i)
			}
		}
		// A refused wider grant, which the gateway logs, with its token
		// revoked.
		w.sim.SetFaults(github.Faults{WiderGrant: true})
		if r := h.do(t, http.MethodGet, "/payments/repos/acme/payments/contents/README.md", "", nil); r.refusal.Error != "credential_scope_mismatch" {
			t.Fatalf("a wider grant: %d %+v", r.code, r.refusal)
		}
		for _, rec := range h.auth.snap().records {
			raw, err := proto.Marshal(rec)
			if err != nil || bytes.Contains(raw, []byte("ghs_")) {
				t.Fatalf("an execution record carries a token: %v", err)
			}
		}
		if out := logs.String(); out == "" || strings.Contains(out, "ghs_") {
			t.Fatalf("the gateway's log (%d bytes) carries a token or is empty", len(out))
		}
	})
}
