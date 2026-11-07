// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package edge

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// holdRig is an edge before a fake gateway that holds every request for
// approval until approve is set, and records the action id of each.
type holdRig struct {
	agent   *http.Client
	mu      sync.Mutex
	actions []string
	approve bool
}

func newHoldRig(t *testing.T) *holdRig {
	t.Helper()
	r := &holdRig{}
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.ReadAll(req.Body)
		r.mu.Lock()
		r.actions = append(r.actions, req.Header.Get(headerAction))
		approve := r.approve
		r.mu.Unlock()
		if approve {
			w.Header().Set(headerDecision, "ALLOW")
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set(headerDecision, decisionApproval)
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(gw.Close)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	e, err := New(Options{
		Session: "0f3c", GatewayURL: gw.URL + "/", Hosts: hosts, Run: ids.NewV7().String(), Key: key, Token: func() string { return "tok" },
		Log: pclog.New(&bytes.Buffer{}, pclog.Options{}),
	})
	if err != nil {
		t.Fatal(err)
	}
	ps := httptest.NewServer(e)
	t.Cleanup(ps.Close)
	proxy, _ := url.Parse(ps.URL)
	r.agent = (&rig{edge: e, proxy: proxy}).agent()
	return r
}

func (r *holdRig) send(t *testing.T, method, u, body string) string {
	t.Helper()
	req, _ := http.NewRequestWithContext(t.Context(), method, u, strings.NewReader(body))
	res, err := r.agent.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(res.Body)
	_ = res.Body.Close()
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.actions[len(r.actions)-1]
}

// TestHR717_OnlyTheExactHeldRequestReusesItsActionID (G0 M30 D945a,
// HR-717): a request the gateway held for approval, sent again unchanged
// through the edge in the same session, carries the same action id, so the
// approval releases it; once released, the next identical request is a new
// action. A different method, URL or body gets a fresh id.
func TestHR717_OnlyTheExactHeldRequestReusesItsActionID(t *testing.T) {
	r := newHoldRig(t)
	const merge = "https://api.github.com/repos/acme/app/pulls/7/merge"
	held := r.send(t, http.MethodPut, merge, `{"sha":"abc"}`)
	if again := r.send(t, http.MethodPut, merge, `{"sha":"abc"}`); again != held {
		t.Fatalf("the same held request got %s, want %s", again, held)
	}
	for name, tc := range map[string][3]string{
		"another body":   {http.MethodPut, merge, `{"sha":"abd"}`},
		"another URL":    {http.MethodPut, "https://api.github.com/repos/acme/app/pulls/8/merge", `{"sha":"abc"}`},
		"another method": {http.MethodPost, merge, `{"sha":"abc"}`},
	} {
		if got := r.send(t, tc[0], tc[1], tc[2]); got == held {
			t.Errorf("%s reused the held action id", name)
		}
	}
	r.mu.Lock()
	r.approve = true
	r.mu.Unlock()
	if got := r.send(t, http.MethodPut, merge, `{"sha":"abc"}`); got != held {
		t.Fatalf("the approved request got %s, want %s", got, held)
	}
	if got := r.send(t, http.MethodPut, merge, `{"sha":"abc"}`); got == held {
		t.Fatal("a released action id was reused")
	}
}

// TestHR717_AHeldActionIDLapsesAfter24Hours (G0 M30 D945a, HR-717): the map
// forgets a hold after 24 hours and stays bounded.
func TestHR717_AHeldActionIDLapsesAfter24Hours(t *testing.T) {
	now := time.Now()
	h := newHeldActions()
	h.now = func() time.Time { return now }
	k := fingerprint(http.MethodPut, "https://gw/x", []byte("b"))
	id := h.action(k)
	h.answered(k, id, approval())
	if h.action(k) != id {
		t.Fatal("a fresh hold was not reused")
	}
	now = now.Add(heldTTL)
	if h.action(k) == id {
		t.Fatal("a 24-hour-old hold was reused")
	}
	for i := range maxHeld + 10 {
		kk := fingerprint(http.MethodPut, "https://gw/x", []byte{byte(i), byte(i >> 8)})
		h.answered(kk, "a", approval())
	}
	if len(h.m) > maxHeld {
		t.Fatalf("%d entries, bound %d", len(h.m), maxHeld)
	}
}

func approval() http.Header {
	h := http.Header{}
	h.Set(headerDecision, decisionApproval)
	return h
}

// TestT326_AnApprovalReleasesOnlyTheRequestItWasGivenFor (T-326): a second,
// different request sent while the first is held never takes over the
// first's action id, so approving the first cannot release it.
func TestT326_AnApprovalReleasesOnlyTheRequestItWasGivenFor(t *testing.T) {
	r := newHoldRig(t)
	const u = "https://payments.example/v1/refunds"
	first := r.send(t, http.MethodPost, u, `{"amount":100}`)
	second := r.send(t, http.MethodPost, u, `{"amount":100000}`)
	if first == second {
		t.Fatal("two different requests share an action id")
	}
	if again := r.send(t, http.MethodPost, u, `{"amount":100000}`); again != second || again == first {
		t.Fatalf("the second request resent got %s (first %s, second %s)", again, first, second)
	}
}
