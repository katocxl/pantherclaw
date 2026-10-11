// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

package client_test

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/sdk/go/client"
	"github.com/katocxl/pantherclaw/sdk/go/internal/vectors"
)

// TestConformanceExchanges: token issuance, long-polls and the SSE stream
// read as the contract says.
func TestConformanceExchanges(t *testing.T) {
	var f struct {
		Exchanges []struct {
			Name      string            `json:"name"`
			Path      string            `json:"path"`
			Status    int               `json:"status"`
			Headers   map[string]string `json:"headers"`
			Body      string            `json:"body"`
			Token     string            `json:"token"`
			ExpiresAt int64             `json:"expires_at"`
			States    []string          `json:"states"`
			Outcome   string            `json:"outcome"`
		} `json:"exchanges"`
	}
	vectors.Load(t, "sdk_face.json", &f)
	for _, e := range f.Exchanges {
		h := http.Header{}
		for k, v := range e.Headers {
			h.Set(k, v)
		}
		var states []string
		next := ""
		switch {
		case client.Retry(e.Status, h) != "":
			next = client.Retry(e.Status, h)
		case e.Outcome == "token":
			var tok struct {
				Token  string    `json:"workloadToken"`
				Expire time.Time `json:"expireTime"`
			}
			if err := json.Unmarshal([]byte(e.Body), &tok); err != nil || tok.Token != e.Token || tok.Expire.Unix() != e.ExpiresAt {
				t.Errorf("%s: %+v %v", e.Name, tok, err)
			}
			next = "token"
		case strings.HasPrefix(e.Path, "/v1/wait/"):
			err := client.ReadStream(strings.NewReader(e.Body), func(w client.WaitState) bool {
				states, next = append(states, w.State), w.Next()
				return true
			})
			if err != nil {
				t.Fatal(err)
			}
		default:
			w, _, err := client.ParseWaitResponse([]byte(e.Body))
			if err != nil {
				t.Fatalf("%s: %v", e.Name, err)
			}
			states, next = []string{w.State}, w.Next()
		}
		if next != e.Outcome || strings.Join(states, ",") != strings.Join(e.States, ",") {
			t.Errorf("%s: %s %v, want %s %v", e.Name, next, states, e.Outcome, e.States)
		}
	}
}

// heldThenReady answers a hold first, then an allow for the same action.
func heldThenReady(t *testing.T, f *fake, calls *atomic.Int32) {
	t.Helper()
	f.sdk = func(w http.ResponseWriter, r *http.Request, _ []byte) {
		if calls.Add(1) > 1 {
			allowed(w, r)
			return
		}
		id := r.Header.Get("PC-Action-Id")
		answer(w, map[string]any{
			"decision": "hold", "action_id": id, "action_hash": sha256Hex([]byte(`{"action_id":"` + id + `"}`)), "coverage": "PARTIAL",
			"mode": "enforce", "wait": map[string]any{"handle": actionID, "state": "PENDING", "retry_after_seconds": 1},
		})
	}
}

// A held call waits on the SSE stream and, once ready, is resubmitted with
// the same action id and allowed.
func TestAuthorizeAndWaitResubmitsWhenReady(t *testing.T) {
	f := newFake(t)
	var calls atomic.Int32
	heldThenReady(t, f, &calls)
	f.wait = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		handle := strings.TrimPrefix(r.URL.Path, "/v1/wait/")
		for _, s := range []string{"PENDING", "READY"} {
			_, _ = fmt.Fprintf(w, ": heartbeat\n\nevent: state\ndata: {\"handle\":%q,\"state\":%q,\"retry_after_seconds\":1}\n\n", handle, s)
		}
	}
	res := f.client(t).AuthorizeAndWait(context.Background(), "local", refund, client.NewActionID())
	if res.Outcome != client.Allow || calls.Load() != 2 {
		t.Fatalf("%s (%s %v) after %d calls", res.Outcome, res.Why, res.Err, calls.Load())
	}
}

// Without the stream, the client long-polls; a declined hold denies.
func TestAuthorizeAndWaitLongPollsAndDeniesADeclinedHold(t *testing.T) {
	f := newFake(t)
	var calls atomic.Int32
	heldThenReady(t, f, &calls)
	var polls atomic.Int32
	f.wait = func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			http.NotFound(w, r)
			return
		}
		state := "WAIT_STATE_PENDING"
		if polls.Add(1) > 1 {
			state = "WAIT_STATE_DECLINED"
		}
		answer(w, map[string]any{"wait": map[string]any{"handle": actionID, "state": state, "code": "APPROVAL_DECLINED"}, "timedOut": state == "WAIT_STATE_PENDING"})
	}
	res := f.client(t).AuthorizeAndWait(context.Background(), "local", refund, client.NewActionID())
	if res.Outcome != client.Deny || calls.Load() != 1 || polls.Load() != 2 {
		t.Fatalf("%s (%s) after %d calls and %d polls", res.Outcome, res.Why, calls.Load(), polls.Load())
	}
}

// A wait that outlives the caller's deadline cannot decide: the call does
// not run.
func TestHR200_AWaitPastTheDeadlineCannotDecide(t *testing.T) {
	f := newFake(t)
	var calls atomic.Int32
	heldThenReady(t, f, &calls)
	f.wait = func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if res := f.client(t).AuthorizeAndWait(ctx, "local", refund, client.NewActionID()); res.Outcome != client.CannotDecide {
		t.Fatalf("%s (%s)", res.Outcome, res.Why)
	}
}
