// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"slices"
	"strings"
	"testing"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/sim/mcpsim"
)

// elicitRig is a connection whose create_refund asks for channel, with a
// run, and helpers for the question and the answer (G0 M15 D44).
type elicitRig struct {
	t   *testing.T
	h   *harness
	sim *mcpsim.Server
	run string
}

func newElicitRig(t *testing.T) *elicitRig {
	sim, opt := withSurface(t, mcpsim.Faults{}, channelField)
	h := setup(t, opt)
	sim.SetElicit(&mcpsim.Elicit{Message: "Where should the receipt go?", Schema: jsontext.Value(channelSchema), RequestState: "st-1"})
	return &elicitRig{t: t, h: h, sim: sim, run: ids.NewV7().String()}
}

// ask makes the first call and returns the handle it got.
func (r *elicitRig) ask() string {
	r.t.Helper()
	first := r.h.rawCall(r.t, "tools/call", refundArgs, "create_refund", r.run, nil)
	var handle string
	if json.Unmarshal(first.Result["requestState"], &handle) != nil || handle == "" {
		r.t.Fatalf("input_required = %+v %v", first.Error, first.Result)
	}
	return handle
}

// answer sends the retry answering channel with handle; tasks adds the
// tasks extension.
func (r *elicitRig) answer(handle, channel string, tasks bool) rawReply {
	r.t.Helper()
	body := jsonRPC("tools/call", refundArgs+`,"inputResponses":{"confirm":{"action":"accept","content":{"channel":"`+channel+`"}}},`+
		`"requestState":"`+handle+`"`)
	if tasks {
		body = withTasks(body)
	}
	return r.h.rawPost(r.t, "tools/call", body, "create_refund", r.run, nil)
}

// sent are the inputResponses the server got.
func (r *elicitRig) sent() []string {
	got, states := r.sim.InputResponses()
	out := make([]string, len(got))
	for i := range got {
		out[i] = string(got[i]) + " " + states[i]
	}
	return out
}

const emailSent = `{"confirm":{"action":"accept","content":{"channel":"email"}}} st-1`

// TestHR420_ARetryThatIsNotSentKeepsItsHandle (D44): the handle is spent
// only right before the send. A retry refused for its credentials (401)
// or held for approval leaves it as it was; the identical retry after the
// approval reuses the held action and answers the server once.
// Covers: PN-015.2
func TestHR420_ARetryThatIsNotSentKeepsItsHandle(t *testing.T) {
	r := newElicitRig(t)
	handle := r.ask()
	r.h.auth.setIdentity("use_nonce")
	if a := r.answer(handle, "email", false); a.code != 401 {
		t.Fatalf("a retry without a fresh nonce: %d %+v", a.code, a.Error)
	}
	r.h.auth.setIdentity("")
	r.h.auth.decide(pb.Decision_DECISION_REQUIRE_APPROVAL)
	held := r.answer(handle, "email", false)
	if !strings.Contains(string(held.Result["_meta"]), "io.pantherclaw/hold") || len(r.sent()) != 0 {
		t.Fatalf("a held retry: %v, sent %q", held.Result, r.sent())
	}
	heldID := r.h.auth.snap().actions[len(r.h.auth.snap().actions)-1].Action.ActionID
	r.h.auth.decide(pb.Decision_DECISION_ALLOW)
	if a := r.answer(handle, "email", false); string(a.Result["isError"]) != "false" {
		t.Fatalf("the retry after approval: %v", a.Result)
	}
	s := r.h.auth.snap()
	if id := s.actions[len(s.actions)-1].Action.ActionID; id != heldID || !slices.Equal(r.sent(), []string{emailSent}) {
		t.Fatalf("action %s, want the held %s; sent %q", id, heldID, r.sent())
	}
}

// TestHR420_AHeldRetryTaskAnswersOnResubmission (D44): a held retry from
// a client with tasks becomes a task that keeps the handle; the poll after
// the approval resubmits the decided action and answers the server with
// the stored request state. When the handle is spent or expired first,
// the task completes with "elicitation expired; call the tool again" and
// nothing more is sent.
// Covers: PN-015.2
func TestHR420_AHeldRetryTaskAnswersOnResubmission(t *testing.T) {
	for _, spent := range []bool{false, true} {
		r := newElicitRig(t)
		handle := r.ask()
		r.h.auth.decide(pb.Decision_DECISION_REQUIRE_APPROVAL)
		task := r.answer(handle, "email", true)
		var id string
		if json.Unmarshal(task.Result["taskId"], &id) != nil || string(task.Result["resultType"]) != `"task"` {
			t.Fatalf("a held retry with tasks: %+v %v", task.Error, task.Result)
		}
		r.h.auth.decide(pb.Decision_DECISION_ALLOW)
		if spent {
			// The identical retry without tasks runs first and spends it.
			if a := r.answer(handle, "email", false); string(a.Result["isError"]) != "false" {
				t.Fatalf("the other retry: %v", a.Result)
			}
		}
		poll := r.h.rawPost(t, "tasks/get", taskBody("tasks/get", id), id, r.run, nil)
		res := string(poll.Result["result"])
		switch {
		case !spent && (strings.Contains(res, `"isError":true`) || !slices.Equal(r.sent(), []string{emailSent})):
			t.Fatalf("resubmission: %v, sent %q", poll.Result, r.sent())
		case spent && (!strings.Contains(res, "elicitation_expired") || !strings.Contains(res, "elicitation expired; call the tool again") ||
			!slices.Equal(r.sent(), []string{emailSent})):
			t.Fatalf("resubmission after the handle was spent: %v, sent %q", poll.Result, r.sent())
		}
	}
}

// TestHR420_ALostClaimSendsNothing (D44): two permitted retries race for
// one handle; the one that loses the claim after its BeginDispatch is
// recorded FAILED elicitation_handle_spent, and the server is answered
// once.
// Covers: PN-015.2
func TestHR420_ALostClaimSendsNothing(t *testing.T) {
	r := newElicitRig(t)
	handle := r.ask()
	var other rawReply
	r.h.auth.mu.Lock()
	r.h.auth.onBegin = func() { other = r.answer(handle, "sms", false) }
	r.h.auth.mu.Unlock()
	lost := r.answer(handle, "email", false)
	if string(other.Result["isError"]) != "false" ||
		!strings.Contains(string(lost.Result["_meta"]), "elicitation_handle_spent") || string(lost.Result["isError"]) != "true" {
		t.Fatalf("the winner %v, the loser %v", other.Result, lost.Result)
	}
	if got := r.sent(); len(got) != 1 || !strings.Contains(got[0], `"channel":"sms"`) {
		t.Fatalf("sent %q", got)
	}
	s := r.h.auth.snap()
	outcomes := []pb.Outcome{}
	for _, rec := range s.records {
		outcomes = append(outcomes, rec.GetOutcome())
	}
	if want := []pb.Outcome{pb.Outcome_OUTCOME_FAILED, pb.Outcome_OUTCOME_ACCEPTED, pb.Outcome_OUTCOME_FAILED}; !slices.Equal(outcomes, want) {
		t.Fatalf("outcomes %v, want %v", outcomes, want)
	}
}
