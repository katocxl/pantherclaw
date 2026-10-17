// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// TestM14_SuccessCheck: a 2xx answer must carry the success value the
// definition names; otherwise the outcome is FAILED with the answer's own
// error string as a sanitized code, or target_answer_failed (G0 M14 D8).
func TestM14_SuccessCheck(t *testing.T) {
	d := &defs.Definition{Dispatch: &defs.Dispatch{HTTP: &defs.HTTPDispatch{Success: &defs.SuccessCheck{Field: "ok", Equals: true}}}}
	accepted := pb.Outcome_OUTCOME_ACCEPTED
	for body, want := range map[string]string{
		`{"ok":true,"ts":"1"}`:                     "",
		`{"ok":false,"error":"channel_not_found"}`: "channel_not_found",
		`{"ok":false,"error":"Not In Channel!"}`:   "not_in_channel",
		`{"ok":false}`:                             CodeAnswerFailed,
		`{"ok":"true"}`:                            CodeAnswerFailed,
		`{"error":"invalid_auth"}`:                 "invalid_auth",
		`not json`:                                 CodeAnswerFailed,
		`{"ok":false,"error":""}`:                  CodeAnswerFailed,
	} {
		o, class, code := checkSuccess(d, accepted, []byte(body))
		if code != want || (want == "") != (o == accepted) || (want != "" && class != ToolFailed) {
			t.Errorf("%s: %s %s %q", body, o, class, code)
		}
	}
	if o, _, _ := checkSuccess(d, pb.Outcome_OUTCOME_FAILED, []byte(`{"ok":true}`)); o != pb.Outcome_OUTCOME_FAILED {
		t.Error("a refused answer became accepted")
	}
	if o, _, _ := checkSuccess(&defs.Definition{Dispatch: &defs.Dispatch{HTTP: &defs.HTTPDispatch{}}}, accepted, []byte(`{}`)); o != accepted {
		t.Error("no success check")
	}
	if got := sanitizeCode(string(make([]byte, 100)) + "x"); len(got) > 64 {
		t.Errorf("long code %q", got)
	}
}

// TestM14_KindSenders: a kind is dispatched only by a registered sender;
// one without a sender, or an unknown kind, is not implemented and fails
// closed, while the built-in kinds need none (G0 M14 D75).
func TestM14_KindSenders(t *testing.T) {
	for _, k := range []string{"postgres", "a2a", "smtp", ""} {
		if !kindNotImplemented(k) {
			t.Errorf("%q is implemented without a sender", k)
		}
	}
	for _, k := range builtinKinds {
		if kindNotImplemented(k) {
			t.Errorf("built-in %q is not implemented", k)
		}
	}
	kindSenders["test-kind"] = func(*Engine, context.Context, Result, *control.Connection, *defs.Definition, actionir.Parsed, permitWant, *timer) Result {
		return Result{}
	}
	defer delete(kindSenders, "test-kind")
	if kindNotImplemented("test-kind") {
		t.Fatal("a registered kind is not implemented")
	}
}

// TestM14_CheckCredentialPattern: the one helper every dispatch path calls
// accepts any credential without a pattern, a static credential matching
// it, and refuses a mismatch and any GitHub App credential under one
// (G0 M14 D85, HR-301).
func TestM14_CheckCredentialPattern(t *testing.T) {
	d := &defs.Definition{Dispatch: &defs.Dispatch{CredentialPattern: `^key_[a-z]{4}$`}}
	for _, c := range []struct {
		def  *defs.Definition
		kind string
		cred string
		ok   bool
	}{
		{nil, "static", "x", true}, {&defs.Definition{}, "static", "x", true}, {&defs.Definition{Dispatch: &defs.Dispatch{}}, "github_app", "", true},
		{d, "static", "key_abcd", true}, {d, "", "key_abcd", true}, {d, "static", "key_abcde", false}, {d, "static", "", false},
		{d, "github_app", "key_abcd", false},
	} {
		if err := CheckCredentialPattern(c.def, c.kind, []byte(c.cred)); (err == nil) != c.ok {
			t.Errorf("%+v %s %q: %v", c.def, c.kind, c.cred, err)
		}
	}
}
