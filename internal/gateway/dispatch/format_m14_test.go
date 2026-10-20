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

// TestM14_KindSenders: a kind is dispatched only by a registered sender:
// one without a sender, or an unknown kind, is KIND_NOT_IMPLEMENTED before
// the Authority is asked; a registered a2a or postgres kind still needs its
// connection's configuration (KIND_CONFIG_MISSING); the built-in kinds need
// neither. It holds whichever M14 senders this build registers (G0 M14
// D75, D94).
func TestM14_KindSenders(t *testing.T) {
	conn := func(kind string, cfg func(*pb.GatewayConnection)) *control.Connection {
		g := &pb.GatewayConnection{Kind: kind}
		if cfg != nil {
			cfg(g)
		}
		return &control.Connection{GatewayConnection: g}
	}
	withPG := func(g *pb.GatewayConnection) { g.Postgres = &pb.PostgresConfig{Database: "shop"} }
	withA2A := func(g *pb.GatewayConnection) { g.A2A = &pb.A2AConfig{CardUrl: "https://peer.example.test/card"} }
	for _, k := range builtinKinds {
		if code := kindRefusal(conn(k, nil)); code != "" {
			t.Errorf("built-in %q: %s", k, code)
		}
	}
	for _, k := range []string{"smtp", ""} {
		if code := kindRefusal(conn(k, nil)); code != CodeKindNotImplemented {
			t.Errorf("%q: %s", k, code)
		}
	}
	for kind, cfg := range map[string]func(*pb.GatewayConnection){"postgres": withPG, "a2a": withA2A} {
		_, registered := kindSenders[kind]
		withCfg, without := kindRefusal(conn(kind, cfg)), kindRefusal(conn(kind, nil))
		switch {
		case registered && (withCfg != "" || without != CodeKindConfigMissing):
			t.Errorf("%s, registered: with its configuration %q, without %q", kind, withCfg, without)
		case !registered && (withCfg != CodeKindNotImplemented || without != CodeKindNotImplemented):
			t.Errorf("%s, unregistered: %q %q", kind, withCfg, without)
		}
	}
	// Registering a sender makes a kind dispatchable, its configuration
	// still required; the registry is restored afterwards.
	prev, had := kindSenders["a2a"]
	kindSenders["a2a"] = func(*Engine, context.Context, Result, *control.Connection, *defs.Definition, actionir.Parsed, permitWant, *timer) Result {
		return Result{}
	}
	defer func() {
		if had {
			kindSenders["a2a"] = prev
		} else {
			delete(kindSenders, "a2a")
		}
	}()
	if kindRefusal(conn("a2a", withA2A)) != "" || kindRefusal(conn("a2a", nil)) != CodeKindConfigMissing {
		t.Fatal("a registered a2a sender")
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
		{nil, "static", "x", true},
		{&defs.Definition{}, "static", "x", true},
		{&defs.Definition{Dispatch: &defs.Dispatch{}}, "github_app", "", true},
		{d, "static", "key_abcd", true},
		{d, "", "key_abcd", true},
		{d, "static", "key_abcde", false},
		{d, "static", "", false},
		{d, "github_app", "key_abcd", false},
	} {
		if err := CheckCredentialPattern(c.def, c.kind, []byte(c.cred)); (err == nil) != c.ok {
			t.Errorf("%+v %s %q: %v", c.def, c.kind, c.cred, err)
		}
	}
}
