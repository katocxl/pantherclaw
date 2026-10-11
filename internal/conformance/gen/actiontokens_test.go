// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gen_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json/jsontext"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/sim/payments"
)

const (
	connectionID = "01920000-0000-7000-8000-000000000007"
	refundBody   = `{"amount":"30.00","charge":"ch_1","currency":"USD","reason":"duplicate"}`
)

// ActionTokenCase is one request a target verifier (PAP-1 §10, HR-202)
// receives: the token in PAP-Action (empty: none), the exact body, the
// route's operation and target, the verifier's issuer, audience, clock and
// replay store, and its answer.
type ActionTokenCase struct {
	Name       string `json:"name"`
	Token      string `json:"token"`
	Body       string `json:"body"`
	Operation  string `json:"operation"`
	TargetType string `json:"target_type"`
	TargetID   string `json:"target_id"`
	Issuer     string `json:"issuer"`
	Audience   string `json:"audience"`
	Now        int64  `json:"now"`
	// Store is "unavailable" for a replay store that cannot record.
	Store string `json:"store,omitzero"`
	// Twice: the same request twice; the first is accepted, the second
	// gets Expect.
	Twice bool `json:"twice,omitzero"`
	// ThenValid: after this request is refused, the same verifier and store
	// accept the minted token's case (the first: its token, body, operation
	// and target), so a refusal never spends its jti, even one carried by a
	// forged token.
	ThenValid bool `json:"then_valid,omitzero"`
	// Expect is "ok" or a refusal code: missing, bad_signature,
	// wrong_issuer, wrong_audience, expired, body_mismatch,
	// operation_mismatch, replayed, store_unavailable.
	Expect string `json:"expect"`
}

// ActionTokenFile is action_tokens.json.
type ActionTokenFile struct {
	header
	JWKS jsontext.Value `json:"jwks"`
	// Claims is the decoded payload of the minted token.
	Claims jsontext.Value    `json:"claims"`
	Cases  []ActionTokenCase `json:"cases"`
}

// mintActionToken runs a refund through the Authority on a target-enforced
// connection and returns the action token BeginDispatch minted.
func mintActionToken(t *testing.T) string {
	t.Helper()
	s := pipelinetest.NewScenario(t, nil)
	s.Authority.ActionTokens, s.Authority.Issuer = signer(t, registry(t), keys.PurposeActionTokens), issuer
	gw := ids.NewV7()
	s.Gateway.ID = gw.String()
	s.W.PutConnection(pipeline.Connection{
		ID: mustUUID(t, connectionID), Gateway: gw, Kind: "http", Package: "pc.mock-payments", State: "ACTIVE",
		AccessMode: finalize.AccessTargetEnforced, DefaultMode: pipeline.ModeEnforce, Modes: map[string]string{},
	})
	run := s.Run(s.Grant(pipelinetest.RootBounds, s.Alice).ID, s.Alice)
	act, err := s.Mapper.MCP(context.Background(), mapping.Context{
		Org: s.Org.String(), Env: s.Env.String(), RunID: run.String(), ActionID: ids.NewV7().String(), AgentInstance: s.Instance.String(),
		Connection: connectionID,
	}, "create_refund", jsontext.Value(pipelinetest.Refund("ch_1", "30.00")))
	if err != nil {
		t.Fatal(err)
	}
	res := s.Authorize(pipeline.Request{
		Org: s.Org, Action: act, Gateway: s.Gateway.ID,
		Identity: pipeline.Identity{InstanceID: s.Instance, AgentID: s.Agent, AttestationLevel: 1, JKT: workloadKey("workload").JKT},
	})
	if !res.Decision.Permits() {
		t.Fatalf("authorize: %s", res.Decision)
	}
	sum := sha256.Sum256([]byte(refundBody))
	tok, err := s.Authority.BeginDispatch(context.Background(), s.Gateway, res.PermitID, res.Epoch,
		finalize.Outbound{Method: http.MethodPost, URL: "https://payments.example.test/v1/refunds", BodySHA256: sum[:]})
	if err != nil || tok == "" {
		t.Fatalf("begin dispatch: %q %v", tok, err)
	}
	return tok
}

// strangerSigner signs with an action-tokens key no JWKS publishes.
func strangerSigner(t *testing.T) *jws.Signer {
	t.Helper()
	r := keys.NewRegistry()
	k, p := key("another deployment"), keys.PurposeActionTokens
	if err := r.Put(keys.SigningKey{KID: keys.KIDFor(p, pub(k)), Purpose: p, State: keys.StateActive, Public: pub(k), Private: pclog.NewSecret(k)}); err != nil {
		t.Fatal(err)
	}
	return signer(t, r, p)
}

func buildActionTokens(t *testing.T) any {
	t.Helper()
	r := registry(t)
	tok := mintActionToken(t)
	h, p := segments(t, tok)
	var c struct {
		Iat int64 `json:"iat"`
		Exp int64 `json:"exp"`
	}
	decodeInto(t, p, &c)
	sign := func(s interface {
		Sign(string, []byte) (string, error)
	}, payload []byte,
	) string {
		out, err := s.Sign(finalize.TypeActionToken, payload)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	ak := key(string(keys.PurposeActionTokens))
	parts := strings.Split(tok, ".")
	lifetime := func(seconds int64) string {
		return string(bytes.Replace(p, []byte(`"exp":`+strconv.FormatInt(c.Exp, 10)), []byte(`"exp":`+strconv.FormatInt(c.Iat+seconds, 10)), 1))
	}
	if c.Exp-c.Iat != 60 {
		t.Fatalf("the minted token lives %d s, want 60", c.Exp-c.Iat)
	}
	ok := ActionTokenCase{
		Token: tok, Body: refundBody, Operation: "payments.refund.create", TargetType: "payments.charge", TargetID: "ch_1",
		Issuer: issuer, Audience: connectionID, Now: c.Iat + 10, Expect: "ok",
	}
	with := func(name, expect string, edit func(*ActionTokenCase)) ActionTokenCase {
		v := ok
		v.Name, v.Expect = name, expect
		edit(&v)
		return v
	}
	f := ActionTokenFile{
		header: head("action_tokens", "internal/authority/finalize BeginDispatch (dispatch.go), checked with internal/sim/payments ActionVerifier",
			"Action tokens (pap-action+jwt, PAP-1 §10) minted for a target-enforced connection. A verifier accepts only "+
				"keys whose kid is \"action-tokens-\" and the first 22 characters of their RFC 7638 thumbprint, alg EdDSA or "+
				"Ed25519; it checks iss, aud (the connection id), a lifetime of at most 60 s with 5 s of skew, pap.v, pap.bh "+
				"(lowercase hex SHA-256 of the exact body), operation and target, and spends each jti once after every other "+
				"check passed."),
		JWKS: jwks(t, r), Claims: p,
		Cases: []ActionTokenCase{
			with("the minted token", "ok", func(*ActionTokenCase) {}),
			with("alg Ed25519 (RFC 9864)", "ok", func(v *ActionTokenCase) {
				v.Token = craft(strings.Replace(string(h), `"EdDSA"`, `"Ed25519"`, 1), string(p), ak)
			}),
			with("the same token twice", "replayed", func(v *ActionTokenCase) { v.Twice = true }),
			with("no token", "missing", func(v *ActionTokenCase) { v.Token = "" }),
			with("signed with the receipts key", "bad_signature", func(v *ActionTokenCase) { v.Token = sign(signer(t, r, keys.PurposeReceipts), p) }),
			with("signed with an action-tokens key not in the JWKS", "bad_signature", func(v *ActionTokenCase) { v.Token = sign(strangerSigner(t), p) }),
			with("a forged token carrying the minted token's jti leaves it unspent", "bad_signature", func(v *ActionTokenCase) {
				v.Token, v.ThenValid = sign(strangerSigner(t), p), true
			}),
			with("alg none", "bad_signature", func(v *ActionTokenCase) {
				v.Token = craft(strings.Replace(string(h), `"EdDSA"`, `"none"`, 1), string(p), nil)
			}),
			with("the payload edited after signing", "bad_signature", func(v *ActionTokenCase) {
				v.Token = parts[0] + "." + b64(bytes.Replace(p, []byte(`"id":"ch_1"`), []byte(`"id":"ch_2"`), 1)) + "." + parts[2]
				v.TargetID = "ch_2"
			}),
			with("a workload token", "bad_signature", func(v *ActionTokenCase) { v.Token = issue(t, tokenSpec{level: 1}) }),
			with("another issuer", "wrong_issuer", func(v *ActionTokenCase) { v.Issuer = "https://another.example.test" }),
			with("another connection's audience", "wrong_audience", func(v *ActionTokenCase) { v.Audience = "01920000-0000-7000-8000-000000000008" }),
			with("typ pap-permit+jwt", "bad_signature", func(v *ActionTokenCase) {
				v.Token = craft(strings.Replace(string(h), finalize.TypeActionToken, "pap-permit+jwt", 1), string(p), ak)
			}),
			with("a kid that is not the key's", "bad_signature", func(v *ActionTokenCase) {
				v.Token = craft(strings.Replace(string(h), `"kid":"action-tokens-`, `"kid":"action-tokens-x`, 1), string(p), ak)
			}),
			with("pap.v 2", "bad_signature", func(v *ActionTokenCase) {
				v.Token = craft(string(h), strings.Replace(string(p), `"v":1`, `"v":2`, 1), ak)
			}),
			with("aud an array holding the connection", "bad_signature", func(v *ActionTokenCase) {
				v.Token = craft(string(h), strings.Replace(string(p), `"aud":"`+connectionID+`"`, `"aud":["`+connectionID+`"]`, 1), ak)
			}),
			with("expired a minute ago", "expired", func(v *ActionTokenCase) { v.Now = c.Exp + 60 }),
			with("4 seconds past exp, within the skew", "ok", func(v *ActionTokenCase) { v.Now = c.Exp + 4 }),
			with("5 seconds past exp", "expired", func(v *ActionTokenCase) { v.Now = c.Exp + 5 }),
			with("issued 5 seconds ahead, within the skew", "ok", func(v *ActionTokenCase) { v.Now = c.Iat - 5 }),
			with("issued 6 seconds ahead", "expired", func(v *ActionTokenCase) { v.Now = c.Iat - 6 }),
			with("issued a minute ahead", "expired", func(v *ActionTokenCase) { v.Now = c.Iat - 60 }),
			with("a lifetime of 61 seconds", "expired", func(v *ActionTokenCase) { v.Token = craft(string(h), lifetime(61), ak) }),
			with("a lifetime of 120 seconds", "expired", func(v *ActionTokenCase) { v.Token = craft(string(h), lifetime(120), ak) }),
			with("the body re-serialized", "body_mismatch", func(v *ActionTokenCase) { v.Body = strings.ReplaceAll(refundBody, ",", ", ") }),
			with("a refused body leaves the token unspent", "body_mismatch", func(v *ActionTokenCase) {
				v.Body, v.ThenValid = strings.ReplaceAll(refundBody, "30.00", "31.00"), true
			}),
			with("another operation", "operation_mismatch", func(v *ActionTokenCase) { v.Operation = "payments.refund.get" }),
			with("a refused operation leaves the token unspent", "operation_mismatch", func(v *ActionTokenCase) {
				v.Operation, v.ThenValid = "payments.refund.get", true
			}),
			with("another target", "operation_mismatch", func(v *ActionTokenCase) { v.TargetID = "ch_2" }),
			with("a replay store that cannot record", "store_unavailable", func(v *ActionTokenCase) { v.Store = "unavailable" }),
		},
	}
	checkWithSimulator(t, f)
	return f
}

// checkWithSimulator runs every case through the payments simulator's
// verifier (the M6 reference target). Its answers are coarser (missing,
// replayed, or invalid for every other refusal), and it predates three
// checks the vectors pin (PAP-1 §10 as of G0 M8): the issuer, the
// RFC 9864 alg name and an unavailable store. Those cases are skipped here;
// the SDK verifiers run them.
func checkWithSimulator(t *testing.T, f ActionTokenFile) {
	t.Helper()
	keysOnly := &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(f.JWKS)), Header: http.Header{}}, nil
	})}
	for _, c := range f.Cases {
		switch c.Expect {
		case "wrong_issuer", "store_unavailable":
			continue
		}
		if strings.Contains(c.Name, "RFC 9864") {
			continue
		}
		v := &payments.ActionVerifier{
			JWKSURL: "https://pantherclaw.example.test/.well-known/pantherclaw/jwks.json", Audience: c.Audience, Client: keysOnly,
			Now: func() time.Time { return time.Unix(c.Now, 0) },
		}
		got := simulator(t, v, c)
		if c.Twice {
			if got != "ok" {
				t.Fatalf("%s: first presentation %s", c.Name, got)
			}
			got = simulator(t, v, c)
		}
		want := c.Expect
		if want != "ok" && want != "missing" && want != "replayed" {
			want = "invalid"
		}
		if got != want {
			t.Fatalf("%s: the simulator's verifier says %s, want %s", c.Name, got, want)
		}
		if c.ThenValid {
			if then := simulator(t, v, f.Cases[0]); then != "ok" {
				t.Fatalf("%s: the minted token after the refusal: %s", c.Name, then)
			}
		}
	}
}

// roundTrip serves HTTP from memory: the generator opens no sockets.
type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func simulator(t *testing.T, v *payments.ActionVerifier, c ActionTokenCase) string {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "https://payments.example.test/v1/refunds", strings.NewReader(c.Body))
	if c.Token != "" {
		r.Header.Set(payments.HeaderAction, c.Token)
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	err = v.Verify(context.Background(), r, body, payments.Want{Operation: c.Operation, TargetType: c.TargetType, TargetID: c.TargetID})
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, payments.ErrNoActionToken):
		return "missing"
	case errors.Is(err, payments.ErrActionTokenReplay):
		return "replayed"
	case errors.Is(err, payments.ErrActionTokenInvalid):
		return "invalid"
	}
	t.Fatalf("%s: unexpected error %v", c.Name, err)
	return ""
}
