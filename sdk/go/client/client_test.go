// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

package client_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/sdk/go/client"
	"github.com/katocxl/pantherclaw/sdk/go/internal/vectors"
	"github.com/katocxl/pantherclaw/sdk/go/pap"
)

const (
	runID    = "01920000-0000-7000-8000-000000000003"
	actionID = "01920000-0000-7000-8000-000000000004"
	ident    = "pc:org/01920000-0000-7000-8000-000000000001/agent/01920000-0000-7000-8000-000000000006/inst/01920000-0000-7000-8000-000000000005"
	nonce    = "Y29uZm9ybWFuY2Utbm9uY2UtMjAyNi0xMC0xMQ"
)

var b64 = base64.RawURLEncoding

// fake is a PantherClaw server and gateway in one: it issues unsigned
// workload tokens (the client never verifies them) and checks every proof
// it receives the way PAP/1 §4 does.
type fake struct {
	t      *testing.T
	srv    *httptest.Server
	key    pap.KeyFile
	jkt    string
	issued atomic.Int32
	// sdk answers the /sdk face once the proof checked out; wait answers
	// the server's long-poll and SSE wait routes.
	sdk  func(w http.ResponseWriter, r *http.Request, body []byte)
	wait func(w http.ResponseWriter, r *http.Request)
	// requireNonce refuses proofs without the fake's nonce (use_nonce).
	requireNonce bool
	// expireFirst refuses the first /sdk call with token_expired.
	expireFirst atomic.Bool
	// calls counts the /sdk requests.
	calls atomic.Int32
	// action is the vectors' sdk-channel action, canonical.
	action string
}

func newFake(t *testing.T) *fake {
	t.Helper()
	k, err := pap.NewKeyFile()
	if err != nil {
		t.Fatal(err)
	}
	k.Identifier = ident
	priv, _ := k.Key()
	f := &fake{t: t, key: k, jkt: pap.Thumbprint(priv.Public().(ed25519.PublicKey))}
	var vs struct {
		Cases []struct {
			Name      string `json:"name"`
			Canonical string `json:"canonical"`
		} `json:"cases"`
	}
	vectors.Load(t, "actionir.json", &vs)
	for _, c := range vs.Cases {
		if c.Name == "sdk channel through a connection" {
			f.action = c.Canonical
		}
	}
	if f.action == "" {
		t.Fatal("no sdk-channel action in the vectors")
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fake) client(t *testing.T) *client.Client {
	t.Helper()
	k := f.key
	k.Server = f.srv.URL
	c, err := client.New(client.Config{Key: k, Gateway: f.srv.URL, RunID: runID, Builtins: []string{"Bash", "Read"}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (f *fake) token(exp time.Time) string {
	claims, _ := json.Marshal(map[string]any{
		"iss": f.srv.URL, "sub": ident, "aud": "pantherclaw-gateway", "iat": time.Now().Unix(), "nbf": time.Now().Unix(),
		"exp": exp.Unix(), "jti": "01920000-0000-7000-8000-0000000000ff", "cnf": map[string]string{"jkt": f.jkt},
		"pap": map[string]any{"v": 1, "org": "01920000-0000-7000-8000-000000000001", "env": "01920000-0000-7000-8000-000000000002", "att_lvl": 1},
	})
	return b64.EncodeToString([]byte(`{"alg":"EdDSA","kid":"k","typ":"pap-wt+jwt"}`)) + "." + b64.EncodeToString(claims) + ".c2ln"
}

func (f *fake) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	token, hasToken := strings.CutPrefix(r.Header.Get("Authorization"), "PAP ")
	if code := f.checkProof(r, body, token); code != "" {
		w.Header().Set(pap.HeaderError, code)
		w.Header().Set(pap.HeaderNonce, nonce)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.Header().Set(pap.HeaderNonce, nonce)
	switch {
	case r.URL.Path == "/pantherclaw.v1.WorkloadService/IssueToken":
		if hasToken {
			f.t.Error("token issuance must use a key-only proof")
		}
		f.issued.Add(1)
		_ = json.MarshalWrite(w, map[string]any{"workloadToken": f.token(time.Now().Add(10 * time.Minute)), "attestationLevel": 1})
	case strings.HasPrefix(r.URL.Path, "/sdk/"):
		if !hasToken || r.Header.Get("PAP-Run-Id") != runID || r.Header.Get("PC-Action-Id") == "" {
			f.t.Errorf("a /sdk call without its token, run or action id: %v", r.Header)
		}
		f.calls.Add(1)
		if f.expireFirst.CompareAndSwap(true, false) {
			w.Header().Set(pap.HeaderError, string(pap.ErrTokenExpired))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.sdk(w, r, body)
	case f.wait != nil && (r.URL.Path == "/pantherclaw.v1.WorkloadService/Wait" || strings.HasPrefix(r.URL.Path, "/v1/wait/")):
		f.wait(w, r)
	default:
		http.NotFound(w, r)
	}
}

// checkProof verifies the proof's signature with its embedded key and its
// htm, htu, bh, ath and nonce; it returns the PAP-Error code of a failure.
func (f *fake) checkProof(r *http.Request, body []byte, token string) string {
	parts := strings.Split(r.Header.Get(pap.HeaderProof), ".")
	if len(parts) != 3 {
		return "invalid_proof"
	}
	h, _ := b64.DecodeString(parts[0])
	c, _ := b64.DecodeString(parts[1])
	sig, _ := b64.DecodeString(parts[2])
	var head struct {
		JWK struct {
			X string `json:"x"`
		} `json:"jwk"`
	}
	var claims struct {
		HTM   string `json:"htm"`
		HTU   string `json:"htu"`
		ATH   string `json:"ath"`
		BH    string `json:"bh"`
		Nonce string `json:"nonce"`
	}
	_ = json.Unmarshal(h, &head)
	_ = json.Unmarshal(c, &claims)
	x, _ := b64.DecodeString(head.JWK.X)
	bh := sha256.Sum256(body)
	switch {
	case len(x) != ed25519.PublicKeySize || !ed25519.Verify(x, []byte(parts[0]+"."+parts[1]), sig):
		return "invalid_proof"
	case pap.Thumbprint(x) != f.jkt:
		return "key_mismatch"
	case claims.HTM != r.Method || claims.HTU != f.srv.URL+r.URL.EscapedPath() || claims.BH != b64.EncodeToString(bh[:]):
		return "invalid_proof"
	case (token == "") != (claims.ATH == "") || (token != "" && claims.ATH != pap.ATH(token)):
		return "invalid_proof"
	case f.requireNonce && claims.Nonce != nonce:
		return "use_nonce"
	}
	return ""
}

func answer(w http.ResponseWriter, a map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.MarshalWrite(w, a)
}

var refund = client.ToolCall{
	Tool: "mcp__payments__create_refund", Server: "payments", Input: jsontext.Value(`{"amount":"30.00","charge":"ch_1"}`), ToolUseID: "toolu_01",
}

// decided answers decision ("allow" or "hold") for the action id the
// request carries, with the canonical sdk-channel action and its hash.
func (f *fake) decided(w http.ResponseWriter, r *http.Request, decision string, extra map[string]any) {
	id := r.Header.Get("PC-Action-Id")
	act := strings.Replace(f.action, `"action_id":"`+actionID+`"`, `"action_id":"`+id+`"`, 1)
	a := map[string]any{
		"decision": decision, "action_id": id, "action_hash": sha256Hex([]byte(act)), "action_ir": b64.EncodeToString([]byte(act)),
		"coverage": "PARTIAL", "mode": "enforce",
	}
	for k, v := range extra {
		a[k] = v
	}
	answer(w, a)
}

// allowed answers an allow for the action id the request carries.
func (f *fake) allowed(w http.ResponseWriter, r *http.Request) { f.decided(w, r, "allow", nil) }

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// TestHR200_FailsClosedWhenPantherClawCannotDecide: unreachable, timed
// out, a server error or an unreadable answer are CannotDecide, never
// Allow.
func TestHR200_FailsClosedWhenPantherClawCannotDecide(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	for name, sdk := range map[string]func(http.ResponseWriter, *http.Request, []byte){
		"a server error": func(w http.ResponseWriter, _ *http.Request, _ []byte) { w.WriteHeader(http.StatusBadGateway) },
		"not JSON":       func(w http.ResponseWriter, _ *http.Request, _ []byte) { _, _ = io.WriteString(w, "<html>") },
		"an empty body":  func(http.ResponseWriter, *http.Request, []byte) {},
		"too slow": func(w http.ResponseWriter, r *http.Request, _ []byte) {
			<-r.Context().Done()
		},
	} {
		f.sdk = sdk
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		res := c.Authorize(ctx, "payments", refund, client.NewActionID())
		cancel()
		if res.Outcome != client.CannotDecide {
			t.Errorf("%s: %s (%s)", name, res.Outcome, res.Why)
		}
	}
	f.srv.Close()
	if res := c.Authorize(context.Background(), "payments", refund, client.NewActionID()); res.Outcome != client.CannotDecide {
		t.Errorf("unreachable: %s", res.Outcome)
	}
}

// The client signs a proof over the exact body, retries once with the
// server's fresh nonce, renews an expired token once, and allows a call
// only when the answer is a checked allow.
func TestAuthorizeRetriesForANonceAndAnExpiredToken(t *testing.T) {
	f := newFake(t)
	f.requireNonce = true
	f.expireFirst.Store(true)
	var sent string
	f.sdk = func(w http.ResponseWriter, r *http.Request, body []byte) {
		var call client.ToolCall
		if err := json.Unmarshal(body, &call, json.RejectUnknownMembers(true)); err != nil || call.Tool != refund.Tool || call.Server != "payments" ||
			string(call.Input) != string(refund.Input) || call.ToolUseID != "toolu_01" || r.URL.Path != "/sdk/payments" {
			t.Errorf("the call arrived as %s at %s", body, r.URL.Path)
		}
		sent = r.Header.Get("PC-Action-Id")
		f.allowed(w, r)
	}
	c := f.client(t)
	id := client.NewActionID()
	res := c.Authorize(context.Background(), "payments", refund, id)
	if res.Outcome != client.Allow || sent != id || f.issued.Load() != 2 {
		t.Fatalf("%s (%s, %v); action %s, tokens issued %d", res.Outcome, res.Why, res.Err, sent, f.issued.Load())
	}
}

// TestHR200_OnlyBuiltinsAreObserved: an observe answer lets a configured
// built-in run and nothing else, and a name that is neither an MCP tool
// nor a built-in is never sent.
func TestHR200_OnlyBuiltinsAreObserved(t *testing.T) {
	f := newFake(t)
	f.sdk = func(w http.ResponseWriter, _ *http.Request, _ []byte) {
		answer(w, map[string]any{"decision": "allow", "mode": "monitor", "coverage": "OBSERVE_ONLY"})
	}
	c := f.client(t)
	read := client.ToolCall{Tool: "Read", Input: jsontext.Value(`{"file_path":"/etc/hosts"}`), ToolUseID: "toolu_02"}
	if res := c.Authorize(context.Background(), "payments", read, client.NewActionID()); res.Outcome != client.Observe {
		t.Errorf("a built-in: %s (%s)", res.Outcome, res.Why)
	}
	if res := c.Authorize(context.Background(), "payments", refund, client.NewActionID()); res.Outcome != client.CannotDecide {
		t.Errorf("an MCP tool answered observe: %s", res.Outcome)
	}
	sent := f.calls.Load()
	for _, name := range []string{"deploy", "bash", "mcp__payments__create_refund"} {
		call := client.ToolCall{Tool: name, Input: jsontext.Value(`{}`), ToolUseID: "toolu_03"}
		if res := c.Authorize(context.Background(), "payments", call, client.NewActionID()); res.Outcome != client.CannotDecide {
			t.Errorf("%s: %s", name, res.Outcome)
		}
	}
	if f.calls.Load() != sent {
		t.Errorf("sent %d calls the client cannot route", f.calls.Load()-sent)
	}
}

// TestHR200_AServerNamedLikeNoConnectionIsNeverSent: a connection governs
// the one MCP server named after it, so a call naming a server that no
// connection can be named after, or a built-in recorded at such a
// connection, is cannot_decide without a request.
func TestHR200_AServerNamedLikeNoConnectionIsNeverSent(t *testing.T) {
	f := newFake(t)
	f.sdk = func(w http.ResponseWriter, _ *http.Request, _ []byte) {
		answer(w, map[string]any{"decision": "allow", "mode": "monitor", "coverage": "OBSERVE_ONLY"})
	}
	c := f.client(t)
	for _, call := range []client.ToolCall{
		{Tool: "mcp__git__hub__merge", Server: "git__hub", Input: jsontext.Value(`{}`), ToolUseID: "toolu_01"},
		{Tool: "mcp__Payments__create_refund", Server: "Payments", Input: jsontext.Value(`{}`), ToolUseID: "toolu_02"},
		{Tool: "mcp__-payments__create_refund", Server: "-payments", Input: jsontext.Value(`{}`), ToolUseID: "toolu_03"},
		{Tool: "mcp__pay%2fments__create_refund", Server: "pay%2fments", Input: jsontext.Value(`{}`), ToolUseID: "toolu_04"},
	} {
		if res := c.Authorize(context.Background(), "payments", call, client.NewActionID()); res.Outcome != client.CannotDecide {
			t.Errorf("%s: %s", call.Server, res.Outcome)
		}
	}
	read := client.ToolCall{Tool: "Read", Input: jsontext.Value(`{"file_path":"/etc/hosts"}`), ToolUseID: "toolu_05"}
	for _, conn := range []string{"Payments", "pay/ments", "", "payments-"} {
		if res := c.Authorize(context.Background(), conn, read, client.NewActionID()); res.Outcome != client.CannotDecide {
			t.Errorf("a built-in recorded at %q: %s", conn, res.Outcome)
		}
	}
	if f.calls.Load() != 0 {
		t.Errorf("sent %d calls", f.calls.Load())
	}
}

// TestNewRefusesPlainHTTPOutsideLoopback: tokens and proofs travel over
// TLS, or over http only to this machine.
func TestNewRefusesPlainHTTPOutsideLoopback(t *testing.T) {
	k, err := pap.NewKeyFile()
	if err != nil {
		t.Fatal(err)
	}
	k.Identifier = ident
	for _, u := range []string{"http://pantherclaw.example.test", "http://10.0.0.1:8443", "https://user@pantherclaw.example.test", "ftp://x"} {
		if _, err := client.New(client.Config{Key: k, Server: "https://pantherclaw.example.test", Gateway: u}); err == nil {
			t.Errorf("gateway %s accepted", u)
		}
		if _, err := client.New(client.Config{Key: k, Server: u}); err == nil {
			t.Errorf("server %s accepted", u)
		}
	}
	for _, u := range []string{"https://pantherclaw.example.test", "http://127.0.0.1:8080", "http://[::1]:8080", "http://localhost:8080"} {
		if _, err := client.New(client.Config{Key: k, Server: u, Gateway: u}); err != nil {
			t.Errorf("%s refused: %v", u, err)
		}
	}
}

// TestRedirectsAreNeverFollowed: a redirect from the gateway is an answer
// the client cannot read, even with a caller's client that follows them,
// so the call and its proof never reach another server.
func TestRedirectsAreNeverFollowed(t *testing.T) {
	var reached atomic.Bool
	elsewhere := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached.Store(true) }))
	t.Cleanup(elsewhere.Close)
	f := newFake(t)
	f.sdk = func(w http.ResponseWriter, r *http.Request, _ []byte) {
		http.Redirect(w, r, elsewhere.URL+"/sdk/payments", http.StatusTemporaryRedirect)
	}
	k := f.key
	k.Server = f.srv.URL
	c, err := client.New(client.Config{Key: k, Gateway: f.srv.URL, RunID: runID, HTTPClient: &http.Client{}})
	if err != nil {
		t.Fatal(err)
	}
	if res := c.Authorize(context.Background(), "payments", refund, client.NewActionID()); res.Outcome != client.CannotDecide || reached.Load() {
		t.Fatalf("%s, reached the redirect target: %v", res.Outcome, reached.Load())
	}
}
