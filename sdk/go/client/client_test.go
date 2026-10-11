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
	// sdk answers the /sdk face once the proof checked out.
	sdk func(w http.ResponseWriter, r *http.Request, body []byte)
	// requireNonce refuses proofs without the fake's nonce (use_nonce).
	requireNonce bool
	// expireFirst refuses the first /sdk call with token_expired.
	expireFirst atomic.Bool
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
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fake) client(t *testing.T) *client.Client {
	t.Helper()
	k := f.key
	k.Server = f.srv.URL
	c, err := client.New(client.Config{Key: k, Gateway: f.srv.URL, RunID: runID})
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
		if f.expireFirst.CompareAndSwap(true, false) {
			w.Header().Set(pap.HeaderError, string(pap.ErrTokenExpired))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.sdk(w, r, body)
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

// allowed answers an allow for the action id the request carries.
func allowed(w http.ResponseWriter, r *http.Request) {
	id := r.Header.Get("PC-Action-Id")
	act := `{"action_id":"` + id + `"}`
	answer(w, map[string]any{
		"decision": "allow", "action_id": id, "action_hash": sha256Hex([]byte(act)), "coverage": "PARTIAL", "mode": "enforce",
	})
}

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
		res := c.Authorize(ctx, "local", refund, client.NewActionID())
		cancel()
		if res.Outcome != client.CannotDecide {
			t.Errorf("%s: %s (%s)", name, res.Outcome, res.Why)
		}
	}
	f.srv.Close()
	if res := c.Authorize(context.Background(), "local", refund, client.NewActionID()); res.Outcome != client.CannotDecide {
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
			string(call.Input) != string(refund.Input) || call.ToolUseID != "toolu_01" || r.URL.Path != "/sdk/local" {
			t.Errorf("the call arrived as %s at %s", body, r.URL.Path)
		}
		sent = r.Header.Get("PC-Action-Id")
		allowed(w, r)
	}
	c := f.client(t)
	id := client.NewActionID()
	res := c.Authorize(context.Background(), "local", refund, id)
	if res.Outcome != client.Allow || sent != id || f.issued.Load() != 2 {
		t.Fatalf("%s (%s, %v); action %s, tokens issued %d", res.Outcome, res.Why, res.Err, sent, f.issued.Load())
	}
}
