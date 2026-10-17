// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

package pep_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/katocxl/pantherclaw/sdk/go/pep"
)

type staticToken string

func (s staticToken) Token(context.Context) (string, error) { return string(s), nil }

// pdp is a fake decision endpoint answering with decide.
type pdp struct {
	mu     sync.Mutex
	got    []map[string]any
	bearer []string
	decide func(ev map[string]any) (int, string)
}

func (p *pdp) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var ev map[string]any
	_ = json.NewDecoder(r.Body).Decode(&ev)
	p.mu.Lock()
	p.got, p.bearer = append(p.got, ev), append(p.bearer, r.Header.Get("Authorization"))
	p.mu.Unlock()
	status, body := p.decide(ev)
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

type upstream struct {
	mu   sync.Mutex
	reqs []*http.Request
	body []string
}

func (u *upstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	u.mu.Lock()
	u.reqs, u.body = append(u.reqs, r), append(u.body, string(b))
	u.mu.Unlock()
	_, _ = io.WriteString(w, `{"id":"re_1"}`)
}

func setup(t *testing.T, protocol string, decide func(map[string]any) (int, string)) (*pdp, *upstream, *httptest.Server) {
	t.Helper()
	p := &pdp{decide: decide}
	ps := httptest.NewServer(p)
	t.Cleanup(ps.Close)
	u := &upstream{}
	us := httptest.NewServer(u)
	t.Cleanup(us.Close)
	h, err := pep.New(pep.Config{
		Server: ps.URL, Connection: "payments", Protocol: protocol, PublicURL: "https://payments.example.test/api",
		Upstream: us.URL, Tokens: staticToken("at_1"), CredentialHeader: "X-Target-Authorization",
	})
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	return p, u, s
}

// answer is what the enforcement point answered.
type answer struct {
	StatusCode int
	Header     http.Header
}

func send(t *testing.T, url, body string, hdr map[string]string) (answer, string) {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, url, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return answer{StatusCode: resp.StatusCode, Header: resp.Header}, string(b)
}

var agent = map[string]string{
	"Authorization": "PAP tok", pep.HeaderProof: "proof", pep.HeaderRunID: "run-1", pep.HeaderActionID: "act-1",
	"X-Target-Authorization": "Bearer target-secret",
}

// TestPEPForwardsOnlyAllowedRequests: the enforcement point asks with the
// agent's token, proof, run and action ids over the request at the
// connection's URL, forwards it unchanged only on decision true (with the
// action token as PAP-Action and the agent's own target credential as
// Authorization, never the PAP/1 headers), and answers 403 with the reason
// otherwise.
func TestPEPForwardsOnlyAllowedRequests(t *testing.T) {
	allow := true
	p, u, s := setup(t, "http", func(map[string]any) (int, string) {
		if allow {
			return http.StatusOK, `{"decision":true,"context":{"pantherclaw":{"outcome":"allow","transaction_id":"tx1","coverage":"PARTIAL","action_token":"at.k.n","nonce":"n1"}}}`
		}
		return http.StatusOK, `{"decision":false,"context":{"pantherclaw":{"outcome":"hold","code":"APPROVAL_REQUIRED","transaction_id":"tx2","coverage":"PARTIAL","wait":{"handle":"tx2"}},"reason_user":{"en":"needs an approval"}}}`
	})
	resp, body := send(t, s.URL+"/v1/refunds?x=1", `{"amount":"5"}`, agent)
	if resp.StatusCode != http.StatusOK || body != `{"id":"re_1"}` || resp.Header.Get(pep.HeaderTransaction) != "tx1" || resp.Header.Get(pep.HeaderNonce) != "n1" {
		t.Fatalf("allowed: %d %s", resp.StatusCode, body)
	}
	got := u.reqs[0]
	if u.body[0] != `{"amount":"5"}` || got.URL.Path != "/v1/refunds" || got.URL.RawQuery != "x=1" ||
		got.Header.Get(pep.HeaderAction) != "at.k.n" || got.Header.Get("Authorization") != "Bearer target-secret" ||
		got.Header.Get(pep.HeaderProof) != "" || got.Header.Get(pep.HeaderRunID) != "" || got.Header.Get("X-Target-Authorization") != "" {
		t.Fatalf("forwarded: %s %v %q", got.URL, got.Header, u.body[0])
	}
	ev := p.got[0]
	sub := ev["subject"].(map[string]any)
	props := sub["properties"].(map[string]any)
	res := ev["resource"].(map[string]any)
	rp := res["properties"].(map[string]any)
	body64, _ := base64.StdEncoding.DecodeString(rp["body_b64"].(string))
	if sub["type"] != "pantherclaw_workload" || props["pap_token"] != "tok" || props["pap_proof"] != "proof" || props["pap_run_id"] != "run-1" ||
		props["pc_action_id"] != "act-1" || res["type"] != "pantherclaw:http_request" || res["id"] != "payments" ||
		rp["url"] != "https://payments.example.test/api/v1/refunds?x=1" || rp["method"] != "POST" || string(body64) != `{"amount":"5"}` ||
		ev["action"].(map[string]any)["name"] != "POST" || p.bearer[0] != "Bearer at_1" {
		t.Fatalf("evaluation: %v %v", ev, p.bearer)
	}

	allow = false
	resp, body = send(t, s.URL+"/v1/refunds", `{}`, agent)
	if resp.StatusCode != http.StatusForbidden || len(u.reqs) != 1 || !strings.Contains(body, "needs an approval") ||
		!strings.Contains(body, `"wait_handle":"tx2"`) || resp.Header.Get(pep.HeaderOutcome) != "hold" {
		t.Fatalf("refused: %d %s", resp.StatusCode, body)
	}
}

// TestPEPFailsClosed: a body over 64 KiB, an unreachable or erroring
// decision endpoint and an unreadable answer forward nothing.
func TestPEPFailsClosed(t *testing.T) {
	status := 500
	_, u, s := setup(t, "http", func(map[string]any) (int, string) { return status, `not json` })
	if resp, _ := send(t, s.URL+"/x", strings.Repeat("a", pep.MaxBody+1), agent); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("too large: %d", resp.StatusCode)
	}
	for _, st := range []int{500, 401, 403, 200} {
		status = st
		if resp, _ := send(t, s.URL+"/x", `{}`, agent); resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("decision endpoint %d: %d", st, resp.StatusCode)
		}
	}
	if len(u.reqs) != 0 {
		t.Fatal("forwarded without a decision")
	}
}

// TestPEPMCPNamesTheJSONRPCMethod: for an MCP server the action is the
// JSON-RPC method.
func TestPEPMCPNamesTheJSONRPCMethod(t *testing.T) {
	p, _, s := setup(t, "mcp", func(map[string]any) (int, string) {
		return http.StatusOK, `{"decision":true,"context":{"pantherclaw":{"outcome":"allow","coverage":"PARTIAL"}}}`
	})
	send(t, s.URL+"/mcp", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_refund"}}`, agent)
	if p.got[0]["action"].(map[string]any)["name"] != "tools/call" || p.got[0]["resource"].(map[string]any)["properties"].(map[string]any)["protocol"] != "mcp" {
		t.Fatalf("mcp evaluation: %v", p.got[0])
	}
}

// TestClientCredentialsAssertion: the token client sends a client
// assertion signed with the account's key, kid its RFC 7638 thumbprint,
// iss and sub the client id, aud the token endpoint, and reuses the token.
func TestClientCredentialsAssertion(t *testing.T) {
	edPub, edKey, _ := ed25519.GenerateKey(rand.Reader)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for name, tc := range map[string]struct {
		key    crypto.Signer
		verify func(input, sig []byte) bool
		alg    string
	}{
		"EdDSA": {edKey, func(in, sig []byte) bool { return ed25519.Verify(edPub, in, sig) }, "EdDSA"},
		"ES256": {ecKey, func(in, sig []byte) bool {
			sum := sha256.Sum256(in)
			return len(sig) == 64 && ecdsa.Verify(&ecKey.PublicKey, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
		}, "ES256"},
	} {
		calls := 0
		var srvURL string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			_ = r.ParseForm()
			a := strings.Split(r.PostForm.Get("client_assertion"), ".")
			if len(a) != 3 || r.PostForm.Get("grant_type") != "client_credentials" || r.PostForm.Get("client_id") != "sa_1" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			h, _ := base64.RawURLEncoding.DecodeString(a[0])
			c, _ := base64.RawURLEncoding.DecodeString(a[1])
			sig, _ := base64.RawURLEncoding.DecodeString(a[2])
			var hdr map[string]string
			var cl map[string]any
			_ = json.Unmarshal(h, &hdr)
			_ = json.Unmarshal(c, &cl)
			if hdr["alg"] != tc.alg || hdr["kid"] == "" || cl["iss"] != "sa_1" || cl["sub"] != "sa_1" || cl["aud"] != srvURL+"/oauth2/token" ||
				!tc.verify([]byte(a[0]+"."+a[1]), sig) {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = io.WriteString(w, `{"access_token":"tok","token_type":"Bearer","expires_in":300}`)
		}))
		srvURL = srv.URL
		cc := &pep.ClientCredentials{TokenURL: srv.URL + "/oauth2/token", ClientID: "sa_1"}
		cc.Key = tc.key
		for range 2 {
			if tok, err := cc.Token(context.Background()); err != nil || tok != "tok" {
				t.Fatalf("%s: %q %v", name, tok, err)
			}
		}
		if calls != 1 {
			t.Fatalf("%s: %d token requests", name, calls)
		}
		srv.Close()
	}
}
