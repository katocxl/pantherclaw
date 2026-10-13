// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gen_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

const (
	envID      = "01920000-0000-7000-8000-000000000002"
	actionID   = "01920000-0000-7000-8000-000000000004"
	gatewayURL = "https://gateway.example.test"
	nonce      = "Y29uZm9ybWFuY2Utbm9uY2UtMjAyNi0xMC0xMQ"
)

// issuedAt is the vectors' clock: 2026-10-11T12:00:00Z.
var issuedAt = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)

func key(name string) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(seed(name)) }

// Key describes a fixed key of the vectors; its seed is never secret.
type Key struct {
	Name string  `json:"name"`
	Seed string  `json:"seed"`
	JWK  jws.JWK `json:"jwk"`
	JKT  string  `json:"jkt"`
}

// workloadKey is the agent's key: a bare Ed25519 JWK, no kid.
func workloadKey(name string) Key {
	k := key(name)
	x := b64(pub(k))
	return Key{Name: name, Seed: b64(seed(name)), JWK: jws.JWK{Kty: "OKP", Crv: "Ed25519", X: x}, JKT: jws.Thumbprint(pub(k))}
}

// registry holds the Authority's keys: workload tokens, action tokens and
// receipts, all published in the JWKS, so a verifier must tell them apart.
func registry(t *testing.T) *keys.Registry {
	t.Helper()
	r := keys.NewRegistry()
	for _, p := range []keys.Purpose{keys.PurposeWorkloadTokens, keys.PurposeActionTokens, keys.PurposeReceipts} {
		k := key(string(p))
		if err := r.Put(keys.SigningKey{KID: keys.KIDFor(p, pub(k)), Purpose: p, State: keys.StateActive, Public: pub(k), Private: pclog.NewSecret(k)}); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

func signer(t *testing.T, r *keys.Registry, p keys.Purpose) *jws.Signer {
	t.Helper()
	s, err := r.Signer(p)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func jwks(t *testing.T, r *keys.Registry) jsontext.Value {
	t.Helper()
	b, err := r.JWKS()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustUUID(t *testing.T, s string) ids.UUID {
	t.Helper()
	u, err := ids.ParseUUID(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// segments decodes a compact JWS's header and payload.
func segments(t *testing.T, compact string) (head, payload []byte) {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %q", compact)
	}
	h, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	p, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	if err1 != nil || err2 != nil {
		t.Fatalf("segments of %q", compact)
	}
	return h, p
}

// craft signs header and claims as given with k (nil: no signature).
func craft(header, claims string, k ed25519.PrivateKey) string {
	in := b64([]byte(header)) + "." + b64([]byte(claims))
	if k == nil {
		return in + "."
	}
	return in + "." + b64(ed25519.Sign(k, []byte(in)))
}

func decodeInto(t *testing.T, b []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}

func athOf(token string) string {
	s := sha256.Sum256([]byte(token))
	return b64(s[:])
}

// TokenCase is a workload token (PAP-1 §3.4) an SDK reads without
// verifying: its claims and ath, or a refusal of something no PAP/1
// workload token can be (PantherClaw refuses it too).
type TokenCase struct {
	Name   string         `json:"name"`
	Token  string         `json:"token"`
	Claims jsontext.Value `json:"claims,omitzero"`
	ATH    string         `json:"ath,omitzero"`
	// ValidAt is a Unix time at which PantherClaw accepts the token.
	ValidAt int64  `json:"valid_at,omitzero"`
	Reject  string `json:"reject,omitzero"`
}

// TokenFile is workload_tokens.json.
type TokenFile struct {
	header
	Issuer      string         `json:"issuer"`
	JWKS        jsontext.Value `json:"jwks"`
	WorkloadKey Key            `json:"workload_key"`
	Cases       []TokenCase    `json:"cases"`
}

type tokenSpec struct {
	name, state, jkt string
	level            int
	notAfter         time.Time
}

func issue(t *testing.T, sp tokenSpec) string {
	t.Helper()
	tok := pap.Token{
		Instance:    pap.Instance{Org: ids.MustParse[ids.Org](orgID), Agent: mustUUID(t, agentID), Instance: mustUUID(t, instanceID)},
		Environment: mustUUID(t, envID), JKT: sp.jkt, Level: sp.level,
	}
	if tok.JKT == "" {
		tok.JKT = workloadKey("workload").JKT
	}
	if sp.state != "" {
		tok.ReleaseState, tok.ReleaseDigest = sp.state, "sha256:"+sha256Hex([]byte("release"))
	}
	compact, _, err := pap.Issue(signer(t, registry(t), keys.PurposeWorkloadTokens), issuer, tok, issuedAt, sp.notAfter)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func buildWorkloadTokens(t *testing.T) any {
	t.Helper()
	r := registry(t)
	v, err := r.Verifier(keys.PurposeWorkloadTokens, pap.TokenType)
	if err != nil {
		t.Fatal(err)
	}
	f := TokenFile{
		header: head("workload_tokens", "internal/identity/pap Issue and VerifyToken",
			"Workload tokens (pap-wt+jwt, PAP-1 §3.4) signed with the workload-token key in jwks. SDKs read them without "+
				"verifying: exp to renew, cnf.jkt to check the token is bound to their key, ath for proofs. A token that is "+
				"not a compact JWS, not version 1, for another audience or without exp or cnf.jkt is refused."),
		Issuer: issuer, JWKS: jwks(t, r), WorkloadKey: workloadKey("workload"),
	}
	for _, sp := range []tokenSpec{
		{name: "level 1, no release identity", level: 1},
		{name: "level 1, declared release", level: 1, state: pap.ReleaseDeclared},
		{name: "level 2 until its attestation expires", level: 2, state: pap.ReleaseAttested, notAfter: issuedAt.Add(4 * time.Minute)},
	} {
		tok := issue(t, sp)
		if _, err := pap.VerifyToken(v, issuer, tok, issuedAt.Add(time.Minute)); err != nil {
			t.Fatalf("%s: %v", sp.name, err)
		}
		_, p := segments(t, tok)
		f.Cases = append(f.Cases, TokenCase{Name: sp.name, Token: tok, Claims: p, ATH: athOf(tok), ValidAt: issuedAt.Add(time.Minute).Unix()})
	}
	_, claims := segments(t, issue(t, tokenSpec{level: 1}))
	ws := signer(t, r, keys.PurposeWorkloadTokens)
	for _, c := range []struct{ name, from, to string }{
		{"version 2", `"v":1`, `"v":2`},
		{"another audience", `"aud":"pantherclaw-gateway"`, `"aud":"another-service"`},
		{"no expiry", `"exp":1791720600,`, ``},
		{"no key binding", `"cnf":{"jkt":"` + workloadKey("workload").JKT + `"},`, ``},
	} {
		edited := bytes.Replace(claims, []byte(c.from), []byte(c.to), 1)
		if bytes.Equal(edited, claims) {
			t.Fatalf("%s: %q not in the claims", c.name, c.from)
		}
		tok, err := ws.Sign(pap.TokenType, edited)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pap.VerifyToken(v, issuer, tok, issuedAt.Add(time.Minute)); err == nil {
			t.Fatalf("%s: PantherClaw accepts it", c.name)
		}
		f.Cases = append(f.Cases, TokenCase{Name: c.name, Token: tok, Reject: c.name})
	}
	twoParts := b64([]byte(`{"alg":"EdDSA"}`)) + "." + b64([]byte(`{}`))
	f.Cases = append(f.Cases, TokenCase{Name: "not a compact JWS", Token: twoParts, Reject: "not a compact JWS"})
	return f
}

// ProofCase is a request proof (PAP-1 §4) as a workload signs it: from the
// key, the request and jti an SDK reproduces header, claims and proof byte
// for byte (Ed25519 is deterministic).
type ProofCase struct {
	Name   string `json:"name"`
	Method string `json:"method"`
	URL    string `json:"url"`
	Body   string `json:"body"`
	Token  string `json:"token,omitzero"`
	Nonce  string `json:"nonce,omitzero"`
	IAT    int64  `json:"iat"`
	JTI    string `json:"jti"`
	BH     string `json:"bh"`
	ATH    string `json:"ath,omitzero"`
	Header string `json:"header"`
	Claims string `json:"claims"`
	Proof  string `json:"proof"`
}

// ProofCheck is a proof PantherClaw receives with a request at a time, and
// its answer: "ok" or the PAP-Error code (steps 2–5 of PAP-1 §4; the token
// in every check is valid, so the answer is about the proof).
type ProofCheck struct {
	Name   string `json:"name"`
	Proof  string `json:"proof"`
	Method string `json:"method"`
	URL    string `json:"url"`
	Body   string `json:"body"`
	Token  string `json:"token,omitzero"`
	Now    int64  `json:"now"`
	Answer string `json:"answer"`
}

// HTUCase is the htu a client signs for a request URL, as PantherClaw's
// client computes it (internal/identity/workloadclient): the URL without
// query and fragment, the scheme in lower case, the host as written and the
// path as Go's url.URL.EscapedPath gives it. Reject: an SDK refuses to sign.
type HTUCase struct {
	URL    string `json:"url"`
	HTU    string `json:"htu,omitzero"`
	Reject bool   `json:"reject,omitzero"`
}

// ProofFile is proofs.json.
type ProofFile struct {
	header
	Key    Key          `json:"key"`
	Proofs []ProofCase  `json:"proofs"`
	HTUs   []HTUCase    `json:"htus"`
	Checks []ProofCheck `json:"checks"`
}

// htus are request URLs and the htu PantherClaw's client signs for them.
func htus(t *testing.T) []HTUCase {
	t.Helper()
	var out []HTUCase
	for _, raw := range []string{
		gatewayURL + "/sdk/payments",
		"HTTPS://Gateway.Example.TEST/sdk/payments",
		"https://gateway.example.test:443/sdk/payments",
		"https://gateway.example.test/sdk/../sdk/payments",
		"https://gateway.example.test/v1/wait/a b",
		"https://gateway.example.test/repos/a%2Fb",
		"https://gateway.example.test/p%7eq",
		"https://gateway.example.test/caf" + string(rune(0xe9)),
		"https://gateway.example.test/a(b)!*'$&+,;=:@[]",
		"https://gateway.example.test/a~%7e b",
		"https://gateway.example.test/x?q=1#f",
		"https://gateway.example.test",
		"http://127.0.0.1:8080/sdk/payments",
		"https://[::1]:8443/sdk/payments",
		"https://user@gateway.example.test/x",
		"ftp://gateway.example.test/x",
		"/sdk/payments",
		"https:///x",
		"https://gateway.example.test/a%zz",
	} {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
			out = append(out, HTUCase{URL: raw, Reject: true})
			continue
		}
		u.RawQuery, u.Fragment = "", ""
		out = append(out, HTUCase{URL: raw, HTU: u.String()})
	}
	return out
}

func buildProofs(t *testing.T) any {
	t.Helper()
	wk := key("workload")
	token := issue(t, tokenSpec{level: 1})
	other := issue(t, tokenSpec{level: 1, state: pap.ReleaseDeclared})
	strangerToken := issue(t, tokenSpec{level: 1, jkt: workloadKey("another workload").JKT})
	f := ProofFile{header: head("proofs", "internal/identity/pap NewProof and VerifyRequest",
		"PAP-Proof JWS (pap-proof+jwt). proofs: header {alg, jwk, typ} with jwk members crv, kty, x; claims htm, htu, "+
			"iat, jti, ath (with a token), bh, nonce (once the server sent one), in that order and without whitespace; bh "+
			"and ath are base64url SHA-256 of the exact body and token. checks: what PantherClaw answers a proof with a "+
			"request at a time, in the order of PAP-1 §4: proof header and signature, key binding, htm, htu (scheme and "+
			"host without case, path exactly), ath, bh, iat (at most 60 s ahead, 6 min behind), jti (22 to 128 printable "+
			"ASCII characters), nonce shape."), Key: workloadKey("workload")}
	sdkBody := `{"input":{"amount":"30.00","charge":"ch_1","currency":"USD","reason":"duplicate"},"server":"payments",` +
		`"tool":"mcp__payments__create_refund","tool_use_id":"toolu_01"}`
	sdkURL := gatewayURL + "/sdk/payments"
	at := issuedAt.Add(time.Minute)
	sign := func(name, method, url, body, tok, n string) ProofCase {
		p, err := pap.NewProof(wk, pap.ProofParams{Method: method, URL: url, Body: []byte(body), Token: tok, Nonce: n, Now: at})
		if err != nil {
			t.Fatal(err)
		}
		h, c := segments(t, p)
		var claims struct {
			JTI string `json:"jti"`
			BH  string `json:"bh"`
			ATH string `json:"ath"`
		}
		decodeInto(t, c, &claims)
		return ProofCase{
			Name: name, Method: method, URL: url, Body: body, Token: tok, Nonce: n, IAT: at.Unix(), JTI: claims.JTI, BH: claims.BH,
			ATH: claims.ATH, Header: string(h), Claims: string(c), Proof: p,
		}
	}
	f.Proofs = []ProofCase{
		sign("authorize through the /sdk face", http.MethodPost, sdkURL, sdkBody, token, nonce),
		sign("the wait stream (GET, empty body)", http.MethodGet, issuer+"/v1/wait/"+actionID, "", token, nonce),
		sign("token issuance (key-only)", http.MethodPost, issuer+"/pantherclaw.v1.WorkloadService/IssueToken",
			`{"identifier":"`+identifier()+`"}`, "", nonce),
		sign("the first request, before any nonce", http.MethodPost, sdkURL, sdkBody, token, ""),
	}
	f.HTUs = htus(t)
	slash := sign("a percent-encoded slash", http.MethodGet, gatewayURL+"/repos/a%2Fb", "", token, nonce)
	authz, keyOnly := f.Proofs[0], f.Proofs[2]
	check := func(name string, p ProofCase, edit func(*ProofCheck)) ProofCheck {
		c := ProofCheck{Name: name, Proof: p.Proof, Method: p.Method, URL: p.URL, Body: p.Body, Token: p.Token, Now: at.Unix()}
		if edit != nil {
			edit(&c)
		}
		return c
	}
	hdr := authz.Header
	claimsWith := func(from, to string) string { return strings.Replace(authz.Claims, from, to, 1) }
	f.Checks = []ProofCheck{
		check("the /sdk proof", authz, nil),
		check("the wait-stream proof", f.Proofs[1], nil),
		check("the key-only proof", keyOnly, nil),
		check("no nonce yet", f.Proofs[3], nil),
		check("htu with an upper-case scheme and host", authz, func(c *ProofCheck) {
			c.Proof = craft(hdr, claimsWith(`"htu":"https://gateway.example.test`, `"htu":"HTTPS://Gateway.Example.Test`), wk)
		}),
		check("another method", authz, func(c *ProofCheck) { c.Method = http.MethodPut }),
		check("htu with the default port written", authz, func(c *ProofCheck) {
			c.Proof = craft(hdr, claimsWith(`"htu":"https://gateway.example.test`, `"htu":"https://gateway.example.test:443`), wk)
		}),
		check("htu with a dot segment", authz, func(c *ProofCheck) {
			c.Proof = craft(hdr, claimsWith(`/sdk/payments"`, `/sdk/x/../payments"`), wk)
		}),
		check("htu escaping an unreserved character", authz, func(c *ProofCheck) {
			c.Proof = craft(hdr, claimsWith(`/sdk/payments"`, `/sdk/p%61yments"`), wk)
		}),
		check("a percent-encoded slash", slash, nil),
		check("a percent-encoded slash checked against the decoded path", slash, func(c *ProofCheck) { c.URL = gatewayURL + "/repos/a/b" }),
		check("another path", authz, func(c *ProofCheck) { c.URL = gatewayURL + "/sdk/other" }),
		check("another host", authz, func(c *ProofCheck) { c.URL = "https://evil.example.test/sdk/payments/actions" }),
		check("the body changed", authz, func(c *ProofCheck) { c.Body = strings.Replace(sdkBody, "30.00", "300.00", 1) }),
		check("sent with another token", authz, func(c *ProofCheck) { c.Token = other }),
		check("a token bound to another key", authz, func(c *ProofCheck) { c.Token = strangerToken }),
		check("a key-only proof sent with a token", keyOnly, func(c *ProofCheck) { c.Token = token }),
		check("ath without a token", authz, func(c *ProofCheck) { c.Token = "" }),
		check("issued 7 minutes ago", keyOnly, func(c *ProofCheck) { c.Now = at.Add(7 * time.Minute).Unix() }),
		check("issued 6 minutes ago", keyOnly, func(c *ProofCheck) { c.Now = at.Add(6 * time.Minute).Unix() }),
		check("issued 6 minutes and 1 second ago", keyOnly, func(c *ProofCheck) { c.Now = at.Add(6*time.Minute + time.Second).Unix() }),
		check("issued 2 minutes ahead", keyOnly, func(c *ProofCheck) { c.Now = at.Add(-2 * time.Minute).Unix() }),
		check("issued 60 seconds ahead", keyOnly, func(c *ProofCheck) { c.Now = at.Add(-time.Minute).Unix() }),
		check("issued 61 seconds ahead", keyOnly, func(c *ProofCheck) { c.Now = at.Add(-time.Minute - time.Second).Unix() }),
		check("a claim changed after signing", authz, func(c *ProofCheck) {
			parts := strings.Split(authz.Proof, ".")
			c.Proof = parts[0] + "." + b64([]byte(claimsWith(`"htm":"POST"`, `"htm":"PUT"`))) + "." + parts[2]
			c.Method = http.MethodPut
		}),
		check("alg none", authz, func(c *ProofCheck) { c.Proof = craft(strings.Replace(hdr, `"EdDSA"`, `"none"`, 1), authz.Claims, nil) }),
		check("alg Ed25519 (RFC 9864), not yet accepted on proofs", authz, func(c *ProofCheck) {
			c.Proof = craft(strings.Replace(hdr, `"EdDSA"`, `"Ed25519"`, 1), authz.Claims, wk)
		}),
		check("a private key in the jwk", authz, func(c *ProofCheck) {
			c.Proof = craft(strings.Replace(hdr, `"kty":"OKP",`, `"d":"`+b64(seed("workload"))+`","kty":"OKP",`, 1), authz.Claims, wk)
		}),
		check("another typ", authz, func(c *ProofCheck) {
			c.Proof = craft(strings.Replace(hdr, "pap-proof+jwt", "JWT", 1), authz.Claims, wk)
		}),
		check("a jti shorter than 128 bits", authz, func(c *ProofCheck) { c.Proof = craft(hdr, claimsWith(authz.JTI, "short-jti"), wk) }),
		check("a malformed nonce", authz, func(c *ProofCheck) { c.Proof = craft(hdr, claimsWith(nonce, "short"), wk) }),
	}
	want := []string{
		"ok", "ok", "ok", "use_nonce", "ok", "invalid_proof", "invalid_proof", "invalid_proof", "invalid_proof", "ok",
		"invalid_proof", "invalid_proof", "invalid_proof", "body_hash_mismatch", "invalid_proof", "key_mismatch", "invalid_proof",
		"invalid_proof", "invalid_proof", "ok", "invalid_proof", "invalid_proof", "ok", "invalid_proof", "invalid_proof",
		"invalid_proof", "invalid_proof", "invalid_proof", "invalid_proof", "invalid_proof", "use_nonce",
	}
	if len(want) != len(f.Checks) {
		t.Fatalf("%d answers for %d checks", len(want), len(f.Checks))
	}
	v, err := registry(t).Verifier(keys.PurposeWorkloadTokens, pap.TokenType)
	if err != nil {
		t.Fatal(err)
	}
	for i := range f.Checks {
		c := &f.Checks[i]
		_, err := pap.VerifyRequest(v, issuer, pap.Request{Method: c.Method, URL: c.URL, BodySHA256: sha256.Sum256([]byte(c.Body)), Token: c.Token},
			c.Proof, time.Unix(c.Now, 0))
		c.Answer = "ok"
		if err != nil {
			c.Answer = string(pap.CodeOf(err))
		}
		if c.Answer != want[i] {
			t.Fatalf("%s: PantherClaw answers %s (%v), want %s", c.Name, c.Answer, err, want[i])
		}
	}
	return f
}
