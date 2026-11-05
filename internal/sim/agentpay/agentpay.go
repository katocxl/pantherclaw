// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package agentpay is a simulated AP2 merchant and credentials provider for
// tests and demos (pantherclaw-sim agentpay, G0 M39 D1124). Everything it
// does is SIMULATED, on loopback, with fixed development keys that are
// public by design: no card, network token or payment credential exists
// here, and nothing reaches a payment network.
//
// The merchant:
//
//   - POST /ap2/checkouts makes a merchant-signed checkout JWT (EdDSA) for
//     {amount (minor units), currency}, with checkout_hash, the base64url
//     SHA-256 of the JWT, which an AP2 v0.2 payment mandate's
//     transaction_id carries;
//   - POST /ap2/checkout takes {merchant, amount, currency, checkout_jwt,
//     payment_mandate, pantherclaw_key} with an Idempotency-Key header and
//     answers {transaction_id, status}; the same key answers the same
//     transaction (the merchant's own idempotency);
//   - GET /ap2/transactions/{id} reads one transaction;
//   - GET /merchant/.well-known/jwks.json is the merchant's key, the static
//     JWKS a MERCHANT trust anchor holds in development.
//
// The credentials provider:
//
//   - POST /cp/mandates signs, for {checkout_jwt, aud, nonce}, an AP2 v0.2
//     checkout mandate (vct mandate.checkout.1: checkout_jwt and
//     checkout_hash) and payment mandate (vct mandate.payment.1:
//     transaction_id, payee, payment_amount and a synthetic
//     payment_instrument) as SD-JWTs whose claims are all selectively
//     disclosable, and answers the envelope ap2.Verify takes,
//     {"checkout_mandate", "payment_mandate"}, as JSON text; cnf.jwk is
//     the development holder (agent) key, which also signs each key-binding
//     JWT (typ kb+jwt) over aud, nonce and sd_hash. A real agent signs its
//     own key binding; the simulator does both so a demo needs nothing
//     else;
//   - GET /cp/.well-known/jwks.json is the issuer key, the static JWKS a
//     MANDATE_ISSUER trust anchor holds in development.
//
// Faults: Mismatch signs mandates for one minor unit more than the checkout
// (MANDATE_MISMATCH), Expired signs mandates that expired a minute ago
// (MANDATE_INVALID), and Decline answers every checkout as declined. GET
// /__sim/stats lists what was asked, for tests.
package agentpay

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

// Simulated identities.
const (
	// Merchant is the simulated merchant's id, as pc.agentpay's merchant
	// param spells it.
	Merchant = "sim-merchant.example"
	// MerchantName is its display name.
	MerchantName = "Simulated Merchant (SIMULATED)"
	// Issuer is the credentials provider's issuer id (iss).
	Issuer = "https://cp.sim.pantherclaw.invalid"
	// PaymentVCT and CheckoutVCT are the AP2 v0.2 mandate types.
	PaymentVCT  = "mandate.payment.1"
	CheckoutVCT = "mandate.checkout.1"
	// MerchantKID, IssuerKID and HolderKID name the development keys.
	MerchantKID = "sim-merchant-1"
	IssuerKID   = "sim-cp-1"
	HolderKID   = "sim-agent-1"
)

const (
	maxBody     = 64 << 10
	checkoutTTL = 15 * time.Minute
	mandateTTL  = 15 * time.Minute
)

// devKey derives a fixed development key from a label: public by design,
// never a secret (SIMULATED).
func devKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("pantherclaw-sim agentpay development key: " + label))
	return ed25519.NewKeyFromSeed(seed[:])
}

var (
	merchantKey = devKey("merchant")
	issuerKey   = devKey("credentials-provider")
	holderKey   = devKey("holder")
)

// JWK is a public Ed25519 key as a JWK (RFC 8037).
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Kid string `json:"kid,omitzero"`
	Alg string `json:"alg,omitzero"`
	Use string `json:"use,omitzero"`
}

func jwkOf(k ed25519.PrivateKey, kid string) JWK {
	pub, _ := k.Public().(ed25519.PublicKey)
	return JWK{Kty: "OKP", Crv: "Ed25519", X: b64(pub), Kid: kid, Alg: "EdDSA", Use: "sig"}
}

// JWKS is a key set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// MerchantJWKS is the merchant's development JWKS, for a MERCHANT trust
// anchor (the dev seed).
func MerchantJWKS() []byte { return mustJSON(JWKS{Keys: []JWK{jwkOf(merchantKey, MerchantKID)}}) }

// IssuerJWKS is the credentials provider's development JWKS, for a
// MANDATE_ISSUER trust anchor (the dev seed).
func IssuerJWKS() []byte { return mustJSON(JWKS{Keys: []JWK{jwkOf(issuerKey, IssuerKID)}}) }

// HolderJWK is the development agent's holder key (cnf.jwk).
func HolderJWK() JWK { return jwkOf(holderKey, HolderKID) }

func mustJSON(v any) []byte {
	b, err := json.Marshal(v, json.Deterministic(true))
	if err != nil {
		panic(err)
	}
	return b
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// sign makes a compact EdDSA JWS of claims.
func sign(k ed25519.PrivateKey, typ, kid string, claims any) string {
	h := map[string]string{"alg": "EdDSA", "typ": typ}
	if kid != "" {
		h["kid"] = kid
	}
	in := b64(mustJSON(h)) + "." + b64(mustJSON(claims))
	return in + "." + b64(ed25519.Sign(k, []byte(in)))
}

// Hash is the base64url SHA-256 of s, as AP2 hashes a checkout JWT.
func Hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return b64(h[:])
}

// Faults configures fault injection.
type Faults struct {
	// Mismatch signs mandates for one minor unit more than the checkout.
	Mismatch bool `json:"mismatch,omitzero"`
	// Expired signs mandates that expired a minute ago.
	Expired bool `json:"expired,omitzero"`
	// Decline answers every checkout as declined.
	Decline bool `json:"decline,omitzero"`
}

// Sim is the simulated merchant and credentials provider.
type Sim struct {
	faults Faults
	log    *slog.Logger
	now    func() time.Time

	mu    sync.Mutex
	txs   map[string]transaction // by transaction id
	byKey map[string]string      // Idempotency-Key -> transaction id
	stats map[string]int
}

type transaction struct {
	ID        string `json:"transaction_id"`
	Merchant  string `json:"merchant"`
	Amount    int64  `json:"amount"`
	Currency  string `json:"currency"`
	Status    string `json:"status"`
	Mandate   string `json:"mandate_digest"`
	Simulated bool   `json:"simulated"`
}

// New returns the simulator.
func New(f Faults, log *slog.Logger) *Sim {
	return &Sim{faults: f, log: log, now: time.Now, txs: map[string]transaction{}, byKey: map[string]string{}, stats: map[string]int{}}
}

// Handler serves the simulator's routes.
func (s *Sim) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /ap2/checkouts", s.checkouts)
	mux.HandleFunc("POST /ap2/checkout", s.checkout)
	mux.HandleFunc("GET /ap2/transactions/{id}", s.transaction)
	mux.HandleFunc("GET /merchant/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) { s.raw(w, MerchantJWKS()) })
	mux.HandleFunc("POST /cp/mandates", s.mandates)
	mux.HandleFunc("GET /cp/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) { s.raw(w, IssuerJWKS()) })
	mux.HandleFunc("GET /__sim/stats", func(w http.ResponseWriter, _ *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.write(w, http.StatusOK, s.stats)
	})
	return mux
}

func (s *Sim) count(k string) {
	s.mu.Lock()
	s.stats[k]++
	s.mu.Unlock()
}

func (s *Sim) raw(w http.ResponseWriter, b []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Simulated", "true")
	_, _ = w.Write(b)
}

func (s *Sim) write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Simulated", "true")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, v, json.Deterministic(true))
}

func (s *Sim) fail(w http.ResponseWriter, status int, code string) {
	s.write(w, status, map[string]any{"error": code, "simulated": true})
}

func read(r *http.Request, v any) bool {
	b, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	return err == nil && len(b) <= maxBody && json.Unmarshal(b, v) == nil
}

var currencyRe = regexp.MustCompile(`^[A-Z]{3}$`)

// checkoutClaims are the merchant-signed checkout's claims.
type checkoutClaims struct {
	Iss      string `json:"iss"`
	Vct      string `json:"vct"`
	Jti      string `json:"jti"`
	Merchant string `json:"merchant"`
	Amount   int64  `json:"amount"`
	Currency string `json:"currency"`
	Items    []item `json:"items"`
	Iat      int64  `json:"iat"`
	Exp      int64  `json:"exp"`
}

type item struct {
	Label  string `json:"label"`
	Amount int64  `json:"amount"`
}

func nonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Sim) checkouts(w http.ResponseWriter, r *http.Request) {
	s.count("checkouts")
	var in struct {
		Amount   int64  `json:"amount"`
		Currency string `json:"currency"`
	}
	if !read(r, &in) || in.Amount < 1 || in.Amount > 9_999_999 || !currencyRe.MatchString(in.Currency) {
		s.fail(w, http.StatusBadRequest, "invalid_checkout")
		return
	}
	now := s.now()
	jwt := sign(merchantKey, "JWT", MerchantKID, checkoutClaims{
		Iss: Merchant, Vct: CheckoutVCT, Jti: nonce(), Merchant: Merchant, Amount: in.Amount, Currency: in.Currency,
		Items: []item{{Label: "Simulated item (SIMULATED)", Amount: in.Amount}}, Iat: now.Unix(), Exp: now.Add(checkoutTTL).Unix(),
	})
	s.write(w, http.StatusOK, map[string]any{"checkout_jwt": jwt, "checkout_hash": Hash(jwt), "merchant": Merchant, "simulated": true})
}

// checkoutOf reads a checkout JWT's claims without checking its signature:
// the simulator trusts its own checkouts (SIMULATED).
func checkoutOf(jwt string) (checkoutClaims, bool) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return checkoutClaims{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	var c checkoutClaims
	return c, err == nil && json.Unmarshal(raw, &c) == nil && c.Merchant != ""
}

// disclosure is one SD-JWT disclosure: base64url of [salt, name, value].
func disclosure(name string, value any) string {
	return b64(mustJSON([]any{nonce(), name, value}))
}

// present issues an SD-JWT of vct whose claims are all disclosable, bound
// to the development holder key, and presents it with a KB-JWT over aud and
// nonce (RFC 9901).
func present(vct string, claims map[string]any, now, exp time.Time, aud, nonceValue string) string {
	ds := make([]string, 0, len(claims))
	sd := make([]string, 0, len(claims))
	for _, name := range sortedKeys(claims) {
		d := disclosure(name, claims[name])
		ds = append(ds, d)
		sd = append(sd, Hash(d))
	}
	issued := sign(issuerKey, "dc+sd-jwt", IssuerKID, map[string]any{
		"iss": Issuer, "vct": vct, "iat": now.Unix(), "exp": exp.Unix(), "_sd_alg": "sha-256", "_sd": sd,
		"cnf": map[string]any{"jwk": HolderJWK()},
	})
	presented := issued + "~" + strings.Join(ds, "~") + "~"
	kb := sign(holderKey, "kb+jwt", "", map[string]any{"iat": now.Unix(), "aud": aud, "nonce": nonceValue, "sd_hash": Hash(presented)})
	return presented + kb
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// mandates signs an AP2 v0.2 checkout mandate and payment mandate for a
// checkout and answers the envelope pc.agentpay's payment_mandate param
// carries: {"checkout_mandate": ..., "payment_mandate": ...}.
func (s *Sim) mandates(w http.ResponseWriter, r *http.Request) {
	s.count("mandates")
	var in struct {
		CheckoutJWT string `json:"checkout_jwt"`
		Aud         string `json:"aud"`
		Nonce       string `json:"nonce"`
	}
	if !read(r, &in) {
		s.fail(w, http.StatusBadRequest, "invalid_request")
		return
	}
	c, ok := checkoutOf(in.CheckoutJWT)
	if !ok || in.Aud == "" || len(in.Aud) > 512 || in.Nonce == "" || len(in.Nonce) > 128 {
		s.fail(w, http.StatusBadRequest, "invalid_request")
		return
	}
	amount := c.Amount
	if s.faults.Mismatch {
		amount++
	}
	now := s.now()
	exp := now.Add(mandateTTL)
	if s.faults.Expired {
		exp = now.Add(-time.Minute)
	}
	hash := Hash(in.CheckoutJWT)
	checkout := present(CheckoutVCT, map[string]any{"checkout_jwt": in.CheckoutJWT, "checkout_hash": hash}, now, exp, in.Aud, in.Nonce)
	payment := present(PaymentVCT, map[string]any{
		"transaction_id": hash,
		"payee":          map[string]string{"id": c.Merchant, "name": MerchantName},
		"payment_amount": map[string]any{"amount": amount, "currency": c.Currency},
		// A synthetic instrument: no card or token exists here.
		"payment_instrument": map[string]string{"id": "sim-instrument-" + c.Jti[:8], "type": "card", "description": "SIMULATED"},
	}, now, exp, in.Aud, in.Nonce)
	envelope := string(mustJSON(map[string]string{"checkout_mandate": checkout, "payment_mandate": payment}))
	s.write(w, http.StatusOK, map[string]any{"payment_mandate": envelope, "simulated": true})
}

func (s *Sim) checkout(w http.ResponseWriter, r *http.Request) {
	s.count("checkout")
	var in struct {
		Merchant       string `json:"merchant"`
		Amount         int64  `json:"amount"`
		Currency       string `json:"currency"`
		CheckoutJWT    string `json:"checkout_jwt"`
		PaymentMandate string `json:"payment_mandate"`
		Key            string `json:"pantherclaw_key"`
	}
	if !read(r, &in) || in.Merchant != Merchant || in.CheckoutJWT == "" || in.PaymentMandate == "" {
		s.fail(w, http.StatusBadRequest, "invalid_checkout")
		return
	}
	idem := r.Header.Get("Idempotency-Key")
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, ok := s.byKey[idem]; ok && idem != "" {
		s.write(w, http.StatusOK, s.txs[id])
		return
	}
	status := "succeeded"
	if s.faults.Decline {
		status = "declined"
	}
	md := sha256.Sum256([]byte(in.PaymentMandate))
	t := transaction{
		ID: Hash(in.CheckoutJWT), Merchant: in.Merchant, Amount: in.Amount, Currency: in.Currency, Status: status,
		Mandate: "sha256:" + hex.EncodeToString(md[:]), Simulated: true,
	}
	s.txs[t.ID] = t
	if idem != "" {
		s.byKey[idem] = t.ID
	}
	code := http.StatusOK
	if status == "declined" {
		code = http.StatusPaymentRequired
	}
	s.write(w, code, t)
}

func (s *Sim) transaction(w http.ResponseWriter, r *http.Request) {
	s.count("transaction")
	s.mu.Lock()
	t, ok := s.txs[r.PathValue("id")]
	s.mu.Unlock()
	if !ok {
		s.fail(w, http.StatusNotFound, "not_found")
		return
	}
	s.write(w, http.StatusOK, t)
}
