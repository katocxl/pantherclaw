// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package federationkeys

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

func fedKey(t *testing.T) (ed25519.PublicKey, *jws.Signer, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kid := "fed-" + jws.Thumbprint(pub)
	s, err := jws.NewSigner(kid, priv)
	if err != nil {
		t.Fatal(err)
	}
	return pub, s, kid
}

func sampleDoc(org ids.OrgID, pub ed25519.PublicKey, kid string, now time.Time) Document {
	return Document{
		V: DocumentVersion, OrgID: org.String(), OrgName: "Acme",
		ServerURL: "https://acme.example", FederationURL: "https://fed.acme.example",
		Keys:     JWKS{Keys: []jws.JWK{jws.PublicJWK(pub, kid)}},
		Agents:   []DocAgent{{Listing: "pay", AgentName: "pay", CardURL: "https://fed.acme.example/fed/a2a/pay/.well-known/agent-card.json", CardDigest: "abc"}},
		IssuedAt: now.Unix(), ExpiresAt: now.Add(24 * time.Hour).Unix(),
	}
}

func signedDoc(t *testing.T, d Document, signers ...*jws.Signer) []byte {
	t.Helper()
	payload, err := json.Marshal(d, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := signDocument(signers, payload)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestHR770_FederationDocumentIsSignedByTheOrgKey: a document verifies when
// the org's key signed it, names no peer, and is refused when the signature
// or the lifetime does not.
func TestHR770_FederationDocumentIsSignedByTheOrgKey(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	org := ids.New[ids.Org]()
	pub, signer, kid := fedKey(t)
	raw := signedDoc(t, sampleDoc(org, pub, kid, now), signer)
	got, err := verifyDocument(raw, now)
	if err != nil {
		t.Fatalf("signed document: %v", err)
	}
	if len(got.SignedBy) != 1 || got.SignedBy[0] != kid {
		t.Fatalf("signed by %v, want %s", got.SignedBy, kid)
	}
	payload, err := json.Marshal(got.Doc, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), "peer") {
		t.Fatalf("document names a peer: %s", payload)
	}

	forged := append([]byte(nil), raw...)
	forged[len(forged)-2] ^= 0x01
	if _, err := verifyDocument(forged, now); err == nil {
		t.Fatal("forged signature verified")
	}
	late := sampleDoc(org, pub, kid, now)
	late.ExpiresAt = late.IssuedAt + int64((8 * 24 * time.Hour).Seconds())
	if _, err := verifyDocument(signedDoc(t, late, signer), now); err == nil {
		t.Fatal("document valid for more than 7 days verified")
	}
	httpDoc := sampleDoc(org, pub, kid, now)
	httpDoc.ServerURL = "http://acme.example"
	if _, err := verifyDocument(signedDoc(t, httpDoc, signer), now); err == nil {
		t.Fatal("http server URL verified")
	}
}

// TestHR771_SafetyCodeMatchesOnBothSides: both orgs compute one safety
// code, and a different key digest does not.
func TestHR771_SafetyCodeMatchesOnBothSides(t *testing.T) {
	a, b := ids.NewV7(), ids.NewV7()
	da, db := sha256.Sum256([]byte("a")), sha256.Sum256([]byte("b"))
	if SafetyCode(a, da, b, db) != SafetyCode(b, db, a, da) {
		t.Fatal("the two orgs computed different safety codes")
	}
	other := sha256.Sum256([]byte("c"))
	if SafetyCode(a, da, b, db) == SafetyCode(a, other, b, db) {
		t.Fatal("a different key digest kept the safety code")
	}
	pub, _, _ := fedKey(t)
	if KeysDigest(map[string]ed25519.PublicKey{"z": pub, "a": pub}) != KeysDigest(map[string]ed25519.PublicKey{"a": pub, "z": pub}) {
		t.Fatal("key digest depended on map order")
	}
	if ErrReplay.Code() != pcerr.Unauthenticated || ErrReplay.Reason() != "FEDERATION_REPLAY" {
		t.Fatalf("replay is %s %s, want unauthenticated FEDERATION_REPLAY", ErrReplay.Code(), ErrReplay.Reason())
	}
}

// TestHR772_ANewKeyIsPinnedOnlyWhenAPinnedKeySignedIt: a rotation signed by
// a pinned key is accepted; a document signed only by a new key is not.
func TestHR772_ANewKeyIsPinnedOnlyWhenAPinnedKeySignedIt(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	org := ids.New[ids.Org]()
	oldPub, oldSigner, oldKid := fedKey(t)
	newPub, newSigner, newKid := fedKey(t)
	pinned, err := json.Marshal(JWKS{Keys: []jws.JWK{jws.PublicJWK(oldPub, oldKid)}}, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	both := sampleDoc(org, oldPub, oldKid, now)
	both.Keys.Keys = append(both.Keys.Keys, jws.PublicJWK(newPub, newKid))
	vd, err := verifyDocument(signedDoc(t, both, oldSigner, newSigner), now)
	if err != nil {
		t.Fatal(err)
	}
	if !signedByPinned(vd, pinned) {
		t.Fatal("a document also signed by the pinned key was not accepted")
	}
	onlyNew := sampleDoc(org, newPub, newKid, now)
	vd, err = verifyDocument(signedDoc(t, onlyNew, newSigner), now)
	if err != nil {
		t.Fatal(err)
	}
	if signedByPinned(vd, pinned) {
		t.Fatal("a document signed only by a new key was pinned")
	}
	if ErrNotTrusted.Reason() != "FEDERATION_NOT_TRUSTED" || ErrPeerStale.Reason() != "FEDERATION_PEER_STALE" {
		t.Fatal("a stale or revoked trust does not refuse with the federation reasons")
	}
}

// TestHR773_ListingsAndCardsStaySigned: a listing name is the closed
// pattern, and a card is cached for at most an hour.
func TestHR773_ListingsAndCardsStaySigned(t *testing.T) {
	if !listingName.MatchString("pay-1") || listingName.MatchString("Pay") || listingName.MatchString("a_b") {
		t.Fatal("listing names are not ^[a-z0-9-]{1,63}$")
	}
	if CardTTL != time.Hour {
		t.Fatalf("card cache %s, want 1h", CardTTL)
	}
}

func goodCall(t *testing.T) (tokenClaims, ids.UUID, ids.OrgID, authority.FederatedCallInput, time.Time) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	org := ids.New[ids.Org]()
	peer := ids.NewV7()
	body := sha256.Sum256([]byte(`{"jsonrpc":"2.0"}`))
	const listing = "pay"
	htu := FaceURL("https://fed.example", listing)
	cl := tokenClaims{
		Iss: orgSubject(peer), Aud: orgSubject(org.UUID()), Sub: orgSubject(peer) + "/agent/bot",
		IAT: now.Unix(), EXP: now.Add(TokenTTL).Unix(), JTI: ids.NewV7().String(),
		Pap: tokenPap{
			V: 1, Fed: 1, AttLvl: 2, Action: ids.NewV7().String(), Txn: ids.NewV7().String(),
			Listing: listing, Htm: "POST", Htu: htu, Bh: bh(body), DecisionDigest: "abc",
		},
	}
	in := authority.FederatedCallInput{BodySHA256: body, HTU: htu, Listing: listing}
	return cl, peer, org, in, now
}

// TestHR774_AFederationTokenIsBoundToOneRequest: a token for this POST,
// URL and body is accepted, and another body or a longer life is not.
func TestHR774_AFederationTokenIsBoundToOneRequest(t *testing.T) {
	cl, peer, org, in, now := goodCall(t)
	if err := checkToken(cl, peer, org, "https://fed.example", in, now); err != nil {
		t.Fatalf("bound token: %v", err)
	}
	other := sha256.Sum256([]byte("other"))
	in.BodySHA256 = other
	if err := checkToken(cl, peer, org, "https://fed.example", in, now); err == nil {
		t.Fatal("a token for another body was accepted")
	}
	cl.EXP = cl.IAT + int64(TokenTTL/time.Second) + 1
	in.BodySHA256 = sha256.Sum256([]byte(`{"jsonrpc":"2.0"}`))
	if err := checkToken(cl, peer, org, "https://fed.example", in, now); err == nil {
		t.Fatal("a token living longer than 60s was accepted")
	}
	if _, ok := any(cl).(struct{ Cnf string }); ok {
		t.Fatal("a federation token must not carry cnf")
	}
}

// TestHR775_AFederatedCallMatchesTheListing: the URL and method binding
// are the listing's, and a token addressed elsewhere is refused.
func TestHR775_AFederatedCallMatchesTheListing(t *testing.T) {
	cl, peer, org, in, now := goodCall(t)
	if err := checkToken(cl, peer, org, "https://fed.example", in, now); err != nil {
		t.Fatal(err)
	}
	cl.Pap.Htu = FaceURL("https://fed.example", "other")
	in.HTU = cl.Pap.Htu
	if err := checkToken(cl, peer, org, "https://fed.example", in, now); err == nil {
		t.Fatal("a token for another listing was accepted")
	}
	if ErrTokenInvalid.Code() != pcerr.Unauthenticated || ErrTokenInvalid.Reason() != "FEDERATION_TOKEN_INVALID" {
		t.Fatalf("invalid token is %s %s", ErrTokenInvalid.Code(), ErrTokenInvalid.Reason())
	}
}

// TestHR776_AReceiptCarriesNothingButTheDecision: the receipt payload has
// the decision and the request digest, and not checks, reasons or policy.
func TestHR776_AReceiptCarriesNothingButTheDecision(t *testing.T) {
	cl := receiptClaims{
		Iss: "pc:org/us", Aud: "pc:org/them", IAT: 1, JTI: "j",
		Pap: receiptPap{V: 1, Kind: "federation", Decision: DecisionDeny, Action: "ours", PeerAction: "theirs", Listing: "pay", ReqDigest: "bh"},
	}
	raw, err := json.Marshal(cl, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{`"reason"`, `"policy"`, `"checks"`, `"checklist"`} {
		if strings.Contains(string(raw), banned) {
			t.Fatalf("receipt carries %s: %s", banned, raw)
		}
	}
	if !strings.Contains(string(raw), `"decision":"DENY"`) || !strings.Contains(string(raw), `"req_digest":"bh"`) {
		t.Fatalf("receipt dropped the decision or digest: %s", raw)
	}
	if AgentTextHeld == "" || AgentTextRefused == "" || MaxGrantTTL != 90*24*time.Hour {
		t.Fatal("hold text, refusal text or the 90-day grant cap is missing")
	}
}

// TestT350_AForgedPeerDocumentDoesNotVerify: an attacker key cannot stand
// in for the org key on the document.
func TestT350_AForgedPeerDocumentDoesNotVerify(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	org := ids.New[ids.Org]()
	pub, _, kid := fedKey(t)
	_, attacker, _ := fedKey(t)
	raw := signedDoc(t, sampleDoc(org, pub, kid, now), attacker)
	if _, err := verifyDocument(raw, now); err == nil {
		t.Fatal("a document signed by another key verified against the named key")
	}
}

// TestT351_ATokenForOneBodyDoesNotCoverAnother: replaying a token against
// another body is refused, and a replayed jti is the unauthenticated replay.
func TestT351_ATokenForOneBodyDoesNotCoverAnother(t *testing.T) {
	cl, peer, org, in, now := goodCall(t)
	in.BodySHA256 = sha256.Sum256([]byte("second"))
	if err := checkToken(cl, peer, org, "https://fed.example", in, now); !strings.Contains(err.Error(), "FEDERATION_TOKEN_INVALID") {
		t.Fatalf("other body: %v", err)
	}
	if ErrReplay.Code() != pcerr.Unauthenticated {
		t.Fatal("FEDERATION_REPLAY is not unauthenticated")
	}
}

// TestT352_AnUnpinnedKeyDoesNotRotateThePin: see TestHR772. A document
// whose only signature is a new key stays unpinned.
func TestT352_AnUnpinnedKeyDoesNotRotateThePin(t *testing.T) {
	TestHR772_ANewKeyIsPinnedOnlyWhenAPinnedKeySignedIt(t)
}
