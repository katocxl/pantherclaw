// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package federationkeys is cross-organization federation (G0 M35
// D1020–D1025; HR-770..776): an organization's federation document and
// keys, the trust ceremony with a peer org (safety code, a person's
// step-up confirmation on both sides, peer confirmation and revocation),
// the daily refresh of each peer's document, listings of this org's agents
// that peers may reach, cross-org grants to a peer org's agents, the
// federation calls the gateway's federation face admits, and the minimal
// pap-fed-receipt+jwt receipts in both directions. Only the Enterprise
// edition federates (FEDERATION_EDITION).
package federationkeys

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// JOSE types (G0 M35 D1020, D1021, D1024, D1025).
const (
	TypeDocument = "pc-federation+jws"
	TypeConfirm  = "pc-federation-confirm+jws"
	TypeRevoke   = "pc-federation-revoke+jws"
	TypeToken    = "pap-fed+jwt" //nolint:gosec // G101: a JOSE type, not a credential
	TypeReceipt  = "pap-fed-receipt+jwt"
)

// DocumentVersion is the document payload's version.
const DocumentVersion = "pantherclaw.federation/1"

// Limits.
const (
	// DocumentTTL bounds a document's validity.
	DocumentTTL = 7 * 24 * time.Hour
	// MaxDocumentBytes bounds a fetched document.
	MaxDocumentBytes = 64 << 10
	// MaxPeerMessageBytes bounds a peer confirmation or revocation body.
	MaxPeerMessageBytes = 16 << 10
	// ConfirmTTL bounds a confirmation or revocation's lifetime.
	ConfirmTTL = 10 * time.Minute
	// TokenTTL is a pap-fed+jwt's lifetime.
	TokenTTL = 60 * time.Second
	// clockSkew is the allowed issuer clock skew.
	clockSkew = 30 * time.Second
	// MaxGrantTTL bounds a cross-org grant.
	MaxGrantTTL = 90 * 24 * time.Hour
)

// Refusals (agent-safe and operator texts; G0 M35 D1025).
var (
	ErrNotTrusted = pcerr.New(pcerr.PermissionDenied, "FEDERATION_NOT_TRUSTED",
		"this organization has no active federation trust with the peer organization")
	ErrPeerStale = pcerr.New(pcerr.FailedPrecondition, "FEDERATION_PEER_STALE",
		"the peer organization's federation document has expired and could not be refreshed")
	ErrTokenInvalid = pcerr.New(pcerr.Unauthenticated, "FEDERATION_TOKEN_INVALID",
		"the federation token did not verify for this organization and request")
	ErrReplay = pcerr.New(pcerr.Unauthenticated, "FEDERATION_REPLAY",
		"the federation token or message was already used")
	ErrSafetyCode = pcerr.New(pcerr.FailedPrecondition, "FEDERATION_SAFETY_CODE",
		"the safety code no longer matches both organizations' keys; propose the trust again")
	ErrKeyUnverified = pcerr.New(pcerr.FailedPrecondition, "FEDERATION_KEY_UNVERIFIED",
		"the peer's federation document is not signed by a key this organization pinned")
	ErrListingUnknown = pcerr.New(pcerr.NotFound, "FEDERATION_LISTING_UNKNOWN",
		"no active federation listing has that name")
	ErrEdition = pcerr.New(pcerr.PermissionDenied, "FEDERATION_EDITION",
		"federation needs the Enterprise edition")
	ErrDocument = pcerr.New(pcerr.InvalidArgument, "FEDERATION_DOCUMENT_INVALID",
		"the peer's federation document did not verify")
	ErrStepUp = pcerr.New(pcerr.PermissionDenied, "STEP_UP_REQUIRED",
		"verify with one of your security keys on this page first")
	ErrPersonOnly = pcerr.New(pcerr.PermissionDenied, "PERSON_REQUIRED",
		"only a person can change federation")
	ErrNoEndpoint = pcerr.New(pcerr.FailedPrecondition, "FEDERATION_ENDPOINT_UNSET",
		"set this organization's federation face URL first")
	ErrTrustState = pcerr.New(pcerr.FailedPrecondition, "FEDERATION_TRUST_STATE",
		"the federation trust is not in a state that allows this")
	ErrTrustNotFound = pcerr.New(pcerr.NotFound, "FEDERATION_TRUST_NOT_FOUND", "no such federation trust")
	ErrTrustExists   = pcerr.New(pcerr.AlreadyExists, "FEDERATION_TRUST_EXISTS",
		"this organization already has a trust with the peer organization")
	ErrListingInvalid = pcerr.New(pcerr.InvalidArgument, "FEDERATION_LISTING_INVALID",
		"the listing's connection must be an active a2a connection to the listed agent, and its skills must be the connection's")
	ErrGrantInvalid = pcerr.New(pcerr.InvalidArgument, "FEDERATION_GRANT_INVALID",
		"a cross-org grant names a peer agent of the trust's peer org and expires within 90 days")
)

// AgentTextHeld and AgentTextRefused are the agent-safe texts of a peer's
// answer (D1025).
const (
	AgentTextHeld    = "held for the receiving organization's approval; ask again later"
	AgentTextRefused = "the receiving organization refused this message"
)

// DocAgent is one listed agent in a document.
type DocAgent struct {
	Listing    string `json:"listing"`
	AgentName  string `json:"agent_name"`
	CardURL    string `json:"card_url"`
	CardDigest string `json:"card_digest"`
}

// JWKS is a JSON Web Key Set of Ed25519 keys.
type JWKS struct {
	Keys []jws.JWK `json:"keys"`
}

// Document is a federation document's payload. It never names peers.
type Document struct {
	V             string     `json:"v"`
	OrgID         string     `json:"org_id"`
	OrgName       string     `json:"org_name"`
	ServerURL     string     `json:"server_url"`
	FederationURL string     `json:"federation_url,omitzero"`
	Keys          JWKS       `json:"keys"`
	Agents        []DocAgent `json:"agents"`
	IssuedAt      int64      `json:"issued_at"`
	ExpiresAt     int64      `json:"expires_at"`
}

// general is the JWS JSON general serialization (RFC 7515 §7.2.1).
type general struct {
	Payload    string       `json:"payload"`
	Signatures []generalSig `json:"signatures"`
}

type generalSig struct {
	Protected string `json:"protected"`
	Signature string `json:"signature"`
}

// DocumentURL is where an org's document is served.
func DocumentURL(serverURL string, org ids.OrgID) string {
	return strings.TrimSuffix(serverURL, "/") + "/.well-known/pantherclaw/orgs/" + org.String() + "/federation.json"
}

// FaceURL is a listing's URL on the federation face.
func FaceURL(federationURL, listing string) string {
	return strings.TrimSuffix(federationURL, "/") + "/fed/a2a/" + listing
}

// CardURL is a listing's card on the federation face.
func CardURL(federationURL, listing string) string {
	return FaceURL(federationURL, listing) + "/.well-known/agent-card.json"
}

// signDocument signs payload with every signer (the ACTIVE key first)
// into one general serialization.
func signDocument(signers []*jws.Signer, payload []byte) ([]byte, error) {
	if len(signers) == 0 {
		return nil, fmt.Errorf("federation: no signing key")
	}
	var g general
	for _, s := range signers {
		compact, err := s.Sign(TypeDocument, payload)
		if err != nil {
			return nil, err
		}
		parts := strings.Split(compact, ".")
		if len(parts) != 3 {
			return nil, fmt.Errorf("federation: malformed signature")
		}
		g.Payload = parts[1]
		g.Signatures = append(g.Signatures, generalSig{Protected: parts[0], Signature: parts[2]})
	}
	return json.Marshal(g, json.Deterministic(true))
}

// keySet returns the Ed25519 keys of a JWKS by kid.
func keySet(set JWKS) (map[string]ed25519.PublicKey, error) {
	out := map[string]ed25519.PublicKey{}
	for _, k := range set.Keys {
		pub, err := k.Key()
		if err != nil || k.Kid == "" {
			return nil, ErrDocument
		}
		if _, dup := out[k.Kid]; dup {
			return nil, ErrDocument
		}
		out[k.Kid] = pub
	}
	if len(out) == 0 {
		return nil, ErrDocument
	}
	return out, nil
}

// verifiedDocument is a document whose signatures verified.
type verifiedDocument struct {
	Doc     Document
	Keys    map[string]ed25519.PublicKey
	KeysRaw []byte // the JWKS as pinned
	// SignedBy are the kids whose signatures verified.
	SignedBy []string
}

// verifyDocument checks raw: every signature verifies with its kid's key
// from the document itself, at least one is present, and the payload is a
// current version-1 document (HR-770).
func verifyDocument(raw []byte, now time.Time) (verifiedDocument, error) {
	var g general
	if len(raw) > MaxDocumentBytes || json.Unmarshal(raw, &g) != nil || len(g.Signatures) == 0 || len(g.Signatures) > 8 {
		return verifiedDocument{}, ErrDocument
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(g.Payload)
	if err != nil {
		return verifiedDocument{}, ErrDocument
	}
	var d Document
	if err := json.Unmarshal(payload, &d); err != nil || d.V != DocumentVersion {
		return verifiedDocument{}, ErrDocument
	}
	if _, err := ids.ParseUUID(d.OrgID); err != nil || !strings.HasPrefix(d.ServerURL, "https://") ||
		(d.FederationURL != "" && !strings.HasPrefix(d.FederationURL, "https://")) {
		return verifiedDocument{}, ErrDocument
	}
	issued, expires := time.Unix(d.IssuedAt, 0), time.Unix(d.ExpiresAt, 0)
	if issued.After(now.Add(clockSkew)) || !expires.After(issued) || expires.Sub(issued) > DocumentTTL {
		return verifiedDocument{}, ErrDocument
	}
	keys, err := keySet(d.Keys)
	if err != nil {
		return verifiedDocument{}, err
	}
	out := verifiedDocument{Doc: d, Keys: keys}
	if out.KeysRaw, err = json.Marshal(d.Keys, json.Deterministic(true)); err != nil {
		return verifiedDocument{}, err
	}
	for _, s := range g.Signatures {
		compact := s.Protected + "." + g.Payload + "." + s.Signature
		kid, typ, err := jws.Unverified(compact)
		if err != nil || typ != TypeDocument || keys[kid] == nil {
			return verifiedDocument{}, ErrDocument
		}
		v, err := jws.NewVerifier(TypeDocument, map[string]ed25519.PublicKey{kid: keys[kid]})
		if err != nil {
			return verifiedDocument{}, err
		}
		got, _, err := v.WithMaxBytes(MaxDocumentBytes).Verify(compact)
		if err != nil || !bytes.Equal(got, payload) {
			return verifiedDocument{}, ErrDocument
		}
		out.SignedBy = append(out.SignedBy, kid)
	}
	return out, nil
}

// KeysDigest is SHA-256 over the sorted RFC 7638 thumbprints of keys,
// joined by ",".
func KeysDigest(keys map[string]ed25519.PublicKey) [sha256.Size]byte {
	tps := make([]string, 0, len(keys))
	for _, k := range keys {
		tps = append(tps, jws.Thumbprint(k))
	}
	slices.Sort(tps)
	return sha256.Sum256([]byte(strings.Join(tps, ",")))
}

// SafetyCode is what both organizations' people compare (D1021): the first
// 20 base32 characters of SHA-256("pc-fed-v1|" + lower org | higher org |
// lower org's keys digest | higher org's keys digest), in five groups of
// four.
func SafetyCode(orgA ids.UUID, digestA [sha256.Size]byte, orgB ids.UUID, digestB [sha256.Size]byte) string {
	a, b, da, db := orgA.String(), orgB.String(), digestA, digestB
	if b < a {
		a, b, da, db = b, a, db, da
	}
	sum := sha256.Sum256([]byte("pc-fed-v1|" + a + "|" + b + "|" + hex.EncodeToString(da[:]) + "|" + hex.EncodeToString(db[:])))
	s := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:])[:20]
	return s[0:4] + " " + s[4:8] + " " + s[8:12] + " " + s[12:16] + " " + s[16:20]
}

// unverifiedPayload decodes a compact JWS's payload for routing only (the
// issuer's org); nothing in it is trusted before the signature verifies.
func unverifiedPayload(compact string, into any) error {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 || len(compact) > MaxPeerMessageBytes {
		return ErrTokenInvalid
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		return ErrTokenInvalid
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return ErrTokenInvalid
	}
	return nil
}

// verifyPinned verifies compact of type typ with the keys pinned for a
// peer.
func verifyPinned(compact, typ string, pinned []byte, into any) error {
	var set JWKS
	if err := json.Unmarshal(pinned, &set); err != nil {
		return ErrKeyUnverified
	}
	keys, err := keySet(set)
	if err != nil {
		return ErrKeyUnverified
	}
	v, err := jws.NewVerifier(typ, keys)
	if err != nil {
		return err
	}
	payload, _, err := v.WithMaxBytes(MaxPeerMessageBytes).Verify(compact)
	if err != nil {
		return ErrTokenInvalid
	}
	if err := json.Unmarshal(payload, into); err != nil {
		return ErrTokenInvalid
	}
	return nil
}

// orgSubject is an org's federation name.
func orgSubject(org ids.UUID) string { return "pc:org/" + org.String() }

// peerOrgOf parses "pc:org/<uuid>".
func peerOrgOf(s string) (ids.UUID, bool) {
	rest, ok := strings.CutPrefix(s, "pc:org/")
	if !ok {
		return ids.UUID{}, false
	}
	id, err := ids.ParseUUID(rest)
	return id, err == nil && id.String() == rest
}

// agentPart is a peer agent name without its instance part.
func agentPart(peerAgent string) string {
	if i := strings.Index(peerAgent, "/inst/"); i > 0 {
		return peerAgent[:i]
	}
	return peerAgent
}

// syntheticJKT is a federated instance's jkt: a digest no key has (00018
// CHECK: 43 base64url characters; D1024c).
func syntheticJKT(trust ids.UUID, peerAgent string) string {
	sum := sha256.Sum256([]byte("pc-fed-instance|" + trust.String() + "|" + peerAgent))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
