// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package a2a

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"math/big"
	"slices"
)

// Card limits.
const (
	// MaxCardBytes caps an agent card (D30).
	MaxCardBytes = 256 << 10
	// MaxKeysBytes caps a pinned JWKS (D30).
	MaxKeysBytes  = 64 << 10
	maxSignatures = 8
	maxCardKeys   = 16
)

// Card errors: each refuses the card, and a connection whose card fails
// is not pinned (or, at a re-read, is drift, HR-322).
var (
	ErrCardInvalid      = errors.New("a2a: agent card invalid")
	ErrCardUnsigned     = errors.New("a2a: agent card carries no signature, but keys are pinned")
	ErrCardKeysRequired = errors.New("a2a: agent card is signed, but no keys are pinned to verify it")
	ErrCardSignature    = errors.New("a2a: no agent card signature verifies with a pinned key")
	ErrKeysInvalid      = errors.New("a2a: pinned card keys invalid")
	ErrInterface        = errors.New("a2a: the interface is not one the agent card declares")
	ErrSkill            = errors.New("a2a: a skill is not one the agent card declares")
)

// AgentCard is the part of an agent card (§4.4.1) PantherClaw reads; the
// card is kept and served as fetched.
type AgentCard struct {
	Name                string           `json:"name"`
	Description         string           `json:"description"`
	Version             string           `json:"version"`
	SupportedInterfaces []AgentInterface `json:"supportedInterfaces"`
	Capabilities        struct {
		Streaming         bool `json:"streaming"`
		PushNotifications bool `json:"pushNotifications"`
		ExtendedAgentCard bool `json:"extendedAgentCard"`
	} `json:"capabilities"`
	SecuritySchemes map[string]jsontext.Value `json:"securitySchemes"`
	Skills          []AgentSkill              `json:"skills"`
	Signatures      []CardSignature           `json:"signatures"`
}

// AgentInterface is one interface of a card (§4.4.6).
type AgentInterface struct {
	URL             string `json:"url"`
	ProtocolBinding string `json:"protocolBinding"`
	Tenant          string `json:"tenant,omitzero"`
	ProtocolVersion string `json:"protocolVersion"`
}

// AgentSkill is one skill of a card (§4.4.5).
type AgentSkill struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Tags        []string `json:"tags,omitzero"`
}

// CardSignature is one JWS over the card (§4.4.7, §8.4).
type CardSignature struct {
	Protected string         `json:"protected"`
	Signature string         `json:"signature"`
	Header    map[string]any `json:"header,omitzero"`
}

// ParseCard reads an agent card: one JSON object (no duplicate names) of
// at most MaxCardBytes with a name and at least one interface.
func ParseCard(raw []byte) (*AgentCard, error) {
	if len(raw) == 0 || len(raw) > MaxCardBytes {
		return nil, fmt.Errorf("%w: size", ErrCardInvalid)
	}
	var c AgentCard
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCardInvalid, err)
	}
	if c.Name == "" || len(c.SupportedInterfaces) == 0 || len(c.Signatures) > maxSignatures {
		return nil, fmt.Errorf("%w: name, interfaces or signatures", ErrCardInvalid)
	}
	return &c, nil
}

// Digest is SHA-256 of the card's JCS form (RFC 8785), signatures
// included: any change to the document is a change of digest (D30).
func Digest(raw []byte) ([32]byte, error) {
	v := jsontext.Value(slices.Clone(raw))
	if err := v.Canonicalize(); err != nil {
		return [32]byte{}, fmt.Errorf("%w: %w", ErrCardInvalid, err)
	}
	return sha256.Sum256(v), nil
}

// SigningPayload is what a card signature covers (§8.4): the card without
// signatures and without default-valued members, in JCS form.
func SigningPayload(raw []byte) ([]byte, error) {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, fmt.Errorf("%w: not an object", ErrCardInvalid)
	}
	delete(m, "signatures")
	pruned, _ := prune(m)
	b, err := json.Marshal(pruned, json.Deterministic(true))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCardInvalid, err)
	}
	v := jsontext.Value(b)
	if err := v.Canonicalize(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCardInvalid, err)
	}
	return v, nil
}

// prune drops default-valued members (null, false, 0, "", empty arrays and
// objects) from objects, recursively; keep is false for a default value.
func prune(v any) (out any, keep bool) {
	switch t := v.(type) {
	case nil:
		return nil, false
	case bool:
		return t, t
	case float64:
		return t, t != 0
	case string:
		return t, t != ""
	case []any:
		arr := make([]any, 0, len(t))
		for _, e := range t {
			p, _ := prune(e)
			arr = append(arr, p)
		}
		return arr, len(arr) > 0
	case map[string]any:
		obj := make(map[string]any, len(t))
		for k, e := range t {
			if p, ok := prune(e); ok {
				obj[k] = p
			}
		}
		return obj, len(obj) > 0
	}
	return v, true
}

// Keys are the pinned card keys by key id.
type Keys map[string]crypto.PublicKey

// jwk is the part of a JWK the card keys use.
type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y,omitzero"`
	Kid string `json:"kid"`
	Alg string `json:"alg,omitzero"`
}

// ParseKeys reads a pinned JWKS ({"keys": [...]}) of Ed25519 (OKP) and
// P-256 (EC) keys, each with a distinct kid. Anything else is refused.
func ParseKeys(raw []byte) (Keys, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if len(raw) > MaxKeysBytes {
		return nil, fmt.Errorf("%w: size", ErrKeysInvalid)
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil || len(set.Keys) == 0 || len(set.Keys) > maxCardKeys {
		return nil, fmt.Errorf("%w: not a JWKS of 1 to %d keys", ErrKeysInvalid, maxCardKeys)
	}
	out := Keys{}
	for _, k := range set.Keys {
		if k.Kid == "" || out[k.Kid] != nil {
			return nil, fmt.Errorf("%w: kid", ErrKeysInvalid)
		}
		pub, err := k.public()
		if err != nil {
			return nil, err
		}
		out[k.Kid] = pub
	}
	return out, nil
}

func (k jwk) public() (crypto.PublicKey, error) {
	dec := base64.RawURLEncoding.Strict()
	switch {
	case k.Kty == "OKP" && k.Crv == "Ed25519" && (k.Alg == "" || k.Alg == "EdDSA"):
		x, err := dec.DecodeString(k.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: Ed25519 key", ErrKeysInvalid)
		}
		return ed25519.PublicKey(x), nil
	case k.Kty == "EC" && k.Crv == "P-256" && (k.Alg == "" || k.Alg == "ES256"):
		x, errX := dec.DecodeString(k.X)
		y, errY := dec.DecodeString(k.Y)
		if errX != nil || errY != nil || len(x) != 32 || len(y) != 32 {
			return nil, fmt.Errorf("%w: P-256 key", ErrKeysInvalid)
		}
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
		if err != nil {
			return nil, fmt.Errorf("%w: P-256 key", ErrKeysInvalid)
		}
		return pub, nil
	}
	return nil, fmt.Errorf("%w: only Ed25519 and P-256 keys", ErrKeysInvalid)
}

// protectedHeader is a card signature's protected header.
type protectedHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ,omitzero"`
	Jku string `json:"jku,omitzero"`
}

// VerifySignatures checks a card against the pinned keys (D30, §8.4): with
// keys pinned, the card must carry a signature and one must verify (alg
// matching its key's type, kid naming a pinned key); a signed card with no
// keys pinned is refused, as nothing could verify it. A card with neither
// passes. jku is never followed: only pinned keys count.
func VerifySignatures(raw []byte, keys Keys) error {
	c, err := ParseCard(raw)
	if err != nil {
		return err
	}
	switch {
	case len(c.Signatures) == 0 && len(keys) == 0:
		return nil
	case len(c.Signatures) == 0:
		return ErrCardUnsigned
	case len(keys) == 0:
		return ErrCardKeysRequired
	}
	payload, err := SigningPayload(raw)
	if err != nil {
		return err
	}
	enc := base64.RawURLEncoding
	for _, s := range c.Signatures {
		hb, err := enc.Strict().DecodeString(s.Protected)
		if err != nil {
			continue
		}
		// Only alg, kid and typ: no crit, and no member that carries or
		// points at a key (jku, jwk, x5u, x5c); such a signature never counts.
		var h protectedHeader
		if json.Unmarshal(hb, &h, json.RejectUnknownMembers(true)) != nil || h.Jku != "" {
			continue
		}
		sig, err := enc.Strict().DecodeString(s.Signature)
		if err != nil {
			continue
		}
		input := []byte(s.Protected + "." + enc.EncodeToString(payload))
		if verify(keys[h.Kid], h.Alg, input, sig) {
			return nil
		}
	}
	return ErrCardSignature
}

// verify checks one JWS signature with a pinned key of the matching type.
func verify(key crypto.PublicKey, alg string, input, sig []byte) bool {
	switch k := key.(type) {
	case ed25519.PublicKey:
		return alg == "EdDSA" && ed25519.Verify(k, input, sig)
	case *ecdsa.PublicKey:
		if alg != "ES256" || len(sig) != 64 {
			return false
		}
		sum := sha256.Sum256(input)
		r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
		return ecdsa.Verify(k, sum[:], r, s)
	}
	return false
}

// Sign returns raw with one more signature by key (Ed25519 → EdDSA, P-256
// → ES256), for simulators and tests: an agent signs its own card.
func Sign(raw []byte, kid string, key crypto.Signer) ([]byte, error) {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, fmt.Errorf("%w: not an object", ErrCardInvalid)
	}
	payload, err := SigningPayload(raw)
	if err != nil {
		return nil, err
	}
	var alg string
	switch key.Public().(type) {
	case ed25519.PublicKey:
		alg = "EdDSA"
	case *ecdsa.PublicKey:
		alg = "ES256"
	default:
		return nil, errors.New("a2a: only Ed25519 and P-256 keys sign cards")
	}
	hb, err := json.Marshal(protectedHeader{Alg: alg, Kid: kid, Typ: "JOSE"})
	if err != nil {
		return nil, err
	}
	enc := base64.RawURLEncoding
	protected := enc.EncodeToString(hb)
	input := []byte(protected + "." + enc.EncodeToString(payload))
	var sig []byte
	switch k := key.(type) {
	case ed25519.PrivateKey:
		sig = ed25519.Sign(k, input)
	case *ecdsa.PrivateKey:
		sum := sha256.Sum256(input)
		r, s, err := ecdsa.Sign(rand.Reader, k, sum[:])
		if err != nil {
			return nil, err
		}
		sig = make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
	default:
		return nil, errors.New("a2a: unsupported signing key")
	}
	sigs, _ := m["signatures"].([]any)
	m["signatures"] = append(sigs, map[string]any{"protected": protected, "signature": enc.EncodeToString(sig)})
	return json.Marshal(m, json.Deterministic(true))
}

// PublicJWKS returns the JWKS of public keys by kid, as a card's owner
// publishes them and a connection manager pins them.
func PublicJWKS(keys map[string]crypto.PublicKey) ([]byte, error) {
	enc := base64.RawURLEncoding
	set := struct {
		Keys []jwk `json:"keys"`
	}{}
	kids := make([]string, 0, len(keys))
	for kid := range keys {
		kids = append(kids, kid)
	}
	slices.Sort(kids)
	for _, kid := range kids {
		switch k := keys[kid].(type) {
		case ed25519.PublicKey:
			set.Keys = append(set.Keys, jwk{Kty: "OKP", Crv: "Ed25519", X: enc.EncodeToString(k), Kid: kid, Alg: "EdDSA"})
		case *ecdsa.PublicKey:
			b, err := k.Bytes()
			if err != nil || len(b) != 65 {
				return nil, ErrKeysInvalid
			}
			set.Keys = append(set.Keys, jwk{Kty: "EC", Crv: "P-256", X: enc.EncodeToString(b[1:33]), Y: enc.EncodeToString(b[33:]), Kid: kid, Alg: "ES256"})
		default:
			return nil, ErrKeysInvalid
		}
	}
	return json.Marshal(set)
}

// FindInterface returns the card's interface with this binding and URL.
// Only version 1.0 interfaces count; gRPC is never one PantherClaw calls.
func (c *AgentCard) FindInterface(binding, url string) (AgentInterface, bool) {
	if binding != BindingJSONRPC && binding != BindingHTTPJSON {
		return AgentInterface{}, false
	}
	for _, i := range c.SupportedInterfaces {
		if i.ProtocolBinding == binding && i.URL == url && (i.ProtocolVersion == Version || i.ProtocolVersion == "") {
			return i, true
		}
	}
	return AgentInterface{}, false
}

// SkillIDs returns the card's skill ids.
func (c *AgentCard) SkillIDs() []string {
	out := make([]string, 0, len(c.Skills))
	for _, s := range c.Skills {
		out = append(out, s.ID)
	}
	return out
}

// CheckPin checks what a connection pins against its card (D30): the card
// parses, its signatures verify against the pinned keys, the interface is
// one it declares, and every allowed skill is one of its skills. It
// returns the card's digest.
func CheckPin(raw []byte, keys Keys, binding, url string, skills []string) ([32]byte, error) {
	c, err := ParseCard(raw)
	if err != nil {
		return [32]byte{}, err
	}
	if err := VerifySignatures(raw, keys); err != nil {
		return [32]byte{}, err
	}
	if _, ok := c.FindInterface(binding, url); !ok {
		return [32]byte{}, ErrInterface
	}
	ids := c.SkillIDs()
	for _, s := range skills {
		if !slices.Contains(ids, s) {
			return [32]byte{}, fmt.Errorf("%w: %s", ErrSkill, s)
		}
	}
	return Digest(raw)
}

// Rewrite returns the card as an agent sees it at the gateway (D31): one
// interface, the gateway's, with the binding the connection uses; only the
// allowed skills (all of them when skills is empty); no signatures (they
// cover the peer's interfaces, not the gateway's) and no security schemes
// (the agent authenticates to the gateway with PAP/1, and the gateway
// holds the peer's credential).
func Rewrite(raw []byte, binding, gatewayURL string, skills []string) ([]byte, error) {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, fmt.Errorf("%w: not an object", ErrCardInvalid)
	}
	delete(m, "signatures")
	delete(m, "securitySchemes")
	delete(m, "securityRequirements")
	delete(m, "security")
	m["supportedInterfaces"] = []any{map[string]any{"url": gatewayURL, "protocolBinding": binding, "protocolVersion": Version}}
	if all, ok := m["skills"].([]any); ok && len(skills) > 0 {
		kept := make([]any, 0, len(all))
		for _, s := range all {
			if sk, ok := s.(map[string]any); ok {
				if id, _ := sk["id"].(string); slices.Contains(skills, id) {
					kept = append(kept, s)
				}
			}
		}
		m["skills"] = kept
	}
	caps, _ := m["capabilities"].(map[string]any)
	if caps != nil {
		caps["pushNotifications"] = false
		caps["extendedAgentCard"] = false
	}
	return json.Marshal(m, json.Deterministic(true))
}
