// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package httpsig verifies agents' HTTP message signatures (RFC 9421) as
// Web Bot Auth (Mastercard Agent Pay) and the Visa Trusted Agent Protocol
// use them (G0 M39 D1123; HR-838, HR-839), for merchant backends:
//
//   - Signature-Input and Signature are RFC 8941 dictionaries; a signature
//     counts only with a tag of agent-browser-auth, agent-payer-auth or
//     agent-pay-auth (case-insensitive);
//   - it covers at least @authority and @path, and has created, expires,
//     keyid and nonce; expires - created is at most 480 seconds, created is
//     not in the future and expires not in the past;
//   - its key is ed25519 or ecdsa-p256-sha256 and comes only from an ACTIVE
//     AGENT_DIRECTORY anchor (Keys): a Signature-Agent header only selects
//     among anchors and is never fetched itself;
//   - a nonce is accepted once per anchor (Nonces);
//   - Trusted Agent Protocol body objects (agenticConsumer,
//     agenticPaymentContainer) must carry the header's nonce and keyid and
//     be signed by the same key; paymentCredentialsHash is returned and
//     never resolved. A Mastercard agentic token is never treated as proof:
//     the network validates it (R-93).
package httpsig

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/jsontext"
	"errors"
	"io"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Limits and parameters (D1123).
const (
	// MaxWindow is the longest a signature may be valid.
	MaxWindow = 480 * time.Second
	// ClockSkew is how far in the future created may be.
	ClockSkew = 30 * time.Second
	// MaxBody bounds the body read for Trusted Agent Protocol objects.
	MaxBody = 64 << 10
	// maxNonce bounds a nonce.
	maxNonce = 256
)

// Tags of agent signatures.
const (
	TagBrowser = "agent-browser-auth"
	TagPayer   = "agent-payer-auth"
	TagPay     = "agent-pay-auth"
)

var tags = []string{TagBrowser, TagPayer, TagPay}

// Algorithms (RFC 9421 §3.3).
const (
	AlgEd25519 = "ed25519"
	AlgP256    = "ecdsa-p256-sha256"
)

// Reasons a signature did not verify.
const (
	ReasonNoSignature  = "no_agent_signature"
	ReasonMalformed    = "malformed"
	ReasonComponents   = "components"
	ReasonWindow       = "window"
	ReasonAgent        = "signature_agent_not_anchored"
	ReasonKey          = "key_unavailable"
	ReasonSignature    = "signature"
	ReasonBody         = "body_object"
	ReasonNonceReplay  = "nonce_replayed"
	ReasonAlgorithm    = "algorithm"
	ReasonNonceMissing = "nonce_missing"
)

// Request is what the merchant received.
type Request struct {
	Method    string
	Authority string
	// Path is the path and, after "?", the query.
	Path   string
	Header http.Header
	Body   []byte
}

// Key is one agent key of an ACTIVE AGENT_DIRECTORY anchor.
type Key struct {
	AnchorID ids.UUID
	Key      crypto.PublicKey
}

// Keys looks agent keys up (anchors.Resolver).
type Keys interface {
	// AgentKeys returns the keys named keyid of the org's ACTIVE
	// AGENT_DIRECTORY anchors; with agent (a Signature-Agent value) set,
	// only of the anchor whose URL it names. None is not an error.
	AgentKeys(ctx context.Context, agent, keyid string) ([]Key, error)
}

// Nonces is the nonce cache (pc.payment_sig_nonces).
type Nonces interface {
	// Use records nonce for anchor and reports whether it was new.
	Use(ctx context.Context, anchor ids.UUID, nonce string) (bool, error)
}

// Result is the outcome of one verification.
type Result struct {
	Valid    bool
	AnchorID ids.UUID
	KeyID    string
	Tag      string
	Nonce    string
	// Claims are what the verified request carried (signature_agent,
	// consumer_verified, payment_container_verified,
	// payment_credentials_hash, id_token_present).
	Claims map[string]string
	// Reason is why it did not verify.
	Reason string
}

func refuse(reason string) Result { return Result{Reason: reason} }

// sig is one candidate signature.
type sig struct {
	label      string
	params     member
	signature  []byte
	created    int64
	expires    int64
	keyid      string
	nonce      string
	tag        string
	alg        string
	components []string
}

// Verify checks the request's agent signature at now. Verification
// failures are a Result with Valid false and a Reason; an error is a
// failure to check (the key store or nonce cache), and fails closed.
func Verify(ctx context.Context, req Request, keys Keys, nonces Nonces, now time.Time) (Result, error) {
	if keys == nil || nonces == nil {
		return Result{}, errors.New("httpsig: no keys or nonce cache")
	}
	inputs, err := parseDictionary(strings.Join(req.Header.Values("Signature-Input"), ", "))
	if err != nil {
		return refuse(ReasonMalformed), nil
	}
	sigs, err := parseDictionary(strings.Join(req.Header.Values("Signature"), ", "))
	if err != nil {
		return refuse(ReasonMalformed), nil
	}
	var cands []sig
	for _, in := range inputs {
		s, ok := candidate(in, sigs)
		if ok {
			cands = append(cands, s)
		}
	}
	if len(cands) == 0 {
		return refuse(ReasonNoSignature), nil
	}
	agent, err := signatureAgent(req.Header, cands[0].label)
	if err != nil {
		return refuse(ReasonMalformed), nil
	}
	last := refuse(ReasonSignature)
	for _, s := range cands {
		r, err := verifyOne(ctx, req, s, agent, keys, nonces, now)
		if err != nil {
			return Result{}, err
		}
		if r.Valid {
			return r, nil
		}
		last = r
	}
	return last, nil
}

// candidate reads one Signature-Input member with an agent tag and its
// Signature value.
func candidate(in member, sigs []member) (sig, bool) {
	if !in.inner {
		return sig{}, false
	}
	s := sig{label: in.name, params: in}
	for _, p := range in.params {
		v := p.value
		switch p.name {
		case "created":
			if v.kind != kindInteger {
				return sig{}, false
			}
			s.created = v.i
		case "expires":
			if v.kind != kindInteger {
				return sig{}, false
			}
			s.expires = v.i
		case "keyid":
			if v.kind != kindString {
				return sig{}, false
			}
			s.keyid = v.s
		case "nonce":
			if v.kind != kindString {
				return sig{}, false
			}
			s.nonce = v.s
		case "tag":
			if v.kind != kindString {
				return sig{}, false
			}
			s.tag = strings.ToLower(v.s)
		case "alg":
			if v.kind != kindString {
				return sig{}, false
			}
			s.alg = strings.ToLower(v.s)
		}
	}
	if !slices.Contains(tags, s.tag) {
		return sig{}, false
	}
	for i, c := range in.list {
		if c.kind != kindString || len(in.lparam[i]) > 0 {
			return sig{}, false // component parameters (;sf, ;key, ;req, ;bs) are not accepted
		}
		s.components = append(s.components, c.s)
	}
	for _, m := range sigs {
		if m.name == s.label && !m.inner && m.item.kind == kindBytes && len(m.params) == 0 {
			s.signature = m.item.b
			return s, true
		}
	}
	return sig{}, false
}

// signatureAgent reads Signature-Agent: an sf-string, or a dictionary
// whose member named label (else the first) is a string. Empty when absent.
func signatureAgent(h http.Header, label string) (string, error) {
	raw := strings.TrimSpace(strings.Join(h.Values("Signature-Agent"), ", "))
	if raw == "" {
		return "", nil
	}
	if strings.HasPrefix(raw, `"`) {
		return parseString(raw)
	}
	d, err := parseDictionary(raw)
	if err != nil || len(d) == 0 {
		return "", errSyntax
	}
	pick := d[0]
	for _, m := range d {
		if m.name == label {
			pick = m
		}
	}
	if pick.inner || pick.item.kind != kindString {
		return "", errSyntax
	}
	return pick.item.s, nil
}

func verifyOne(ctx context.Context, req Request, s sig, agent string, keys Keys, nonces Nonces, now time.Time) (Result, error) {
	if !slices.Contains(s.components, "@authority") || !slices.Contains(s.components, "@path") {
		return refuse(ReasonComponents), nil
	}
	if s.keyid == "" || s.created == 0 || s.expires == 0 {
		return refuse(ReasonMalformed), nil
	}
	if s.nonce == "" || len(s.nonce) > maxNonce {
		return refuse(ReasonNonceMissing), nil
	}
	created, expires := time.Unix(s.created, 0), time.Unix(s.expires, 0)
	if !expires.After(created) || expires.Sub(created) > MaxWindow || created.After(now.Add(ClockSkew)) || !now.Before(expires) {
		return refuse(ReasonWindow), nil
	}
	if s.alg != "" && s.alg != AlgEd25519 && s.alg != AlgP256 {
		return refuse(ReasonAlgorithm), nil
	}
	base, err := signatureBase(req, s)
	if err != nil {
		return refuse(ReasonComponents), nil
	}
	ks, err := keys.AgentKeys(ctx, agent, s.keyid)
	if err != nil {
		return Result{}, err
	}
	if len(ks) == 0 {
		if agent != "" {
			return refuse(ReasonAgent), nil
		}
		return refuse(ReasonKey), nil
	}
	var key *Key
	for i := range ks {
		if fits(ks[i].Key, s.alg) && verifySig(ks[i].Key, base, s.signature) {
			key = &ks[i]
			break
		}
	}
	if key == nil {
		return refuse(ReasonSignature), nil
	}
	out := Result{AnchorID: key.AnchorID, KeyID: s.keyid, Tag: s.tag, Nonce: s.nonce, Claims: map[string]string{}}
	if agent != "" {
		out.Claims["signature_agent"] = agent
	}
	if reason := tapBody(req.Body, s, key.Key, out.Claims); reason != "" {
		out.Reason = reason
		return out, nil
	}
	fresh, err := nonces.Use(ctx, key.AnchorID, s.nonce)
	if err != nil {
		return Result{}, err
	}
	if !fresh {
		out.Reason = ReasonNonceReplay
		return out, nil
	}
	out.Valid = true
	return out, nil
}

// signatureBase builds the RFC 9421 §2.5 signature base.
func signatureBase(req Request, s sig) ([]byte, error) {
	var b bytes.Buffer
	path, query, _ := strings.Cut(req.Path, "?")
	seen := map[string]bool{}
	for _, c := range s.components {
		if seen[c] {
			return nil, errSyntax
		}
		seen[c] = true
		var v string
		switch c {
		case "@method":
			v = strings.ToUpper(req.Method)
		case "@authority":
			v = authority(req.Authority)
		case "@path":
			v = path
			if v == "" {
				v = "/"
			}
		case "@query":
			v = "?" + query
		default:
			if strings.HasPrefix(c, "@") || c != strings.ToLower(c) || c == "" {
				return nil, errSyntax // other derived components are not accepted
			}
			vals := req.Header.Values(c)
			if len(vals) == 0 {
				return nil, errSyntax
			}
			for i := range vals {
				vals[i] = strings.TrimSpace(vals[i])
			}
			v = strings.Join(vals, ", ")
		}
		if strings.ContainsAny(v, "\r\n") {
			return nil, errSyntax
		}
		b.WriteString(`"` + c + `": ` + v + "\n")
	}
	b.WriteString(`"@signature-params": ` + s.params.serializeInner())
	return b.Bytes(), nil
}

// authority normalizes an authority: lowercase, without the https default
// port.
func authority(a string) string {
	a = strings.ToLower(strings.TrimSpace(a))
	return strings.TrimSuffix(a, ":443")
}

// fits reports whether key can verify alg (or any supported alg when alg
// is empty).
func fits(key crypto.PublicKey, alg string) bool {
	switch k := key.(type) {
	case ed25519.PublicKey:
		return (alg == "" || alg == AlgEd25519) && len(k) == ed25519.PublicKeySize
	case *ecdsa.PublicKey:
		return (alg == "" || alg == AlgP256) && k.Curve == elliptic.P256()
	}
	return false
}

// verifySig verifies an ed25519 signature or a 64-byte r||s P-256 one.
func verifySig(key crypto.PublicKey, msg, signature []byte) bool {
	switch k := key.(type) {
	case ed25519.PublicKey:
		return len(signature) == ed25519.SignatureSize && ed25519.Verify(k, msg, signature)
	case *ecdsa.PublicKey:
		if len(signature) != 64 {
			return false
		}
		sum := sha256.Sum256(msg)
		r, s := new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])
		return ecdsa.Verify(k, sum[:], r, s)
	}
	return false
}

// tapBody verifies the Trusted Agent Protocol objects of a JSON body and
// fills claims; a non-empty reason means one did not verify. A body that
// is not a JSON object, or has neither object, is left alone.
func tapBody(body []byte, s sig, key crypto.PublicKey, claims map[string]string) string {
	if len(body) == 0 || len(body) > MaxBody {
		return ""
	}
	objs, ok := topObjects(body, "agenticConsumer", "agenticPaymentContainer")
	if !ok {
		return ""
	}
	for name, raw := range objs {
		fields, signed, signature, ok := splitObject(raw)
		if !ok {
			return ReasonBody
		}
		if fields["nonce"] != s.nonce || fields["kid"] != s.keyid {
			return ReasonBody
		}
		if a := strings.ToLower(fields["alg"]); a != "" && !bodyAlg(a, key) {
			return ReasonBody
		}
		if !verifySig(key, signed, signature) {
			return ReasonBody
		}
		switch name {
		case "agenticConsumer":
			claims["consumer_verified"] = "true"
			if fields["idToken"] != "" {
				claims["id_token_present"] = "true" // never resolved or trusted as proof
			}
		case "agenticPaymentContainer":
			claims["payment_container_verified"] = "true"
			if h := fields["paymentCredentialsHash"]; h != "" {
				claims["payment_credentials_hash"] = h
			}
		}
	}
	return ""
}

func bodyAlg(a string, key crypto.PublicKey) bool {
	switch key.(type) {
	case ed25519.PublicKey:
		return a == "ed25519" || a == "eddsa"
	case *ecdsa.PublicKey:
		return a == "es256" || a == AlgP256
	}
	return false
}

// topObjects returns the named members of a top-level JSON object, as raw
// values; false when the body is not an object or names none.
func topObjects(body []byte, names ...string) (map[string]jsontext.Value, bool) {
	dec := jsontext.NewDecoder(bytes.NewReader(body))
	if tok, err := dec.ReadToken(); err != nil || tok.Kind() != '{' {
		return nil, false
	}
	out := map[string]jsontext.Value{}
	for dec.PeekKind() != '}' {
		tok, err := dec.ReadToken()
		if err != nil {
			return nil, false
		}
		v, err := dec.ReadValue()
		if err != nil {
			return nil, false
		}
		if slices.Contains(names, tok.String()) {
			out[tok.String()] = slices.Clone(v)
		}
	}
	return out, len(out) > 0
}

// splitObject reads a TAP object: its string fields, the bytes it signs
// (the object in the order received, without signature, compact JSON) and
// the decoded signature.
func splitObject(raw jsontext.Value) (map[string]string, []byte, []byte, bool) {
	dec := jsontext.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.ReadToken(); err != nil || tok.Kind() != '{' {
		return nil, nil, nil, false
	}
	var signed bytes.Buffer
	enc := jsontext.NewEncoder(&signed)
	if enc.WriteToken(jsontext.BeginObject) != nil {
		return nil, nil, nil, false
	}
	fields := map[string]string{}
	var signature []byte
	for dec.PeekKind() != '}' {
		tok, err := dec.ReadToken()
		if err != nil {
			return nil, nil, nil, false
		}
		name := tok.String()
		v, err := dec.ReadValue()
		if err != nil {
			return nil, nil, nil, false
		}
		if v.Kind() == '"' {
			var s string
			if jsonString(v, &s) {
				fields[name] = s
			}
		}
		if name == "signature" {
			if signature, err = decodeB64(fields[name]); err != nil {
				return nil, nil, nil, false
			}
			continue
		}
		if enc.WriteToken(jsontext.String(name)) != nil || enc.WriteValue(v) != nil {
			return nil, nil, nil, false
		}
	}
	if enc.WriteToken(jsontext.EndObject) != nil || signature == nil {
		return nil, nil, nil, false
	}
	if _, err := dec.ReadToken(); err != nil {
		return nil, nil, nil, false
	}
	if _, err := dec.ReadToken(); !errors.Is(err, io.EOF) {
		return nil, nil, nil, false
	}
	return fields, bytes.TrimRight(signed.Bytes(), "\n"), signature, true
}

func jsonString(v jsontext.Value, dst *string) bool {
	dec := jsontext.NewDecoder(bytes.NewReader(v))
	tok, err := dec.ReadToken()
	if err != nil || tok.Kind() != '"' {
		return false
	}
	*dst = tok.String()
	return true
}

// decodeB64 accepts standard or URL base64, padded or not.
func decodeB64(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.Strict().DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errSyntax
}
