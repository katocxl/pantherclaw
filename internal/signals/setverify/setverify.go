// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package setverify verifies Security Event Tokens (RFC 8417) pushed by a
// configured Shared Signals transmitter (G0 M10 D37, D39; PN-024, HR-261,
// T-113). A token is accepted only when:
//
//   - it is a compact JWS of at most MaxToken bytes, signed with RS256 or
//     ES256 by a key named by its kid in the transmitter's pinned JWKS (on
//     the issuer's host, fetched through the egress client); its header
//     carries only alg, kid and typ: never jwk, jku, x5u, x5c or crit, so
//     no key ever comes from the token;
//   - iss is the transmitter's issuer and aud names its audience;
//   - iat is within MaxSkew of the server's clock;
//   - jti is present (the receiver refuses a jti it has seen);
//   - events has exactly one member, an object.
//
// Each refusal carries the RFC 8935 error code the receiver answers with.
package setverify

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-jose/go-jose/v4"
)

// Limits (D37).
const (
	MaxToken   = 64 << 10
	MaxSkew    = 5 * time.Minute
	MaxJTI     = 256
	MaxType    = 256
	MaxSubject = 512
)

// RFC 8935 §2.3 error codes.
const (
	CodeInvalidRequest  = "invalid_request"
	CodeInvalidKey      = "invalid_key"
	CodeInvalidIssuer   = "invalid_issuer"
	CodeInvalidAudience = "invalid_audience"
	CodeAuthFailed      = "authentication_failed"
)

// Error is a refusal with its RFC 8935 code. Description is safe to return
// to the transmitter: it never echoes token content.
type Error struct {
	Code        string
	Description string
}

func (e *Error) Error() string { return "setverify: " + e.Code + ": " + e.Description }

func refuse(code, desc string) error { return &Error{Code: code, Description: desc} }

// CodeOf returns the RFC 8935 code of err (invalid_request for others).
func CodeOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return CodeInvalidRequest
}

// Keys finds a transmitter's signing key by kid (a *JWKS).
type Keys interface {
	Key(ctx context.Context, kid string) (any, error)
}

// Transmitter is what a token is checked against.
type Transmitter struct {
	Issuer   string
	Audience string
	Keys     Keys
}

// Subject identifies the person an event is about (SSF subject
// identifiers, RFC 9493): email, iss_sub or opaque. Other formats are kept
// with their format only.
type Subject struct {
	Format string
	Email  string
	Iss    string
	Sub    string
	ID     string
}

// SET is a verified token.
type SET struct {
	JTI       string
	IssuedAt  time.Time
	EventType string
	Subject   Subject
	// Event is the event's own object, as sent (bounded by MaxToken).
	Event jsontext.Value
}

var allowedAlgs = []jose.SignatureAlgorithm{jose.RS256, jose.ES256}

// Verify checks compact against t at now.
func Verify(ctx context.Context, t Transmitter, compact string, now time.Time) (SET, error) {
	if len(compact) == 0 || len(compact) > MaxToken {
		return SET{}, refuse(CodeInvalidRequest, "the token is empty or larger than 64 KiB")
	}
	alg, kid, err := checkHeader(compact)
	if err != nil {
		return SET{}, err
	}
	obj, err := jose.ParseSignedCompact(compact, allowedAlgs)
	if err != nil || len(obj.Signatures) != 1 {
		return SET{}, refuse(CodeInvalidRequest, "the token is not a compact JWS")
	}
	key, err := t.Keys.Key(ctx, kid)
	if err != nil {
		return SET{}, refuse(CodeInvalidKey, "the signing key is not in the transmitter's key set")
	}
	switch key.(type) {
	case *rsa.PublicKey:
		if alg != string(jose.RS256) {
			return SET{}, refuse(CodeAuthFailed, "the algorithm does not match the key")
		}
	case *ecdsa.PublicKey:
		if alg != string(jose.ES256) {
			return SET{}, refuse(CodeAuthFailed, "the algorithm does not match the key")
		}
	default:
		return SET{}, refuse(CodeInvalidKey, "unsupported key")
	}
	payload, err := obj.Verify(key)
	if err != nil {
		return SET{}, refuse(CodeAuthFailed, "the signature does not verify")
	}
	return claims(payload, t, now)
}

// checkHeader reads the protected header before parsing: only alg, kid and
// typ, alg in the allow-list, a kid, and typ (when present) secevent+jwt.
func checkHeader(compact string) (alg, kid string, err error) {
	seg, _, ok := strings.Cut(compact, ".")
	if !ok {
		return "", "", refuse(CodeInvalidRequest, "the token is not a compact JWS")
	}
	raw, derr := base64.RawURLEncoding.Strict().DecodeString(seg)
	if derr != nil {
		return "", "", refuse(CodeInvalidRequest, "the header is not base64url")
	}
	var h map[string]jsontext.Value
	if err := json.Unmarshal(raw, &h); err != nil {
		return "", "", refuse(CodeInvalidRequest, "the header is not a JSON object")
	}
	for k := range h {
		switch k {
		case "alg", "kid", "typ":
		default:
			// jwk, jku, x5u, x5c, crit and anything else: keys never come
			// from the token.
			return "", "", refuse(CodeAuthFailed, "the header may carry only alg, kid and typ")
		}
	}
	var typ string
	if err := strField(h, "alg", &alg); err != nil || (alg != string(jose.RS256) && alg != string(jose.ES256)) {
		return "", "", refuse(CodeAuthFailed, "the algorithm must be RS256 or ES256")
	}
	if err := strField(h, "kid", &kid); err != nil || kid == "" || len(kid) > 256 {
		return "", "", refuse(CodeInvalidKey, "the header must name a key id")
	}
	if _, ok := h["typ"]; ok {
		if err := strField(h, "typ", &typ); err != nil || !strings.EqualFold(strings.TrimPrefix(strings.ToLower(typ), "application/"), "secevent+jwt") {
			return "", "", refuse(CodeInvalidRequest, "typ must be secevent+jwt")
		}
	}
	return alg, kid, nil
}

func strField(h map[string]jsontext.Value, k string, out *string) error {
	v, ok := h[k]
	if !ok {
		return errors.New("missing")
	}
	return json.Unmarshal(v, out)
}

// payloadClaims are the SET claims PantherClaw reads.
type payloadClaims struct {
	Iss    *string                   `json:"iss"`
	Aud    jsontext.Value            `json:"aud"`
	Iat    *float64                  `json:"iat"`
	JTI    *string                   `json:"jti"`
	SubID  jsontext.Value            `json:"sub_id"`
	Events map[string]jsontext.Value `json:"events"`
}

func claims(payload []byte, t Transmitter, now time.Time) (SET, error) {
	var c payloadClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return SET{}, refuse(CodeInvalidRequest, "the claims are not a JSON object")
	}
	if c.Iss == nil || *c.Iss != t.Issuer {
		return SET{}, refuse(CodeInvalidIssuer, "iss is not the transmitter's issuer")
	}
	if !audienceHas(c.Aud, t.Audience) {
		return SET{}, refuse(CodeInvalidAudience, "aud does not name this receiver")
	}
	if c.Iat == nil || math.IsNaN(*c.Iat) || math.IsInf(*c.Iat, 0) || *c.Iat < 0 || *c.Iat > 1e11 {
		return SET{}, refuse(CodeInvalidRequest, "iat is missing")
	}
	iat := time.Unix(int64(*c.Iat), 0)
	if d := now.Sub(iat); d > MaxSkew || d < -MaxSkew {
		return SET{}, refuse(CodeInvalidRequest, "iat is more than 5 minutes from the receiver's clock")
	}
	if c.JTI == nil || *c.JTI == "" || len(*c.JTI) > MaxJTI || !utf8.ValidString(*c.JTI) {
		return SET{}, refuse(CodeInvalidRequest, "jti is missing or too long")
	}
	if len(c.Events) != 1 {
		return SET{}, refuse(CodeInvalidRequest, "events must hold exactly one event")
	}
	out := SET{JTI: *c.JTI, IssuedAt: iat}
	for typ, ev := range c.Events {
		if typ == "" || len(typ) > MaxType || ev.Kind() != '{' {
			return SET{}, refuse(CodeInvalidRequest, "the event must be an object under its type URI")
		}
		out.EventType, out.Event = typ, ev
	}
	// The subject is the top-level sub_id (SSF), or the event's subject
	// member (CAEP and RISC before sub_id).
	sub := c.SubID
	if len(sub) == 0 {
		var inner struct {
			Subject jsontext.Value `json:"subject"`
		}
		_ = json.Unmarshal(out.Event, &inner)
		sub = inner.Subject
	}
	out.Subject = subjectOf(sub)
	return out, nil
}

func audienceHas(aud jsontext.Value, want string) bool {
	if want == "" || len(aud) == 0 {
		return false
	}
	var one string
	if json.Unmarshal(aud, &one) == nil {
		return one == want
	}
	var many []string
	if json.Unmarshal(aud, &many) == nil {
		for _, a := range many {
			if a == want {
				return true
			}
		}
	}
	return false
}

func subjectOf(raw jsontext.Value) Subject {
	var s struct {
		Format string `json:"format"`
		Email  string `json:"email"`
		Iss    string `json:"iss"`
		Sub    string `json:"sub"`
		ID     string `json:"id"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &s) != nil {
		return Subject{}
	}
	ok := func(v string) bool { return v != "" && len(v) <= MaxSubject && utf8.ValidString(v) }
	switch s.Format {
	case "email":
		if ok(s.Email) {
			return Subject{Format: "email", Email: s.Email}
		}
	case "iss_sub":
		if ok(s.Iss) && ok(s.Sub) {
			return Subject{Format: "iss_sub", Iss: s.Iss, Sub: s.Sub}
		}
	case "opaque":
		if ok(s.ID) {
			return Subject{Format: "opaque", ID: s.ID}
		}
	}
	if len(s.Format) > 0 && len(s.Format) <= 32 && strings.Trim(s.Format, "abcdefghijklmnopqrstuvwxyz_") == "" {
		return Subject{Format: s.Format}
	}
	return Subject{}
}

// CheckHeader is the header check Verify starts with (allowed members,
// algorithm, kid, typ), without keys: the receiver runs it before a
// token counts against its transmitter's rate budget.
func CheckHeader(compact string) error {
	if len(compact) == 0 || len(compact) > MaxToken {
		return refuse(CodeInvalidRequest, "the token is empty or larger than 64 KiB")
	}
	_, _, err := checkHeader(compact)
	return err
}
