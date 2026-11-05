// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package ap2

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/payments/sdjwt"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// MaxEnvelope bounds the envelope Verify accepts (the payment block's
// mandate_param, D1124).
const MaxEnvelope = 32 << 10

// Envelope members.
const (
	// v0.2: one SD-JWT presentation, or [open, closed].
	memberCheckout = "checkout_mandate"
	memberPayment  = "payment_mandate"
	// v0.1: the AP2 v0.1 data keys.
	memberCart     = "ap2.mandates.CartMandate"
	memberPayment1 = "ap2.mandates.PaymentMandate"
	memberIntent   = "ap2.mandates.IntentMandate"
)

// vct values (AP2 v0.2).
const (
	VCTCheckout     = "mandate.checkout.1"
	VCTCheckoutOpen = "mandate.checkout.open.1"
	VCTPayment      = "mandate.payment.1"
	VCTPaymentOpen  = "mandate.payment.open.1"
)

// typ of a closed mandate signed by an open mandate's cnf key.
const typDelegated = "kb+sd-jwt"

// Verify verifies a mandate envelope against the org's ACTIVE sandbox
// trust anchors at now (D1122). raw is a JSON object, either
//
//	{"checkout_mandate": <sd-jwt> | [<open sd-jwt>, <closed sd-jwt>],
//	 "payment_mandate":  <sd-jwt> | [<open sd-jwt>, <closed sd-jwt>]}  (v0.2)
//	{"ap2.mandates.CartMandate": {...}, "ap2.mandates.PaymentMandate": {...},
//	 "ap2.mandates.IntentMandate": {...}?}                               (v0.1)
//
// Every failure is ErrInvalid (with the detail wrapped for logs) except a
// live anchor, ErrLiveRefused.
func Verify(ctx context.Context, raw string, anchors Anchors, now time.Time) (Verified, error) {
	if anchors == nil {
		return Verified{}, fail(errors.New("no trust anchors"))
	}
	if len(raw) == 0 || len(raw) > MaxEnvelope {
		return Verified{}, fail(errors.New("envelope size"))
	}
	var top map[string]jsontext.Value
	if err := json.Unmarshal([]byte(raw), &top); err != nil || top == nil {
		return Verified{}, fail(errors.New("envelope is not a JSON object"))
	}
	v := &verifier{anchors: anchors, now: now}
	var out Verified
	var err error
	switch {
	case has(top, memberPayment) || has(top, memberCheckout):
		out, err = v.v02(ctx, top)
	case has(top, memberPayment1) || has(top, memberCart):
		out, err = v.v01(ctx, top)
	default:
		err = errors.New("no AP2 mandates in the envelope")
	}
	if err != nil {
		return Verified{}, fail(err)
	}
	if !now.Before(out.ExpiresAt) {
		return Verified{}, fail(errors.New("expired"))
	}
	return out, nil
}

func has(m map[string]jsontext.Value, k string) bool {
	_, ok := m[k]
	return ok
}

// fail maps a cause to ErrInvalid, keeping ErrLiveRefused.
func fail(err error) error {
	if errors.Is(err, ErrLiveRefused) {
		return err
	}
	return pcerr.Wrap(err, pcerr.Deny, "MANDATE_INVALID", "the payment mandate did not verify")
}

type verifier struct {
	anchors Anchors
	now     time.Time
	// expires is the earliest expiry seen.
	expires time.Time
}

func (v *verifier) expiry(t time.Time) {
	if v.expires.IsZero() || t.Before(v.expires) {
		v.expires = t
	}
}

// bySignature verifies compact with the keys of the ACTIVE anchors of kind
// named by its kid, and returns the payload and the anchor that signed.
func (v *verifier) bySignature(ctx context.Context, kind Kind, compact string, typOK func(string) bool) ([]byte, ids.UUID, error) {
	h, err := sdjwt.HeaderOf(compact)
	if err != nil {
		return nil, ids.UUID{}, err
	}
	if h.Kid == "" || !typOK(h.Typ) {
		return nil, ids.UUID{}, fmt.Errorf("%s JWT kid or typ", kind)
	}
	keys, err := v.anchors.Keys(ctx, kind, h.Kid)
	if err != nil {
		return nil, ids.UUID{}, err
	}
	for _, k := range keys {
		if payload, _, err := sdjwt.VerifyJWT(compact, nil, k.Key); err == nil {
			return payload, k.AnchorID, nil
		}
	}
	return nil, ids.UUID{}, fmt.Errorf("no ACTIVE %s anchor key verifies kid %q", kind, h.Kid)
}

func sdJWTTyp(t string) bool { return strings.HasSuffix(t, "+sd-jwt") && t != typDelegated }

func plainJWTTyp(t string) bool { return t == "" || t == "JWT" || t == "jwt" }

// checkTimes applies exp (must be after now) and nbf of verified claims.
func (v *verifier) checkTimes(claims map[string]any) error {
	exp, ok, err := sdjwt.NumericDate(claims, "exp")
	if err != nil {
		return err
	}
	if ok {
		if !v.now.Before(exp) {
			return errors.New("expired")
		}
		v.expiry(exp)
	}
	nbf, ok, err := sdjwt.NumericDate(claims, "nbf")
	if err != nil {
		return err
	}
	if ok && v.now.Add(sdjwt.ClockSkew).Before(nbf) {
		return errors.New("not yet valid")
	}
	return nil
}

// chain is one verified v0.2 mandate: its closed claims, the open claims
// when delegated, and the root issuer anchor.
type chain struct {
	closed, open map[string]any
	issuer       ids.UUID
	canonical    []string
}

// presentations reads a member: one presentation or [open, closed].
func presentations(raw jsontext.Value) ([]string, error) {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}, nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err != nil || len(list) == 0 || len(list) > 2 {
		return nil, errors.New("a mandate is one presentation or [open, closed]")
	}
	return list, nil
}

// mandate verifies a v0.2 mandate chain with the given closed and open vct.
func (v *verifier) mandate(ctx context.Context, raw jsontext.Value, closedVCT, openVCT string) (chain, error) {
	list, err := presentations(raw)
	if err != nil {
		return chain{}, err
	}
	if len(list) == 1 {
		return v.closedAlone(ctx, list[0], closedVCT)
	}
	return v.delegated(ctx, list[0], list[1], closedVCT, openVCT)
}

// issued verifies an anchor-issued SD-JWT and returns it and its claims.
func (v *verifier) issued(ctx context.Context, s string) (*sdjwt.Presentation, map[string]any, ids.UUID, error) {
	p, err := sdjwt.Parse(s)
	if err != nil {
		return nil, nil, ids.UUID{}, err
	}
	payload, anchor, err := v.bySignature(ctx, KindMandateIssuer, p.IssuerJWT, sdJWTTyp)
	if err != nil {
		return nil, nil, ids.UUID{}, err
	}
	claims, err := p.Disclose(payload)
	if err != nil {
		return nil, nil, ids.UUID{}, err
	}
	if err := v.checkTimes(claims); err != nil {
		return nil, nil, ids.UUID{}, err
	}
	return p, claims, anchor, nil
}

// closedAlone verifies a closed mandate an anchor issued to a holder key,
// presented with a KB-JWT by that key.
func (v *verifier) closedAlone(ctx context.Context, s, vct string) (chain, error) {
	p, claims, anchor, err := v.issued(ctx, s)
	if err != nil {
		return chain{}, err
	}
	if claims["vct"] != vct {
		return chain{}, fmt.Errorf("vct %v, want %s", claims["vct"], vct)
	}
	if _, open := claims["constraints"]; open {
		return chain{}, errors.New("a closed mandate has no constraints")
	}
	holder, err := sdjwt.HolderKey(claims)
	if err != nil {
		return chain{}, err
	}
	kb, err := p.VerifyKB(holder, v.anchors.Audiences(), v.now)
	if err != nil {
		return chain{}, err
	}
	v.expiry(kb.IssuedAt.Add(sdjwt.KBMaxAge))
	return chain{closed: claims, issuer: anchor, canonical: []string{p.Canonical()}}, nil
}

// delegated verifies an open mandate an anchor issued with a cnf key and
// the closed mandate that key signed (typ kb+sd-jwt, sd_hash over the open
// presentation, fresh iat, aud and nonce).
func (v *verifier) delegated(ctx context.Context, openS, closedS, closedVCT, openVCT string) (chain, error) {
	op, open, anchor, err := v.issued(ctx, openS)
	if err != nil {
		return chain{}, err
	}
	if op.KB != "" {
		return chain{}, errors.New("an open mandate in a chain has no KB-JWT")
	}
	if open["vct"] != openVCT {
		return chain{}, fmt.Errorf("open vct %v, want %s", open["vct"], openVCT)
	}
	holder, err := sdjwt.HolderKey(open)
	if err != nil {
		return chain{}, err
	}
	cp, err := sdjwt.Parse(closedS)
	if err != nil {
		return chain{}, err
	}
	if cp.KB != "" {
		return chain{}, errors.New("a delegated closed mandate has no KB-JWT")
	}
	payload, _, err := sdjwt.VerifyJWT(cp.IssuerJWT, []string{typDelegated}, holder)
	if err != nil {
		return chain{}, err
	}
	closed, err := cp.Disclose(payload)
	if err != nil {
		return chain{}, err
	}
	if closed["vct"] != closedVCT {
		return chain{}, fmt.Errorf("closed vct %v, want %s", closed["vct"], closedVCT)
	}
	if _, isOpen := closed["constraints"]; isOpen {
		return chain{}, errors.New("a closed mandate has no constraints")
	}
	if h, _ := closed["sd_hash"].(string); h != sdjwt.Digest(op.WithoutKB()) {
		return chain{}, errors.New("closed sd_hash does not bind the open mandate")
	}
	iat, _ := closed["iat"].(float64)
	at, err := sdjwt.Fresh(iat, v.now)
	if err != nil {
		return chain{}, err
	}
	v.expiry(at.Add(sdjwt.KBMaxAge))
	aud, _ := closed["aud"].(string)
	nonce, _ := closed["nonce"].(string)
	if aud == "" || nonce == "" || (len(v.anchors.Audiences()) > 0 && !slices.Contains(v.anchors.Audiences(), aud)) {
		return chain{}, errors.New("closed mandate aud or nonce")
	}
	if err := v.checkTimes(closed); err != nil {
		return chain{}, err
	}
	if err := unchanged(open, closed); err != nil {
		return chain{}, err
	}
	return chain{closed: closed, open: open, issuer: anchor, canonical: []string{op.Canonical(), cp.Canonical()}}, nil
}

// openOnly are the open mandate claims that do not carry into the closed
// one.
var openOnly = map[string]bool{
	"vct": true, "cnf": true, "constraints": true, "iat": true, "exp": true, "nbf": true, "iss": true, "sub": true,
	"status": true, "jti": true,
}

// unchanged checks that every value the open mandate sets is in the closed
// mandate unchanged (AP2 v0.2 agent authorization rule 2).
func unchanged(open, closed map[string]any) error {
	for k, ov := range open {
		if openOnly[k] {
			continue
		}
		cv, ok := closed[k]
		if !ok {
			return fmt.Errorf("closed mandate lacks %q", k)
		}
		a, err := canonicalJSON(ov)
		if err != nil {
			return err
		}
		b, err := canonicalJSON(cv)
		if err != nil {
			return err
		}
		if a != b {
			return fmt.Errorf("closed mandate changed %q", k)
		}
	}
	return nil
}

// canonicalJSON returns the RFC 8785 form of v.
func canonicalJSON(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	val := jsontext.Value(raw)
	if err := val.Canonicalize(); err != nil {
		return "", err
	}
	return string(val), nil
}

// canonicalRaw returns the RFC 8785 form of a raw JSON value.
func canonicalRaw(raw jsontext.Value) ([]byte, error) {
	val := jsontext.Value(append([]byte(nil), raw...))
	if err := val.Canonicalize(); err != nil {
		return nil, err
	}
	return val, nil
}

// hashB64 returns base64url(SHA-256(b)).
func hashB64(b []byte) string { return sdjwt.Digest(string(b)) }

// digestOf is the MandateDigest of a canonical form.
func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// reclaim re-decodes a processed claim into a typed value.
func reclaim(v, dst any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, dst)
}
