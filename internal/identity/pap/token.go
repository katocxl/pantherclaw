// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pap

import (
	"encoding/json/v2"
	"regexp"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Release identity states (PAP-1 §3.3): a value the workload reports about
// itself is always declared; only values PantherClaw reads from an issuer
// or a cluster are attested.
const (
	ReleaseDeclared = "declared"
	ReleaseAttested = "attested"
)

var (
	jktPattern    = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// Token is the content of a workload token (PAP-1 §3.4).
type Token struct {
	Instance    Instance
	Environment ids.UUID
	// JKT is the RFC 7638 thumbprint of the instance key (cnf.jkt).
	JKT string
	// Level is the attestation level in force (1, 2 or 3).
	Level int
	// ReleaseState and ReleaseDigest describe the release identity; both
	// empty when none is known.
	ReleaseState  string
	ReleaseDigest string
	ID            ids.UUID
	IssuedAt      time.Time
	ExpiresAt     time.Time
}

type tokenClaims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  string   `json:"aud"`
	IssuedAt  int64    `json:"iat"`
	NotBefore int64    `json:"nbf"`
	Expiry    int64    `json:"exp"`
	ID        string   `json:"jti"`
	Cnf       cnf      `json:"cnf"`
	PAP       tokenPAP `json:"pap"`
}

type cnf struct {
	JKT string `json:"jkt"`
}

type tokenPAP struct {
	V       int      `json:"v"`
	Org     string   `json:"org"`
	Env     string   `json:"env"`
	Level   int      `json:"att_lvl"`
	Release *release `json:"release,omitzero"`
}

type release struct {
	State  string `json:"state"`
	Digest string `json:"digest"`
}

// Issue signs a workload token for t. It is valid from now until
// min(now + MaxTokenTTL, notAfter): a token never outlives the attestation
// behind its level (HR-143), so the caller passes the attestation's expiry
// for L2 and L3 and the zero time otherwise.
func Issue(signer *jws.Signer, issuer string, t Token, now, notAfter time.Time) (string, Token, error) {
	now = now.Truncate(time.Second)
	exp := now.Add(MaxTokenTTL)
	if !notAfter.IsZero() && notAfter.Before(exp) {
		exp = notAfter.Truncate(time.Second)
	}
	switch {
	case signer == nil || issuer == "":
		return "", Token{}, fail(CodeInvalidToken, "signer and issuer required")
	case t.Instance.Org.IsZero() || t.Instance.Agent.IsZero() || t.Instance.Instance.IsZero() || t.Environment.IsZero():
		return "", Token{}, fail(CodeInvalidToken, "incomplete instance")
	case !jktPattern.MatchString(t.JKT):
		return "", Token{}, fail(CodeInvalidToken, "jkt")
	case t.Level < 1 || t.Level > 3: // L3: PAP-1 §3.3, G0 M35 D1030
		return "", Token{}, fail(CodeInvalidToken, "level")
	case !exp.After(now):
		return "", Token{}, fail(CodeAttestationLow, "attestation already expired")
	}
	p := tokenPAP{V: 1, Org: t.Instance.Org.String(), Env: t.Environment.String(), Level: t.Level}
	if t.ReleaseState != "" || t.ReleaseDigest != "" {
		if (t.ReleaseState != ReleaseDeclared && t.ReleaseState != ReleaseAttested) || !digestPattern.MatchString(t.ReleaseDigest) {
			return "", Token{}, fail(CodeInvalidToken, "release")
		}
		p.Release = &release{State: t.ReleaseState, Digest: t.ReleaseDigest}
	}
	t.ID, t.IssuedAt, t.ExpiresAt = ids.NewV7(), now, exp
	payload, err := json.Marshal(tokenClaims{
		Issuer: issuer, Subject: t.Instance.String(), Audience: TokenAudience,
		IssuedAt: now.Unix(), NotBefore: now.Unix(), Expiry: exp.Unix(), ID: t.ID.String(),
		Cnf: cnf{JKT: t.JKT}, PAP: p,
	})
	if err != nil {
		return "", Token{}, err
	}
	compact, err := signer.Sign(TokenType, payload)
	if err != nil {
		return "", Token{}, err
	}
	return compact, t, nil
}

// VerifyToken checks a workload token: size, signature with a workload-token
// key (EdDSA, typ pap-wt+jwt, kid from the Authority's keys), issuer,
// audience, validity window, lifetime and claim shapes (PAP-1 §4 step 1).
// Unknown claims are ignored (PAP-1 §13).
func VerifyToken(v *jws.Verifier, issuer, compact string, now time.Time) (Token, error) {
	if v == nil || len(compact) > MaxTokenBytes {
		return Token{}, fail(CodeInvalidToken, "size")
	}
	payload, _, err := v.Verify(compact)
	if err != nil {
		return Token{}, fail(CodeInvalidToken, "signature: %v", err)
	}
	var c tokenClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return Token{}, fail(CodeInvalidToken, "claims: %v", err)
	}
	iat, nbf, exp := time.Unix(c.IssuedAt, 0), time.Unix(c.NotBefore, 0), time.Unix(c.Expiry, 0)
	switch {
	case c.Issuer != issuer || c.Audience != TokenAudience:
		return Token{}, fail(CodeInvalidToken, "issuer or audience")
	case c.PAP.V != 1:
		return Token{}, fail(CodeInvalidToken, "version")
	case !now.Before(exp.Add(Leeway)):
		return Token{}, fail(CodeTokenExpired, "expired")
	case nbf.After(now.Add(Leeway)) || iat.After(now.Add(Leeway)) || nbf.Before(iat):
		return Token{}, fail(CodeInvalidToken, "not yet valid")
	case !exp.After(iat) || exp.Sub(iat) > MaxTokenTTL:
		return Token{}, fail(CodeInvalidToken, "lifetime")
	case !jktPattern.MatchString(c.Cnf.JKT):
		return Token{}, fail(CodeInvalidToken, "cnf")
	case c.PAP.Level < 1 || c.PAP.Level > 3:
		return Token{}, fail(CodeInvalidToken, "level")
	}
	inst, err := ParseInstance(c.Subject)
	if err != nil || inst.Org.String() != c.PAP.Org {
		return Token{}, fail(CodeInvalidToken, "subject")
	}
	env, err := ids.ParseUUID(c.PAP.Env)
	if err != nil || env.IsZero() {
		return Token{}, fail(CodeInvalidToken, "env")
	}
	id, err := ids.ParseUUID(c.ID)
	if err != nil || id.IsZero() {
		return Token{}, fail(CodeInvalidToken, "jti")
	}
	t := Token{
		Instance: inst, Environment: env, JKT: c.Cnf.JKT, Level: c.PAP.Level,
		ID: id, IssuedAt: iat, ExpiresAt: exp,
	}
	if r := c.PAP.Release; r != nil {
		if (r.State != ReleaseDeclared && r.State != ReleaseAttested) || !digestPattern.MatchString(r.Digest) {
			return Token{}, fail(CodeInvalidToken, "release")
		}
		t.ReleaseState, t.ReleaseDigest = r.State, r.Digest
	}
	return t, nil
}
