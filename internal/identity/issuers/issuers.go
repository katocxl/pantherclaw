// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package issuers holds the trusted-issuer presets for L2 attestation
// (PAP-1 §3.3, ADR-0018, G0 M3): how an entry pins the claims that bind a
// platform token to one agent, which rules each preset enforces whatever
// the configuration says, and which revisions widen an entry. Signature
// and TokenReview checks happen in adapters; this package decides on
// claims that were already verified there. Nothing here is configurable
// beyond the binding: only preset kinds exist (HR-140).
package issuers

import (
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Kind is a preset.
type Kind string

// Presets: GitHub Actions and Kubernetes shipped in M3 (PN-002.2), the
// rest in M17 (PN-002.3).
const (
	KindGitHub     Kind = "github_actions"
	KindKubernetes Kind = "kubernetes"
	KindGitLab     Kind = "gitlab_ci"
	KindSPIFFE     Kind = "spiffe_jwt"
	KindGCP        Kind = "gcp_workload"
	KindAWS        Kind = "aws_iam"
)

// kinds are the presets this build implements.
var kinds = []Kind{KindGitHub, KindKubernetes, KindGitLab, KindSPIFFE, KindGCP, KindAWS}

// Known reports whether k is a preset this build implements. Anything else
// is refused, never mapped to a default preset (HR-465).
func Known(k Kind) bool { return slices.Contains(kinds, k) }

// MaxTokenLifetime bounds exp - iat of an attestation token (HR-143).
const MaxTokenLifetime = time.Hour

// Leeway tolerates issuer clock skew.
const Leeway = 60 * time.Second

var (
	// ErrInvalidEntry reports an entry that pins too little or the wrong
	// shape (HR-140).
	ErrInvalidEntry = errors.New("issuers: invalid issuer entry")
	// ErrRejected reports an attestation token that does not match its
	// entry or breaks a preset rule. The detail is for logs only.
	ErrRejected = errors.New("issuers: attestation rejected")
)

func rejected(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrRejected, fmt.Sprintf(format, a...))
}

// Audience is the only audience an attestation token for org may carry
// (HR-140, HR-143).
func Audience(org ids.OrgID) string { return "pantherclaw:" + org.String() }

// Lifetime checks an attestation token's validity window at now: it must be
// current and live at most MaxTokenLifetime (HR-143).
func Lifetime(iat, nbf, exp, now time.Time) error {
	switch {
	case exp.IsZero() || iat.IsZero():
		return rejected("exp and iat are required")
	case !now.Before(exp.Add(Leeway)):
		return rejected("expired")
	case iat.After(now.Add(Leeway)) || (!nbf.IsZero() && nbf.After(now.Add(Leeway))):
		return rejected("not yet valid")
	case !exp.After(iat) || exp.Sub(iat) > MaxTokenLifetime:
		return rejected("lifetime over %s", MaxTokenLifetime)
	}
	return nil
}

// Window is the validity window and jti of an attestation token, read from
// a payload that was verified (GitHub) or authenticated by TokenReview
// (Kubernetes).
type Window struct {
	IssuedAt  time.Time
	NotBefore time.Time
	ExpiresAt time.Time
	JTI       string
}

// ParseWindow reads iat, nbf and exp (whole seconds since the epoch) and jti.
func ParseWindow(payload []byte) (Window, error) {
	var c struct {
		IAT int64  `json:"iat"`
		NBF int64  `json:"nbf"`
		EXP int64  `json:"exp"`
		JTI string `json:"jti"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return Window{}, rejected("token times: %v", err)
	}
	w := Window{JTI: c.JTI}
	for _, f := range []struct {
		sec int64
		to  *time.Time
	}{{c.IAT, &w.IssuedAt}, {c.NBF, &w.NotBefore}, {c.EXP, &w.ExpiresAt}} {
		if f.sec > 0 {
			*f.to = time.Unix(f.sec, 0)
		}
	}
	return w, nil
}

// Check applies Lifetime to the window at now.
func (w Window) Check(now time.Time) error {
	return Lifetime(w.IssuedAt, w.NotBefore, w.ExpiresAt, now)
}

// ReplayKey is the single-use key of an attestation token: the SHA-256 of
// its jti, or of the whole token when it has none (HR-143). The two cases
// are domain-separated so a jti can never collide with a token. A token is
// keyed by its canonical encoding: changing the unused bits of a segment's
// last base64 character still verifies, and must give the same key.
func ReplayKey(jti, token string) [32]byte {
	if jti != "" {
		return sha256.Sum256([]byte("jti:" + jti))
	}
	if c, ok := jws.Canonical(token); ok {
		token = c
	}
	return sha256.Sum256([]byte("tok:" + token))
}

// Binding is the set of verified claim values an instance enrolled with.
// It never changes: a re-attestation must produce exactly the same binding
// (HR-147).
type Binding map[string]string

// Equal reports whether two bindings are identical.
func (b Binding) Equal(o Binding) bool {
	if len(b) != len(o) {
		return false
	}
	for k, v := range b {
		if w, ok := o[k]; !ok || w != v {
			return false
		}
	}
	return true
}

// Match is a successful attestation: the binding it proves and, when the
// preset can see it, the attested release digest.
type Match struct {
	Binding       Binding
	ReleaseDigest string
}

// widened lists what moves from old to new for a pinned set: added values
// widen; and an emptied list (which means "any") widens.
func widenedList(name string, prev, next []string) []string {
	var out []string
	if len(prev) > 0 && len(next) == 0 {
		return []string{name + ": any value now accepted"}
	}
	if len(prev) == 0 {
		return nil // was "any": any list narrows
	}
	for _, v := range next {
		if !slices.Contains(prev, v) {
			out = append(out, name+" added: "+v)
		}
	}
	return out
}

// widenedPin reports a single optional pin that was removed or changed.
func widenedPin(name, prev, next string) []string {
	switch {
	case prev == "" || prev == next:
		return nil
	case next == "":
		return []string{name + ": pin removed"}
	default:
		return []string{name + " changed: " + prev + " to " + next}
	}
}
