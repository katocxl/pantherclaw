// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package credential defines PantherClaw's secret credential formats
// (ADR-0016). Every credential carries the org it belongs to, so the server
// can open a tenant transaction for that org and look the credential up by
// its SHA-256 under forced RLS, without any cross-tenant index:
//
//	pck_<env>_<org>_<secret>   API key (env: dev, test or live)
//	pci_<org>_<secret>         invitation (and the bootstrap admin token)
//	pcd_<org>_<secret>         device code (CLI login)
//	pcr_<org>_<secret>         refresh token (CLI session)
//	pcs_<org>_<secret>         OAuth state (browser leg of the device flow)
//	pcb_<org>_<secret>         browser session (the __Host-pc_session cookie, M5)
//	pcl_<org>_<secret>         browser sign-in state (M5)
//	pcu_<platform>_<secret>    account browser session (G0 UI D8)
//	pcm_<platform>_<secret>    sign-in state without an org (G0 UI D8)
//
// <org> is the org's UUID as 32 lowercase hex digits; <secret> is 256 random
// bits in 43 base62 characters. Only hashes are stored. Service-account
// client ids (pcsa_<org>_<account>) are identifiers, not secrets.
package credential

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strings"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Kind is a credential type, encoded as its prefix.
type Kind string

// Credential kinds.
const (
	APIKey       Kind = "pck"
	Invitation   Kind = "pci"
	DeviceCode   Kind = "pcd"
	RefreshToken Kind = "pcr"
	OAuthState   Kind = "pcs"
	// EnrollmentToken is an owner's single-use agent enrollment token (PAP-1
	// §3.2, M3).
	EnrollmentToken Kind = "pce"
	// Browser sign-in and sessions (G0 M5 part 1).
	BrowserSession Kind = "pcb"
	LoginState     Kind = "pcl"
	// GatewayEnrollmentToken is a single-use gateway enrollment token
	// (G0 M6, HR-180).
	GatewayEnrollmentToken Kind = "pcg"
	// Hosted accounts (G0 UI D8): an account browser session (the
	// __Host-pc_account cookie) and the state of a sign-in without an org.
	// They belong to no org: their <org> is the platform org, a fixed
	// routing value, and the hash is looked up only in the account tables.
	AccountSession    Kind = "pcu"
	AccountLoginState Kind = "pcm"
)

// Env labels API keys by deployment, so that a key made for one deployment
// class cannot be used against another and secret scanners can rate leaks.
type Env string

// API key environments.
const (
	EnvDev  Env = "dev"
	EnvTest Env = "test"
	EnvLive Env = "live"
)

// Valid reports whether e is a known environment.
func (e Env) Valid() bool { return e == EnvDev || e == EnvTest || e == EnvLive }

const (
	secretLen = 43 // base62 digits for 256 bits
	orgLen    = 32 // hex digits of a UUID
	base62    = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	// MaxLen bounds any credential string before parsing.
	MaxLen = 128
)

// ErrMalformed reports a string that is not a well-formed credential of the
// expected kind. Callers answer with a generic authentication error.
var ErrMalformed = errors.New("credential: malformed")

// Token is a parsed secret credential. Its String and LogValue never reveal
// the secret.
type Token struct {
	kind Kind
	env  Env
	org  ids.OrgID
	raw  string
}

// New mints a credential of kind for org. env is required for API keys and
// must be empty otherwise.
func New(kind Kind, env Env, org ids.OrgID) (Token, error) {
	if org.IsZero() || !kind.valid() || (kind == APIKey) != (env != "") || (env != "" && !env.Valid()) {
		return Token{}, fmt.Errorf("credential: invalid kind %q / env %q / org", kind, env)
	}
	secret, err := Secret()
	if err != nil {
		return Token{}, err
	}
	var b strings.Builder
	b.WriteString(string(kind))
	b.WriteByte('_')
	if kind == APIKey {
		b.WriteString(string(env))
		b.WriteByte('_')
	}
	b.WriteString(orgHex(org))
	b.WriteByte('_')
	b.WriteString(secret)
	return Token{kind: kind, env: env, org: org, raw: b.String()}, nil
}

// Parse parses s as a credential of kind.
func Parse(kind Kind, s string) (Token, error) {
	if len(s) > MaxLen || !kind.valid() {
		return Token{}, ErrMalformed
	}
	rest, ok := strings.CutPrefix(s, string(kind)+"_")
	if !ok {
		return Token{}, ErrMalformed
	}
	var env Env
	if kind == APIKey {
		e, r, ok := strings.Cut(rest, "_")
		if !ok || !Env(e).Valid() {
			return Token{}, ErrMalformed
		}
		env, rest = Env(e), r
	}
	if len(rest) != orgLen+1+secretLen || rest[orgLen] != '_' || !isBase62(rest[orgLen+1:]) {
		return Token{}, ErrMalformed
	}
	org, err := parseOrgHex(rest[:orgLen])
	if err != nil {
		return Token{}, ErrMalformed
	}
	return Token{kind: kind, env: env, org: org, raw: s}, nil
}

// Kind returns the credential kind.
func (t Token) Kind() Kind { return t.kind }

// Env returns the API key environment ("" for other kinds).
func (t Token) Env() Env { return t.env }

// Org returns the org the credential belongs to. It is a routing hint only:
// the credential is authentic only if its hash is found in that org.
func (t Token) Org() ids.OrgID { return t.org }

// Hash returns SHA-256 of the whole credential string, the stored form.
func (t Token) Hash() []byte {
	h := sha256.Sum256([]byte(t.raw))
	return h[:]
}

// Hint returns the last four characters, to help people recognize a key.
func (t Token) Hint() string { return t.raw[len(t.raw)-4:] }

// Reveal returns the credential string. Call it only to hand the credential
// to its owner once, or to send it to PantherClaw.
func (t Token) Reveal() string { return t.raw }

// String redacts the secret.
func (t Token) String() string {
	if t.raw == "" {
		return ""
	}
	return string(t.kind) + "_…" + t.Hint()
}

// LogValue implements slog.LogValuer, so a token logged by mistake shows
// only its kind and hint.
func (t Token) LogValue() slog.Value { return slog.StringValue(t.String()) }

// HashString returns SHA-256 of s, for secrets that are not Tokens (the
// browser binding cookie).
func HashString(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

// Secret returns 256 random bits as 43 base62 characters. It is also a valid
// PKCE code verifier (RFC 7636 §4.1).
func Secret() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	n := new(big.Int).SetBytes(b[:])
	out := make([]byte, secretLen)
	base := big.NewInt(62)
	mod := new(big.Int)
	for i := secretLen - 1; i >= 0; i-- {
		n.DivMod(n, base, mod)
		out[i] = base62[mod.Int64()]
	}
	return string(out), nil
}

func (k Kind) valid() bool {
	switch k {
	case APIKey, Invitation, DeviceCode, RefreshToken, OAuthState, EnrollmentToken:
		return true
	case BrowserSession, LoginState, GatewayEnrollmentToken, AccountSession, AccountLoginState:
		return true
	}
	return false
}

func isBase62(s string) bool {
	for i := range len(s) {
		if strings.IndexByte(base62, s[i]) < 0 {
			return false
		}
	}
	return true
}

func orgHex(org ids.OrgID) string {
	u := org.UUID()
	return hex.EncodeToString(u[:])
}

func parseOrgHex(s string) (ids.OrgID, error) {
	return parseIDHex[ids.Org](s)
}

func parseIDHex[K ids.Kind](s string) (ids.ID[K], error) {
	if len(s) != orgLen || strings.ToLower(s) != s {
		return ids.ID[K]{}, ErrMalformed
	}
	var u ids.UUID
	if _, err := hex.Decode(u[:], []byte(s)); err != nil {
		return ids.ID[K]{}, ErrMalformed
	}
	return ids.FromUUID[K](u)
}

// ClientIDPrefix starts every service-account client id.
const ClientIDPrefix = "pcsa_"

// FormatClientID returns the OAuth client id of a service account:
// pcsa_<org>_<account>, both as 32 hex digits.
func FormatClientID[K ids.Kind](org ids.OrgID, account ids.ID[K]) string {
	u := account.UUID()
	return ClientIDPrefix + orgHex(org) + "_" + hex.EncodeToString(u[:])
}

// ParseClientID parses a service-account client id.
func ParseClientID[K ids.Kind](s string) (ids.OrgID, ids.ID[K], error) {
	rest, ok := strings.CutPrefix(s, ClientIDPrefix)
	if !ok || len(rest) != 2*orgLen+1 || rest[orgLen] != '_' {
		return ids.OrgID{}, ids.ID[K]{}, ErrMalformed
	}
	org, err := parseOrgHex(rest[:orgLen])
	if err != nil {
		return ids.OrgID{}, ids.ID[K]{}, ErrMalformed
	}
	acct, err := parseIDHex[K](rest[orgLen+1:])
	if err != nil {
		return ids.OrgID{}, ids.ID[K]{}, ErrMalformed
	}
	return org, acct, nil
}

// userCodeAlphabet has no vowels (no accidental words) and no look-alike
// characters (RFC 8628 §6.1): 20 letters, 8 characters ≈ 34.5 bits.
const userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"

// UserCodeLen is the length of a device-flow user code.
const UserCodeLen = 8

// NewUserCode returns a random user code (unformatted).
func NewUserCode() (string, error) {
	out := make([]byte, 0, UserCodeLen)
	var b [16]byte
	for len(out) < UserCodeLen {
		if _, err := rand.Read(b[:]); err != nil {
			return "", err
		}
		for _, c := range b {
			// 240 = 12 × 20: rejection sampling keeps the distribution uniform.
			if c < 240 && len(out) < UserCodeLen {
				out = append(out, userCodeAlphabet[c%20])
			}
		}
	}
	return string(out), nil
}

// NormalizeUserCode accepts what a person typed (any case, with spaces or
// hyphens) and returns the stored form, or false.
func NormalizeUserCode(s string) (string, bool) {
	if len(s) > 32 {
		return "", false
	}
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		switch {
		case r == '-' || r == ' ':
			continue
		case strings.ContainsRune(userCodeAlphabet, r):
			b.WriteRune(r)
		default:
			return "", false
		}
	}
	if b.Len() != UserCodeLen {
		return "", false
	}
	return b.String(), true
}

// FormatUserCode renders a stored user code for display: XXXX-XXXX.
func FormatUserCode(code string) string {
	if len(code) != UserCodeLen {
		return code
	}
	return code[:4] + "-" + code[4:]
}
