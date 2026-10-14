// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package report is the containment sandbox's signed probe and canary
// report (G0 M9 contracts, HR-215): a compact JWS, typ pap-probe+jwt, alg
// EdDSA, signed with the session's probe key over the RFC 8785 canonical
// JSON of a Report. The probe container signs its own report and the
// canary signs its own; pclaw creates the key outside every container and
// registers its public half when it opens the session, and the server
// verifies each report against that key and a single-use server nonce.
// Results use the closure-evidence vocabulary of the coverage calculus.
// Everything in a report is untrusted and bounded.
package report

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
)

// Format and JWS type of a report.
const (
	Format = "pantherclaw.probe-report/v1"
	Type   = "pap-probe+jwt"
)

// Kinds of report.
const (
	KindSandbox = "sandbox"
	KindControl = "control"
	KindCanary  = "canary"
)

// Roles and observations of a result (the closure contract).
const (
	RoleProbe    = "probe"
	RolePositive = "positive_control"
	RoleNegative = "negative_control"
	RoleCanary   = "canary"

	Blocked   = "blocked"
	Reachable = "reachable"
	Error     = "error"
)

// Bounds (G0 M9: details ≤ 512 bytes, ≤ 256 results). A signed report is
// also at most jws.MaxCompactBytes.
const (
	MaxResults = 256
	MaxDetail  = 512
	MaxHits    = 256
	MaxChecks  = 64
)

// ErrInvalid reports a report that is malformed, unsigned or signed with
// another key; callers treat every cause alike and record it.
var ErrInvalid = errors.New("report: invalid probe report")

// Report is one probe, control or canary report.
type Report struct {
	Format     string    `json:"format"`
	Session    string    `json:"session"`
	Nonce      string    `json:"nonce"`
	Kind       string    `json:"kind"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Images     Images    `json:"images"`
	Engine     Engine    `json:"engine"`
	Network    Network   `json:"network"`
	Config     Config    `json:"config"`
	Results    []Result  `json:"results"`
	Canary     Canary    `json:"canary"`
}

// Images are the digests of the session's images.
type Images struct {
	Agent string `json:"agent"`
	Edge  string `json:"edge"`
	Probe string `json:"probe"`
}

// Engine is the Docker engine the session ran on (HR-218).
type Engine struct {
	Version    string `json:"version"`
	APIVersion string `json:"api_version"`
	Runtime    string `json:"runtime"`
	Desktop    bool   `json:"desktop"`
}

// Network is the sandbox network as pclaw inspected it.
type Network struct {
	Name            string `json:"name"`
	Internal        bool   `json:"internal"`
	GatewayModeIPv4 string `json:"gateway_mode_ipv4"`
	IPv6            bool   `json:"ipv6"`
}

// Config is the sandbox configuration's digest and the checks pclaw made
// with docker inspect, outside the sandbox (G0 M9 design decision 5).
type Config struct {
	Digest string  `json:"digest"`
	Checks []Check `json:"checks"`
}

// Check is one configuration check.
type Check struct {
	ID     string `json:"id"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// Result is one probe's outcome.
type Result struct {
	Name     string `json:"name"`
	Role     string `json:"role"`
	Expect   string `json:"expect"`
	Observed string `json:"observed"`
	Detail   string `json:"detail,omitempty"`
}

// Passed reports whether the observation is what was expected; an error
// never passes.
func (r Result) Passed() bool {
	return r.Observed == r.Expect && (r.Observed == Blocked || r.Observed == Reachable)
}

// Canary is what the canary saw: every hit carrying a session's marker.
type Canary struct {
	Hits []Hit `json:"hits"`
}

// Hit is one arrival at the canary.
type Hit struct {
	Proto  string    `json:"proto"`
	Port   int       `json:"port"`
	Marker string    `json:"marker"`
	At     time.Time `json:"at"`
}

var (
	digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	nameRE   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	markerRE = regexp.MustCompile(`^[0-9A-Za-z_-]{16,128}$`)
)

// Validate checks the shape and bounds of a report. It says nothing about
// whether the results pass.
func (r Report) Validate() error {
	bad := func(what string) error { return fmt.Errorf("%w: %s", ErrInvalid, what) }
	switch {
	case r.Format != Format:
		return bad("format")
	case r.Kind != KindSandbox && r.Kind != KindControl && r.Kind != KindCanary:
		return bad("kind")
	case r.Session == "" || len(r.Session) > 64 || !markerRE.MatchString(r.Nonce):
		return bad("session or nonce")
	case r.StartedAt.IsZero() || r.FinishedAt.Before(r.StartedAt):
		return bad("times")
	case r.Engine.Runtime != "runc" && r.Engine.Runtime != "runsc":
		return bad("runtime")
	case len(r.Results) > MaxResults || len(r.Canary.Hits) > MaxHits || len(r.Config.Checks) > MaxChecks:
		return bad("too many entries")
	}
	for _, d := range []string{r.Images.Agent, r.Images.Edge, r.Images.Probe, r.Config.Digest} {
		if d != "" && !digestRE.MatchString(d) {
			return bad("digest " + d)
		}
	}
	for _, c := range r.Config.Checks {
		if !nameRE.MatchString(c.ID) || !bounded(c.Detail) {
			return bad("check")
		}
	}
	for _, x := range r.Results {
		switch {
		case !nameRE.MatchString(x.Name) || !bounded(x.Detail):
			return bad("result name or detail")
		case !slices.Contains([]string{RoleProbe, RolePositive, RoleNegative, RoleCanary}, x.Role):
			return bad("role")
		case x.Expect != Blocked && x.Expect != Reachable:
			return bad("expect")
		case x.Observed != Blocked && x.Observed != Reachable && x.Observed != Error:
			return bad("observed")
		}
	}
	for _, h := range r.Canary.Hits {
		if (h.Proto != "tcp" && h.Proto != "udp") || h.Port < 1 || h.Port > 65535 || !markerRE.MatchString(h.Marker) {
			return bad("hit")
		}
	}
	return nil
}

func bounded(s string) bool { return len(s) <= MaxDetail && utf8.ValidString(s) }

// Canonical is the RFC 8785 canonical JSON of a report, the bytes it is
// signed over.
func (r Report) Canonical() ([]byte, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	v := jsontext.Value(b)
	if err := v.Canonicalize(); err != nil {
		return nil, err
	}
	return v, nil
}

// KeyID is the RFC 7638 thumbprint of a probe key: the kid of its reports
// and the session's SigningKeyJKT.
func KeyID(pub ed25519.PublicKey) string { return jws.Thumbprint(pub) }

// Sign validates a report and signs it with the session's probe key.
func Sign(key ed25519.PrivateKey, r Report) (string, error) {
	if err := r.Validate(); err != nil {
		return "", err
	}
	payload, err := r.Canonical()
	if err != nil {
		return "", err
	}
	pub, _ := key.Public().(ed25519.PublicKey)
	s, err := jws.NewSigner(KeyID(pub), key)
	if err != nil {
		return "", err
	}
	return s.Sign(Type, payload)
}

// Verify checks a signed report against the session's probe key and
// returns it: the signature, the type, canonical JSON that decodes
// strictly, and the report's shape and bounds. The caller checks the
// session, the nonce and the digests against what it registered.
func Verify(compact string, pub ed25519.PublicKey) (Report, error) {
	v, err := jws.NewVerifier(Type, map[string]ed25519.PublicKey{KeyID(pub): pub})
	if err != nil {
		return Report{}, err
	}
	payload, _, err := v.Verify(compact)
	if err != nil {
		return Report{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	canon := jsontext.Value(slices.Clone(payload))
	if err := canon.Canonicalize(); err != nil || string(canon) != string(payload) {
		return Report{}, fmt.Errorf("%w: the payload is not canonical JSON", ErrInvalid)
	}
	var r Report
	if err := json.Unmarshal(payload, &r, json.RejectUnknownMembers(true)); err != nil {
		return Report{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if err := r.Validate(); err != nil {
		return Report{}, err
	}
	return r, nil
}

// Marker is the canary marker of a run whose report carries nonce: "pc" and
// 32 hex digits, short enough for a DNS label. Every probe aimed at the
// canary carries it, and the canary report lists the hits that do.
func Marker(nonce string) string {
	sum := sha256.Sum256([]byte("pantherclaw-canary:" + nonce))
	return "pc" + hex.EncodeToString(sum[:16])
}
