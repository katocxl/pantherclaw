// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package actionir implements ActionIR v1, the canonical representation of
// one requested agent action (PAP-1 §6, ADR-0011). The gateway builds it,
// the Authority decides on it, and the gateway re-serializes the outbound
// request from it, so all three agree on exactly the same bytes:
//
//	action_hash = SHA-256(JCS(ActionIR))
//
// Parsing is strict and fails closed: duplicate keys, invalid UTF-8, unknown
// fields, JSON numbers in parameters, excessive depth or size, ambiguous or
// non-ASCII identifiers all make the action CANNOT_AUTHORIZE (HR-100..103).
// The package is pure: no I/O, clock or randomness.
package actionir

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Limits (PAP-1 §6).
const (
	MaxBytes          = 1 << 20
	MaxDepth          = 16
	MaxStringBytes    = 64 << 10
	MaxMaterialString = 8 << 10
	Version           = 1
)

// ErrAmbiguous reports input that cannot be authorized as given. Callers map
// it to CANNOT_AUTHORIZE (never to a default).
var ErrAmbiguous = errors.New("actionir: ambiguous or invalid action")

// Definition pins the reviewed meaning of the operation.
type Definition struct {
	Package string `json:"package"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
}

// Target identifies the object the action affects.
type Target struct {
	Type    string `json:"type"`
	ID      string `json:"id"`
	Account string `json:"account,omitempty"`
}

// Destination classifies where data may flow (HR-079, later milestones).
type Destination struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// ActionIR is one canonical action.
type ActionIR struct {
	V             int        `json:"v"`
	Org           string     `json:"org"`
	Env           string     `json:"env"`
	RunID         string     `json:"run_id"`
	ActionID      string     `json:"action_id"`
	AgentInstance string     `json:"agent_instance"`
	Operation     string     `json:"operation"`
	Definition    Definition `json:"definition"`
	Channel       string     `json:"channel"`
	Route         string     `json:"route"`
	// Connection is the registered connection the request came through
	// (PAP-1 §6); optional, set by the gateway for http, mcp and hook.
	Connection   string         `json:"connection,omitempty"`
	Target       Target         `json:"target"`
	Params       jsontext.Value `json:"params"`
	Destinations []Destination  `json:"destinations"`
	DedupeKey    string         `json:"dedupe_key,omitempty"`
}

// Parsed is a validated ActionIR with its canonical bytes and hash.
type Parsed struct {
	Action    ActionIR
	Canonical []byte
	Hash      [sha256.Size]byte
}

// HashHex returns the action hash as lowercase hex.
func (p Parsed) HashHex() string { return hex.EncodeToString(p.Hash[:]) }

var (
	operationPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+){1,7}$`)
	routePattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	packagePattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,127}$`)
	semverPattern    = regexp.MustCompile(`^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$`)
	digestPattern    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	channels         = []string{"mcp", "http", "sdk", "hook", "authzen", "a2a"}
)

func ambiguous(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrAmbiguous}, args...)...)
}

// Parse validates raw ActionIR JSON and returns its canonical form and hash.
func Parse(raw []byte) (Parsed, error) {
	if len(raw) == 0 || len(raw) > MaxBytes {
		return Parsed{}, ambiguous("size %d outside 1..%d bytes", len(raw), MaxBytes)
	}
	if err := scan(raw); err != nil {
		return Parsed{}, err
	}
	var a ActionIR
	if err := json.Unmarshal(raw, &a, json.RejectUnknownMembers(true)); err != nil {
		return Parsed{}, ambiguous("%v", err)
	}
	if err := a.validate(); err != nil {
		return Parsed{}, err
	}
	c := jsontext.Value(bytes.Clone(raw))
	if err := c.Canonicalize(); err != nil {
		return Parsed{}, ambiguous("canonicalize: %v", err)
	}
	return Parsed{Action: a, Canonical: c, Hash: sha256.Sum256(c)}, nil
}

// Encode marshals a, validates it as Parse would, and returns the result.
// The gateway uses it to build ActionIR.
func Encode(a ActionIR) (Parsed, error) {
	if a.Destinations == nil {
		a.Destinations = []Destination{}
	}
	b, err := json.Marshal(a)
	if err != nil {
		return Parsed{}, ambiguous("%v", err)
	}
	return Parse(b)
}

// scan enforces depth and string limits and allows a JSON number only at
// /v (amounts are decimal strings, HR-101).
func scan(raw []byte) error {
	d := jsontext.NewDecoder(bytes.NewReader(raw))
	for {
		tok, err := d.ReadToken()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return ambiguous("%v", err)
		}
		if d.StackDepth() > MaxDepth {
			return ambiguous("nesting deeper than %d", MaxDepth)
		}
		//exhaustive:ignore // only numbers and strings need checks; structure is validated by the decoder
		switch tok.Kind() {
		case '0':
			if p := d.StackPointer(); p != "/v" {
				return ambiguous("JSON number at %s; amounts must be decimal strings", p)
			}
		case '"':
			if len(tok.String()) > MaxStringBytes {
				return ambiguous("string longer than %d bytes", MaxStringBytes)
			}
		}
	}
}

func (a ActionIR) validate() error {
	if a.V != Version {
		return ambiguous("unsupported version %d", a.V)
	}
	for name, v := range map[string]string{"org": a.Org, "env": a.Env, "run_id": a.RunID, "action_id": a.ActionID, "agent_instance": a.AgentInstance} {
		if _, err := ids.ParseUUID(v); err != nil {
			return ambiguous("%s must be a canonical UUID", name)
		}
	}
	switch {
	case !operationPattern.MatchString(a.Operation):
		return ambiguous("invalid operation")
	case !packagePattern.MatchString(a.Definition.Package) || !semverPattern.MatchString(a.Definition.Version) ||
		!digestPattern.MatchString(a.Definition.Digest):
		return ambiguous("definition must pin package, semver version and sha256 digest")
	case !slices.Contains(channels, a.Channel):
		return ambiguous("unknown channel")
	case !routePattern.MatchString(a.Route):
		return ambiguous("invalid route")
	}
	if a.Connection != "" {
		if _, err := ids.ParseUUID(a.Connection); err != nil {
			return ambiguous("connection must be a canonical UUID")
		}
	}
	if err := identifier("target.type", a.Target.Type, true); err != nil {
		return err
	}
	if err := identifier("target.id", a.Target.ID, true); err != nil {
		return err
	}
	if err := identifier("target.account", a.Target.Account, false); err != nil {
		return err
	}
	if len(a.Params) == 0 || a.Params.Kind() != '{' {
		return ambiguous("params must be an object")
	}
	if a.Destinations == nil {
		return ambiguous("destinations must be present (possibly empty)")
	}
	for i, d := range a.Destinations {
		if d.Kind != "internal" && d.Kind != "external" {
			return ambiguous("destinations[%d].kind must be internal or external", i)
		}
		if err := identifier(fmt.Sprintf("destinations[%d].id", i), d.ID, true); err != nil {
			return err
		}
	}
	return identifier("dedupe_key", a.DedupeKey, false)
}

// identifier accepts printable ASCII without spaces only. Non-ASCII,
// confusable or bidi characters in identifiers are rejected, not normalized
// (HR-102); the bytes are never case-folded.
func identifier(name, v string, required bool) error {
	if v == "" {
		if required {
			return ambiguous("%s is required", name)
		}
		return nil
	}
	if len(v) > MaxMaterialString {
		return ambiguous("%s too long", name)
	}
	for i := range len(v) {
		if c := v[i]; c < 0x21 || c > 0x7e {
			return ambiguous("%s contains a non-printable or non-ASCII byte", name)
		}
	}
	return nil
}

// ValidOperation reports whether s is a valid operation name.
func ValidOperation(s string) bool { return operationPattern.MatchString(s) }

// ValidRoute reports whether s is a valid route id.
func ValidRoute(s string) bool { return routePattern.MatchString(s) }

// ValidPackage reports whether s is a valid tool package name.
func ValidPackage(s string) bool { return packagePattern.MatchString(s) }

// ValidVersion reports whether s is a valid package version (MAJOR.MINOR.PATCH).
func ValidVersion(s string) bool { return semverPattern.MatchString(s) }

// CheckIdentifier applies the identifier rules (HR-102) to a required value.
// The error wraps ErrAmbiguous.
func CheckIdentifier(name, v string) error { return identifier(name, v, true) }

// OrgID returns the org as a typed ID.
func (a ActionIR) OrgID() (ids.OrgID, error) { return ids.Parse[ids.Org](a.Org) }

// DecodeParams strictly decodes params into dst (unknown fields rejected).
func (a ActionIR) DecodeParams(dst any) error {
	if err := json.Unmarshal(a.Params, dst, json.RejectUnknownMembers(true)); err != nil {
		return ambiguous("params: %v", err)
	}
	return nil
}
