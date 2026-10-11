// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

package pap

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
)

// ActionIR limits (PAP/1 §6).
const (
	maxActionBytes   = 1 << 20
	maxActionDepth   = 16
	maxStringBytes   = 64 << 10
	maxIdentifierLen = 8 << 10
)

// ErrAction reports ActionIR that PantherClaw would refuse (HR-100..103).
var ErrAction = errors.New("pap: invalid ActionIR")

// Action is ActionIR v1 (PAP/1 §6), the canonical action the gateway
// mapped. SDKs never build or send one (HR-201): they parse the action a
// gateway returns to check it and its hash.
type Action struct {
	V             int    `json:"v"`
	Org           string `json:"org"`
	Env           string `json:"env"`
	RunID         string `json:"run_id"`
	ActionID      string `json:"action_id"`
	AgentInstance string `json:"agent_instance"`
	Operation     string `json:"operation"`
	Definition    struct {
		Package string `json:"package"`
		Version string `json:"version"`
		Digest  string `json:"digest"`
	} `json:"definition"`
	Channel    string `json:"channel"`
	Route      string `json:"route"`
	Connection string `json:"connection,omitempty"`
	Target     struct {
		Type    string `json:"type"`
		ID      string `json:"id"`
		Account string `json:"account,omitempty"`
	} `json:"target"`
	Params       jsontext.Value `json:"params"`
	Destinations []struct {
		Kind string `json:"kind"`
		ID   string `json:"id"`
	} `json:"destinations"`
	DedupeKey string `json:"dedupe_key,omitempty"`
}

// ParsedAction is a checked action with its canonical bytes and hash.
type ParsedAction struct {
	Action    Action
	Canonical []byte
	// Hash is the action hash: lowercase hex SHA-256 of Canonical.
	Hash string
}

var (
	uuidPattern      = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	operationPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+){1,7}$`)
	routePattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	packagePattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,127}$`)
	versionPattern   = regexp.MustCompile(`^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$`)
	digestPattern    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

func bad(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrAction}, a...)...)
}

// ParseAction checks ActionIR as strictly as PantherClaw does: strict JSON
// (no duplicate or unknown members, valid UTF-8, depth at most 16, strings
// at most 64 KiB, at most 1 MiB), no JSON numbers except the version,
// printable-ASCII identifiers, and every required field present and well
// formed. It returns the canonical bytes and the action hash.
func ParseAction(raw []byte) (ParsedAction, error) {
	if len(raw) == 0 || len(raw) > maxActionBytes {
		return ParsedAction{}, bad("size %d", len(raw))
	}
	if err := scanAction(raw); err != nil {
		return ParsedAction{}, err
	}
	var a Action
	if err := json.Unmarshal(raw, &a, json.RejectUnknownMembers(true)); err != nil {
		return ParsedAction{}, bad("%v", err)
	}
	if err := a.check(); err != nil {
		return ParsedAction{}, err
	}
	c, err := Canonical(raw)
	if err != nil {
		return ParsedAction{}, bad("%v", err)
	}
	s := sha256.Sum256(c)
	return ParsedAction{Action: a, Canonical: c, Hash: hex.EncodeToString(s[:])}, nil
}

// scanAction enforces depth and string limits and allows a JSON number only
// as the version.
func scanAction(raw []byte) error {
	d := jsontext.NewDecoder(bytes.NewReader(raw))
	for {
		tok, err := d.ReadToken()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return bad("%v", err)
		}
		if d.StackDepth() > maxActionDepth {
			return bad("nested deeper than %d", maxActionDepth)
		}
		//exhaustive:ignore // only numbers and strings have limits; the decoder checks structure
		switch tok.Kind() {
		case '0':
			if d.StackPointer() != "/v" {
				return bad("a JSON number at %s", d.StackPointer())
			}
		case '"':
			if len(tok.String()) > maxStringBytes {
				return bad("a string longer than %d bytes", maxStringBytes)
			}
		}
	}
}

func (a Action) check() error {
	if a.V != Version {
		return bad("version %d", a.V)
	}
	for name, v := range map[string]string{"org": a.Org, "env": a.Env, "run_id": a.RunID, "action_id": a.ActionID, "agent_instance": a.AgentInstance} {
		if !uuidPattern.MatchString(v) {
			return bad("%s is not a UUID", name)
		}
	}
	switch {
	case !operationPattern.MatchString(a.Operation):
		return bad("operation")
	case !packagePattern.MatchString(a.Definition.Package) || !versionPattern.MatchString(a.Definition.Version) ||
		!digestPattern.MatchString(a.Definition.Digest):
		return bad("definition")
	case a.Channel != "mcp" && a.Channel != "http" && a.Channel != "sdk" && a.Channel != "hook":
		return bad("channel")
	case !routePattern.MatchString(a.Route):
		return bad("route")
	case a.Connection != "" && !uuidPattern.MatchString(a.Connection):
		return bad("connection")
	case len(a.Params) == 0 || a.Params.Kind() != '{':
		return bad("params must be an object")
	case a.Destinations == nil:
		return bad("destinations must be present")
	}
	ids := [][3]string{{"target.type", a.Target.Type, "1"}, {"target.id", a.Target.ID, "1"}, {"target.account", a.Target.Account, ""}, {"dedupe_key", a.DedupeKey, ""}}
	for i, d := range a.Destinations {
		if d.Kind != "internal" && d.Kind != "external" {
			return bad("destinations[%d].kind", i)
		}
		ids = append(ids, [3]string{"destination id", d.ID, "1"})
	}
	for _, id := range ids {
		if err := identifier(id[0], id[1], id[2] != ""); err != nil {
			return err
		}
	}
	return nil
}

// identifier accepts printable ASCII without spaces (HR-102): confusable,
// non-ASCII and bidi characters are refused, never normalized.
func identifier(name, v string, required bool) error {
	if v == "" {
		if required {
			return bad("%s is required", name)
		}
		return nil
	}
	if len(v) > maxIdentifierLen {
		return bad("%s is too long", name)
	}
	for i := range len(v) {
		if v[i] < 0x21 || v[i] > 0x7e {
			return bad("%s is not printable ASCII", name)
		}
	}
	return nil
}
