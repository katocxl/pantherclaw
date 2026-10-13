// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

package pap

import (
	"bytes"
	"encoding/base64"
	"encoding/json/jsontext"
	"fmt"
)

// Canonical returns the RFC 8785 (JCS) form of one JSON value. Duplicate
// member names, invalid UTF-8 and lone surrogates are refused, numbers are
// written as ECMAScript does and members are sorted by UTF-16 code units.
func Canonical(raw []byte) ([]byte, error) {
	v := jsontext.Value(bytes.Clone(raw))
	if err := v.Canonicalize(); err != nil {
		return nil, fmt.Errorf("pap: canonical JSON: %w", err)
	}
	return v, nil
}

// ActionHash returns the action hash of ActionIR JSON (PAP/1 §6),
// lowercase hex SHA-256 of its canonical form, after checking the action
// (ParseAction).
func ActionHash(action []byte) (string, error) {
	p, err := ParseAction(action)
	return p.Hash, err
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
