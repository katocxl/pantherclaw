// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"crypto/sha256"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"maps"
	"slices"
	"strings"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
)

// ContentDigest is SHA-256 of the JCS form (RFC 8785, ADR-0011) of the
// bundle's {"id", "rules", "tests"}: what a validation or test run was
// computed over (M11.1 D1, D2). The version number is left out, so the same
// content keeps its digest when it is stored as a new version.
func ContentDigest(b *Bundle) [32]byte {
	tests := b.Tests
	if tests == nil {
		tests = []TestCase{}
	}
	return jcsDigest(struct {
		ID    string     `json:"id"`
		Rules []Rule     `json:"rules"`
		Tests []TestCase `json:"tests"`
	}{b.ID, b.Rules, tests})
}

// RuleDigest is SHA-256 of the rule's JCS form; an exception names the rule
// it waives by it (M11.1 D14).
func RuleDigest(r Rule) [32]byte { return jcsDigest(r) }

// jcsDigest hashes v's canonical JSON. Bundles hold only strings, numbers,
// booleans and decoded JSON values, so marshaling cannot fail for a value
// that decoded; a failure would be a programming error.
func jcsDigest(v any) [32]byte {
	raw, err := json.Marshal(v, json.Deterministic(true))
	if err != nil {
		panic("policy: digest: " + err.Error())
	}
	val := jsontext.Value(raw)
	if err := val.Canonicalize(); err != nil {
		panic("policy: digest: " + err.Error())
	}
	return sha256.Sum256(val)
}

// DefinitionsDigest is SHA-256 over the sorted digests of the active
// definitions, one per line: a validation or test run is current only while
// the definitions it read are (M11.1 D7a, D11).
func DefinitionsDigest(ds []*defs.Definition) [32]byte {
	digests := make([]string, 0, len(ds))
	for _, d := range ds {
		digests = append(digests, d.Digest)
	}
	slices.Sort(digests)
	var sb strings.Builder
	for _, d := range digests {
		sb.WriteString(d)
		sb.WriteByte('\n')
	}
	return sha256.Sum256([]byte(sb.String()))
}

// CatalogDigest is SHA-256 over the fact catalog's sorted "name=type;"
// pairs (M11.1 D7a).
func CatalogDigest(catalog map[string]fdomain.Type) [32]byte {
	var sb strings.Builder
	for _, name := range slices.Sorted(maps.Keys(catalog)) {
		sb.WriteString(name)
		sb.WriteByte('=')
		sb.WriteString(string(catalog[name]))
		sb.WriteByte(';')
	}
	return sha256.Sum256([]byte(sb.String()))
}
