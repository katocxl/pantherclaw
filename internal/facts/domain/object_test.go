// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"encoding/json/jsontext"
	"errors"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestObjectFacts: an object fact keeps its members (strings, integers,
// booleans, lists and objects) and round-trips byte for byte; floats,
// nulls, depth and size beyond the limits are refused (HR-160).
func TestObjectFacts(t *testing.T) {
	raw := jsontext.Value(`{"object":{"sha":"abc","draft":false,"changed_files":3,"people":{"authors":[1,2]},"unknown":"why"}}`)
	v, err := DecodeValue(TypeObject, raw)
	if err != nil {
		t.Fatal(err)
	}
	if v.Object["sha"] != "abc" || v.Object["changed_files"] != int64(3) || v.Object["draft"] != false {
		t.Fatalf("members %v", v.Object)
	}
	enc, err := EncodeValue(v)
	if err != nil {
		t.Fatal(err)
	}
	again, err := DecodeValue(TypeObject, enc)
	if err != nil || again.String() != v.String() || !strings.Contains(v.String(), `"unknown":"why"`) {
		t.Fatalf("round trip: %s %v", enc, err)
	}
	for name, raw := range map[string]string{
		"a float":         `{"object":{"a":1.5}}`,
		"a null":          `{"object":{"a":null}}`,
		"not an object":   `{"object":[1]}`,
		"too deep":        `{"object":{"a":{"b":{"c":{"d":{"e":1}}}}}}`,
		"another field":   `{"object":{"a":1},"bool":true}`,
		"too large":       `{"object":{"a":"` + strings.Repeat("x", maxObjectBytes) + `"}}`,
		"an empty object": `{"object":{}}`,
	} {
		if _, err := DecodeValue(TypeObject, jsontext.Value(raw)); !errors.Is(err, ErrInvalid) && name != "an empty object" {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A scalar fact keeps the 1 KiB limit.
	if _, err := DecodeValue(TypeIdentifier, jsontext.Value(`{"id":"`+strings.Repeat("a", 2000)+`"}`)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a long identifier: %v", err)
	}
}

// TestProviderSources: a provider is bound to exactly one of a service
// account or a gateway and one of its connections.
func TestProviderSources(t *testing.T) {
	base := Provider{
		ID: ids.NewV7(), Org: ids.New[ids.Org](), Name: "github", State: ProviderActive,
		Facts: []Declaration{{Name: "github.pull.head", Type: TypeObject, SubjectType: "github.pull_request", MaxLag: 30e9}},
	}
	sa, gw, conn := ids.NewV7(), ids.NewV7(), ids.NewV7()
	for name, c := range map[string]struct {
		sa, gw, conn ids.UUID
		ok           bool
	}{
		"service account":            {sa: sa, ok: true},
		"gateway and connection":     {gw: gw, conn: conn, ok: true},
		"neither":                    {},
		"both":                       {sa: sa, gw: gw, conn: conn},
		"gateway without connection": {gw: gw},
		"connection without gateway": {conn: conn},
	} {
		p := base
		p.ServiceAccountID, p.GatewayID, p.ConnectionID = c.sa, c.gw, c.conn
		if err := p.Validate(nil); (err == nil) != c.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
}
