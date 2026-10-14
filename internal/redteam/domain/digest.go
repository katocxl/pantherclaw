// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"sort"
	"strings"
)

// Digest returns 64 lowercase hex, no prefix, of the RFC 8785 canonical JSON of the parsed
// scenario, so spelling and defaults in the YAML do not change it.
func Digest(s *Scenario) (string, error) {
	raw, err := json.Marshal(s)
	if err != nil {
		return "", invalid("%v", err)
	}
	v := jsontext.Value(raw)
	if err := v.Canonicalize(); err != nil {
		return "", invalid("%v", err)
	}
	sum := sha256.Sum256(v)
	return hex.EncodeToString(sum[:]), nil
}

// SetDigest returns 64 lowercase hex, no prefix, over the sorted "id:digest" lines of a
// scenario set (id to scenario digest).
func SetDigest(digests map[string]string) string {
	ids := make([]string, 0, len(digests))
	for id := range digests {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var b strings.Builder
	for _, id := range ids {
		fmt.Fprintf(&b, "%s:%s\n", id, digests[id])
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}
