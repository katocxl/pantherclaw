// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package cohorts_test

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"testing"

	"github.com/katocxl/pantherclaw/internal/cohorts"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR291_RuleIdsAreStoredAsBase64 (D120 G2) pins the stored form of a
// cohort rule's ids that AgentBaselineCohorts decodes in SQL
// (encode(decode(rule->>'<field>', 'base64'), 'hex')::uuid): each id field
// is the base64 of the UUID's 16 bytes. A change of ids.UUID's JSON form
// fails here before it silently stops rule matches.
func TestHR291_RuleIdsAreStoredAsBase64(t *testing.T) {
	team, env := ids.NewV7(), ids.NewV7()
	raw, err := json.Marshal(cohorts.Rule{TeamID: &team, EnvironmentID: &env}, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	var stored map[string]string
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatalf("rule %s: %v", raw, err)
	}
	for field, want := range map[string]ids.UUID{"team_id": team, "environment_id": env} {
		b, err := base64.StdEncoding.DecodeString(stored[field])
		if err != nil {
			t.Fatalf("%s %q is not base64: %v", field, stored[field], err)
		}
		h := hex.EncodeToString(b) // what Postgres casts to uuid
		if len(h) != 32 {
			t.Fatalf("%s %q is %d bytes, want 16", field, stored[field], len(b))
		}
		got, err := ids.ParseUUID(h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:])
		if err != nil || got != want {
			t.Fatalf("%s %q decodes to %s (%v), want %s", field, stored[field], got, err, want)
		}
	}
}
