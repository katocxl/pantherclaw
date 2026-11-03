// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package feed_test

import (
	"encoding/json/v2"
	"fmt"
	"strings"
	"testing"

	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	"github.com/katocxl/pantherclaw/internal/reflex/feed"
)

// TestHR684_ReflexEntriesCarryTechniques: alert and incident entries pass
// their ATLAS and ATT&CK techniques and OWASP risks on as sorted,
// de-duplicated, comma-joined attributes (G0 M28 D718). Covers: F964, HR-684
func TestHR684_ReflexEntriesCarryTechniques(t *testing.T) {
	for _, kind := range []string{reflexdomain.KindAlert, reflexdomain.KindIncident} {
		body := `{"id":"a1","severity":"HIGH","attention":"ALERT","basis":"RULE_MATCH","subjects":[],` +
			`"atlas":["AML.T0051","AML.T0024","AML.T0051"],"attack":["T1552.001","T1078"],"owasp":["ASI03","ASI01"]}`
		e, err := feed.Normalize(kind, "system", "reflex", at, []byte(body))
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]string{"atlas": "AML.T0024,AML.T0051", "attack": "T1078,T1552.001", "owasp": "ASI01,ASI03"}
		for k, v := range want {
			if e.Attrs[k] != v {
				t.Errorf("%s: attr %s = %q, want %q", kind, k, e.Attrs[k], v)
			}
		}
	}
}

// TestHR684_LongTechniqueListIsCutNotDropped: an incident's union of up to
// 64 ids does not fit one attribute; the feed keeps the smallest ids that
// fit instead of losing the attribute (G0 M28 D718). Covers: HR-684
func TestHR684_LongTechniqueListIsCutNotDropped(t *testing.T) {
	ids := make([]string, 0, 64)
	for i := range 64 {
		ids = append(ids, fmt.Sprintf("AML.T%04d.000", 63-i))
	}
	raw, err := json.Marshal(map[string]any{"id": "i1", "subjects": []any{}, "atlas": ids})
	if err != nil {
		t.Fatal(err)
	}
	e, err := feed.Normalize(reflexdomain.KindIncident, "system", "reflex", at, raw)
	if err != nil {
		t.Fatal(err)
	}
	got := e.Attrs["atlas"]
	if got == "" || len(got) > feed.MaxAttrValue {
		t.Fatalf("atlas attr %d bytes: %q", len(got), got)
	}
	parts := strings.Split(got, ",")
	if parts[0] != "AML.T0000.000" {
		t.Errorf("first id %q, want the smallest", parts[0])
	}
	for _, p := range parts {
		if len(p) != len("AML.T0000.000") {
			t.Errorf("an id was cut: %q", p)
		}
	}
}
