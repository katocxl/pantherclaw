// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mapset

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"flag"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/detection/rules"
	hubdomain "github.com/katocxl/pantherclaw/internal/hub/domain"
	"github.com/katocxl/pantherclaw/internal/hub/seed"
	rtdomain "github.com/katocxl/pantherclaw/internal/redteam/domain"
)

var update = flag.Bool("update", false, "rewrite hub.json from hub/items")

// ruleTrigger finds the rule ids an automation's event filter names
// (`event.attrs["rule"] in [...]` or `== "..."`).
var (
	ruleTrigger = regexp.MustCompile(`event\.attrs\["rule"\]\s*(?:in\s*\[[^\]]*\]|==\s*"[^"]*")`)
	ruleID      = regexp.MustCompile(`"((?:pc|org)\.[a-z0-9_.-]+)"`)
)

// hubTable reads the Hub source tree into the golden table (G0 M28 D714b).
func hubTable(t *testing.T) HubTable {
	t.Helper()
	items, err := seed.Load(os.DirFS("../../../hub"))
	if err != nil {
		t.Fatal(err)
	}
	table := HubTable{Rules: []HubRule{}, Playbooks: []HubPlaybook{}}
	for _, it := range items {
		switch it.Entry.Kind {
		case hubdomain.KindDetectionRule:
			var body struct {
				Content string `json:"content"`
			}
			if err := json.Unmarshal(it.Item.Body, &body); err != nil {
				t.Fatalf("%s: %v", it.Dir, err)
			}
			r, err := rules.Parse([]byte(body.Content))
			if err != nil {
				t.Fatalf("%s: %v", it.Dir, err)
			}
			table.Rules = append(table.Rules, HubRule{ID: r.ID, Item: it.Entry.Name, ATLAS: r.ATLAS, ATTACK: r.ATTACK})
		case hubdomain.KindAutomation:
			var body struct {
				Definition string `json:"definition"`
			}
			if err := json.Unmarshal(it.Item.Body, &body); err != nil {
				t.Fatalf("%s: %v", it.Dir, err)
			}
			if _, err := rtdomain.ToJSON([]byte(body.Definition)); err != nil {
				t.Fatalf("%s: %v", it.Dir, err)
			}
			var ids []string
			for _, filter := range ruleTrigger.FindAllString(body.Definition, -1) {
				for _, m := range ruleID.FindAllStringSubmatch(filter, -1) {
					ids = append(ids, m[1])
				}
			}
			if len(ids) == 0 {
				continue
			}
			slices.Sort(ids)
			table.Playbooks = append(table.Playbooks, HubPlaybook{Name: it.Entry.Name, Rules: slices.Compact(ids)})
		case hubdomain.KindPolicyTemplate, hubdomain.KindRangeScenario, hubdomain.KindToolPackage:
			// Name no technique (D714b: rules and playbooks only).
		}
	}
	slices.SortFunc(table.Rules, func(a, b HubRule) int { return strings.Compare(a.ID, b.ID) })
	return table
}

// TestHR683_HubTableIsCurrent: hub.json is what hub/items says, so the
// threat map's Hub rules and playbooks follow the Hub (G0 M28 D714b, D715
// #5). Run with -update after changing a Hub item.
// Covers: F974, HR-683
func TestHR683_HubTableIsCurrent(t *testing.T) {
	raw, err := json.Marshal(hubTable(t), json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	v := jsontext.Value(raw)
	if err := v.Indent(jsontext.WithIndent("  ")); err != nil {
		t.Fatal(err)
	}
	want := append([]byte(v), '\n')
	if *update {
		if err := os.WriteFile("hub.json", want, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	if !bytes.Equal(hubRaw, want) {
		t.Fatal("hub.json is stale: go test ./internal/threatmap/mapset -run TestHR683_HubTableIsCurrent -update")
	}
	// Every playbook in the table is a Hub automation item (D715 #5).
	items, err := seed.Load(os.DirFS("../../../hub"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range hubTable(t).Playbooks {
		if !slices.ContainsFunc(items, func(it seed.Item) bool {
			return it.Entry.Name == p.Name && it.Entry.Kind == hubdomain.KindAutomation && strings.HasPrefix(it.Dir, "items/automation/")
		}) {
			t.Errorf("playbook %s is not under hub/items/automation", p.Name)
		}
	}
}
