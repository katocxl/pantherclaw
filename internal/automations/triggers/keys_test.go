// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package triggers

import (
	"slices"
	"strings"
	"testing"
	"time"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

func defWithKey(key string, window time.Duration) *autodomain.Definition {
	d := &autodomain.Definition{}
	if key != "" {
		d.When.Dedupe = &autodomain.Dedupe{Key: key, Window: autodomain.Duration(window)}
	}
	return d
}

func str(s string) autodomain.Value { return autodomain.Value{Type: autodomain.ParamString, String: s} }

// TestT122_DedupeKeyIsTheDeclaredParameterKey: the declared key depends
// only on the automation and the named typed parameters, so a replay with
// the same ticket is a duplicate and another ticket is not (HR-277).
func TestT122_DedupeKeyIsTheDeclaredParameterKey(t *testing.T) {
	t.Parallel()
	a := ids.NewV7()
	def := defWithKey("ticket-{{params.ticket}}", 24*time.Hour)
	ref := func(p map[string]autodomain.Value) autodomain.TriggerRef {
		return autodomain.TriggerRef{ID: ids.NewV7(), Automation: a, Params: p, OccurredAt: time.Now()}
	}
	k1 := DedupeKey(def, ref(map[string]autodomain.Value{"ticket": str("T-1"), "note": str("x")}))
	k2 := DedupeKey(def, ref(map[string]autodomain.Value{"ticket": str("T-1"), "note": str("y")}))
	k3 := DedupeKey(def, ref(map[string]autodomain.Value{"ticket": str("T-2")}))
	k4 := DedupeKey(def, ref(map[string]autodomain.Value{}))
	k5 := DedupeKey(def, ref(map[string]autodomain.Value{"ticket": str("")}))
	if k1 == "" || k1 != k2 {
		t.Fatalf("same declared parameter, different keys: %q %q", k1, k2)
	}
	if k1 == k3 || k4 == k5 || k4 == k1 {
		t.Fatalf("different parameters collide: %q %q %q %q", k1, k3, k4, k5)
	}
	// Another automation never shares a key.
	other := autodomain.TriggerRef{Automation: ids.NewV7(), Params: map[string]autodomain.Value{"ticket": str("T-1")}}
	if DedupeKey(def, other) == k1 {
		t.Fatal("keys are per automation")
	}
	// Types are part of the key: the string "1" is not the int 1.
	ki := DedupeKey(def, ref(map[string]autodomain.Value{"ticket": {Type: autodomain.ParamInt, Int: 1}}))
	ks := DedupeKey(def, ref(map[string]autodomain.Value{"ticket": str("1")}))
	if ki == ks {
		t.Fatal("typed values collide")
	}
	// No declaration, no key.
	if got := DedupeKey(defWithKey("", 0), ref(nil)); got != "" {
		t.Fatalf("undeclared key: %q", got)
	}
	if got := DedupeKey(nil, ref(nil)); got != "" {
		t.Fatalf("nil definition: %q", got)
	}
	// Values that look like template syntax are data.
	kx := DedupeKey(def, ref(map[string]autodomain.Value{"ticket": str("{{params.note}}")}))
	if kx == k1 || !strings.HasPrefix(kx, "key:"+a.String()+":") {
		t.Fatalf("template injection: %q", kx)
	}
	if DedupeWindow(defWithKey("k", 90*24*time.Hour)) != MaxDedupeWindow {
		t.Fatal("window not capped at 30 days")
	}
}

func TestT122_BaseKeys(t *testing.T) {
	t.Parallel()
	a, src, exec := ids.NewV7(), ids.NewV7(), ids.NewV7()
	at := time.Date(2027, 3, 28, 1, 0, 0, 0, time.UTC)
	keys := []string{
		ScheduleKey(a, at), ScheduleKey(a, at.Add(time.Minute)), EventKey(src),
		InboundKey(src, "msg_1"), InboundKey(src, "msg_2"), ManualKey("k"), RetryKey(exec, "k"),
		ThresholdKey(a, "agent:x", at), ConditionKey(a, "grant:x", at),
	}
	for i, k := range keys {
		if len(k) > 512 || slices.Contains(keys[i+1:], k) {
			t.Fatalf("key %d %q is too long or not unique", i, k)
		}
	}
	// The same occurrence in another zone's reading is the same key.
	lon, _ := time.LoadLocation("Europe/London")
	if ScheduleKey(a, at) != ScheduleKey(a, at.In(lon)) {
		t.Fatal("schedule key depends on the zone")
	}
	if InboundKey(src, strings.Repeat("x", 256)) == "" {
		t.Fatal("long webhook id")
	}
}

// TestT123_LineageRefusesLoopsAndDepth: an automation upstream of itself,
// or a chain of depth 4, is refused (HR-278).
func TestT123_LineageRefusesLoopsAndDepth(t *testing.T) {
	t.Parallel()
	a, b, c := ids.NewV7(), ids.NewV7(), ids.NewV7()
	root := ids.NewV7()
	p := Parent{Trigger: root, Automation: a}
	l1 := p.Child()
	if l1.Depth != 1 || l1.Root != root || !slices.Equal(l1.Ancestry, []ids.UUID{a}) {
		t.Fatalf("child: %+v", l1)
	}
	if !l1.Loop(a) || l1.Loop(b) {
		t.Fatal("A → A must loop, A → B must not")
	}
	l2 := Parent{Trigger: ids.NewV7(), Automation: b, Root: l1.Root, Ancestry: l1.Ancestry, Depth: l1.Depth}.Child()
	if !l2.Loop(a) || !l2.Loop(b) || l2.Loop(c) || l2.Root != root {
		t.Fatalf("A → B → A must loop: %+v", l2)
	}
	l3 := Parent{Trigger: ids.NewV7(), Automation: c, Root: root, Ancestry: l2.Ancestry, Depth: l2.Depth}.Child()
	d := ids.NewV7()
	if l3.Depth != 3 || l3.Loop(d) {
		t.Fatalf("depth 3 is allowed: %+v", l3)
	}
	l4 := Parent{Trigger: ids.NewV7(), Automation: d, Root: root, Ancestry: l3.Ancestry, Depth: l3.Depth}.Child()
	if !l4.Loop(ids.NewV7()) {
		t.Fatalf("depth 4 is refused: %+v", l4)
	}
	// Union (thresholds, D58): the ancestries merge, the depth is the
	// greatest and untriggered events add nothing.
	u := Union(Lineage{}, l1, l2, Lineage{Root: ids.NewV7(), Ancestry: []ids.UUID{c}, Depth: 1})
	if u.Depth != 2 || u.Root != root || !slices.Equal(u.Ancestry, []ids.UUID{a, b, c}) {
		t.Fatalf("union: %+v", u)
	}
	if !u.Contains(b) || u.Contains(d) {
		t.Fatal("contains")
	}
	if z := Union(Lineage{}, Lineage{}); z.Depth != 0 || len(z.Ancestry) != 0 {
		t.Fatalf("union of nothing: %+v", z)
	}
}
