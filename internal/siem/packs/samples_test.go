// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package packs_test

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"flag"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	"github.com/katocxl/pantherclaw/internal/reflex/feed"
	"github.com/katocxl/pantherclaw/internal/siem/ocsf"
)

var update = flag.Bool("update", false, "rewrite the golden OCSF samples")

// packRoot is integrations/siem from this package.
const packRoot = "../../../integrations/siem"

// sampleEvents are the feed events behind the golden samples, by file name:
// one each that a rule must fire on, and the near misses it must not.
func sampleEvents() map[string]feed.Event {
	alert := func(severity, state string, test bool, more ...string) feed.Event {
		e := base("reflex.alert")
		e.Outcome, e.Test = state, test
		e.Subjects = []reflexdomain.Subject{{Type: reflexdomain.SubjectRun, ID: "0192f944-0000-7000-8000-0000000000c1"}}
		e.Attrs = map[string]string{
			ocsf.AttrID: "0192f944-0000-7000-8000-0000000000d1", ocsf.AttrRuleID: "pc.authority.self_issue", ocsf.AttrSeverity: severity,
			"attention": "ALERT",
		}
		for i := 0; i+1 < len(more); i += 2 {
			e.Attrs[more[i]] = more[i+1]
		}
		return e
	}
	incident := func(state string) feed.Event {
		e := base("reflex.incident")
		e.Outcome = state
		e.Attrs = map[string]string{ocsf.AttrID: "0192f944-0000-7000-8000-0000000000d2", ocsf.AttrSeverity: "HIGH"}
		return e
	}
	decision := func(verdict, reason string) feed.Event {
		e := base("receipt.decision")
		e.Decision, e.Reason, e.Operation, e.Mode, e.Environment = verdict, reason, "github.pulls.merge", "ENFORCED", "production"
		e.Attrs = map[string]string{ocsf.AttrPolicyVersion: "12"}
		return e
	}
	audit := func(kind, outcome string) feed.Event {
		e := base(kind)
		e.ActorType, e.ActorID, e.Outcome = "user", "0192f944-0000-7000-8000-0000000000b2", outcome
		return e
	}
	invalidated := base("coverage.invalidation")
	invalidated.Reason = "gateway_changed"
	invalidated.Attrs = map[string]string{"invalidation": "0192f944-0000-7000-8000-0000000000e1", "kind": "gateway_changed"}
	snapshot := base("coverage.snapshot")
	snapshot.Attrs = map[string]string{"state": "ENFORCED", ocsf.AttrCoverage: "ENFORCED"}
	return map[string]feed.Event{
		"alert-critical":                 alert("CRITICAL", "OPEN", false, ocsf.AttrBasis, "OBSERVED"),
		"alert-high-inferred":            alert("HIGH", "OPEN", false, ocsf.AttrBasis, "INFERRED"),
		"alert-high-simulated":           alert("HIGH", "OPEN", true, ocsf.AttrBasis, "OBSERVED"),
		"alert-high-resolved":            alert("HIGH", "RESOLVED", false, ocsf.AttrBasis, "OBSERVED"),
		"alert-low":                      alert("LOW", "OPEN", false, ocsf.AttrBasis, "OBSERVED"),
		"incident-open":                  incident("OPEN"),
		"incident-closed":                incident("CLOSED"),
		"decision-deny":                  decision("DENY", "NO_GRANT"),
		"decision-allow":                 decision("ALLOW", ""),
		"coverage-invalidation":          invalidated,
		"coverage-snapshot":              snapshot,
		"response-contain":               audit("audit.response.contain", "SUCCESS"),
		"kill-switch-engaged":            audit("audit.security.kill_switch_engaged", "SUCCESS"),
		"kill-switch-restored":           audit("audit.security.kill_switch_restored", "SUCCESS"),
		"siem-destination-state-changed": audit("audit.siem.destination_state_changed", "SUCCESS"),
		"siem-destination-retried":       audit("audit.siem.destination_retried", "SUCCESS"),
		"agent-discovered":               audit("audit.agent.discovered", "SUCCESS"),
	}
}

func base(kind string) feed.Event {
	id, err := ids.ParseUUID("0192f944-0000-7000-8000-0000000000a1")
	if err != nil {
		panic(err)
	}
	return feed.Event{
		Seq: 1042, ID: id, Org: ids.MustParse[ids.Org]("0192f944-0000-7000-8000-0000000000aa"),
		Kind: kind, OccurredAt: time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC),
		ActorType: "agent", ActorID: "0192f944-0000-7000-8000-0000000000b1",
	}
}

// TestSamples_AreWhatTheExporterWrites: a sample is byte for byte the mapper's
// output, so a change to the OCSF mapping that a pack depends on fails here
// rather than in a customer's SIEM. `-update` rewrites the files.
//
// Covers: F945
func TestSamples_AreWhatTheExporterWrites(t *testing.T) {
	events := sampleEvents()
	for _, name := range slices.Sorted(maps.Keys(events)) {
		enc, err := ocsf.Encode(ocsf.Map(events[name], "1.0.0"))
		if err != nil {
			t.Fatal(err)
		}
		enc = append(enc, '\n')
		file := filepath.Join(packRoot, "samples", name+".json")
		if *update {
			if err := os.WriteFile(file, enc, 0o644); err != nil { //nolint:gosec // a sample is a public repository file
				t.Fatal(err)
			}
			continue
		}
		got, err := os.ReadFile(file) //nolint:gosec // a fixed path in the repository
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(bytes.ReplaceAll(got, []byte("\r\n"), []byte("\n")), enc) {
			t.Errorf("%s differs from the mapper's output:\n got %s\nwant %s", name, got, enc)
		}
	}
	files, err := filepath.Glob(filepath.Join(packRoot, "samples", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != len(events) {
		t.Errorf("%d sample files for %d events", len(files), len(events))
	}
	// The batch: every sample, in name order, in the body the exporter posts.
	var b ocsf.Builder
	for _, name := range slices.Sorted(maps.Keys(events)) {
		enc, err := ocsf.Encode(ocsf.Map(events[name], "1.0.0"))
		if err != nil {
			t.Fatal(err)
		}
		if ok, err := b.Add(enc); !ok || err != nil {
			t.Fatalf("batch: %v %v", ok, err)
		}
	}
	body, err := b.Body(batchID, 1026, 1042)
	if err != nil {
		t.Fatal(err)
	}
	body = append(body, '\n')
	if *update {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(packRoot, batchFile)), 0o755); err != nil { //nolint:gosec // a public repository directory
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(packRoot, batchFile), body, 0o644); err != nil { //nolint:gosec // a sample is a public repository file
			t.Fatal(err)
		}
		return
	}
	if got := read(t, batchFile); !bytes.Equal(got, body) {
		t.Errorf("%s differs from the exporter's batch:\n got %s\nwant %s", batchFile, got, body)
	}
}

// batchFile holds every sample in one export batch, as the exporter posts it.
const (
	batchFile = "samples/batch/batch.json"
	batchID   = "0192f944-0000-7000-8000-0000000000f1"
)

// sampleOrder is the sample names in the batch's order.
func sampleOrder() []string { return slices.Sorted(maps.Keys(sampleEvents())) }

// sampleBytes is one sample's line, without its newline.
func sampleBytes(t *testing.T, name string) []byte {
	t.Helper()
	return bytes.TrimSuffix(read(t, "samples/"+name+".json"), []byte("\n"))
}

// batchEvents is the golden batch's data.events, each as raw JSON.
func batchEvents(t *testing.T) []jsontext.Value {
	t.Helper()
	var doc struct {
		Type string `json:"type"`
		Data struct {
			Events []jsontext.Value `json:"events"`
		} `json:"data"`
	}
	if err := json.Unmarshal(read(t, batchFile), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Type != ocsf.BatchType {
		t.Fatalf("batch type %q", doc.Type)
	}
	return doc.Data.Events
}

// TestSamples_TheBatchHoldsEverySample: the golden batch's events are the
// samples, byte for byte and in name order, so a split that yields them
// yields what the rules were tested on.
//
// Covers: F945
func TestSamples_TheBatchHoldsEverySample(t *testing.T) {
	evs, names := batchEvents(t), sampleOrder()
	if len(evs) != len(names) {
		t.Fatalf("%d events in the batch, %d samples", len(evs), len(names))
	}
	for i, name := range names {
		if !bytes.Equal(evs[i], sampleBytes(t, name)) {
			t.Errorf("batch event %d is not %s", i, name)
		}
	}
}

// fields is a sample flattened to dotted paths; an array's values share its
// path.
type fields map[string][]string

func (f fields) any(path string, ok func(string) bool) bool {
	return slices.ContainsFunc(f[path], ok)
}

func flatten(prefix string, v any, out fields) {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			flatten(p, e, out)
		}
	case []any:
		for _, e := range x {
			flatten(prefix, e, out)
		}
	case string:
		out[prefix] = append(out[prefix], x)
	case float64:
		out[prefix] = append(out[prefix], strconv.FormatFloat(x, 'f', -1, 64))
	case bool:
		out[prefix] = append(out[prefix], strconv.FormatBool(x))
	}
}

// samples reads the golden samples, by name.
func samples(t *testing.T) map[string]fields {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(packRoot, "samples", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no samples")
	}
	out := map[string]fields{}
	for _, file := range files {
		raw, err := os.ReadFile(file) //nolint:gosec // a fixed path in the repository
		if err != nil {
			t.Fatal(err)
		}
		var doc any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		f := fields{}
		flatten("", doc, f)
		out[strings.TrimSuffix(filepath.Base(file), ".json")] = f
	}
	return out
}
