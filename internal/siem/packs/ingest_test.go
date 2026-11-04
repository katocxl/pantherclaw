// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package packs_test

import (
	"bytes"
	"encoding/json/v2"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/siem/ocsf"
)

// The Ingest configs: each splits the export's batch into the events the
// rules read, or, where the SIEM can't split, takes one event per record.
// None verifies the webhook signature; each README says so.

// recordKeys are the top-level keys an OCSF event can have.
func recordKeys(t *testing.T) []string {
	t.Helper()
	var out []string
	rt := reflect.TypeFor[ocsf.Record]()
	for i := range rt.NumField() {
		name, _, _ := strings.Cut(rt.Field(i).Tag.Get("json"), ",")
		if name == "" || name == "-" {
			t.Fatalf("field %s has no JSON name", rt.Field(i).Name)
		}
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

func jsonValue(t *testing.T, raw []byte) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// TestIngest_SplunkSplitsTheBatchIntoTheSamples applies the batch
// sourcetype's LINE_BREAKER, SEDCMD and index-time transforms, as Splunk
// documents them, to the golden batch: what is left is the samples, byte for
// byte, each filed as pantherclaw:ocsf with its time read from `time`.
//
// Covers: F944
func TestIngest_SplunkSplitsTheBatchIntoTheSamples(t *testing.T) {
	props := conf(t, read(t, "splunk/pantherclaw_ocsf/default/props.conf"))["pantherclaw:ocsf:batch"]
	transforms := conf(t, read(t, "splunk/pantherclaw_ocsf/default/transforms.conf"))
	if props == nil {
		t.Fatal("no pantherclaw:ocsf:batch sourcetype")
	}
	// LINE_BREAKER: the first capturing group is dropped; the previous event
	// ends at its start and the next begins at its end.
	breaker := regexp.MustCompile(props["LINE_BREAKER"])
	body := bytes.TrimSuffix(read(t, batchFile), []byte("\n"))
	var chunks [][]byte
	start := 0
	for _, m := range breaker.FindAllSubmatchIndex(body, -1) {
		chunks = append(chunks, body[start:m[2]])
		start = m[3]
	}
	chunks = append(chunks, body[start:])
	// SEDCMD: s/regex/replacement/.
	sed := strings.Split(props["SEDCMD-pantherclaw_batch_end"], "/")
	if len(sed) != 4 || sed[0] != "s" {
		t.Fatalf("SEDCMD %q", sed)
	}
	sedRe := regexp.MustCompile(sed[1])
	// TRANSFORMS: drop the envelope, file the rest as pantherclaw:ocsf.
	names := strings.Split(props["TRANSFORMS-pantherclaw_batch"], ", ")
	if len(names) != 2 {
		t.Fatalf("transforms %q", names)
	}
	drop, file := transforms[names[0]], transforms[names[1]]
	if drop["DEST_KEY"] != "queue" || drop["FORMAT"] != "nullQueue" ||
		file["DEST_KEY"] != "MetaData:Sourcetype" || file["FORMAT"] != "sourcetype::pantherclaw:ocsf" {
		t.Fatalf("transforms %v %v", drop, file)
	}
	dropRe, fileRe := regexp.MustCompile(drop["REGEX"]), regexp.MustCompile(file["REGEX"])
	timeRe := regexp.MustCompile(regexp.QuoteMeta(props["TIME_PREFIX"]) + `([0-9]{13})`)
	var events [][]byte
	for _, c := range chunks {
		c = sedRe.ReplaceAll(c, []byte(sed[2]))
		if dropRe.Match(c) {
			continue
		}
		if !fileRe.Match(c) {
			t.Fatalf("an event is neither dropped nor filed: %s", c)
		}
		events = append(events, c)
	}
	names = sampleOrder()
	if len(events) != len(names) {
		t.Fatalf("%d events from the batch, want %d", len(events), len(names))
	}
	for i, name := range names {
		if !bytes.Equal(events[i], sampleBytes(t, name)) {
			t.Errorf("event %d:\n got %s\nwant %s", i, events[i], sampleBytes(t, name))
		}
		var ev struct {
			Time int64 `json:"time"`
		}
		if err := json.Unmarshal(events[i], &ev); err != nil {
			t.Fatal(err)
		}
		if m := timeRe.FindSubmatch(events[i]); m == nil || string(m[1]) != jsonInt(ev.Time) {
			t.Errorf("%s: TIME_PREFIX does not find the event's time", name)
		}
	}
}

func jsonInt(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

var (
	lsSplit  = regexp.MustCompile(`(?m)^\s*split \{\s*field => "\[data\]\[events\]"\s*\}`)
	lsGuard  = regexp.MustCompile(`(?m)^\s*if \[type\] != "pantherclaw\.ocsf\.batch" \{\s*drop \{\}\s*\}`)
	lsRename = regexp.MustCompile(`(?m)^\s*"\[data\]\[events\]\[([a-z_]+)\]" => "\[([a-z_]+)\]"$`)
	lsRemove = regexp.MustCompile(`(?m)^\s*remove_field => \[(.*)\]$`)
)

// TestIngest_ElasticLogstashSplitsTheBatchIntoTheSamples reads the Logstash
// pipeline's split, renames and removals and applies them to the golden
// batch: each document is a sample, with every top-level OCSF key moved to
// the root.
//
// Covers: F944
func TestIngest_ElasticLogstashSplitsTheBatchIntoTheSamples(t *testing.T) {
	cfg := string(read(t, "elastic/logstash/pantherclaw-batch.conf"))
	if !lsGuard.MatchString(cfg) || !lsSplit.MatchString(cfg) {
		t.Fatal("the pipeline does not drop non-batches and split data.events")
	}
	rename := map[string]string{}
	for _, m := range lsRename.FindAllStringSubmatch(cfg, -1) {
		rename[m[1]] = m[2]
	}
	keys := slices.Sorted(func(yield func(string) bool) {
		for k, v := range rename {
			if k != v {
				t.Errorf("%s is renamed to %s", k, v)
			}
			if !yield(k) {
				return
			}
		}
	})
	if want := recordKeys(t); !slices.Equal(keys, want) {
		t.Fatalf("renamed %v, want every OCSF key %v", keys, want)
	}
	rm := lsRemove.FindStringSubmatch(cfg)
	if rm == nil {
		t.Fatal("no remove_field")
	}
	removed := unquoteAll(rm[1], ",")
	for _, k := range removed {
		if slices.Contains(keys, strings.Trim(k, "[]")) {
			t.Errorf("remove_field drops the OCSF key %s", k)
		}
	}
	batch := jsonValue(t, read(t, batchFile)).(map[string]any)
	data := batch["data"].(map[string]any)
	names := sampleOrder()
	evs := data["events"].([]any)
	if len(evs) != len(names) {
		t.Fatalf("%d events, want %d", len(evs), len(names))
	}
	for i, ev := range evs {
		// split: a copy of the document per element, holding that element.
		doc := map[string]any{"type": batch["type"], "data": map[string]any{"batch": data["batch"], "events": ev}}
		for k, to := range rename {
			if v, ok := doc["data"].(map[string]any)["events"].(map[string]any)[k]; ok {
				doc[to] = v
				delete(doc["data"].(map[string]any)["events"].(map[string]any), k)
			}
		}
		for _, k := range removed {
			delete(doc, strings.Trim(k, "[]"))
		}
		if want := jsonValue(t, sampleBytes(t, names[i])); !reflect.DeepEqual(doc, want) {
			t.Errorf("document %d is not %s:\n got %v\nwant %v", i, names[i], doc, want)
		}
	}
}

var kqlPackPair = regexp.MustCompile(`"([a-z_]+)", ([a-z_]+)`)

// TestIngest_SentinelRuleTakesEveryEventKey: Sentinel can't split a batch,
// so the data collection rule takes one event per record. Its stream declares
// every top-level OCSF key and its transformation packs each back into Ocsf,
// so every sample arrives whole.
//
// Covers: F944
func TestIngest_SentinelRuleTakesEveryEventKey(t *testing.T) {
	var dcr struct {
		Kind       string `json:"kind"`
		Properties struct {
			Streams map[string]struct {
				Columns []struct {
					Name string `json:"name"`
					Type string `json:"type"`
				} `json:"columns"`
			} `json:"streamDeclarations"`
			DataFlows []struct {
				Streams      []string `json:"streams"`
				OutputStream string   `json:"outputStream"`
				TransformKql string   `json:"transformKql"`
			} `json:"dataFlows"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(read(t, "sentinel/dcr.json"), &dcr); err != nil {
		t.Fatal(err)
	}
	stream, ok := dcr.Properties.Streams["Custom-PantherClawOCSF"]
	if !ok || dcr.Kind != "Direct" || len(dcr.Properties.DataFlows) != 1 {
		t.Fatalf("rule %+v", dcr)
	}
	flow := dcr.Properties.DataFlows[0]
	if !slices.Equal(flow.Streams, []string{"Custom-PantherClawOCSF"}) || flow.OutputStream != "Custom-PantherClawOCSF_CL" {
		t.Fatalf("data flow %+v", flow)
	}
	types := map[string]string{}
	for _, c := range stream.Columns {
		types[c.Name] = c.Type
	}
	want := recordKeys(t)
	if got := slices.Sorted(func(yield func(string) bool) {
		for k := range types {
			if !yield(k) {
				return
			}
		}
	}); !slices.Equal(got, want) {
		t.Fatalf("declared %v, want every OCSF key %v", got, want)
	}
	_, pack, ok := strings.Cut(flow.TransformKql, "Ocsf = pack(")
	if !ok {
		t.Fatal("the transformation does not pack Ocsf")
	}
	var packed []string
	for _, m := range kqlPackPair.FindAllStringSubmatch(pack, -1) {
		if m[1] != m[2] {
			t.Errorf("Ocsf.%s is packed from %s", m[1], m[2])
		}
		packed = append(packed, m[1])
	}
	slices.Sort(packed)
	if !slices.Equal(packed, want) {
		t.Fatalf("packed %v, want %v", packed, want)
	}
	for _, name := range sampleOrder() {
		for k, v := range jsonValue(t, sampleBytes(t, name)).(map[string]any) {
			var fits bool
			switch v.(type) {
			case float64:
				fits = types[k] == "int" || types[k] == "long"
			case string:
				fits = types[k] == "string"
			case map[string]any, []any:
				fits = types[k] == "dynamic"
			}
			if !fits {
				t.Errorf("%s: %s is declared %q", name, k, types[k])
			}
		}
	}
}

// TestIngest_WazuhIgnoresAnUnsplitBatch: Wazuh can't split a batch; one
// written whole as a line decodes with its events under data.events, and no
// rule fires on it, as the README says.
//
// Covers: F944
func TestIngest_WazuhIgnoresAnUnsplitBatch(t *testing.T) {
	f := fields{}
	flatten("", jsonValue(t, read(t, batchFile)), f)
	for id, rule := range wazuhRules(t) {
		if rule(f) {
			t.Errorf("%s fires on a whole batch", id)
		}
	}
}

// TestIngest_ChronicleParserLoopsOverTheBatch: the parser has never run, so
// this only checks its shape: it drops anything but a batch, writes one UDM
// event per entry of data.events, and reads every OCSF value from the loop's
// entry.
//
// Covers: F944
func TestIngest_ChronicleParserLoopsOverTheBatch(t *testing.T) {
	parser := string(read(t, "chronicle/parser/pantherclaw_ocsf.conf"))
	for _, want := range []string{
		`if [type] != "pantherclaw.ocsf.batch" {`,
		"for index, ev in data.events {",
		`mutate { remove_field => ["event"] }`,
	} {
		if !strings.Contains(parser, want) {
			t.Errorf("the parser lacks %q", want)
		}
	}
	_, loop, ok := strings.Cut(parser, "for index, ev in data.events {")
	if !ok {
		t.Fatal("the parser has no loop over data.events")
	}
	if !strings.Contains(loop, `mutate { merge => { "@output" => "event" } }`) {
		t.Error("the loop does not write an event per entry")
	}
	// A loop over a list inside the batch entry binds a name that reads from
	// the entry too (the attacks loops, G0 M28 D718).
	fromEntry := map[string]bool{"ev": true}
	for _, m := range regexp.MustCompile(`for _, ([a-z_]+) in ([a-z_.]+) \{`).FindAllStringSubmatch(parser, -1) {
		if root, _, ok := strings.Cut(m[2], "."); ok && fromEntry[root] {
			fromEntry[m[1]] = true
		}
	}
	for _, m := range regexp.MustCompile(`%\{([a-z_.]+)\}`).FindAllStringSubmatch(parser, -1) {
		root, _, ok := strings.Cut(m[1], ".")
		if m[1] != "ocsf_test" && (!ok || !fromEntry[root]) {
			t.Errorf("%%{%s} is not read from the batch entry", m[1])
		}
	}
}
