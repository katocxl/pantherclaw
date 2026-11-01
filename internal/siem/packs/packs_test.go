// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package packs_test

import (
	"bufio"
	"bytes"
	"encoding/json/v2"
	"encoding/xml"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// pred is one rule, read from the vendor's own file.
type pred func(fields) bool

func read(t *testing.T, rel string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(packRoot, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))
}

func glob(t *testing.T, pattern string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(packRoot, filepath.FromSlash(pattern)))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatalf("nothing matches %s", pattern)
	}
	out := make([]string, 0, len(files))
	for _, f := range files {
		rel, err := filepath.Rel(packRoot, f)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, filepath.ToSlash(rel))
	}
	return out
}

// catalogRule is one entry of rules.yaml.
type catalogRule struct {
	ID       string   `yaml:"id"`
	Title    string   `yaml:"title"`
	Severity string   `yaml:"severity"`
	FiresOn  []string `yaml:"fires_on"`
}

func catalog(t *testing.T) []catalogRule {
	t.Helper()
	var doc struct {
		Rules []catalogRule `yaml:"rules"`
	}
	if err := yaml.Unmarshal(read(t, "rules.yaml"), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Rules) == 0 {
		t.Fatal("rules.yaml lists no rules")
	}
	return doc.Rules
}

func oneOf(vals ...string) func(string) bool {
	return func(s string) bool { return slices.Contains(vals, s) }
}

func prefixed(p string) func(string) bool {
	return func(s string) bool { return strings.HasPrefix(s, p) }
}

func unquote(s string) string { return strings.Trim(strings.TrimSpace(s), `"`) }

func unquoteAll(s, sep string) []string {
	var out []string
	for v := range strings.SplitSeq(s, sep) {
		out = append(out, unquote(v))
	}
	return out
}

func all(ps ...pred) pred {
	return func(f fields) bool {
		for _, p := range ps {
			if !p(f) {
				return false
			}
		}
		return true
	}
}

func not(p pred) pred { return func(f fields) bool { return !p(f) } }

func has(path string, ok func(string) bool) pred {
	return func(f fields) bool { return f.any(path, ok) }
}

// --- Splunk: savedsearches.conf, with search terms field=value, field IN (…)
// and NOT field=value.

var (
	splunkNot = regexp.MustCompile(`^NOT "([a-z_.{}]+)"="([^"]*)"\s*`)
	splunkEq  = regexp.MustCompile(`^([a-z_.]+)=("[^"]*"|[0-9]+)\s*`)
	splunkIn  = regexp.MustCompile(`^([a-z_.]+) IN \(([^)]*)\)\s*`)
)

func conf(t *testing.T, raw []byte) map[string]map[string]string {
	t.Helper()
	out := map[string]map[string]string{}
	var stanza string
	s := bufio.NewScanner(bytes.NewReader(raw))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		switch {
		case line == "", strings.HasPrefix(line, "#"):
		case strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]"):
			stanza = line[1 : len(line)-1]
			out[stanza] = map[string]string{}
		default:
			k, v, ok := strings.Cut(line, " = ")
			if !ok || stanza == "" {
				t.Fatalf("not a conf line: %q", line)
			}
			out[stanza][k] = v
		}
	}
	return out
}

func splunkRules(t *testing.T) map[string]pred {
	t.Helper()
	out := map[string]pred{}
	for stanza, kv := range conf(t, read(t, "splunk/pantherclaw_ocsf/default/savedsearches.conf")) {
		id, _, _ := strings.Cut(stanza, " ")
		q, ok := strings.CutPrefix(kv["search"], "`pantherclaw_ocsf` ")
		if !ok {
			t.Fatalf("%s: the search does not start from the macro", id)
		}
		var ps []pred
		for q != "" {
			if m := splunkNot.FindStringSubmatch(q); m != nil {
				ps = append(ps, not(has(strings.TrimSuffix(m[1], "{}"), oneOf(m[2]))))
				q = q[len(m[0]):]
			} else if m := splunkIn.FindStringSubmatch(q); m != nil {
				ps = append(ps, has(m[1], oneOf(unquoteAll(m[2], ",")...)))
				q = q[len(m[0]):]
			} else if m := splunkEq.FindStringSubmatch(q); m != nil {
				if v := unquote(m[2]); strings.HasSuffix(v, "*") {
					ps = append(ps, has(m[1], prefixed(strings.TrimSuffix(v, "*"))))
				} else {
					ps = append(ps, has(m[1], oneOf(v)))
				}
				q = q[len(m[0]):]
			} else {
				t.Fatalf("%s: cannot read %q", id, q)
			}
		}
		out[id] = all(ps...)
	}
	return out
}

// --- Sentinel: an ARM template of Scheduled rules, with KQL where clauses.

type armRule struct {
	Type       string `json:"type"`
	Kind       string `json:"kind"`
	Properties struct {
		DisplayName string `json:"displayName"`
		Enabled     bool   `json:"enabled"`
		Query       string `json:"query"`
	} `json:"properties"`
}

func sentinelTemplate(t *testing.T) []armRule {
	t.Helper()
	var doc struct {
		Resources []armRule `json:"resources"`
	}
	if err := json.Unmarshal(read(t, "sentinel/analytic-rules.json"), &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Resources
}

var (
	kqlEq     = regexp.MustCompile(`^(?:toint|tostring)\(Ocsf\.([a-z_.]+)\) == ("[^"]*"|[0-9]+)$`)
	kqlIn     = regexp.MustCompile(`^(?:toint|tostring)\(Ocsf\.([a-z_.]+)\) in \(([^)]*)\)$`)
	kqlPrefix = regexp.MustCompile(`^tostring\(Ocsf\.([a-z_.]+)\) startswith "([^"]*)"$`)
	kqlNotHas = regexp.MustCompile(`^not\(Ocsf\.([a-z_.]+) has "([^"]*)"\)$`)
)

func sentinelRules(t *testing.T) map[string]pred {
	t.Helper()
	byTitle := map[string]string{}
	for _, r := range catalog(t) {
		byTitle[r.Title] = r.ID
	}
	out := map[string]pred{}
	for _, r := range sentinelTemplate(t) {
		id, ok := byTitle[r.Properties.DisplayName]
		if !ok {
			t.Fatalf("rule %q is not in rules.yaml", r.Properties.DisplayName)
		}
		if r.Kind != "Scheduled" || !strings.HasSuffix(r.Type, "/alertRules") {
			t.Fatalf("%s: kind %q type %q", id, r.Kind, r.Type)
		}
		lines := strings.Split(r.Properties.Query, "\n")
		if lines[0] != "PantherClawOCSF_CL" {
			t.Fatalf("%s: the query does not read the pack's table: %q", id, lines[0])
		}
		var ps []pred
		for _, line := range lines[1:] {
			where, ok := strings.CutPrefix(line, "| where ")
			if !ok {
				t.Fatalf("%s: cannot read %q", id, line)
			}
			for term := range strings.SplitSeq(where, " and ") {
				switch {
				case kqlEq.MatchString(term):
					m := kqlEq.FindStringSubmatch(term)
					ps = append(ps, has(m[1], oneOf(unquote(m[2]))))
				case kqlIn.MatchString(term):
					m := kqlIn.FindStringSubmatch(term)
					ps = append(ps, has(m[1], oneOf(unquoteAll(m[2], ",")...)))
				case kqlPrefix.MatchString(term):
					m := kqlPrefix.FindStringSubmatch(term)
					ps = append(ps, has(m[1], prefixed(m[2])))
				case kqlNotHas.MatchString(term):
					m := kqlNotHas.FindStringSubmatch(term)
					ps = append(ps, not(has(m[1], oneOf(m[2]))))
				default:
					t.Fatalf("%s: cannot read %q", id, term)
				}
			}
		}
		out[id] = all(ps...)
	}
	return out
}

// --- Chronicle: YARA-L single-event rules over UDM, read through udm-map.json.

type udmField struct {
	OCSF     string `json:"ocsf"`
	Contains string `json:"contains"`
}

func udmMap(t *testing.T) map[string]udmField {
	t.Helper()
	var m map[string]udmField
	if err := json.Unmarshal(read(t, "chronicle/udm-map.json"), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// udmValue is what udm-map.json says path holds for a sample. A field the
// sample lacks is empty, as YARA-L reads it.
func udmValue(t *testing.T, m map[string]udmField, f fields, path string) string {
	t.Helper()
	u, ok := m[path]
	if !ok {
		t.Fatalf("%s is not in udm-map.json", path)
	}
	if u.Contains != "" {
		return strconv.FormatBool(f.any(u.OCSF, oneOf(u.Contains)))
	}
	if len(f[u.OCSF]) == 0 {
		return ""
	}
	return f[u.OCSF][0]
}

var (
	yaralRule  = regexp.MustCompile(`(?s)^// SPDX[^\n]*\nrule ([a-z0-9_]+) \{\n  meta:\n.*?rule_id = "([a-z0-9-]+)"\n\n  events:\n(.*?)\n\n  condition:\n    \$e\n\}\n$`)
	yaralCmp   = regexp.MustCompile(`^\$e\.(.+?) (=|!=) "([^"]*)"$`)
	yaralRegex = regexp.MustCompile("^re\\.regex\\(\\$e\\.(.+?), `([^`]*)`\\)$")
)

func chronicleRules(t *testing.T) map[string]pred {
	t.Helper()
	m := udmMap(t)
	cmp := func(term string) pred {
		c := yaralCmp.FindStringSubmatch(term)
		if c == nil {
			t.Fatalf("cannot read %q", term)
		}
		return func(f fields) bool { return (udmValue(t, m, f, c[1]) == c[3]) == (c[2] == "=") }
	}
	out := map[string]pred{}
	for _, file := range glob(t, "chronicle/rules/*.yaral") {
		doc := yaralRule.FindStringSubmatch(string(read(t, file)))
		if doc == nil {
			t.Fatalf("%s: not a single-event rule", file)
		}
		var ps []pred
		for line := range strings.SplitSeq(doc[3], "\n") {
			line = strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(line, "("):
				var alt []pred
				for term := range strings.SplitSeq(strings.Trim(line, "()"), " or ") {
					alt = append(alt, cmp(term))
				}
				ps = append(ps, func(f fields) bool {
					return slices.ContainsFunc(alt, func(p pred) bool { return p(f) })
				})
			case strings.HasPrefix(line, "re.regex"):
				r := yaralRegex.FindStringSubmatch(line)
				if r == nil {
					t.Fatalf("%s: cannot read %q", file, line)
				}
				re := regexp.MustCompile(r[2])
				ps = append(ps, func(f fields) bool { return re.MatchString(udmValue(t, m, f, r[1])) })
			default:
				ps = append(ps, cmp(line))
			}
		}
		out[doc[2]] = all(ps...)
	}
	return out
}

// --- Elastic: an NDJSON rule export with KQL queries.

type elasticRule struct {
	Tags     []string `json:"tags"`
	Type     string   `json:"type"`
	Language string   `json:"language"`
	Query    string   `json:"query"`
	Enabled  bool     `json:"enabled"`
}

func elasticExport(t *testing.T) []elasticRule {
	t.Helper()
	var out []elasticRule
	for line := range bytes.SplitSeq(bytes.TrimSpace(read(t, "elastic/rules.ndjson")), []byte("\n")) {
		var r elasticRule
		if err := json.Unmarshal(line, &r); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

var (
	kueryNot = regexp.MustCompile(`^not ([a-z_.]+): "([^"]*)"$`)
	kueryIn  = regexp.MustCompile(`^([a-z_.]+): \(([^)]*)\)$`)
	kueryEq  = regexp.MustCompile(`^([a-z_.]+): ("[^"]*"|[0-9]+)$`)
	kueryPre = regexp.MustCompile(`^([a-z_.]+): ([a-z_.]+)\*$`)
)

func elasticRules(t *testing.T) map[string]pred {
	t.Helper()
	out := map[string]pred{}
	for _, r := range elasticExport(t) {
		if r.Type != "query" || r.Language != "kuery" || len(r.Tags) != 2 {
			t.Fatalf("rule %+v", r)
		}
		var ps []pred
		for term := range strings.SplitSeq(r.Query, " and ") {
			switch {
			case kueryNot.MatchString(term):
				m := kueryNot.FindStringSubmatch(term)
				ps = append(ps, not(has(m[1], oneOf(m[2]))))
			case kueryIn.MatchString(term):
				m := kueryIn.FindStringSubmatch(term)
				ps = append(ps, has(m[1], oneOf(unquoteAll(m[2], " or ")...)))
			case kueryEq.MatchString(term):
				m := kueryEq.FindStringSubmatch(term)
				ps = append(ps, has(m[1], oneOf(unquote(m[2]))))
			case kueryPre.MatchString(term):
				m := kueryPre.FindStringSubmatch(term)
				ps = append(ps, has(m[1], prefixed(m[2])))
			default:
				t.Fatalf("%s: cannot read %q", r.Tags[1], term)
			}
		}
		out[r.Tags[1]] = all(ps...)
	}
	return out
}

// --- Wazuh: rules.xml, with field conditions under one parent. The first
// child that matches takes the event, as Wazuh does.

type wazuhDoc struct {
	Groups []struct {
		Name  string      `xml:"name,attr"`
		Rules []wazuhRule `xml:"rule"`
	} `xml:"group"`
}

type wazuhRule struct {
	ID     int `xml:"id,attr"`
	Level  int `xml:"level,attr"`
	IfSID  int `xml:"if_sid"`
	Fields []struct {
		Name  string `xml:"name,attr"`
		Type  string `xml:"type,attr"`
		Value string `xml:",chardata"`
	} `xml:"field"`
	Description string `xml:"description"`
}

func (r wazuhRule) match(t *testing.T, f fields) bool {
	t.Helper()
	for _, c := range r.Fields {
		if c.Type != "pcre2" {
			t.Fatalf("rule %d: field %s is not pcre2", r.ID, c.Name)
		}
		// Wazuh's JSON decoder joins an array with commas.
		if !regexp.MustCompile(c.Value).MatchString(strings.Join(f[c.Name], ",")) || len(f[c.Name]) == 0 {
			return false
		}
	}
	return true
}

func wazuhRuleset(t *testing.T) []wazuhRule {
	t.Helper()
	var doc wazuhDoc
	// A Wazuh rules file has several roots allowed; wrap it to read it.
	wrapped := append(append([]byte("<root>"), read(t, "wazuh/pantherclaw_rules.xml")...), "</root>"...)
	if err := xml.Unmarshal(wrapped, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Groups) != 1 || len(doc.Groups[0].Rules) < 3 {
		t.Fatalf("groups %+v", doc.Groups)
	}
	return doc.Groups[0].Rules
}

func wazuhRules(t *testing.T) map[string]pred {
	t.Helper()
	set := wazuhRuleset(t)
	parent, children := set[0], set[1:]
	first := func(f fields) (wazuhRule, bool) {
		if !parent.match(t, f) {
			return wazuhRule{}, false
		}
		for _, c := range children {
			if c.IfSID != parent.ID {
				t.Fatalf("rule %d: if_sid %d", c.ID, c.IfSID)
			}
			if c.match(t, f) {
				return c, true
			}
		}
		return wazuhRule{}, false
	}
	out := map[string]pred{}
	for _, r := range children {
		if r.Level == 0 {
			continue
		}
		id, _, ok := strings.Cut(r.Description, ": ")
		if !ok {
			t.Fatalf("rule %d: description %q", r.ID, r.Description)
		}
		if r.ID < 100700 || r.ID > 100799 {
			t.Fatalf("rule %d is outside 100700-100799", r.ID)
		}
		out[id] = func(f fields) bool {
			c, ok := first(f)
			return ok && c.ID == r.ID
		}
	}
	return out
}

// --- Sigma: rule files with a selection and a filter.

var sigmaID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func sigmaPred(t *testing.T, sel map[string]any) pred {
	t.Helper()
	var ps []pred
	for k, v := range sel {
		field, mod, _ := strings.Cut(k, "|")
		var vals []string
		switch x := v.(type) {
		case []any:
			for _, e := range x {
				vals = append(vals, fmt.Sprint(e))
			}
		default:
			vals = []string{fmt.Sprint(x)}
		}
		switch mod {
		case "":
			ps = append(ps, has(field, oneOf(vals...)))
		case "startswith":
			ps = append(ps, has(field, prefixed(vals[0])))
		case "contains":
			ps = append(ps, has(field, func(s string) bool { return strings.Contains(s, vals[0]) }))
		default:
			t.Fatalf("modifier %q", mod)
		}
	}
	return all(ps...)
}

func sigmaRules(t *testing.T) map[string]pred {
	t.Helper()
	out := map[string]pred{}
	for _, file := range glob(t, "sigma/rules/*.yml") {
		var doc struct {
			Title     string         `yaml:"title"`
			ID        string         `yaml:"id"`
			Tags      []string       `yaml:"tags"`
			Level     string         `yaml:"level"`
			LogSource map[string]any `yaml:"logsource"`
			Detection struct {
				Selection map[string]any `yaml:"selection"`
				Simulated map[string]any `yaml:"simulated"`
				Condition string         `yaml:"condition"`
			} `yaml:"detection"`
		}
		if err := yaml.Unmarshal(read(t, file), &doc); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		if !sigmaID.MatchString(doc.ID) || doc.Title == "" || doc.Level == "" || doc.LogSource["product"] != "pantherclaw" ||
			doc.Detection.Condition != "selection and not simulated" || len(doc.Tags) != 1 {
			t.Fatalf("%s: %+v", file, doc)
		}
		out[doc.Tags[0]] = all(sigmaPred(t, doc.Detection.Selection), not(sigmaPred(t, doc.Detection.Simulated)))
	}
	return out
}

// TestPacks_EachRuleFiresOnItsSamples reads every rule from each vendor's own
// file and runs it over every sample: it fires on the samples rules.yaml
// lists and on no other, a simulated event among them. A vendor's own engine
// is not involved: each pack's README says what that leaves unchecked.
//
// Covers: F944
func TestPacks_EachRuleFiresOnItsSamples(t *testing.T) {
	cat := catalog(t)
	data := samples(t)
	for _, r := range cat {
		for _, s := range r.FiresOn {
			if _, ok := data[s]; !ok {
				t.Fatalf("%s fires on %q, which is not a sample", r.ID, s)
			}
		}
	}
	packs := map[string]func(*testing.T) map[string]pred{
		"splunk": splunkRules, "sentinel": sentinelRules, "chronicle": chronicleRules,
		"elastic": elasticRules, "wazuh": wazuhRules, "sigma": sigmaRules,
	}
	want := make([]string, 0, len(cat))
	for _, r := range cat {
		want = append(want, r.ID)
	}
	slices.Sort(want)
	for _, name := range slices.Sorted(maps.Keys(packs)) {
		t.Run(name, func(t *testing.T) {
			rules := packs[name](t)
			if got := slices.Sorted(maps.Keys(rules)); !slices.Equal(got, want) {
				t.Fatalf("rules %v, want %v", got, want)
			}
			for _, r := range cat {
				for _, s := range slices.Sorted(maps.Keys(data)) {
					if got, should := rules[r.ID](data[s]), slices.Contains(r.FiresOn, s); got != should {
						t.Errorf("%s on %s: fired %v, want %v", r.ID, s, got, should)
					}
				}
			}
		})
	}
}

// TestPacks_ChronicleParserSetsWhatTheMapReads: the parser writes every field
// the rules read through udm-map.json. The parser itself has never run: the
// pack's README says so.
//
// Covers: F944
func TestPacks_ChronicleParserSetsWhatTheMapReads(t *testing.T) {
	parser := string(read(t, "chronicle/parser/pantherclaw_ocsf.conf"))
	field := regexp.MustCompile(`^additional\.fields\["([a-z_]+)"\]$`)
	for k := range udmMap(t) {
		want := `"event.idm.read_only_udm.` + k + `"`
		if m := field.FindStringSubmatch(k); m != nil {
			want = `"field_` + m[1] + `.key" => "` + m[1] + `"`
		}
		if !strings.Contains(parser, want) {
			t.Errorf("the parser does not set %s (%s)", k, want)
		}
	}
}

// TestHR654_PacksAreDataAndShipDisabled: a pack is data of the kinds below,
// no script and no third-party content, and nothing in it runs until a person
// turns it on: searches and rules ship disabled, and the Wazuh rules, which
// have no such switch, raise alerts and start no active response.
//
// Covers: F944
func TestHR654_PacksAreDataAndShipDisabled(t *testing.T) {
	allowed := []string{"", ".md", ".json", ".ndjson", ".yaml", ".yml", ".conf", ".xml", ".yaral"}
	err := fs.WalkDir(os.DirFS(packRoot), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if ext := path.Ext(p); !slices.Contains(allowed, ext) {
			t.Errorf("%s: %q is not a data file", p, ext)
		} else if ext == "" && !slices.Contains([]string{"LICENSE", "NOTICE"}, path.Base(p)) {
			t.Errorf("%s: a file with no extension", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for stanza, kv := range conf(t, read(t, "splunk/pantherclaw_ocsf/default/savedsearches.conf")) {
		if kv["disabled"] != "1" {
			t.Errorf("splunk %s: disabled = %q", stanza, kv["disabled"])
		}
		for k := range kv {
			if strings.HasPrefix(k, "action.") {
				t.Errorf("splunk %s: %s runs an alert action", stanza, k)
			}
		}
	}
	for _, r := range sentinelTemplate(t) {
		if r.Properties.Enabled {
			t.Errorf("sentinel %s is enabled", r.Properties.DisplayName)
		}
	}
	for _, r := range elasticExport(t) {
		if r.Enabled {
			t.Errorf("elastic %s is enabled", r.Tags[1])
		}
	}
	if bytes.Contains(read(t, "wazuh/pantherclaw_rules.xml"), []byte("active-response")) {
		t.Error("the Wazuh rules name an active response")
	}
}

// TestHR654_ReadmesSayWhatWasNotChecked: every pack says plainly what no
// offline test could check, and none claims a store listing or certification.
//
// Covers: F945
func TestHR654_ReadmesSayWhatWasNotChecked(t *testing.T) {
	claims := regexp.MustCompile(`(?i)\b(certified|officially supported|approved by|listed on)\b`)
	for _, pack := range []string{"splunk", "sentinel", "chronicle", "elastic", "wazuh", "sigma"} {
		raw := read(t, pack+"/README.md")
		if !bytes.Contains(raw, []byte("## What was not checked")) {
			t.Errorf("%s: no \"What was not checked\" section", pack)
		}
		if m := claims.Find(raw); m != nil {
			t.Errorf("%s: claims %q", pack, m)
		}
	}
	top := read(t, "README.md")
	for _, want := range []string{"outside PantherClaw's control", "not certified"} {
		if !bytes.Contains(top, []byte(want)) {
			t.Errorf("the README does not say %q", want)
		}
	}
}
