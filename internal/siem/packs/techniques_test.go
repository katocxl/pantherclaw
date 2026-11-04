// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package packs_test

import (
	"bytes"
	"encoding/csv"
	"encoding/json/v2"
	"encoding/xml"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	tmcatalog "github.com/katocxl/pantherclaw/internal/threatmap/catalog"
)

// mitre is what one rules.yaml rule names, resolved in the pinned ATT&CK
// catalog: tactics in the catalog's order, parent technique ids, and
// sub-technique ids.
type mitre struct {
	Tactics    []tmcatalog.Tactic
	Techniques []string
	Subs       []string
}

func mitreOf(t *testing.T, r catalogRule) mitre {
	t.Helper()
	c := tmcatalog.Load(tmcatalog.FrameworkATTACK)
	var m mitre
	for _, id := range r.Attack {
		x, ok := c.Technique(id)
		if !ok {
			t.Fatalf("%s: %s is not in the ATT&CK catalog", r.ID, id)
		}
		parent := id
		if x.Parent != "" {
			parent = x.Parent
			m.Subs = append(m.Subs, id)
		}
		if !slices.Contains(m.Techniques, parent) {
			m.Techniques = append(m.Techniques, parent)
		}
		for _, short := range x.Tactics {
			ta, ok := c.Tactic(short)
			if !ok {
				t.Fatalf("%s: tactic %s of %s is not in the catalog", r.ID, short, id)
			}
			if !slices.ContainsFunc(m.Tactics, func(y tmcatalog.Tactic) bool { return y.ID == ta.ID }) {
				m.Tactics = append(m.Tactics, ta)
			}
		}
	}
	return m
}

func (m mitre) tacticIDs() []string {
	var out []string
	for _, x := range m.Tactics {
		out = append(out, x.ID)
	}
	return out
}

// sigmaAttackTags are a rule's Sigma tags after its id tag: each tactic's
// short name, then each technique id, lowercase.
func sigmaAttackTags(t *testing.T, r catalogRule) []string {
	t.Helper()
	m := mitreOf(t, r)
	out := []string{}
	for _, x := range m.Tactics {
		out = append(out, "attack."+x.ShortName)
	}
	for _, id := range r.Attack {
		out = append(out, "attack."+strings.ToLower(id))
	}
	return out
}

var attackID = regexp.MustCompile(`^T[0-9]{4}(\.[0-9]{3})?$`)

// sentinelTactics names each ATT&CK Enterprise tactic as Sentinel's
// analytic rule `tactics` field spells it (G0 M28 D718f). A fixed table,
// never a name with its spaces removed.
var sentinelTactics = map[string]string{
	"TA0043": "Reconnaissance",
	"TA0042": "ResourceDevelopment",
	"TA0001": "InitialAccess",
	"TA0002": "Execution",
	"TA0003": "Persistence",
	"TA0004": "PrivilegeEscalation",
	"TA0005": "DefenseEvasion",
	"TA0006": "CredentialAccess",
	"TA0007": "Discovery",
	"TA0008": "LateralMovement",
	"TA0009": "Collection",
	"TA0011": "CommandAndControl",
	"TA0010": "Exfiltration",
	"TA0040": "Impact",
	// Defense Impairment is new in ATT&CK 20.0. Whether Sentinel accepts
	// this name has not been tried (see sentinel/README.md).
	"TA0112": "DefenseImpairment",
}

// TestT306_EveryATTACKTacticHasASentinelName: the table names every tactic
// of the pinned ATT&CK catalog (G0 M28 D718f). Covers: F965, T-306
func TestT306_EveryATTACKTacticHasASentinelName(t *testing.T) {
	c := tmcatalog.Load(tmcatalog.FrameworkATTACK)
	for _, ta := range c.Tactics {
		if _, ok := sentinelTactics[ta.ID]; !ok {
			t.Errorf("ATT&CK %s tactic %s (%s) has no Sentinel name", c.Version, ta.ID, ta.Name)
		}
	}
}

// TestT306_SIEMRulesNameActiveATTACKTechniquesOrSayWhyNot: every
// rules.yaml rule names ATT&CK Enterprise ids or one line saying why it
// names none, never both; every id is active in the pinned catalog, neither
// revoked, deprecated nor retired (G0 M28 D718, D714e L6). Covers: F965, T-306
func TestT306_SIEMRulesNameActiveATTACKTechniquesOrSayWhyNot(t *testing.T) {
	c := tmcatalog.Load(tmcatalog.FrameworkATTACK)
	for _, r := range catalog(t) {
		if (len(r.Attack) == 0) == (r.TechniquesNone == "") {
			t.Errorf("%s: attack %v and techniques_none %q: exactly one is set", r.ID, r.Attack, r.TechniquesNone)
		}
		if n := utf8.RuneCountInString(r.TechniquesNone); n > 200 || strings.Contains(r.TechniquesNone, "\n") {
			t.Errorf("%s: techniques_none is not one line of at most 200 runes", r.ID)
		}
		if len(r.Attack) > 16 {
			t.Errorf("%s: %d techniques", r.ID, len(r.Attack))
		}
		for _, id := range r.Attack {
			if !attackID.MatchString(id) {
				t.Errorf("%s: %q is not an ATT&CK technique id", r.ID, id)
				continue
			}
			x, ok := c.Technique(id)
			if !ok || !c.Active(id) || x.Deprecated || x.Revoked {
				t.Errorf("%s: %s is not active in ATT&CK %s", r.ID, id, c.Version)
			}
		}
		if len(slices.Compact(slices.Sorted(slices.Values(r.Attack)))) != len(r.Attack) {
			t.Errorf("%s: a technique is listed twice", r.ID)
		}
	}
}

// TestT306_EveryPackNamesRulesYamlsTechniques: each format's static MITRE
// fields equal rules.yaml's ATT&CK ids, resolved in the pinned catalog
// (G0 M28 D718). Covers: F944, F965, T-306
func TestT306_EveryPackNamesRulesYamlsTechniques(t *testing.T) {
	cat := catalog(t)
	byTitle := map[string]catalogRule{}
	for _, r := range cat {
		byTitle[r.Title] = r
	}

	t.Run("sentinel", func(t *testing.T) {
		var doc struct {
			Resources []struct {
				Properties struct {
					DisplayName   string   `json:"displayName"`
					Tactics       []string `json:"tactics"`
					Techniques    []string `json:"techniques"`
					SubTechniques []string `json:"subTechniques"`
				} `json:"properties"`
			} `json:"resources"`
		}
		if err := json.Unmarshal(read(t, "sentinel/analytic-rules.json"), &doc); err != nil {
			t.Fatal(err)
		}
		for _, x := range doc.Resources {
			r := byTitle[x.Properties.DisplayName]
			m := mitreOf(t, r)
			var tactics []string
			for _, ta := range m.Tactics {
				name, ok := sentinelTactics[ta.ID]
				if !ok {
					t.Fatalf("%s: tactic %s has no Sentinel name", r.ID, ta.ID)
				}
				tactics = append(tactics, name)
			}
			if !eq(x.Properties.Tactics, tactics) || !eq(x.Properties.Techniques, m.Techniques) || !eq(x.Properties.SubTechniques, m.Subs) ||
				x.Properties.Tactics == nil || x.Properties.Techniques == nil || x.Properties.SubTechniques == nil {
				t.Errorf("%s: tactics %v techniques %v subTechniques %v, want %v %v %v", r.ID,
					x.Properties.Tactics, x.Properties.Techniques, x.Properties.SubTechniques, tactics, m.Techniques, m.Subs)
			}
		}
	})

	t.Run("elastic", func(t *testing.T) {
		type ref struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			Reference string `json:"reference"`
		}
		type technique struct {
			ref
			Subtechnique []ref `json:"subtechnique"`
		}
		for line := range bytes.SplitSeq(bytes.TrimSpace(read(t, "elastic/rules.ndjson")), []byte("\n")) {
			var x struct {
				Name   string `json:"name"`
				Threat []struct {
					Framework string      `json:"framework"`
					Tactic    ref         `json:"tactic"`
					Technique []technique `json:"technique"`
				} `json:"threat"`
			}
			if err := json.Unmarshal(line, &x); err != nil {
				t.Fatal(err)
			}
			r := byTitle[x.Name]
			m := mitreOf(t, r)
			c := tmcatalog.Load(tmcatalog.FrameworkATTACK)
			// One threat entry per tactic, each listing every technique of
			// the rule under that tactic.
			if len(x.Threat) != len(m.Tactics) {
				t.Errorf("%s: %d threat entries, want %d", r.ID, len(x.Threat), len(m.Tactics))
				continue
			}
			for i, th := range x.Threat {
				ta := m.Tactics[i]
				if th.Framework != "MITRE ATT&CK" || th.Tactic.ID != ta.ID || th.Tactic.Name != ta.Name ||
					th.Tactic.Reference != "https://attack.mitre.org/tactics/"+ta.ID+"/" {
					t.Errorf("%s: tactic %+v", r.ID, th)
				}
				var techs, subs []string
				for _, te := range th.Technique {
					p, _ := c.Technique(te.ID)
					if te.Name != p.Name || te.Reference != "https://attack.mitre.org/techniques/"+te.ID+"/" {
						t.Errorf("%s: technique %+v", r.ID, te.ref)
					}
					techs = append(techs, te.ID)
					for _, s := range te.Subtechnique {
						x, _ := c.Technique(s.ID)
						if x.Parent != te.ID || s.Name != x.Name ||
							s.Reference != "https://attack.mitre.org/techniques/"+strings.Replace(s.ID, ".", "/", 1)+"/" {
							t.Errorf("%s: sub-technique %+v", r.ID, s)
						}
						subs = append(subs, s.ID)
					}
				}
				if !eq(techs, m.Techniques) || !eq(subs, m.Subs) {
					t.Errorf("%s: techniques %v subs %v, want %v %v", r.ID, techs, subs, m.Techniques, m.Subs)
				}
			}
		}
	})

	t.Run("chronicle", func(t *testing.T) {
		metaRe := regexp.MustCompile(`(?m)^    (mitre_attack_tactic|mitre_attack_technique|rule_id) = "([^"]*)"$`)
		for _, file := range glob(t, "chronicle/rules/*.yaral") {
			got := map[string][]string{}
			var order []string
			for _, m := range metaRe.FindAllStringSubmatch(string(read(t, file)), -1) {
				got[m[1]] = append(got[m[1]], m[2])
				order = append(order, m[1])
			}
			id := strings.Join(got["rule_id"], "")
			var r catalogRule
			for _, x := range cat {
				if x.ID == id {
					r = x
				}
			}
			m := mitreOf(t, r)
			var tactics []string
			for _, ta := range m.Tactics {
				tactics = append(tactics, ta.Name)
			}
			wantTactic, wantTechnique := strings.Join(tactics, ", "), strings.Join(r.Attack, ", ")
			if strings.Join(got["mitre_attack_tactic"], "") != wantTactic || strings.Join(got["mitre_attack_technique"], "") != wantTechnique {
				t.Errorf("%s: meta %v, want tactic %q technique %q", file, got, wantTactic, wantTechnique)
			}
			// Before rule_id.
			if len(r.Attack) > 0 && !slices.Equal(order, []string{"mitre_attack_tactic", "mitre_attack_technique", "rule_id"}) {
				t.Errorf("%s: meta order %v", file, order)
			}
		}
	})

	t.Run("wazuh", func(t *testing.T) {
		var doc struct {
			Groups []struct {
				Rules []struct {
					Description string   `xml:"description"`
					Mitre       []string `xml:"mitre>id"`
				} `xml:"rule"`
			} `xml:"group"`
		}
		wrapped := append(append([]byte("<root>"), read(t, "wazuh/pantherclaw_rules.xml")...), "</root>"...)
		if err := xml.Unmarshal(wrapped, &doc); err != nil {
			t.Fatal(err)
		}
		seen := 0
		for _, x := range doc.Groups[0].Rules {
			id, _, ok := strings.Cut(x.Description, ": ")
			if !ok || !strings.HasPrefix(id, "pc-siem-") {
				if len(x.Mitre) != 0 {
					t.Errorf("rule %q names techniques", x.Description)
				}
				continue
			}
			seen++
			for _, r := range cat {
				if r.ID == id && !eq(x.Mitre, r.Attack) {
					t.Errorf("%s: mitre %v, want %v", id, x.Mitre, r.Attack)
				}
			}
		}
		if seen != len(cat) {
			t.Errorf("%d wazuh rules carry a rules.yaml id, want %d", seen, len(cat))
		}
	})

	t.Run("splunk", func(t *testing.T) {
		rows, err := csv.NewReader(bytes.NewReader(read(t, "splunk/pantherclaw_ocsf/lookups/pantherclaw_mitre.csv"))).ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) == 0 || !slices.Equal(rows[0], []string{"rule_id", "attack_tactics", "attack_techniques"}) {
			t.Fatalf("header %v", rows)
		}
		if len(rows)-1 != len(cat) {
			t.Fatalf("%d rows, want %d", len(rows)-1, len(cat))
		}
		for i, r := range cat {
			m := mitreOf(t, r)
			want := []string{r.ID, strings.Join(m.tacticIDs(), " "), strings.Join(r.Attack, " ")}
			if !slices.Equal(rows[i+1], want) {
				t.Errorf("row %v, want %v", rows[i+1], want)
			}
		}
		stanza := conf(t, read(t, "splunk/pantherclaw_ocsf/default/transforms.conf"))["pantherclaw_mitre"]
		if stanza["filename"] != "pantherclaw_mitre.csv" {
			t.Errorf("transforms stanza %v", stanza)
		}
	})
}

// TestT306_PacksCopyBothFrameworksPerEvent: the Elastic pipeline and the
// Chronicle parser read the techniques of an alert and of an incident, and
// the samples they read carry ATLAS and ATT&CK ids (G0 M28 D718).
// Covers: F965, T-306
func TestT306_PacksCopyBothFrameworksPerEvent(t *testing.T) {
	pipeline := string(read(t, "elastic/ingest-pipeline.json"))
	for _, want := range []string{
		"ctx.finding_info.attacks", "ctx.finding_info_list", "a.technique.uid", "a.sub_technique.uid", "a.tactic.uid",
		"technique.id", "technique.subtechnique", "'tactic'",
	} {
		if !strings.Contains(pipeline, want) {
			t.Errorf("the Elastic pipeline lacks %q", want)
		}
	}
	template := string(read(t, "elastic/index-template.json"))
	if !strings.Contains(template, `"threat"`) || !strings.Contains(template, `"subtechnique"`) {
		t.Error("the Elastic template does not map threat.*")
	}
	parser := string(read(t, "chronicle/parser/pantherclaw_ocsf.conf"))
	for _, want := range []string{
		"for _, ev_attack in ev.finding_info.attacks {", "for _, ev_finding in ev.finding_info_list {",
		"for _, ev_finding_attack in ev_finding.attacks {",
		`"attack_result.attack_details.tactics" => "attack_tactic"`, `"attack_result.attack_details.techniques" => "attack_technique"`,
		`"event.idm.read_only_udm.security_result" => "attack_result"`,
	} {
		if !strings.Contains(parser, want) {
			t.Errorf("the Chronicle parser lacks %q", want)
		}
	}
	alert := string(read(t, "samples/alert-critical.json"))
	incident := string(read(t, "samples/incident-open.json"))
	for name, s := range map[string]string{"alert": alert, "incident": incident} {
		if !strings.Contains(s, `"ATLAS 2026.10"`) || !strings.Contains(s, `"20.0"`) {
			t.Errorf("the %s sample lacks a framework version", name)
		}
	}
}

// eq compares two id lists, nil and empty alike.
func eq(a, b []string) bool { return len(a) == len(b) && (len(a) == 0 || slices.Equal(a, b)) }
