// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package main

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// goodSTIX is a small Enterprise bundle: two tactics in matrix order, an
// active technique with a sub-technique, a deprecated and a revoked one
// (neither needs a tactic), and a phase from another kill chain that the
// generator ignores (G0 M28 D711, D714c M1).
const goodSTIX = `{"type":"bundle","objects":[
{"type":"x-mitre-collection","id":"x-mitre-collection--1","x_mitre_version":"20.0"},
{"type":"x-mitre-matrix","id":"x-mitre-matrix--1","x_mitre_domains":["enterprise-attack"],"tactic_refs":["x-mitre-tactic--b","x-mitre-tactic--a"]},
{"type":"x-mitre-tactic","id":"x-mitre-tactic--a","name":"Execution","x_mitre_shortname":"execution","x_mitre_domains":["enterprise-attack"],
 "external_references":[{"source_name":"mitre-attack","external_id":"TA0002","url":"https://attack.mitre.org/tactics/TA0002"}]},
{"type":"x-mitre-tactic","id":"x-mitre-tactic--b","name":"Initial Access","x_mitre_shortname":"initial-access","x_mitre_domains":["enterprise-attack"],
 "external_references":[{"source_name":"mitre-attack","external_id":"TA0001","url":"https://attack.mitre.org/tactics/TA0001"}]},
{"type":"attack-pattern","id":"attack-pattern--1","name":"Command and Scripting Interpreter","x_mitre_domains":["enterprise-attack"],
 "x_mitre_platforms":["Linux"],"description":"never copied",
 "kill_chain_phases":[{"kill_chain_name":"mitre-attack","phase_name":"execution"},{"kill_chain_name":"mitre-attack","phase_name":"initial-access"},{"kill_chain_name":"other-chain","phase_name":"nowhere"}],
 "external_references":[{"source_name":"mitre-attack","external_id":"T1059","url":"https://attack.mitre.org/techniques/T1059"},{"source_name":"capec","external_id":"CAPEC-1"}]},
{"type":"attack-pattern","id":"attack-pattern--2","name":"Unix Shell","x_mitre_domains":["enterprise-attack"],"x_mitre_is_subtechnique":true,
 "kill_chain_phases":[{"kill_chain_name":"mitre-attack","phase_name":"execution"}],
 "external_references":[{"source_name":"mitre-attack","external_id":"T1059.004","url":"https://attack.mitre.org/techniques/T1059/004"}]},
{"type":"attack-pattern","id":"attack-pattern--3","name":"Old","x_mitre_domains":["enterprise-attack"],"x_mitre_deprecated":true,
 "external_references":[{"source_name":"mitre-attack","external_id":"T1000","url":"https://attack.mitre.org/techniques/T1000"}]},
{"type":"attack-pattern","id":"attack-pattern--4","name":"Replaced","x_mitre_domains":["enterprise-attack"],"revoked":true,
 "external_references":[{"source_name":"mitre-attack","external_id":"T1001","url":"https://attack.mitre.org/techniques/T1001"}]}
]}`

var attackPin = Pin{Version: "20.0", URL: "https://example.test/a.json", SHA256: strings.Repeat("0", 64)}

// Covers: F974, HR-682
func TestHR682_GeneratorReadsATTACKSTIX(t *testing.T) {
	c, err := buildATTACK([]byte(goodSTIX), attackPin)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Tactics) != 2 || c.Tactics[0].ShortName != "initial-access" || c.Tactics[1].Order != 2 {
		t.Fatalf("tactics follow the matrix order: %+v", c.Tactics)
	}
	byID := map[string]Technique{}
	for _, tc := range c.Techniques {
		byID[tc.ID] = tc
	}
	if got := byID["T1059"].Tactics; !slices.Equal(got, []string{"initial-access", "execution"}) {
		t.Errorf("T1059 tactics %v: matrix order, other kill chains ignored", got)
	}
	if byID["T1059.004"].Parent != "T1059" || byID["T1059"].Parent != "" {
		t.Error("parent comes from the id")
	}
	if !byID["T1000"].Deprecated || !byID["T1001"].Revoked || byID["T1059"].Deprecated || byID["T1059"].Revoked {
		t.Error("deprecated and revoked flags are carried as given")
	}
	b, err := encode(c)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "never copied") || strings.Contains(string(b), "CAPEC") {
		t.Error("only the read fields reach the catalog")
	}
}

// Covers: F974, HR-682
func TestHR682_GeneratorRefusesUnknownATTACKShapes(t *testing.T) {
	one := func(old, repl string) func(string) string {
		return func(s string) string {
			if !strings.Contains(s, old) {
				panic("fixture lacks " + old)
			}
			return strings.Replace(s, old, repl, 1)
		}
	}
	cases := map[string]func(string) string{
		"another release":               one(`"x_mitre_version":"20.0"`, `"x_mitre_version":"19.1"`),
		"no collection":                 one(`{"type":"x-mitre-collection","id":"x-mitre-collection--1","x_mitre_version":"20.0"},`, ``),
		"matrix of another domain":      one(`"id":"x-mitre-matrix--1","x_mitre_domains":["enterprise-attack"]`, `"id":"x-mitre-matrix--1","x_mitre_domains":["mobile-attack"]`),
		"tactic without domain":         one(`"x_mitre_shortname":"execution","x_mitre_domains":["enterprise-attack"]`, `"x_mitre_shortname":"execution"`),
		"technique of another domain":   one(`"name":"Unix Shell","x_mitre_domains":["enterprise-attack"]`, `"name":"Unix Shell","x_mitre_domains":["ics-attack"]`),
		"matrix names a missing tactic": one(`"tactic_refs":["x-mitre-tactic--b","x-mitre-tactic--a"]`, `"tactic_refs":["x-mitre-tactic--b","x-mitre-tactic--a","x-mitre-tactic--z"]`),
		"phase not in the matrix":       one(`{"kill_chain_name":"mitre-attack","phase_name":"execution"}]`, `{"kill_chain_name":"mitre-attack","phase_name":"impact"}]`),
		"active technique without tactic": one(`"kill_chain_phases":[{"kill_chain_name":"mitre-attack","phase_name":"execution"}],
 "external_references":[{"source_name":"mitre-attack","external_id":"T1059.004"`, `"kill_chain_phases":[{"kill_chain_name":"other-chain","phase_name":"execution"}],
 "external_references":[{"source_name":"mitre-attack","external_id":"T1059.004"`),
		"sub-technique flag without a dotted id":   one(`"name":"Old","x_mitre_domains":["enterprise-attack"],"x_mitre_deprecated":true`, `"name":"Old","x_mitre_domains":["enterprise-attack"],"x_mitre_deprecated":true,"x_mitre_is_subtechnique":true`),
		"dotted id without the sub-technique flag": one(`"name":"Unix Shell","x_mitre_domains":["enterprise-attack"],"x_mitre_is_subtechnique":true`, `"name":"Unix Shell","x_mitre_domains":["enterprise-attack"]`),
		"two mitre-attack references":              one(`{"source_name":"capec","external_id":"CAPEC-1"}`, `{"source_name":"mitre-attack","external_id":"T1060","url":"https://attack.mitre.org/techniques/T1060"}`),
		"duplicate technique id":                   one(`"external_id":"T1001"`, `"external_id":"T1000"`),
		"missing parent":                           one(`"external_id":"T1059.004"`, `"external_id":"T1058.004"`),
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := buildATTACK([]byte(edit(goodSTIX)), attackPin); !errors.Is(err, errShape) {
				t.Fatalf("got %v, want a shape error", err)
			}
		})
	}
}
