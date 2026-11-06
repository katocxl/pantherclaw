// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package mapdoc renders docs/security/MITRE_MAPPING.md from the declared
// technique mappings (G0 M28, F974): every technique of both MITRE
// matrices, under each of its tactics, with its place (mapped, Outside
// PantherClaw, or No PantherClaw control yet) and what PantherClaw maps to
// it. The document is generated and checked in task check, never edited by
// hand.
//
//nolint:misspell // MITRE is a proper noun (the ATT&CK and ATLAS publisher), not "miter".
package mapdoc

import (
	"bytes"
	"fmt"
	"slices"
	"strings"

	"github.com/katocxl/pantherclaw/internal/redteam/library"
	"github.com/katocxl/pantherclaw/internal/threatmap/catalog"
	"github.com/katocxl/pantherclaw/internal/threatmap/mapping"
	"github.com/katocxl/pantherclaw/internal/threatmap/mapset"
)

// Statement is the threat map's fixed statement (HR-681), word for word.
const Statement = "This map shows the PantherClaw controls mapped to each technique and the evidence for them. " +
	"A mapped control covers the technique, not every way of carrying it out. " +
	"Techniques outside PantherClaw need other tools. It is not a score or a guarantee."

var titles = map[catalog.Framework]string{
	catalog.FrameworkATLAS:  "MITRE ATLAS",
	catalog.FrameworkATTACK: "MITRE ATT&CK Enterprise",
}

var reasons = map[mapping.OutsideReason]string{
	mapping.OutsideEndpoint:            "needs an endpoint",
	mapping.OutsideNetwork:             "needs a network",
	mapping.OutsideEmail:               "needs a mailbox",
	mapping.OutsidePhysical:            "needs physical access",
	mapping.OutsideHuman:               "needs a person",
	mapping.OutsidePreCompromise:       "happens before compromise",
	mapping.OutsideCloudInfrastructure: "needs cloud infrastructure",
	mapping.OutsideIdentityProvider:    "happens at the identity provider",
	mapping.OutsideModelDevelopment:    "happens in model development",
}

var tools = map[mapping.ToolKind]string{
	mapping.ToolEDR:                "EDR",
	mapping.ToolNetworkSecurity:    "network security",
	mapping.ToolEmailSecurity:      "email security",
	mapping.ToolPhysicalSecurity:   "physical security",
	mapping.ToolSecurityAwareness:  "security awareness",
	mapping.ToolThreatIntelligence: "threat intelligence",
	mapping.ToolCloudSecurity:      "cloud security",
	mapping.ToolIdentityProvider:   "the identity provider",
	mapping.ToolModelSecurity:      "model security",
}

// Render returns the document for s, byte for byte the same for the same
// set, catalogs, library and threats. threats maps a library scenario id
// to the abuse cases (T-###) its file cites; it feeds the section
// "Techniques by abuse case", whose ids come from the library entries.
func Render(s *mapset.Set, threats map[string][]string) []byte {
	var b bytes.Buffer
	b.WriteString("# MITRE ATLAS and ATT&CK Enterprise mapping\n\n")
	b.WriteString("Generated from the code by `internal/threatmap/mapdoc`; do not edit. Regenerate with `task docs:mitre` ([G0 M28](../g0/M28.md), [ADR-0055](../adr/0055-mitre-threat-map.md)).\n\n")
	fmt.Fprintf(&b, "> %s\n\n", Statement)
	b.WriteString("Every technique of both matrices has exactly one place:\n\n")
	b.WriteString("- **Mapped:** PantherClaw controls, detection rules, signal kinds, Hub content or range scenarios are mapped to the technique or one of its sub-techniques. What the organization's map shows for it depends on that organization's evidence ([runbook](../runbooks/threat-map.md)).\n")
	b.WriteString("- **Mapped (partly):** mapped, but some of its sub-techniques have nothing mapped and no other place; they are named as not covered.\n")
	b.WriteString("- **Outside PantherClaw:** the technique needs something PantherClaw does not see; the kind of tool that covers it is named.\n")
	b.WriteString("- **No PantherClaw control yet:** the technique is within an agent platform's reach and PantherClaw ships no control for it; why is given.\n\n")
	fmt.Fprintf(&b, "Mapping digest: `%s`.\n\n", s.Digest())
	b.WriteString("| Framework | Catalogue version | Catalogue digest |\n|---|---|---|\n")
	for _, f := range catalog.Frameworks() {
		c := catalog.Load(f)
		fmt.Fprintf(&b, "| %s | %s | `%s` |\n", titles[f], cell(c.Version), catalog.Digest(f))
	}
	for _, f := range catalog.Frameworks() {
		framework(&b, f, catalog.Load(f), s.Techniques(f))
	}
	abuseCases(&b, threats)
	return b.Bytes()
}

// abuseCases writes "Techniques by abuse case" (G0 M28): one row per abuse
// case cited by a library scenario, with the sorted union of the ATLAS and
// ATT&CK ids of those scenarios' library entries. A scenario with no
// library entry, or one that maps no technique, adds nothing; an abuse case
// with no id gets no row.
func abuseCases(b *bytes.Buffer, threats map[string][]string) {
	ids := map[string][]string{}
	for sid, ts := range threats {
		e, ok := library.Lookup(sid)
		if !ok {
			continue
		}
		techniques := append(slices.Clone(e.ATLAS), e.ATTACK...)
		if len(techniques) == 0 {
			continue
		}
		for _, t := range ts {
			ids[t] = append(ids[t], techniques...)
		}
	}
	keys := make([]string, 0, len(ids))
	for t := range ids {
		keys = append(keys, t)
	}
	slices.Sort(keys)
	b.WriteString("\n## Techniques by abuse case\n\n")
	b.WriteString("Abuse cases from [THREAT_MODEL](THREAT_MODEL.md) that no library range scenario tests, or whose scenarios map to no MITRE technique, are not listed.\n\n")
	b.WriteString("| Abuse case | ATLAS | ATT&CK Enterprise |\n|---|---|---|\n")
	for _, t := range keys {
		all := ids[t]
		slices.Sort(all)
		all = slices.Compact(all)
		var atlas, attack []string
		for _, id := range all {
			if f, _ := catalog.FrameworkOf(id); f == catalog.FrameworkATLAS {
				atlas = append(atlas, id)
			} else {
				attack = append(attack, id)
			}
		}
		fmt.Fprintf(b, "| %s | %s | %s |\n", cell(t), orDash(atlas), orDash(attack))
	}
}

func orDash(ids []string) string {
	if len(ids) == 0 {
		return "—"
	}
	return strings.Join(ids, ", ")
}

func framework(b *bytes.Buffer, f catalog.Framework, c *catalog.Catalog, m map[string]mapset.TechniqueMappings) {
	fmt.Fprintf(b, "\n## %s\n", titles[f])
	tactics := slices.Clone(c.Tactics)
	slices.SortStableFunc(tactics, func(x, y catalog.Tactic) int { return x.Order - y.Order })
	matrix := c.Matrix()
	slices.SortStableFunc(matrix, func(x, y catalog.Technique) int {
		if n := strings.Compare(x.Name, y.Name); n != 0 {
			return n
		}
		return strings.Compare(x.ID, y.ID)
	})
	for _, ta := range tactics {
		var rows []catalog.Technique
		for _, t := range matrix {
			if slices.Contains(t.Tactics, ta.ShortName) {
				rows = append(rows, t)
			}
		}
		if len(rows) == 0 {
			continue
		}
		fmt.Fprintf(b, "\n### %s (%s)\n\n", cell(ta.Name), ta.ID)
		b.WriteString("| Technique | Name | Place | Mapped to it |\n|---|---|---|---|\n")
		for _, t := range rows {
			place, detail := placeOf(c, t, m)
			fmt.Fprintf(b, "| [%s](%s) | %s | %s | %s |\n", t.ID, t.URL, cell(t.Name), place, detail)
		}
	}
}

// placeOf says where a matrix technique sits and what maps to it (D712:
// a technique's mappings include its sub-techniques').
func placeOf(c *catalog.Catalog, t catalog.Technique, m map[string]mapset.TechniqueMappings) (place, detail string) {
	own := m[t.ID]
	switch {
	case own.Outside != nil:
		o := own.Outside
		place = "Outside PantherClaw: covered by " + tools[o.CoveredBy]
		detail = "It " + reasons[o.Reason] + "."
		if o.Note != "" {
			detail += " " + cell(o.Note)
		}
		return place, detail
	case own.Unaddressed != nil:
		return "No PantherClaw control yet", cell(own.Unaddressed.Why)
	}
	var parts, uncovered []string
	if s := listed(own); s != "" {
		parts = append(parts, s)
	}
	for _, sub := range c.Subtechniques(t.ID) {
		sm := m[sub.ID]
		switch {
		case sm.Outside != nil:
			parts = append(parts, sub.ID+": Outside PantherClaw, covered by "+tools[sm.Outside.CoveredBy])
		case sm.Unaddressed != nil:
			parts = append(parts, sub.ID+": No PantherClaw control yet")
		default:
			if s := listed(sm); s != "" {
				parts = append(parts, sub.ID+": "+s)
			} else {
				uncovered = append(uncovered, sub.ID)
			}
		}
	}
	if len(parts) == 0 {
		return "Not placed", "—"
	}
	// A parent counts as mapped when one of its sub-techniques is (D712);
	// the sub-techniques nothing maps to are named, so the row never reads
	// as covering them (D1221a R1).
	if len(uncovered) > 0 {
		for _, id := range uncovered {
			parts = append(parts, id+" not covered")
		}
		return "Mapped (partly)", strings.Join(parts, "<br>")
	}
	return "Mapped", strings.Join(parts, "<br>")
}

func listed(m mapset.TechniqueMappings) string {
	var parts []string
	add := func(label string, ids []string) {
		if len(ids) > 0 {
			parts = append(parts, label+" "+code(ids))
		}
	}
	add("prevent", m.Prevent)
	add("rules", m.Rules)
	add("kinds", m.Kinds)
	add("Hub rules", m.HubRules)
	add("Hub playbooks", m.HubPlaybooks)
	add("scenarios", m.Scenarios)
	add("campaigns", m.Campaigns)
	return strings.Join(parts, "; ")
}

func code(ids []string) string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = "`" + cell(id) + "`"
	}
	return strings.Join(out, ", ")
}

// cell keeps text on one line inside a table cell.
func cell(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	return strings.ReplaceAll(s, "|", `\|`)
}
