// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// DisplayVersion is the version of the stored display's shape. Version 2
// (HR-030 option B, founder decision 2026-10-13) shows a fact's value only
// for the members the approval binds and never when it was observed.
const DisplayVersion = 2

// MaxContext caps the earlier approved requests shown as context (decision 9).
const MaxContext = 5

// Display is what an approver sees (HR-034, design decision 9): rendered
// when the hold is recorded, stored as structured JSON and hashed into the
// binding, so what the approver reads is what the binding covers. Every
// value comes from the pinned definition's approval template, canonical
// fields and system-of-record facts; agent- or requester-supplied text is
// only in Untrusted.
type Display struct {
	V           int         `json:"v"`
	Kind        string      `json:"kind"`
	Title       string      `json:"title"`
	Consequence Consequence `json:"consequence"`
	// Consequences are the action's predicted or unknown consequences
	// (G0 M8, F158): predictions, apart from what the action does.
	Consequences []ConsequenceLine `json:"consequences,omitzero"`
	// PayloadFindings are the credential-shaped values the gateway found in
	// the payload (HR-225): the format and where, never the value.
	PayloadFindings []PayloadFindingLine `json:"payload_findings,omitzero"`
	Fields          []Field              `json:"fields"`
	Facts           []FactLine           `json:"facts"`
	Run             *RunLine             `json:"run,omitzero"`
	Basis           []Source             `json:"basis"`
	Deciders        []DeciderRule        `json:"deciders"`
	Deadline        string               `json:"deadline"`
	Variants        []VariantLine        `json:"variants"`
	// Context lists earlier approved requests for the same operation and
	// target: context, never precedent.
	Context   []ContextLine  `json:"context_not_precedent"`
	Untrusted UntrustedBlock `json:"untrusted"`
}

// Consequence comes first: what will happen, to what, and whether it can
// be undone.
type Consequence struct {
	Operation     string          `json:"operation"`
	Summary       string          `json:"summary,omitzero"`
	Target        actionir.Target `json:"target"`
	Effects       []string        `json:"effects,omitzero"`
	Reversibility string          `json:"reversibility,omitzero"`
	Verifier      string          `json:"verifier,omitzero"`
	// Clamped is set when an obligation lowered a parameter: the fields
	// show the action that will run (F108).
	Clamped bool `json:"clamped,omitzero"`
}

// Field is one canonical field of the template. Stable ids are verbatim;
// amounts are canonical decimals with their currency.
type Field struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	// Requested is the agent's value when an obligation clamped it.
	Requested string `json:"requested,omitzero"`
}

// FactLine is one fact the decision used. Value holds only the members the
// approval binds (a merge's head SHA), and is empty for a fact it binds
// nothing of: the page shows that fact's current value and provider, which
// are read and decided on again whenever the approval is used (HR-030
// option B, founder decision 2026-10-13). Provider and ObservedAt are set
// only in a version 1 display: a fact observed again, by whichever
// provider, gives a resubmission the same binding.
type FactLine struct {
	Name       string `json:"name"`
	Subject    string `json:"subject"`
	Value      string `json:"value"`
	Provider   string `json:"provider,omitzero"`
	ObservedAt string `json:"observed_at,omitzero"`
}

// RunLine names the run by ids (readable names come from a directory
// later).
type RunLine struct {
	Run       string `json:"run"`
	Agent     string `json:"agent"`
	Instance  string `json:"instance"`
	Launcher  string `json:"launcher"`
	Principal string `json:"principal"`
}

// DeciderRule says who can decide and why: the rule, not names, because
// eligibility is checked again at every response and at use.
type DeciderRule struct {
	Kind        string `json:"kind"`
	Role        string `json:"role,omitzero"`
	Count       int    `json:"count,omitzero"`
	Independent bool   `json:"independent,omitzero"`
	Subject     string `json:"subject,omitzero"`
	// Scope says where the role must be bound.
	Scope string `json:"scope,omitzero"`
	// Window: the approval counts only inside a change window, and
	// IndependentOf names the fact listing the people it must not be
	// (G0 M8, HR-207).
	Window        bool   `json:"window,omitzero"`
	IndependentOf string `json:"independent_of,omitzero"`
}

// VariantLine is an earlier request for the same grant, operation and
// target (HR-037).
type VariantLine struct {
	Request string `json:"request"`
	Created string `json:"created"`
	State   string `json:"state"`
}

// ContextLine is an earlier approved request for the same operation and
// target.
type ContextLine struct {
	Request  string `json:"request"`
	Approved string `json:"approved"`
}

// UntrustedBlock holds agent- or requester-supplied text under a fixed
// label (HR-034).
type UntrustedBlock struct {
	Label string      `json:"label"`
	Items []Untrusted `json:"items"`
}

// ActionInput is what an action's display is rendered from.
type ActionInput struct {
	Definition *defs.Definition
	Target     actionir.Target
	// Requested are the decoded parameters; Effective the parameters after
	// obligations (equal when nothing was clamped).
	Requested defs.Values
	Effective defs.Values
	Facts     []fdomain.Fact
	// Bound are the fact members the approval binds; only their values are
	// shown (HR-030 option B).
	Bound []BoundFact
	Run   RunLine
	// TaskLabel is the run's UNTRUSTED task label.
	TaskLabel    string
	Requirements []Requirement
	Deadline     time.Time
	Variants     []VariantLine
	Context      []ContextLine
	// Attributes are UNTRUSTED reported attributes (for example a gateway's
	// observations), shown only in the untrusted block.
	Attributes map[string]string
	// Consequences are the action's predicted or unknown consequences.
	Consequences []ConsequenceInput
	// PayloadFindings are the gateway's payload findings (HR-225).
	PayloadFindings []PayloadFindingInput
}

// RenderAction renders an action's display from its template. It fails on
// a definition without an approval template or a template field it cannot
// fill, never falling back to agent text.
func RenderAction(in ActionInput) (Display, error) {
	d := in.Definition
	if d == nil || d.Approval == nil {
		return Display{}, errors.New("approvals: the definition has no approval template")
	}
	values := map[string]Field{}
	field := func(name string) (Field, error) {
		if f, ok := values[name]; ok {
			return f, nil
		}
		f, err := fieldValue(d, name, in)
		if err == nil {
			values[name] = f
		}
		return f, err
	}
	var fields []Field
	for _, name := range d.Approval.Fields {
		f, err := field(name)
		if err != nil {
			return Display{}, err
		}
		fields = append(fields, f)
	}
	title, err := fill(d.Approval.Title, field)
	if err != nil {
		return Display{}, err
	}
	out := Display{
		V: DisplayVersion, Kind: "action", Title: title, Fields: fields, Run: &in.Run,
		Consequence: Consequence{
			Operation: d.Operation, Summary: Clean("summary", d.Summary, 0).Text, Target: in.Target,
			Reversibility: string(d.Reversibility), Clamped: !sameValues(in.Requested, in.Effective),
		},
		Deadline: in.Deadline.UTC().Format(time.RFC3339),
	}
	for _, e := range d.Effects {
		out.Consequence.Effects = append(out.Consequence.Effects, e.Kind+": "+Clean("effect", e.Description, 0).Text)
	}
	if d.Verifier != nil {
		out.Consequence.Verifier = d.Verifier.Operation + " establishes " + d.Verifier.Establishes
	}
	out.Facts = factLines(in.Facts, in.Bound)
	out.Consequences = consequenceLines(in.Consequences)
	out.PayloadFindings = payloadFindingLines(in.PayloadFindings)
	out.finish(in.Requirements, in.Variants, in.Context)
	var untrusted []Untrusted
	if in.TaskLabel != "" {
		untrusted = append(untrusted, Clean("task_label", in.TaskLabel, 0))
	}
	for _, name := range slices.Sorted(maps.Keys(in.Requested)) {
		if v := in.Requested[name]; (v.Type == defs.TypeText || v.Type == defs.TypeContent) && v.Str != "" {
			untrusted = append(untrusted, Clean("param:"+name, v.Str, 0))
		}
	}
	for _, k := range slices.Sorted(maps.Keys(in.Attributes)) {
		untrusted = append(untrusted, Clean("attribute:"+Clean("", k, 64).Text, in.Attributes[k], 0))
	}
	out.Untrusted = untrustedBlock(untrusted)
	return out, nil
}

// RestorationInput is what a restoration's display is rendered from.
type RestorationInput struct {
	AgentID       ids.UUID
	SuspendedFrom string
	SuspendedAt   time.Time
	RequestedBy   ids.UUID
	Reason        string
	Requirements  []Requirement
	Deadline      time.Time
}

// RenderRestoration renders a restoration's display (decision 11). The
// requester's reason is untrusted text.
func RenderRestoration(in RestorationInput) Display {
	out := Display{
		V: DisplayVersion, Kind: "restoration",
		Title: "Restore agent " + in.AgentID.String() + " to " + in.SuspendedFrom,
		Consequence: Consequence{
			Operation: RestoreSubject, Target: actionir.Target{Type: "agent", ID: in.AgentID.String()},
			Effects: []string{"agent.state: the agent returns to " + in.SuspendedFrom + " and its runs may act again"},
		},
		Fields: []Field{
			{Name: "agent", Value: in.AgentID.String()},
			{Name: "suspended_from", Value: in.SuspendedFrom},
			{Name: "suspended_at", Value: in.SuspendedAt.UTC().Format(time.RFC3339)},
			{Name: "requested_by", Value: "user:" + in.RequestedBy.String()},
		},
		Facts: []FactLine{}, Deadline: in.Deadline.UTC().Format(time.RFC3339),
	}
	out.finish(in.Requirements, nil, nil)
	out.Untrusted = untrustedBlock([]Untrusted{Clean("reason", in.Reason, 0)})
	return out
}

func (out *Display) finish(reqs []Requirement, variants []VariantLine, context []ContextLine) {
	out.Basis, out.Deciders = []Source{}, []DeciderRule{}
	for _, r := range reqs {
		for _, s := range r.Sources {
			if !slices.Contains(out.Basis, s) {
				out.Basis = append(out.Basis, s)
			}
		}
		rule := DeciderRule{
			Kind: r.Kind, Role: r.Role, Count: r.Count, Independent: r.Independent, Subject: r.Subject, Window: r.Window,
			IndependentOf: r.IndependentOf,
		}
		if r.Kind == KindApproval {
			rule.Scope = "bound on the agent's environment, team, business unit or org"
		}
		if r.Kind == KindGate {
			rule.Scope = "holding automation.approve at the org"
		}
		out.Deciders = append(out.Deciders, rule)
	}
	out.Variants = append([]VariantLine{}, variants...)
	out.Context = append([]ContextLine{}, context[:min(len(context), MaxContext)]...)
}

func untrustedBlock(items []Untrusted) UntrustedBlock {
	if len(items) > MaxUntrustedItems {
		items = items[:MaxUntrustedItems]
	}
	if items == nil {
		items = []Untrusted{}
	}
	return UntrustedBlock{Label: UntrustedLabel, Items: items}
}

func factLines(facts []fdomain.Fact, bound []BoundFact) []FactLine {
	out := make([]FactLine, 0, len(facts))
	for _, f := range facts {
		out = append(out, FactLine{
			Name: f.Name, Subject: f.SubjectType + ":" + Clean("", f.SubjectID, 512).Text,
			Value: Clean("", boundValue(bound, f.Name, f.SubjectType+":"+f.SubjectID), 256).Text,
		})
	}
	slices.SortFunc(out, func(a, b FactLine) int { return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.Subject, b.Subject)) })
	return out
}

// fieldValue renders one canonical field: operation, target.type,
// target.id, target.account, params.<material param that is not content>
// or facts.<name of a prerequisite fact>. Content is agent-written and
// only ever untrusted.
func fieldValue(d *defs.Definition, name string, in ActionInput) (Field, error) {
	f := Field{Name: name}
	switch name {
	case "operation":
		f.Value = d.Operation
	case "target.type":
		f.Value = in.Target.Type
	case "target.id":
		f.Value = in.Target.ID
	case "target.account":
		f.Value = in.Target.Account
	default:
		if p, ok := strings.CutPrefix(name, "params."); ok {
			spec, declared := d.Params[p]
			v, present := in.Effective[p]
			if !declared || !spec.Material || spec.Type == defs.TypeContent {
				return f, fmt.Errorf("approvals: template field %q is not a canonical material parameter", name)
			}
			if present {
				f.Value = formatValue(v, spec)
			}
			if req, ok := in.Requested[p]; ok && !sameValue(req, v) {
				f.Requested = formatValue(req, spec)
			}
			return f, nil
		}
		if fact, ok := strings.CutPrefix(name, "facts."); ok {
			i := slices.IndexFunc(in.Facts, func(x fdomain.Fact) bool { return x.Name == fact })
			if i < 0 {
				return f, fmt.Errorf("approvals: template field %q names a fact the decision did not use", name)
			}
			x := in.Facts[i]
			f.Value = Clean("", boundValue(in.Bound, x.Name, x.SubjectType+":"+x.SubjectID), 256).Text
			return f, nil
		}
		return f, fmt.Errorf("approvals: template field %q is not canonical", name)
	}
	return f, nil
}

// formatValue writes a parameter canonically: money as its canonical
// decimal and currency, numbers with their unit, ids verbatim.
func formatValue(v defs.Value, spec defs.ParamSpec) string {
	unit := ""
	if spec.Unit != "" {
		unit = " " + string(spec.Unit)
	}
	switch v.Type {
	case defs.TypeMoney:
		return defs.FormatMoney(v.Money) + " " + string(v.Money.Currency)
	case defs.TypeDecimal:
		return v.Decimal.String() + unit
	case defs.TypeInteger:
		return strconv.FormatInt(v.Int, 10) + unit
	case defs.TypeBoolean:
		return strconv.FormatBool(v.Bool)
	case defs.TypeIdentifierList:
		return strings.Join(v.List, ", ")
	case defs.TypeQueryFilter:
		return filterText(v.Filter)
	case defs.TypeEnum, defs.TypeIdentifier, defs.TypeCommand, defs.TypeContent, defs.TypePath, defs.TypeText:
		return Clean("", v.Str, 0).Text
	}
	return ""
}

func sameValue(a, b defs.Value) bool {
	return a.Type == b.Type && formatValue(a, defs.ParamSpec{}) == formatValue(b, defs.ParamSpec{})
}

func sameValues(a, b defs.Values) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || !sameValue(v, w) {
			return false
		}
	}
	return true
}

// fill replaces {field} placeholders in a template title.
func fill(title string, field func(string) (Field, error)) (string, error) {
	var b strings.Builder
	rest := title
	for {
		i := strings.IndexByte(rest, '{')
		if i < 0 {
			b.WriteString(rest)
			return Clean("", b.String(), 200).Text, nil
		}
		j := strings.IndexByte(rest[i:], '}')
		if j < 0 {
			return "", errors.New("approvals: an unclosed placeholder in the template title")
		}
		b.WriteString(rest[:i])
		f, err := field(rest[i+1 : i+j])
		if err != nil {
			return "", err
		}
		b.WriteString(f.Value)
		rest = rest[i+j+1:]
	}
}

// Canonical returns the display's RFC 8785 canonical JSON and its SHA-256,
// the binding's display_hash.
func (d Display) Canonical() (Binding, error) { return canonical(d) }

// filterText shows a query filter's predicates (G0 M14 D9), each value
// cleaned like any untrusted text.
func filterText(ps []defs.Predicate) string {
	parts := make([]string, 0, len(ps))
	for _, p := range ps {
		s := p.Column + " " + p.Op
		switch {
		case p.Value != nil:
			s += " " + Clean("", *p.Value, 0).Text
		case p.Values != nil:
			vs := make([]string, len(p.Values))
			for i, v := range p.Values {
				vs[i] = Clean("", v, 0).Text
			}
			s += " (" + strings.Join(vs, ", ") + ")"
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, "; ")
}
