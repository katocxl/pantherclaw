// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"regexp"
	"slices"
	"strings"

	"github.com/katocxl/pantherclaw/internal/actionir"
)

// Level is a verification level (F491–F495, PAP-1 §9.3), from the weakest:
// the target's acceptance, an independent follow-up read that found the
// object, a read of a field that establishes the domain effect, and a
// confirmation from another system.
type Level string

// Verification levels.
const (
	LevelAcceptance   Level = "acceptance"
	LevelFollowUp     Level = "follow_up"
	LevelDomainEffect Level = "domain_effect"
	LevelDownstream   Level = "downstream"
)

// Levels are the verification levels from the weakest.
var Levels = []Level{LevelAcceptance, LevelFollowUp, LevelDomainEffect, LevelDownstream}

// Rank orders levels: -1 for an unknown level, then 0 (acceptance) to 3.
func (l Level) Rank() int { return slices.Index(Levels, l) }

// VerifierSpec names the follow-up read that establishes the effect of a
// write (F382) and, from G0 M7 (design decision 5, additive to format 1),
// how its observations are read: Reference finds the object after an
// accepted dispatch, Lookup after an unknown one, Expect compares what was
// observed with the action, States maps the target's status to effect
// states, and Limits says in reviewed words what the verifier does not
// establish (F489).
type VerifierSpec struct {
	Operation     string `json:"operation"`
	Establishes   string `json:"establishes"`
	WithinSeconds int    `json:"within_seconds"`

	// Level is what a confirming read reaches: follow_up (the default) or
	// domain_effect.
	Level Level `json:"level,omitzero"`
	// Required is the level the action needs before it counts as verified
	// (default acceptance); it can never exceed Level. A policy may raise
	// it per decision (G0 M7 design decision 2).
	Required  Level              `json:"required,omitzero"`
	Reference *VerifierReference `json:"reference,omitzero"`
	Lookup    *VerifierLookup    `json:"lookup,omitzero"`
	Expect    []Expectation      `json:"expect,omitzero"`
	States    *StateMap          `json:"states,omitzero"`
	Limits    string             `json:"limits,omitzero"`
	// Capture names fields a confirming read also reports, by the param
	// of a consequence they fill: a merge's verifier captures the merge
	// commit for the deployment it starts (G0 M8 W1c, HR-206).
	Capture map[string]string `json:"capture,omitzero"`
}

// Extended reports whether the verifier uses the G0 M7 fields. Only such a
// verifier is checked against the M7 rules (a dispatchable read, a
// reference for a read about another kind of target), so that a package
// that was valid before M7 stays valid: format 1 changes are additive. A
// verifier that is not extended cannot be run, and its effects are
// UNVERIFIABLE.
func (v *VerifierSpec) Extended() bool {
	return v.Level != "" || v.Required != "" || v.Reference != nil || v.Lookup != nil || len(v.Expect) > 0 ||
		v.States != nil || v.Limits != "" || len(v.Capture) > 0
}

// Reaches returns the level a confirming read of this verifier reaches.
func (v *VerifierSpec) Reaches() Level {
	if v.Level == "" {
		return LevelFollowUp
	}
	return v.Level
}

// RequiredLevel returns the level the definition requires.
func (v *VerifierSpec) RequiredLevel() Level {
	if v.Required == "" {
		return LevelAcceptance
	}
	return v.Required
}

// VerifierReference is where the gateway reads the created object's id in
// a 2xx response of the write (a JSON pointer); the value becomes the
// verifier read's target id, so it must match that read's id pattern.
type VerifierReference struct {
	FromResponse string `json:"from_response"`
}

// VerifierLookup is a read that lists objects of the write's target, used
// when the outcome was unknown and no reference came back: an item whose
// correlation field equals the dispatch's idempotency key pc-<transaction>
// is the write's effect (HR-008).
//
// From G0 M8 (W1c, additive), Match finds the item instead by fields equal
// to the action's own (a consequence that was never dispatched carries no
// idempotency key), and IDParam names the verifier read's identifier param
// that the found item's id fills: the gateway then reads the verifier for
// that item in the same lease, and its fields are the observation.
//
// Creator (G0 M8 W1c, coordinator decision D13) names who may have made a
// matched item and its statuses: an item or a status from anyone else
// does not count (the gateway reports how many items it set aside, as
// evidence, under OthersField). Statuses says how the verifier read's
// answer lists statuses, newest first: the latest counted status of each
// matched item is its verdict, a status that Earlier lists counts only
// after one of the statuses it names (a manual "inactive" proves nothing),
// and is otherwise VerdictUnproven; matched items whose verdicts differ
// give VerdictDisagreement. Both verdicts go to a person (states.reconcile).
type VerifierLookup struct {
	Operation string        `json:"operation"`
	List      ListSpec      `json:"list"`
	Match     []Expectation `json:"match,omitzero"`
	IDParam   string        `json:"id_param,omitzero"`
	Creator   *CreatorSpec  `json:"creator,omitzero"`
	Statuses  *StatusList   `json:"statuses,omitzero"`
}

// CreatorSpec is where an item or a status names its creator, and the
// reviewed creators that count.
type CreatorSpec struct {
	Field string   `json:"field"`
	OneOf []string `json:"one_of"`
}

// StatusList is how a verifier read lists an item's statuses.
type StatusList struct {
	Items   string              `json:"items"`
	Field   string              `json:"field"`
	Earlier map[string][]string `json:"earlier,omitzero"`
}

// Verdicts the gateway reports for a matched lookup with statuses, besides
// the statuses themselves; a package lists both under states.reconcile.
const (
	VerdictDisagreement = "disagreement"
	VerdictUnproven     = "unproven"
)

// OthersField is the field under which the gateway reports how many listed
// items matched but were made by someone the lookup's creator does not
// name.
const OthersField = "/others"

// ListSpec says how a listing response is read. Every field is a JSON
// pointer (RFC 6901) except PageParam, the read's identifier parameter the
// gateway sets to the last item's id to fetch the next page while More is
// true.
type ListSpec struct {
	Items     string `json:"items"`
	ID        string `json:"id"`
	Correlate string `json:"correlate"`
	More      string `json:"more,omitzero"`
	PageParam string `json:"page_param,omitzero"`
	Created   string `json:"created,omitzero"`
}

// Expectation requires an observed field (a JSON pointer) to equal a
// canonical field of the action (target.id, params.<name>, or a money
// param's .value or .currency).
type Expectation struct {
	Field  string `json:"field"`
	Equals string `json:"equals"`
}

// StateMap maps the target's status field to effect states: confirmed,
// pending (propagation) and none (the effect did not happen). Reconcile
// (G0 M8 W1c) lists statuses that suggest the effect did not happen
// without showing it: evidence resolves only towards occurred (HR-192), so
// a person decides.
type StateMap struct {
	Field     string   `json:"field"`
	Confirmed []string `json:"confirmed"`
	Pending   []string `json:"pending,omitzero"`
	None      []string `json:"none,omitzero"`
	Reconcile []string `json:"reconcile,omitzero"`
}

// TargetLog is a package-level, reviewed read that lists the objects the
// target created since a time (HR-112, G0 M7 design decision 6). Its
// target is the connection itself (type pc.connection); SinceParam is its
// integer parameter (unix seconds) the server fills; EffectOf is the write
// whose effects the listing shows, correlated by its idempotency key.
type TargetLog struct {
	Operation  string   `json:"operation"`
	EffectOf   string   `json:"effect_of"`
	SinceParam string   `json:"since_param"`
	List       ListSpec `json:"list"`
}

// ConnectionTarget is the target type of a read that is about the
// connection as a whole, such as a target log.
const ConnectionTarget = "pc.connection"

const (
	maxExpect     = 16
	maxStates     = 16
	maxTargetLogs = 16
)

var (
	// pointerRe is an RFC 6901 JSON pointer of 1..8 tokens, each 1..64
	// characters of a conservative alphabet (escapes ~0 and ~1 only).
	pointerRe = regexp.MustCompile(`^(/([A-Za-z0-9_.-]|~[01]){1,64}){1,8}$`)
	// creatorRe is a GitHub login, an App's bot name (name[bot]) or an
	// App's slug.
	creatorRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}(\[bot\])?$`)
	statusRe  = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
)

// ValidPointer reports whether p is a JSON pointer a package may use.
func ValidPointer(p string) bool { return pointerRe.MatchString(p) }

func (l ListSpec) validate(at string, matched bool) error {
	for name, p := range map[string]string{"items": l.Items, "id": l.ID, "correlate": l.Correlate} {
		if (name == "correlate" && matched && p == "") || (name == "items" && p == "") {
			continue // a matched lookup needs no idempotency key; items "" is a listing that is the whole answer
		}
		if !pointerRe.MatchString(p) {
			return invalid("%s.%s must be a JSON pointer", at, name)
		}
	}
	for name, p := range map[string]string{"more": l.More, "created": l.Created} {
		if p != "" && !pointerRe.MatchString(p) {
			return invalid("%s.%s must be a JSON pointer", at, name)
		}
	}
	if l.PageParam != "" && (!nameRe.MatchString(l.PageParam) || l.More == "") {
		return invalid("%s.page_param names an identifier param and needs more", at)
	}
	return nil
}

// validateVerifier checks a definition's verifier on its own; the
// operations it names are checked by Package.Validate.
func (d *Definition) validateVerifier() error {
	v := d.Verifier
	if v == nil {
		return nil
	}
	op, at := d.Operation, d.Operation+": verifier"
	switch {
	case !actionir.ValidOperation(v.Operation) || !kindRe.MatchString(v.Establishes) || v.WithinSeconds <= 0 || v.WithinSeconds > maxSecond:
		return invalid("%s needs an operation, what it establishes and 1..%d within_seconds", at, maxSecond)
	case v.Extended() && d.Access != AccessWrite:
		return invalid("%s: only write operations declare how a verifier reads", op)
	case v.Level != "" && v.Level != LevelFollowUp && v.Level != LevelDomainEffect:
		return invalid("%s.level must be follow_up or domain_effect", at)
	case v.Required != "" && v.Required.Rank() < 0:
		return invalid("%s.required must be one of %v", at, Levels)
	case v.RequiredLevel().Rank() > v.Reaches().Rank():
		return invalid("%s.required %s is above what it reaches (%s)", at, v.RequiredLevel(), v.Reaches())
	case v.Reference != nil && !pointerRe.MatchString(v.Reference.FromResponse):
		return invalid("%s.reference.from_response must be a JSON pointer", at)
	case len(v.Expect) > maxExpect:
		return invalid("%s: at most %d expectations", at, maxExpect)
	}
	if l := v.Lookup; l != nil {
		if !actionir.ValidOperation(l.Operation) {
			return invalid("%s.lookup.operation %q", at, l.Operation)
		}
		matched := len(l.Match) > 0
		switch {
		case !matched && !d.Retry.TargetIdempotency:
			return invalid("%s.lookup correlates by the idempotency key, so it needs target_idempotency", at)
		case !matched && l.IDParam != "":
			return invalid("%s.lookup.id_param needs match", at)
		case matched && (l.List.Correlate != "" || (l.IDParam != "" && !nameRe.MatchString(l.IDParam))):
			return invalid("%s.lookup.match replaces correlate and needs id_param", at)
		case len(l.Match) > maxExpect:
			return invalid("%s.lookup: at most %d matches", at, maxExpect)
		}
		seen := map[string]bool{}
		for _, m := range l.Match {
			if !pointerRe.MatchString(m.Field) || seen[m.Field] || !strings.HasPrefix(m.Equals, "params.") {
				return invalid("%s.lookup.match: field %q must be a JSON pointer, once, equal to a param", at, m.Field)
			}
			seen[m.Field] = true
			if err := d.reference(at+".lookup.match", m.Equals, inArgs); err != nil {
				return err
			}
		}
		if err := l.List.validate(at+".lookup.list", matched); err != nil {
			return err
		}
		if c := l.Creator; c != nil {
			if !matched || !pointerRe.MatchString(c.Field) || len(c.OneOf) == 0 || len(c.OneOf) > maxExpect {
				return invalid("%s.lookup.creator needs match, a field pointer and 1..%d creators", at, maxExpect)
			}
			for _, who := range c.OneOf {
				if !creatorRe.MatchString(who) {
					return invalid("%s.lookup.creator: %q is not a login or App name", at, who)
				}
			}
		}
		if s := l.Statuses; s != nil {
			if l.IDParam == "" || (s.Items != "" && !pointerRe.MatchString(s.Items)) || !pointerRe.MatchString(s.Field) ||
				v.States == nil || v.States.Field != s.Field ||
				!slices.Contains(v.States.Reconcile, VerdictDisagreement) || !slices.Contains(v.States.Reconcile, VerdictUnproven) {
				return invalid("%s.lookup.statuses needs id_param, a field that states.field names, and states.reconcile with %s and %s",
					at, VerdictDisagreement, VerdictUnproven)
			}
			for state, after := range s.Earlier {
				if !statusRe.MatchString(state) || len(after) == 0 {
					return invalid("%s.lookup.statuses.earlier: %q needs the statuses it follows", at, state)
				}
				for _, a := range after {
					if !statusRe.MatchString(a) {
						return invalid("%s.lookup.statuses.earlier: %q is not a status", at, a)
					}
				}
			}
		}
	}
	seen := map[string]bool{}
	for _, e := range v.Expect {
		if !pointerRe.MatchString(e.Field) || seen[e.Field] {
			return invalid("%s.expect: field %q must be a JSON pointer, once", at, e.Field)
		}
		seen[e.Field] = true
		if strings.HasPrefix(e.Equals, "target.id.") {
			return invalid("%s.expect: %s compares the whole target id, not a part of it", at, e.Field)
		}
		if err := d.reference(at+".expect", e.Equals, inArgs); err != nil {
			return err
		}
	}
	if s := v.States; s != nil {
		if !pointerRe.MatchString(s.Field) || len(s.Confirmed) == 0 {
			return invalid("%s.states needs a field pointer and confirmed values", at)
		}
		all := slices.Concat(s.Confirmed, s.Pending, s.None, s.Reconcile)
		if len(all) > maxStates {
			return invalid("%s.states: at most %d values", at, maxStates)
		}
		for i, x := range all {
			if !statusRe.MatchString(x) || slices.Contains(all[:i], x) {
				return invalid("%s.states: value %q must be a status name, listed once", at, x)
			}
		}
	}
	if len(v.Capture) > maxExpect {
		return invalid("%s: at most %d captures", at, maxExpect)
	}
	for name, ptr := range v.Capture {
		if !nameRe.MatchString(name) || !pointerRe.MatchString(ptr) {
			return invalid("%s.capture: %q must name a param and a JSON pointer", at, name)
		}
	}
	if v.Limits != "" {
		return text(at+".limits", v.Limits)
	}
	return nil
}

// validateVerifierRefs checks what a definition's verifier names against
// the package's operations (ops): the verifier names a read operation of
// this package (since M4); an extended verifier's reads are dispatchable,
// a read about another kind of target needs a reference, and a lookup
// lists the write's own target over HTTP GET.
func (d *Definition) validateVerifierRefs(ops map[string]*Definition) error {
	v := d.Verifier
	if v == nil {
		return nil
	}
	if !v.Extended() {
		if r := ops[v.Operation]; r == nil || r.Access != AccessRead {
			return invalid("%s: verifier %s must be a read operation in this package", d.Operation, v.Operation)
		}
		return nil
	}
	read, err := readOperation(d.Operation+": verifier", ops, v.Operation, false)
	if err != nil {
		return err
	}
	if read.Target.Type != d.Target.Type && v.Reference == nil {
		return invalid("%s: verifier %s reads a %s, so it needs reference.from_response", d.Operation, v.Operation, read.Target.Type)
	}
	if l := v.Lookup; l != nil {
		list, err := readOperation(d.Operation+": verifier.lookup", ops, l.Operation, true)
		if err != nil {
			return err
		}
		if list.Target.Type != d.Target.Type {
			return invalid("%s: verifier.lookup %s must list objects of the write's target %s", d.Operation, l.Operation, d.Target.Type)
		}
		if err := list.pageParam(l.List); err != nil {
			return err
		}
		if len(l.Match) > 0 && l.IDParam == "" {
			// Only the read that already returns every item needs no second
			// read by id (D284): the matched items are the observation, and
			// items that differ are a disagreement for a person (HR-191).
			if !list.PostVerificationRead() || v.Operation != l.Operation {
				return invalid("%s: verifier.lookup.match replaces correlate and needs id_param", d.Operation)
			}
			if v.States == nil || !slices.Contains(v.States.Reconcile, VerdictDisagreement) {
				return invalid("%s: verifier.states.reconcile needs %s for a lookup without id_param", d.Operation, VerdictDisagreement)
			}
		}
		if l.IDParam != "" {
			if p, ok := read.Params[l.IDParam]; !ok || (p.Type != TypeIdentifier && p.Type != TypeInteger) || !p.Required {
				return invalid("%s: lookup.id_param %q must be a required identifier or integer param of %s", d.Operation, l.IDParam, v.Operation)
			}
			for _, m := range l.Match {
				name, _, _ := strings.Cut(strings.TrimPrefix(m.Equals, "params."), ".")
				if _, ok := list.Params[name]; !ok {
					return invalid("%s: lookup.match %s must be a param %s takes", d.Operation, m.Equals, l.Operation)
				}
			}
		}
	}
	return nil
}

func (p *Package) validateTargetLogs(ops map[string]*Definition) error {
	if len(p.TargetLogs) > maxTargetLogs {
		return invalid("at most %d target logs", maxTargetLogs)
	}
	seen := map[string]bool{}
	for _, t := range p.TargetLogs {
		at := "target_logs: " + t.Operation
		read, err := readOperation(at, ops, t.Operation, true)
		if err != nil {
			return err
		}
		w := ops[t.EffectOf]
		switch {
		case read.Target.Type != ConnectionTarget:
			return invalid("%s: a target log reads the connection (target type %s)", at, ConnectionTarget)
		case w == nil || w.Access != AccessWrite || !w.Retry.TargetIdempotency:
			return invalid("%s: effect_of %q must be a write of this package with target_idempotency", at, t.EffectOf)
		case read.Params[t.SinceParam].Type != TypeInteger || read.Params[t.SinceParam].Unit != "seconds":
			return invalid("%s: since_param %q must be an integer param in seconds", at, t.SinceParam)
		case t.List.Created == "":
			return invalid("%s: list.created is required", at)
		case seen[t.Operation+" "+t.EffectOf]:
			return invalid("%s: listed twice for %s", at, t.EffectOf)
		}
		seen[t.Operation+" "+t.EffectOf] = true
		if err := t.List.validate(at+".list", false); err != nil {
			return err
		}
		if err := read.pageParam(t.List); err != nil {
			return err
		}
	}
	return nil
}

// readOperation returns op if it is a read of this package with a dispatch
// template the gateway can send: an HTTP GET, or, unless listing (which
// pages through query parameters) requires HTTP, an upstream MCP tool call.
// In M7 the gateway's verifier runs HTTP reads only; a verifier read over
// MCP makes the effect UNVERIFIABLE until it is supported.
func readOperation(at string, ops map[string]*Definition, op string, listing bool) (*Definition, error) {
	r := ops[op]
	if r == nil || r.Access != AccessRead {
		return nil, invalid("%s: %s must be a read operation in this package", at, op)
	}
	switch x := r.Dispatch; {
	case x != nil && x.HTTP != nil && r.VerificationRead(): // GET, or the D283 exception (HR-190)
	case x != nil && x.MCP != nil && !listing:
	case listing:
		return nil, invalid("%s: %s needs an HTTP GET dispatch template, or an aws-json read of exactly %s (HR-190)", at, op, ECSDescribeServicesTarget)
	default:
		return nil, invalid("%s: %s needs an HTTP GET or MCP dispatch template, or an aws-json read of exactly %s (HR-190)", at, op, ECSDescribeServicesTarget)
	}
	return r, nil
}

// HTTPReads returns the package's verification reads over HTTP, sorted: an
// HTTP GET dispatch template, or the one POST HR-190 allows (D283). They are
// the reads a gateway can make for a verifier through a connection to this
// package (in M7 the verifier runner reads over HTTP only, HR-190).
func (p *Package) HTTPReads() []string {
	var out []string
	for i := range p.Definitions {
		d := &p.Definitions[i]
		if d.VerificationRead() {
			out = append(out, d.Operation)
		}
	}
	slices.Sort(out)
	return out
}

// pageParam checks that a listing's page parameter is one of d's
// identifier params.
func (d *Definition) pageParam(l ListSpec) error {
	if l.PageParam == "" {
		return nil
	}
	if p, ok := d.Params[l.PageParam]; !ok || p.Type != TypeIdentifier || p.Required {
		return invalid("%s: page_param %q must be an optional identifier param", d.Operation, l.PageParam)
	}
	return nil
}
