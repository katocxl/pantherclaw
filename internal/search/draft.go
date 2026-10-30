// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package search

import (
	"context"
	"encoding/json/v2"
	"maps"
	"slices"
	"strings"
	"time"

	modelapp "github.com/katocxl/pantherclaw/internal/model/app"
	"github.com/katocxl/pantherclaw/internal/model/ports"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// Drafted queries (G0 M21 D304; F304, HR-543, HR-544, T-235). Ask stays
// deterministic and nothing here runs: a person's text goes to the
// organization's own model, and what comes back is read strictly and then
// rebuilt with the same parser as Interpret, under the viewer's permissions.
// The model sees no record, so it cannot name one by id: it returns the
// phrases of the person's own text, and those are resolved here. A record
// the viewer may not read reads exactly like one that does not exist. The
// result is shown with its generated query, for the person to run or not.

// ModelCaller is the audited path to a provider (model/app.Service).
type ModelCaller interface {
	Draft(ctx context.Context, call modelapp.Call) (modelapp.Result, error)
}

// Drafter drafts queries through a model. It is apart from Service so search
// itself has no path to a provider.
type Drafter struct {
	Search *Service
	Model  ModelCaller
}

// QueryDraft is a drafted query, shown and never run. Interpretation says how
// it was read, as Interpret does; Thresholds are the vague terms the reviewer
// confirms.
type QueryDraft struct {
	Interpretation Interpretation
	Thresholds     []modelapp.Ambiguity
	Call           ids.UUID
}

const maxDraftNames = 8

// draftName is a phrase of the person's text that names a record.
type draftName struct {
	Phrase string `json:"phrase"`
	Kind   string `json:"kind"`
}

// queryOutput is the whole answer to a query draft. It has no id or free
// filter: every value below is checked against a closed list or resolved
// under the viewer's permissions.
type queryOutput struct {
	Entity      string               `json:"entity"`
	Builtin     string               `json:"builtin"`
	Environment string               `json:"environment"`
	Outcomes    []string             `json:"outcomes"`
	Time        string               `json:"time"`
	Names       []draftName          `json:"names"`
	Ambiguities []modelapp.Ambiguity `json:"ambiguities"`
}

// draftNameKinds are the kinds a name may be. An operation is read from the
// catalog instead.
var draftNameKinds = map[string][]FindKind{
	"agent": {FindAgents}, "connection": {FindConnections}, "automation": {FindAutomations},
	"person": {FindPeople}, "service_account": {FindServiceAccounts}, "operation": nil,
}

// draftBuiltins are the built-in queries a draft may name.
var draftBuiltins = []Builtin{
	BuiltinProductionAccess, BuiltinWhyAllowed, BuiltinToolCapability, BuiltinUnusedGrants, BuiltinActionsForPrincipal,
	BuiltinConnectionDependents, BuiltinDenials, BuiltinRecentAuthorityChange, BuiltinWhoCanWrite, BuiltinWidestExposure,
}

// withNone is names and the empty value that means "not this".
func withNone(names []string) []string {
	return append([]string{""}, names...)
}

func querySchema(viewable []string) ports.Schema {
	builtins := make([]string, 0, len(draftBuiltins))
	for _, b := range draftBuiltins {
		builtins = append(builtins, string(b))
	}
	envs := slices.Sorted(maps.Values(environments))
	return ports.Object(map[string]ports.Schema{
		"entity":      ports.Enum(withNone(viewable)),
		"builtin":     ports.Enum(withNone(builtins)),
		"environment": ports.Enum(withNone(slices.Compact(envs))),
		"outcomes":    ports.Array(ports.Enum(slices.Sorted(maps.Keys(outcomes)))),
		"time": ports.Text("empty, or one of: today; yesterday; this week; last N hours; last N days; last N weeks; " +
			"since YYYY-MM-DD; on YYYY-MM-DD; between YYYY-MM-DD and YYYY-MM-DD"),
		"names": ports.Array(ports.Object(map[string]ports.Schema{
			"phrase": ports.Text("the name, exactly as the person wrote it"),
			"kind":   ports.Enum(slices.Sorted(maps.Keys(draftNameKinds))),
		})),
		"ambiguities": modelapp.AmbiguitySchema(),
	})
}

// viewable is the entities c may read somewhere.
func viewable(c tenancy.Caller) []string {
	out := make([]string, 0, len(entities))
	for _, e := range entities {
		if c.CanAnywhere(entityPerm[e]) {
			out = append(out, string(e))
		}
	}
	return out
}

// VisibleOperations returns the operations the caller may read.
func (d *Drafter) VisibleOperations(ctx context.Context) ([]string, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return nil, err
	}
	var out []string
	err = d.Search.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = d.Search.visibleOperations(ctx, c, tx)
		return err
	}, db.ReadOnly())
	return out, err
}

// DraftQuery turns text into a query that is shown and never run (HR-544).
func (d *Drafter) DraftQuery(ctx context.Context, text, timezone string) (QueryDraft, error) {
	c, err := searcher(ctx)
	if err != nil {
		return QueryDraft{}, err
	}
	if timezone == "" {
		timezone = "UTC"
	}
	loc, err := time.LoadLocation(timezone)
	if err != nil || timezone == "Local" {
		return QueryDraft{}, ErrInvalidQuery("timezone must be an IANA time zone name")
	}
	ops, err := d.VisibleOperations(ctx)
	if err != nil {
		return QueryDraft{}, err
	}
	seen := viewable(c)
	schema, err := querySchema(seen).Encode()
	if err != nil {
		return QueryDraft{}, err
	}
	out := QueryDraft{}
	res, err := d.Model.Draft(ctx, modelapp.Call{
		Task: ports.TaskSearchQuery, Text: text, Schema: schema,
		Catalog: ports.Catalog{Entities: seen, OperationGroups: modelapp.OperationGroups(ops)},
		Parse: func(_ ids.UUID, output []byte) error {
			var o queryOutput
			if json.Unmarshal(output, &o, json.RejectUnknownMembers(true)) != nil {
				return ports.ErrInvalidOutput
			}
			if err := modelapp.CheckAmbiguities(text, o.Ambiguities); err != nil {
				return err
			}
			in, err := d.reinterpret(ctx, c, text, timezone, loc, seen, o)
			out.Interpretation, out.Thresholds = in, o.Ambiguities
			return err
		},
	})
	if err != nil {
		return QueryDraft{}, err
	}
	out.Call = res.ID
	return out, nil
}

// reinterpret rebuilds an answer with Interpret's parser, resolving its names
// under the viewer's permissions in one read-only transaction.
func (d *Drafter) reinterpret(ctx context.Context, c tenancy.Caller, text, timezone string, loc *time.Location,
	seen []string, o queryOutput,
) (Interpretation, error) {
	s := d.Search
	var out Interpretation
	err := s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		ops, err := s.visibleOperations(ctx, c, tx)
		if err != nil {
			return err
		}
		toks, err := tokenize(o.Time)
		if err != nil {
			return ports.ErrInvalidOutput
		}
		p := &parser{
			toks: toks, used: make([]bool, len(toks)), loc: loc, now: s.now().In(loc), ops: ops,
			resolve: func(ctx context.Context, phrase string, kinds []FindKind) ([]Match, error) {
				return exactMatches(ctx, s, c, tx, phrase, kinds)
			},
			in: Interpretation{Question: text, Timezone: timezone},
		}
		if err := p.fromDraft(ctx, text, seen, o); err != nil {
			return err
		}
		out = p.in
		return nil
	}, db.ReadOnly())
	return out, err
}

// fromDraft fills the interpretation from a model's answer. A value off its
// closed list refuses the answer (HR-543); a name that does not settle on one
// record the viewer may read asks for clarification, as a question does.
func (p *parser) fromDraft(ctx context.Context, text string, seen []string, o queryOutput) error {
	if err := p.timePhrases(); err != nil || slices.Contains(p.used, false) {
		return ports.ErrInvalidOutput
	}
	switch {
	case o.Entity != "" && o.Builtin != "",
		o.Entity != "" && !slices.Contains(seen, o.Entity),
		o.Builtin != "" && !slices.Contains(draftBuiltins, Builtin(o.Builtin)),
		o.Environment != "" && !slices.Contains(slices.Collect(maps.Values(environments)), o.Environment),
		len(o.Names) > maxDraftNames:
		return ports.ErrInvalidOutput
	}
	var ocs []outcome
	for _, word := range o.Outcomes {
		oc, ok := outcomes[word]
		if !ok {
			return ports.ErrInvalidOutput
		}
		ocs = append(ocs, oc)
	}
	refs, err := p.draftRefs(ctx, text, o.Names)
	if err != nil {
		return err
	}
	if len(p.in.UnknownWords) > 0 {
		p.clarify("no record the viewer may read has these names: " + strings.Join(p.in.UnknownWords, ", "))
	}
	if len(p.in.Ambiguities) > 0 {
		p.clarify("name one record: use its id or a more exact name")
	}
	p.in.Environment = o.Environment
	if o.Builtin != "" {
		p.builtin(Builtin(o.Builtin), o.Environment, ocs, refs)
	} else {
		p.query(Entity(o.Entity), o.Environment, ocs, refs)
	}
	return nil
}

// draftRefs resolves names. A phrase must come from the person's own text, so
// a model cannot look up anything the person did not ask about.
func (p *parser) draftRefs(ctx context.Context, text string, names []draftName) ([]ref, error) {
	lower := strings.ToLower(text)
	var out []ref
	for _, n := range names {
		kinds, ok := draftNameKinds[n.Kind]
		phrase := strings.ToLower(n.Phrase)
		if !ok || phrase == "" || !printable(phrase) || !strings.Contains(lower, phrase) {
			return nil, ports.ErrInvalidOutput
		}
		var ms []Match
		switch {
		case n.Kind != "operation":
			var err error
			if ms, err = p.resolve(ctx, phrase, kinds); err != nil {
				return nil, err
			}
		case slices.Contains(p.ops, phrase):
			ms = []Match{{Kind: FindOperations, ID: phrase, Label: phrase, MatchedBy: MatchedOperation, Evidence: []string{"operation:" + phrase}}}
		default:
			ms = p.operationsNamed(phrase)
		}
		switch len(ms) {
		case 0:
			p.in.UnknownWords = append(p.in.UnknownWords, phrase)
		case 1:
			out = append(out, ref{phrase: phrase, match: ms[0]})
			p.in.Matched = append(p.in.Matched, phrase+" → "+strings.TrimSuffix(string(ms[0].Kind), "s")+" "+ms[0].ID)
		default:
			p.in.Ambiguities = append(p.in.Ambiguities, Ambiguity{Phrase: phrase, Candidates: ms})
		}
	}
	return out, nil
}
