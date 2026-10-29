// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"maps"
	"slices"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/authority/consequences"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/recording"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/transactions/domain"
)

// Gaps an explanation names: what is not known about a decision or its
// effect (F647).
const (
	GapUnknownConsequence  = "UNKNOWN_CONSEQUENCE"
	GapOutcomeUnknown      = "OUTCOME_UNKNOWN"
	GapNoEffectConfirmed   = "NO_EFFECT_CONFIRMED"
	GapCoveragePartial     = "COVERAGE_PARTIAL"
	GapCoverageObserveOnly = "COVERAGE_OBSERVE_ONLY"
	GapCoverageUnknown     = "COVERAGE_UNKNOWN"
	// GapMaterialUnavailable: the evaluation's sealed inputs are missing or
	// truncated, so its material values cannot be shown.
	GapMaterialUnavailable = "MATERIAL_VALUES_UNAVAILABLE"
)

// ChecklistLine is one checklist item of a decision receipt. Detail is
// built from canonical fields and records, never agent text (HR-023).
type ChecklistLine struct {
	Step     int    `json:"step"`
	Check    string `json:"check"`
	Status   string `json:"status"`
	Code     string `json:"code"`
	Detail   string `json:"detail"`
	Level    string `json:"level"`
	Decisive bool   `json:"decisive"`
}

// ExplainedGrant is the grant revision a decision used. Constraints are
// the bounds' names, or "name=value" lines for a caller with grant.read.
type ExplainedGrant struct {
	ID          string
	Revision    int
	Constraints []string
	Expires     time.Time
}

// ExplainedBudget is one budget rule at decision time: Account is the
// budget account the transaction reserved on (empty when it reserved
// nothing on the rule), Owner the grant or guardrail that owns the rule,
// Unknown what this transaction holds on it with its outcome unknown.
type ExplainedBudget struct {
	Account, Owner, Rule, Currency  string
	Limit, Reserved, Spent, Unknown string
}

// Explanation is a decision explained for people (F066, F647).
type Explanation struct {
	Decision     string
	Presentation adomain.Presentation
	// Category is the decisive check; empty for ALLOW and CONSTRAIN.
	Category  string
	Decisive  *ChecklistLine
	Operation string
	// Target is "<type>:<id>".
	Target string
	// Material are the definition's material values, never content (as
	// an approval display shows them), from the sealed inputs.
	Material    map[string]string
	Principal   string
	Environment string
	Grant       *ExplainedGrant
	Policy      string
	// Budgets are left out without budget.read.
	Budgets   []ExplainedBudget
	Gaps      []string
	Execution domain.ExecutionState
	// Consequences are the decision's consequences (G0 M17 D111).
	Consequences []ExplainedConsequence
}

// receiptClaims are what an explanation reads from a decision receipt.
type receiptClaims struct {
	Pap struct {
		Decision  string          `json:"decision"`
		Checklist []ChecklistLine `json:"checklist"`
		Identity  struct {
			Principal string `json:"principal"`
		} `json:"identity"`
		Budgets []struct {
			Level     string `json:"level"`
			Rule      string `json:"rule"`
			Currency  string `json:"currency"`
			Available string `json:"available"`
			Reserved  string `json:"reserved"`
			Spent     string `json:"spent"`
		} `json:"budgets"`
		Consequences []receiptConsequence `json:"consequences"`
		Monitor      bool                 `json:"monitor"`
		Coverage     *struct {
			Unavailable string `json:"unavailable"`
			State       string `json:"state"`
		} `json:"coverage"`
	} `json:"pap"`
}

// receiptConsequence is what a decision receipt says of a consequence (G0
// M8; from pipeline 6 also its source, chain, words, facts and validity,
// G0 M17 D111).
type receiptConsequence struct {
	Rule         string   `json:"rule"`
	State        string   `json:"state"`
	Operation    string   `json:"op"`
	Target       string   `json:"target"`
	Environments []string `json:"envs"`
	Source       string   `json:"src"`
	Chain        []string `json:"chain"`
	Description  string   `json:"desc"`
	Evidence     []string `json:"evidence"`
	ValidUntil   string   `json:"until"`
}

// ExplainedConsequence is one consequence of a decision, explained (G0 M17
// D111; F407, F409, F410): the rule and where it comes from, the chain to
// it, what it is about, the names of the facts the rule needs (never
// their values), its validity, why an UNKNOWN one could not be ruled out,
// and what it is now.
type ExplainedConsequence struct {
	Rule, Source      string
	Chain             []string
	Operation, Target string
	Environments      []string
	Description       string
	Evidence          []string
	ValidUntil        string
	UnknownLinks      []string
	Label             consequences.Label
}

// explainedConsequences labels the receipt's consequences (D111): a
// predicted one is AUTHORIZED under an enforced permit, ACCEPTED once its
// consequence transaction was opened, CONFIRMED once every such
// transaction's effect is CONFIRMED. rows say, in the same order, why an
// UNKNOWN one could not be ruled out.
func explainedConsequences(cs []receiptConsequence, permits bool, rows []dbq.ExplanationConsequencesRow,
	children []dbq.ExplanationConsequenceTransactionsRow,
) []ExplainedConsequence {
	out := make([]ExplainedConsequence, 0, len(cs))
	for i, c := range cs {
		source := c.Source
		if source == "" {
			source = string(consequences.SourcePackage)
		}
		chain := c.Chain
		if len(chain) == 0 {
			chain = []string{c.Rule}
		}
		e := ExplainedConsequence{
			Rule: c.Rule, Source: source, Chain: chain, Operation: c.Operation, Target: c.Target, Environments: c.Environments,
			Description: c.Description, Evidence: c.Evidence, ValidUntil: c.ValidUntil,
		}
		if i < len(rows) && rows[i].RuleID == c.Rule {
			_ = json.Unmarshal(rows[i].Unknown, &e.UnknownLinks)
		}
		accepted, confirmed := false, true
		for _, t := range children {
			if t.Operation == c.Operation && t.TargetType+":"+t.TargetID == c.Target {
				accepted = true
				confirmed = confirmed && t.EffectState == string(domain.Confirmed)
			}
		}
		e.Label = consequences.LabelOf(consequences.State(c.State), permits, accepted, accepted && confirmed)
		out = append(out, e)
	}
	return out
}

// explainInputs are the records an explanation is built from besides the
// evidence itself.
type explainInputs struct {
	facts dbq.ExplanationFactsRow
	// material are the decisive evaluation's material values, opened from
	// its sealed inputs; materialOK is false when they could not be.
	material   map[string]string
	materialOK bool
	// grant is the grant revision's expiry and bounds; nil when unread.
	grant *dbq.ExplanationGrantRevisionRow
	// unknown is what the transaction holds per "<owner>/<rule>" with its
	// outcome unknown.
	unknown map[string]money.Decimal
	// accounts is the budget account the transaction reserved on per
	// "<owner>/<rule>"; a rule it reserved nothing on has none.
	accounts      map[string]string
	grantValues   bool
	budgetsShown  bool
	grantID       string
	grantRevision int
	// consequences are why each consequence of the latest evaluation could
	// not be ruled out, and children the consequence transactions opened
	// (D111).
	consequences []dbq.ExplanationConsequencesRow
	children     []dbq.ExplanationConsequenceTransactionsRow
}

// readExplainInputs reads the records an explanation needs, in the
// evidence read's transaction. Budgets need budget.read and constraint
// values grant.read where the agent lives, besides evidence.read.
func readExplainInputs(ctx context.Context, c tenancy.Caller, q *dbq.Queries, ev *Evidence) (explainInputs, error) {
	var in explainInputs
	id := ev.Transaction.ID
	f, err := q.ExplanationFacts(ctx, c.Org, id)
	if err != nil {
		return in, err
	}
	in.facts = f
	if in.consequences, err = q.ExplanationConsequences(ctx, c.Org, id); err != nil {
		return in, err
	}
	if in.children, err = q.ExplanationConsequenceTransactions(ctx, c.Org, id); err != nil {
		return in, err
	}
	if in.budgetsShown, err = NewAgentScope(c, q, td.PermBudgetRead).Can(ctx, ev.Transaction.Agent); err != nil {
		return in, err
	}
	if in.grantValues, err = NewAgentScope(c, q, td.PermGrantRead).Can(ctx, ev.Transaction.Agent); err != nil {
		return in, err
	}
	if ev.Basis != nil {
		for _, l := range ev.Basis.Levels {
			if l.Kind == "grant" {
				in.grantID, in.grantRevision = l.ID, l.Revision
			}
		}
	}
	if gid, err := ids.ParseUUID(in.grantID); err == nil {
		switch g, err := q.ExplanationGrantRevision(ctx, c.Org, gid, int32(in.grantRevision)); { //nolint:gosec // G115: a revision
		case db.IsNoRows(err):
		case err != nil:
			return in, err
		default:
			in.grant = &g
		}
	}
	if in.budgetsShown {
		holds, err := q.ExplanationUnknownHolds(ctx, c.Org, id)
		if err != nil {
			return in, err
		}
		accounts, err := q.ExplanationBudgetAccounts(ctx, c.Org, id)
		if err != nil {
			return in, err
		}
		in.accounts = map[string]string{}
		for _, a := range accounts {
			if k := a.OwnerID.String() + "/" + a.Rule; in.accounts[k] == "" {
				in.accounts[k] = a.ID.String()
			}
		}
		in.unknown = map[string]money.Decimal{}
		for _, h := range holds {
			k := h.OwnerID.String() + "/" + h.Rule
			sum, err := in.unknown[k].Add(h.Amount)
			if err != nil {
				return in, err
			}
			in.unknown[k] = sum
		}
	}
	return in, nil
}

// explain builds the explanation of the latest decision; nil when the
// transaction has no readable decision receipt.
func explain(ev *Evidence, in explainInputs) *Explanation {
	if len(ev.Decisions) == 0 {
		return nil
	}
	var claims receiptClaims
	if !payload(ev.Decisions[len(ev.Decisions)-1].JWS, &claims) {
		return nil
	}
	t := ev.Transaction
	out := &Explanation{
		Decision: t.Decision, Presentation: adomain.Decision(t.Decision).Presentation(), Operation: t.Operation,
		Principal: claims.Pap.Identity.Principal, Execution: t.Execution, Material: map[string]string{},
	}
	if in.facts.TargetType != "" {
		out.Target = in.facts.TargetType + ":" + in.facts.TargetID
	}
	if !in.facts.EnvironmentID.IsZero() {
		out.Environment = in.facts.EnvironmentID.String()
	}
	for i, it := range claims.Pap.Checklist {
		if it.Decisive {
			out.Decisive = &claims.Pap.Checklist[i]
			if out.Presentation.Explains() {
				out.Category = it.Check
			}
			break
		}
	}
	if in.materialOK {
		out.Material = in.material
	}
	if ev.Basis != nil {
		out.Policy = ev.Basis.Policy
	}
	if in.grantID != "" {
		out.Grant = &ExplainedGrant{ID: in.grantID, Revision: in.grantRevision}
		if in.grant != nil {
			out.Grant.Expires = in.grant.ExpiresAt
			out.Grant.Constraints = constraints(in.grant.Bounds, in.grantValues)
		}
	}
	if in.budgetsShown {
		for _, b := range claims.Pap.Budgets {
			eb := ExplainedBudget{Account: in.accounts[b.Level+"/"+b.Rule], Owner: b.Level, Rule: b.Rule, Currency: b.Currency, Reserved: b.Reserved, Spent: b.Spent}
			eb.Limit = limitOf(b.Available, b.Reserved, b.Spent)
			if u, ok := in.unknown[b.Level+"/"+b.Rule]; ok {
				eb.Unknown = u.String()
			}
			out.Budgets = append(out.Budgets, eb)
		}
	}
	out.Consequences = explainedConsequences(claims.Pap.Consequences, adomain.Decision(t.Decision).Permits() && !claims.Pap.Monitor,
		in.consequences, in.children)
	out.Gaps = gaps(ev, claims)
	if !in.materialOK {
		out.Gaps = append(out.Gaps, GapMaterialUnavailable)
	}
	return out
}

// constraints are a grant revision's bound names, sorted, or with values
// "name=<compact JSON>" lines.
func constraints(bounds []byte, values bool) []string {
	var m map[string]jsontext.Value
	if json.Unmarshal(bounds, &m) != nil {
		return nil
	}
	var out []string
	for _, k := range slices.Sorted(maps.Keys(m)) {
		if !values {
			out = append(out, k)
			continue
		}
		v := m[k].Clone()
		if v.Compact() != nil {
			continue
		}
		out = append(out, k+"="+string(v))
	}
	return out
}

// limitOf is a budget's limit at decision time: what was available plus
// what was reserved and spent; empty for a rule that only counts.
func limitOf(available, reserved, spent string) string {
	if available == "" {
		return ""
	}
	sum := money.Decimal{}
	for _, s := range []string{available, reserved, spent} {
		if s == "" {
			continue
		}
		d, err := money.Parse(s)
		if err != nil {
			return ""
		}
		if sum, err = sum.Add(d); err != nil {
			return ""
		}
	}
	return sum.String()
}

// gaps are what is not known: a consequence not ruled out, an unknown
// outcome, an executed action with no confirmed effect, and coverage that
// was not enforced or not known at decision time.
func gaps(ev *Evidence, claims receiptClaims) []string {
	var out []string
	if slices.ContainsFunc(claims.Pap.Consequences, func(c receiptConsequence) bool { return c.State == "UNKNOWN" }) {
		out = append(out, GapUnknownConsequence)
	}
	t := ev.Transaction
	unknown := (ev.Execution != nil && ev.Execution.Outcome == "unknown") || t.Effect == domain.Unknown
	if unknown {
		out = append(out, GapOutcomeUnknown)
	}
	if ev.Execution != nil && t.Effect != domain.Confirmed {
		out = append(out, GapNoEffectConfirmed)
	}
	switch c := claims.Pap.Coverage; {
	case c == nil || c.Unavailable != "" || c.State == "UNKNOWN":
		out = append(out, GapCoverageUnknown)
	case c.State == "PARTIAL":
		out = append(out, GapCoveragePartial)
	case c.State == "OBSERVE_ONLY":
		out = append(out, GapCoverageObserveOnly)
	}
	return out
}

// Recordings opens an evaluation's sealed inputs and the definition they
// pin: the replay engine's opener and source (F066). Like a replay, it
// needs only evidence.read.
type Recordings interface {
	RecordedInputs(ctx context.Context, org ids.OrgID, txn ids.UUID, evaluation int) (*recording.Recording, error)
	Definition(ctx context.Context, org ids.OrgID, pin actionir.Definition) (pipeline.Pinned, error)
}

// recordedMaterial are an evaluation's material values: each material
// parameter of the definition that is not content, written as an approval
// display writes it. ok is false when the inputs are missing, truncated or
// unreadable, when no opener or sealing key is configured (the opener's
// error), or when no recordings are configured (rows26 D12b).
func recordedMaterial(ctx context.Context, r Recordings, org ids.OrgID, txn ids.UUID, evaluation int) (map[string]string, bool) {
	if r == nil {
		return nil, false
	}
	rec, err := r.RecordedInputs(ctx, org, txn, evaluation)
	if err != nil || rec == nil {
		return nil, false
	}
	p, err := actionir.Parse(rec.Request.Action)
	if err != nil {
		return nil, false
	}
	pinned, err := r.Definition(ctx, org, p.Action.Definition)
	if err != nil || pinned.Definition == nil {
		return nil, false
	}
	vals, err := pinned.Definition.DecodeParams(p.Action.Params)
	if err != nil {
		return nil, false
	}
	out := map[string]string{}
	for name, spec := range pinned.Definition.Params {
		v, ok := vals[name]
		if !ok || !spec.Material || spec.Type == defs.TypeContent {
			continue
		}
		out[name] = apdomain.FormatValue(v, spec)
	}
	return out, true
}
