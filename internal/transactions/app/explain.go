// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"maps"
	"slices"
	"strings"
	"time"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
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

// ExplainedBudget is one budget rule at decision time: Owner is the grant
// or guardrail that owns it, Unknown what this transaction holds on it
// with its outcome unknown.
type ExplainedBudget struct {
	Owner, Rule, Currency           string
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
	// Material are the definition's canonical material values (never
	// content): from the approval display, else the budget amount.
	Material    map[string]string
	Principal   string
	Environment string
	Grant       *ExplainedGrant
	Policy      string
	// Budgets are left out without budget.read.
	Budgets   []ExplainedBudget
	Gaps      []string
	Execution domain.ExecutionState
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
		Coverage     *struct {
			Unavailable string `json:"unavailable"`
			State       string `json:"state"`
		} `json:"coverage"`
	} `json:"pap"`
}

// receiptConsequence is a consequence rule's state in a decision receipt.
type receiptConsequence struct {
	State string `json:"state"`
}

// explainInputs are the records an explanation is built from besides the
// evidence itself.
type explainInputs struct {
	facts dbq.ExplanationFactsRow
	// display is the latest approval request's display; nil without one.
	display []byte
	// grant is the grant revision's expiry and bounds; nil when unread.
	grant *dbq.ExplanationGrantRevisionRow
	// unknown is what the transaction holds per "<owner>/<rule>" with its
	// outcome unknown.
	unknown       map[string]money.Decimal
	grantValues   bool
	budgetsShown  bool
	grantID       string
	grantRevision int
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
	switch d, err := q.ExplanationDisplay(ctx, c.Org, &id); {
	case db.IsNoRows(err):
	case err != nil:
		return in, err
	default:
		in.display = d
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
	out.Material = materialValues(in)
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
			eb := ExplainedBudget{Owner: b.Level, Rule: b.Rule, Currency: b.Currency, Reserved: b.Reserved, Spent: b.Spent}
			eb.Limit = limitOf(b.Available, b.Reserved, b.Spent)
			if u, ok := in.unknown[b.Level+"/"+b.Rule]; ok {
				eb.Unknown = u.String()
			}
			out.Budgets = append(out.Budgets, eb)
		}
	}
	out.Gaps = gaps(ev, claims)
	return out
}

// materialValues are the canonical material parameters an approval display
// recorded ("params.<name>" fields, which are never content), or else the
// transaction's budget amount and currency.
func materialValues(in explainInputs) map[string]string {
	out := map[string]string{}
	if in.display != nil {
		var d struct {
			Fields []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"fields"`
		}
		if json.Unmarshal(in.display, &d) == nil {
			for _, f := range d.Fields {
				if p, ok := strings.CutPrefix(f.Name, "params."); ok && f.Value != "" {
					out[p] = f.Value
				}
			}
		}
	}
	if len(out) == 0 && in.facts.Amount != nil {
		out["amount"] = in.facts.Amount.String()
		if in.facts.Currency != "" {
			out["currency"] = in.facts.Currency
		}
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
