// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"encoding/json/v2"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	bdomain "github.com/katocxl/pantherclaw/internal/budgets/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// Limits are the budget and count rules of a grant or an envelope (F110,
// F111, F112, F121). Numbers are decimal strings, as everywhere else.
type Limits struct {
	Budgets  []BudgetRule `json:"budgets,omitzero"`
	Counters []CountRule  `json:"counters,omitzero"`
}

// BudgetRule limits the value and/or the number of the actions it covers,
// per grouping and period. A grant's rules are task budgets (grouping
// "task"), shared by its runs and by every grant delegated from it; an
// envelope's rules group by principal, account, team or org.
type BudgetRule struct {
	ID         string           `json:"id"`
	Grouping   bdomain.Grouping `json:"grouping"`
	Operations Ops              `json:"operations"`
	Currency   string           `json:"currency,omitzero"`
	Limit      string           `json:"limit,omitzero"`
	MaxCount   string           `json:"max_count,omitzero"`
	Period     bdomain.Period   `json:"period"`
}

// CountRule limits how many of the actions it covers may happen per key
// and window (HR-049). Key is one of: task (the declaring grant, or for an
// envelope the run's grant), run, principal, target, account, or
// params.<name> for an enum or identifier parameter. MaxOutstanding, when
// set, also bounds the actions reserved but not yet settled.
type CountRule struct {
	ID             string         `json:"id"`
	Operations     Ops            `json:"operations"`
	Key            string         `json:"key"`
	Window         bdomain.Window `json:"window"`
	Max            string         `json:"max"`
	MaxOutstanding string         `json:"max_outstanding,omitzero"`
}

const (
	maxRules      = 16
	maxCountValue = 1_000_000_000
)

var (
	ruleIDPattern  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	countKeyFormat = regexp.MustCompile(`^(task|run|principal|target|account|params\.[a-z][a-z0-9_]{0,63})$`)
)

func parseCount(name, s string) (int64, error) {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 1 || n > maxCountValue || strconv.FormatInt(n, 10) != s {
		return 0, invalid("%s: %q is not a whole number from 1 to %d", name, s, maxCountValue)
	}
	return n, nil
}

// validate checks the limits; onGrant says whether a grant declares them.
func (l Limits) validate(onGrant bool) error {
	if len(l.Budgets) > maxRules || len(l.Counters) > maxRules {
		return invalid("limits: at most %d budgets and %d counters", maxRules, maxRules)
	}
	seen := map[string]bool{}
	for _, r := range l.Budgets {
		name := "budgets." + r.ID
		if !ruleIDPattern.MatchString(r.ID) || seen[r.ID] {
			return invalid("%s: rule ids are unique lowercase names", name)
		}
		seen[r.ID] = true
		if err := r.Operations.validate(name + ".operations"); err != nil || len(r.Operations) == 0 {
			return invalid("%s: name the operations it covers", name)
		}
		switch {
		case !r.Grouping.Valid():
			return invalid("%s: unknown grouping %q", name, r.Grouping)
		case onGrant && r.Grouping != bdomain.GroupTask:
			return invalid("%s: a grant's budgets are task budgets", name)
		case !onGrant && r.Grouping == bdomain.GroupTask:
			return invalid("%s: task budgets belong on grants", name)
		case !r.Period.Valid():
			return invalid("%s: unknown period %q", name, r.Period)
		case (r.Currency == "") != (r.Limit == ""):
			return invalid("%s: currency and limit go together", name)
		case r.Limit == "" && r.MaxCount == "":
			return invalid("%s: set a limit, a max_count or both", name)
		}
		if r.Limit != "" {
			m, err := money.ParseMoney(r.Limit, r.Currency)
			if err != nil || m.Amount.Sign() < 0 {
				return invalid("%s: limit %q %q is not a non-negative amount", name, r.Limit, r.Currency)
			}
		}
		if r.MaxCount != "" {
			if _, err := parseCount(name+".max_count", r.MaxCount); err != nil {
				return err
			}
		}
	}
	seen = map[string]bool{}
	for _, r := range l.Counters {
		name := "counters." + r.ID
		if !ruleIDPattern.MatchString(r.ID) || seen[r.ID] {
			return invalid("%s: rule ids are unique lowercase names", name)
		}
		seen[r.ID] = true
		if err := r.Operations.validate(name + ".operations"); err != nil || len(r.Operations) == 0 {
			return invalid("%s: name the operations it covers", name)
		}
		if !countKeyFormat.MatchString(r.Key) {
			return invalid("%s: unknown key %q", name, r.Key)
		}
		if !r.Window.Valid() {
			return invalid("%s: unknown window %q", name, r.Window)
		}
		if _, err := parseCount(name+".max", r.Max); err != nil {
			return err
		}
		if r.MaxOutstanding != "" {
			if _, err := parseCount(name+".max_outstanding", r.MaxOutstanding); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkDispatched refuses a budget or counter that names an operation
// which is only ever a consequence (G0 M8, HR-206): the pipeline decides a
// predicted or unknown consequence with the action that may cause it, but
// never dispatches or reserves it, so the rule would never count anything.
// Such an operation is a write without mappings, which a package defines
// only as a consequence of its own rules. lookup gives the active
// definition of an exact operation. One with none is accepted: limits may
// be set before the package that defines it is installed. A prefix limits
// the dispatched operations it covers and is not resolved.
func (l Limits) checkDispatched(lookup func(op string) *defs.Definition) error {
	if lookup == nil {
		return nil
	}
	check := func(name string, ops Ops) error {
		for _, op := range ops {
			if _, prefix := opPrefix(op); prefix {
				continue
			}
			if d := lookup(op); d != nil && d.Access == defs.AccessWrite && len(d.Mappings) == 0 {
				return invalid("%s: %s is a consequence, which is never dispatched, so it would never be counted; limit the operation that causes it", name, op)
			}
		}
		return nil
	}
	for _, r := range l.Budgets {
		if err := check("budgets."+r.ID, r.Operations); err != nil {
			return err
		}
	}
	for _, r := range l.Counters {
		if err := check("counters."+r.ID, r.Operations); err != nil {
			return err
		}
	}
	return nil
}

// DecodeLimits strictly decodes a limits document, like DecodeBounds.
func DecodeLimits(raw []byte) (Limits, error) {
	if len(raw) == 0 || len(raw) > MaxBoundsBytes {
		return Limits{}, invalid("limits: size %d outside 1..%d bytes", len(raw), MaxBoundsBytes)
	}
	if err := scanBounds(raw); err != nil {
		return Limits{}, err
	}
	var l Limits
	if err := json.Unmarshal(raw, &l, json.RejectUnknownMembers(true)); err != nil {
		return Limits{}, invalid("limits: %v", err)
	}
	return l, nil
}

// Stable reason codes for budgets and counters.
const (
	ReasonBudgetExhausted       = "BUDGET_EXHAUSTED"
	ReasonCountLimitReached     = "COUNT_LIMIT_REACHED"
	ReasonBudgetCurrency        = "BUDGET_CURRENCY_NOT_COVERED"
	ReasonBudgetValueAmbiguous  = "BUDGET_VALUE_AMBIGUOUS"
	ReasonLimitKeyMissing       = "LIMIT_KEY_MISSING"
	ReasonCounterCapacityExceed = "COUNTER_CAPACITY"
)

// DebitContext is what debits are keyed by, besides the action.
type DebitContext struct {
	Now       time.Time
	RunID     ids.UUID
	Principal Principal
	TeamID    ids.UUID
	// Simulated drops the lines owned by guardrails (envelopes): a range
	// run never changes what real agents depend on (HR-222). Grant-owned
	// lines still apply.
	Simulated bool
}

// Plan is everything one action must reserve.
type Plan struct {
	Budgets  []bdomain.Debit
	Counters []bdomain.CounterDebit
}

// Debits returns the budget accounts and counters the action must reserve
// against at every level: each guardrail's, and each grant's from the root
// down, so a child's action also debits its ancestors' task budgets
// (HR-048, F059, F117). It fails when a level cannot be keyed (Unknown) or
// budgets value in other currencies only (Denied).
func (c Chain) Debits(a Action, dc DebitContext) (Plan, *LevelFinding) {
	var plan Plan
	leaf, _ := c.Leaf()
	levels := c.Levels()
	envs := len(c.Envelopes)
	ordered := c.layers()
	for i, l := range ordered {
		var limits Limits
		owner := bdomain.Owner{Kind: string(l.level.Kind), ID: l.level.ID}
		task := leaf.ID.String()
		if i < envs && dc.Simulated {
			continue
		}
		if i < envs {
			limits = c.envelopeAt(levels[i].ID).Limits
		} else {
			g := c.Grants[i-envs]
			limits, owner.Rank, task = g.Limits, g.Depth+1, g.ID.String()
		}
		value, valueErr := moneyParam(a.Params)
		amountRules, inCurrency := 0, 0
		for _, r := range limits.Budgets {
			if !r.Operations.Matches(a.Operation) {
				continue
			}
			d := bdomain.Debit{Grouping: r.Grouping, Period: r.Period}
			if r.MaxCount != "" {
				n, _ := parseCount("", r.MaxCount)
				d.MaxCount = &n
			}
			if r.Currency != "" {
				if valueErr != nil {
					return Plan{}, unknownLimit(l.level, "budgets."+r.ID, ReasonBudgetValueAmbiguous, valueErr.Error())
				}
				if value != nil {
					amountRules++
					if string(value.Currency) != r.Currency {
						continue
					}
					inCurrency++
					lim, _ := money.ParseMoney(r.Limit, r.Currency)
					d.Currency, d.Limit, d.Amount = lim.Currency, &lim.Amount, value.Amount
				} else if r.MaxCount == "" {
					continue // a value budget does not cover an action without a value
				}
			}
			key, ok := groupingKey(r.Grouping, task, a, dc)
			if !ok {
				return Plan{}, unknownLimit(l.level, "budgets."+r.ID, ReasonLimitKeyMissing, "the action has no "+string(r.Grouping)+" to key this budget")
			}
			d.Ref = bdomain.Ref{Owner: owner, Rule: r.ID, Key: bdomain.KeyHash(owner, r.ID, key), Start: r.Period.Start(dc.Now)}
			plan.Budgets = append(plan.Budgets, d)
		}
		if amountRules > 0 && inCurrency == 0 {
			return Plan{}, &LevelFinding{Level: l.level, Finding: Finding{
				Outcome: Denied, Dimension: "budgets", Code: ReasonBudgetCurrency,
				Detail: fmt.Sprintf("budgets here cover other currencies, not %s", value.Currency),
			}}
		}
		for _, r := range limits.Counters {
			if !r.Operations.Matches(a.Operation) {
				continue
			}
			key, ok := counterKey(r.Key, task, a, dc)
			if !ok {
				return Plan{}, unknownLimit(l.level, "counters."+r.ID, ReasonLimitKeyMissing, "the action has no "+r.Key+" to count by")
			}
			n, _ := parseCount("", r.Max)
			cd := bdomain.CounterDebit{
				Window: r.Window, Max: n,
				Ref: bdomain.Ref{Owner: owner, Rule: r.ID, Key: bdomain.KeyHash(owner, r.ID, key), Start: r.Window.Start(dc.Now)},
			}
			if r.MaxOutstanding != "" {
				m, _ := parseCount("", r.MaxOutstanding)
				cd.MaxOutstanding = &m
			}
			plan.Counters = append(plan.Counters, cd)
		}
	}
	return plan, nil
}

func (c Chain) envelopeAt(id ids.UUID) Envelope {
	for _, e := range c.Envelopes {
		if e.ID.UUID() == id {
			return e
		}
	}
	return Envelope{}
}

func unknownLimit(l Level, dim, code, detail string) *LevelFinding {
	return &LevelFinding{Level: l, Finding: Finding{Outcome: Unknown, Dimension: dim, Code: code, Detail: detail}}
}

// moneyParam returns the action's single money parameter: nil when it has
// none, an error when it has several (the package must name one).
func moneyParam(vals defs.Values) (*money.Money, error) {
	var found *money.Money
	for _, v := range vals {
		if v.Type != defs.TypeMoney {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("the operation has several money parameters and its package does not say which one is budgeted")
		}
		m := v.Money
		found = &m
	}
	return found, nil
}

func groupingKey(g bdomain.Grouping, task string, a Action, dc DebitContext) (string, bool) {
	switch g {
	case bdomain.GroupTask:
		return task, true
	case bdomain.GroupPrincipal:
		return dc.Principal.String(), !dc.Principal.ID.IsZero()
	case bdomain.GroupAccount:
		return a.Account, a.Account != ""
	case bdomain.GroupTeam:
		return dc.TeamID.String(), !dc.TeamID.IsZero()
	case bdomain.GroupOrg:
		return "org", true
	}
	return "", false
}

func counterKey(key, task string, a Action, dc DebitContext) (string, bool) {
	switch key {
	case "task":
		return task, true
	case "run":
		return dc.RunID.String(), !dc.RunID.IsZero()
	case "principal":
		return dc.Principal.String(), !dc.Principal.ID.IsZero()
	case "target":
		return a.TargetType + "\x00" + a.TargetID, a.TargetID != ""
	case "account":
		return a.Account, a.Account != ""
	}
	name, _ := strings.CutPrefix(key, "params.")
	v, ok := a.Params[name]
	if !ok || (v.Type != defs.TypeEnum && v.Type != defs.TypeIdentifier) {
		return "", false
	}
	return v.Str, true
}

// limitsKept reports whether next keeps every rule of cur unchanged. A
// rule removed or edited may widen authority, so it is treated as widening.
func limitsKept(cur, next Limits) bool {
	for _, r := range cur.Budgets {
		if !slicesContainsJSON(next.Budgets, r) {
			return false
		}
	}
	for _, r := range cur.Counters {
		if !slicesContainsJSON(next.Counters, r) {
			return false
		}
	}
	return true
}

func slicesContainsJSON[T any](list []T, v T) bool {
	want, err := json.Marshal(v, json.Deterministic(true))
	if err != nil {
		return false
	}
	for _, x := range list {
		got, err := json.Marshal(x, json.Deterministic(true))
		if err == nil && string(got) == string(want) {
			return true
		}
	}
	return false
}
