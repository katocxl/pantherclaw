// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata" // schedules name IANA zones; validation must not depend on the host's zone files
	"unicode/utf8"

	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// Events is the closed platform-event vocabulary (D18).
var Events = []string{
	"action.decided", "action.held", "action.denied", "effect.recorded", "run.ended", "grant.issued", "grant.revoked",
	"coverage.lost", "alert.raised", "incident.opened", "case.closed", "agent.discovered", "approval.expired",
	"automation.finished",
}

// Probes is the closed condition-probe vocabulary (D19).
var Probes = []string{"grant.expiring", "approval.waiting", "coverage.below", "run.long_running", "agent.unclaimed"}

// EventAutomationFinished is produced by every execution.
const EventAutomationFinished = "automation.finished"

// produces maps step kinds to the D18 events their effects can put on the
// feed (D78); contain's REVOKE_GRANT revokes a grant (D91).
var produces = map[string][]string{
	KindLaunchRun: {
		"run.ended", "grant.issued", "grant.revoked", "action.decided", "action.held", "action.denied",
		"effect.recorded", "approval.expired",
	},
	KindRevokeGrant: {"grant.revoked"},
	KindContain:     {"grant.revoked"}, // REVOKE_GRANT (D91)
}

// Produces lists the platform events (D18) a step of kind can cause (D78);
// every execution also produces EventAutomationFinished. LOOP_POSSIBLE and
// assurance's triggered-workflows preview both read it.
func Produces(kind string) []string { return slices.Clone(produces[kind]) }

// Limits of D2.
const (
	MaxReviewWindow  = 90 * 24 * time.Hour
	MaxDeadline      = 7 * 24 * time.Hour
	MaxStepTimeout   = 24 * time.Hour
	MaxGrantTTL      = 24 * time.Hour
	MaxDedupeWindow  = 30 * 24 * time.Hour
	MaxGateDeadline  = 72 * time.Hour
	MaxClaimWithin   = time.Hour
	MaxCatchUpWindow = 24 * time.Hour
	MaxQueueTTL      = 24 * time.Hour
	MaxCoverageWait  = 7 * 24 * time.Hour
	MaxClaimWait     = 30 * 24 * time.Hour
	MaxExpression    = 2000
)

var (
	// NamePattern is an automation's name (D2, D63, D69 C4): at most 52
	// characters so that "automation-<name>" fits a service-account name,
	// never ending in a hyphen.
	NamePattern  = regexp.MustCompile(`^[a-z]([a-z0-9-]{0,50}[a-z0-9])?$`)
	stepIDFormat = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
	paramName    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	templateRef  = regexp.MustCompile(`\{\{\s*([^{}]*?)\s*\}\}`)
	paramRef     = regexp.MustCompile(`^params\.([a-z][a-z0-9_]{0,31})$`)
	outputRef    = regexp.MustCompile(`^steps\.([a-z][a-z0-9_-]{0,62})\.output\.([a-z][a-z0-9_]{0,63})$`)
	eventType    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$`)
	currencyCode = regexp.MustCompile(`^[A-Z]{3}$`)
)

// validator collects findings.
type validator struct {
	ctx context.Context
	env ValidationEnv
	d   *Definition
	out []Finding
	// ceiling operations (exact names and prefixes), resolved infos.
	ops   []string
	infos map[string]OperationInfo
}

func (v *validator) add(sev Severity, code, path, msg string, args ...any) {
	v.out = append(v.out, Finding{Code: code, Severity: sev, Path: path, Message: fmt.Sprintf(msg, args...)})
}

func (v *validator) err(code, path, msg string, args ...any) {
	v.add(SeverityError, code, path, msg, args...)
}

func (v *validator) lookupErr(path string, err error) {
	v.err(CodeLimitRange, path, "could not be checked: %v", err)
}

// Validate checks a parsed definition against D2–D4 and the org's state
// (env). VALIDATED needs zero ERROR findings. Findings are ordered by
// path order of discovery.
func Validate(ctx context.Context, d *Definition, env ValidationEnv) []Finding {
	v := &validator{ctx: ctx, env: env, d: d, infos: map[string]OperationInfo{}}
	v.identity()
	v.authority()
	v.revocable()
	v.trigger()
	v.conditions()
	v.steps()
	v.ifFails()
	v.finish()
	v.limits()
	v.irreversible()
	v.loops()
	return v.out
}

func (v *validator) identity() {
	d := v.d
	if n := utf8.RuneCountInString(strings.TrimSpace(d.Purpose)); n < 1 || n > 2000 {
		v.err(CodeLimitRange, "/purpose", "a purpose of 1 to 2000 characters is required")
	}
	if !d.WorkKind.Valid() {
		v.err(CodeLimitRange, "/work_kind", "work_kind is AGENT_WORK or SECURITY_WORK")
	}
	switch {
	case v.env.Owner().IsZero():
		v.err(CodeOwnerMissing, "", "the automation needs an owner: the person accountable for it")
	default:
		ok, err := v.env.OwnerActivePerson(v.ctx, v.env.Owner())
		switch {
		case err != nil:
			v.lookupErr("", err)
		case !ok:
			v.err(CodeOwnerNotActivePerson, "", "the automation's owner must be an active person of the organization")
		}
	}
	now := v.env.Now()
	switch {
	case d.ReviewBy.IsZero():
		v.err(CodeReviewDate, "/review_by", "a review date (YYYY-MM-DD) within 90 days is required")
	case !d.ReviewBy.End().After(now):
		v.err(CodeReviewDate, "/review_by", "the review date is in the past")
	case d.ReviewBy.Time().After(now.Add(MaxReviewWindow)):
		v.err(CodeReviewDate, "/review_by", "the review date is more than 90 days away")
	}
}

func (v *validator) authority() {
	a := v.d.Authority
	if a.Principal != PrincipalSelf {
		if _, ok := a.PrincipalUser(); !ok {
			v.err(CodePrincipalInvalid, "/authority/principal", `the principal is "self" or "user:<uuid>" (a person who confirms the enabling)`)
		}
	}
	hasLaunch := slices.ContainsFunc(v.d.Do, func(s StepSpec) bool { return s.Step == KindLaunchRun })
	switch {
	case hasLaunch && a.Ceiling == nil:
		v.err(CodeCeilingMissing, "/authority/ceiling", "launch_run needs a ceiling: the agents, operations and caps every issued grant must stay inside")
	case !hasLaunch && a.Ceiling != nil:
		v.err(CodeLimitRange, "/authority/ceiling", "a ceiling is declared only with a launch_run step")
	case a.Ceiling != nil:
		v.ceiling(a.Ceiling)
	}
	for i, p := range a.Platform {
		at := "/authority/platform/" + strconv.Itoa(i)
		k, ok := Catalog[p.Step]
		switch {
		case !ok:
			v.err(CodeUnsupportedCapability, at+"/step", "%q is not a step kind", p.Step)
			continue
		case !k.NeedsPlatformScope():
			v.err(CodeLimitRange, at+"/step", "%s is bounded by the ceiling; do not list it here", p.Step)
			continue
		}
		for j, sc := range p.Scopes {
			if slices.Contains(k.Scopes, sc) {
				continue
			}
			if r, ok := v.destination(sc); ok && len(k.DestinationPurposes) > 0 && slices.Contains(a.Destinations, r) {
				continue
			}
			v.err(CodeUnsupportedCapability, at+"/scopes/"+strconv.Itoa(j), "%q is not a scope of %s (allowed: %s, or a declared destination)",
				sc, p.Step, strings.Join(k.Scopes, ", "))
		}
	}
	for i, dst := range a.Destinations {
		ok, err := v.env.DestinationActive(v.ctx, dst.UUID(), "")
		switch {
		case err != nil:
			v.lookupErr("/authority/destinations/"+strconv.Itoa(i), err)
		case !ok:
			v.err(CodeDestinationInvalid, "/authority/destinations/"+strconv.Itoa(i), "destination %s is not an active automation destination", dst)
		}
	}
}

// revocable checks authority.revocable against the steps that revoke
// beyond their execution (D65).
func (v *validator) revocable() {
	steps := slices.Clone(v.d.Do)
	if v.d.IfFails != nil {
		steps = append(steps, v.d.IfFails.Compensate...)
	}
	revokes := false
	for _, s := range steps {
		if k, ok := Catalog[s.Step]; ok && k.ConfirmRevocable {
			if w, err := s.DecodeWith(); err == nil && RevokesBeyondExecution(w) {
				revokes = true
			}
		}
	}
	r := v.d.Authority.Revocable
	switch {
	case revokes && r == nil:
		v.err(CodeLimitRange, "/authority/revocable",
			"revoke_grant TRIGGER_GRANT or CEILING_AGENTS and contain REVOKE_GRANT need authority.revocable: the agents whose grants this version may revoke, or all: true")
	case !revokes && r != nil:
		v.err(CodeLimitRange, "/authority/revocable", "revocable is declared only with a step that revokes grants beyond its execution")
	case r != nil:
		v.agentScope("/authority/revocable", *r)
	}
}

// agentScope checks an {agents: [ids]} or {all: true} scope.
func (v *validator) agentScope(at string, s AgentScope) {
	if !s.Valid() {
		v.err(CodeLimitRange, at, "list agents by id or set all: true (exactly one)")
		return
	}
	if len(s.Agents) > 50 {
		v.err(CodeLimitRange, at+"/agents", "list at most 50 agents")
	}
	seen := map[RefID]bool{}
	for i, a := range s.Agents {
		if seen[a] {
			v.err(CodeLimitRange, at+"/agents/"+strconv.Itoa(i), "agent %s is listed twice", a)
		}
		seen[a] = true
	}
}

func (v *validator) destination(s string) (RefID, bool) {
	var r RefID
	return r, r.UnmarshalText([]byte(s)) == nil
}

func (v *validator) ceiling(c *Ceiling) {
	const at = "/authority/ceiling"
	if n := len(c.Agents); n < 1 || n > 50 {
		v.err(CodeCeilingUnbounded, at+"/agents", "list 1 to 50 agents by id")
	}
	seen := map[RefID]bool{}
	for i, a := range c.Agents {
		if seen[a] {
			v.err(CodeLimitRange, at+"/agents/"+strconv.Itoa(i), "agent %s is listed twice", a)
			continue
		}
		seen[a] = true
		ok, err := v.env.AgentGrantable(v.ctx, a.UUID())
		switch {
		case err != nil:
			v.lookupErr(at+"/agents/"+strconv.Itoa(i), err)
		case !ok:
			v.err(CodeLimitRange, at+"/agents/"+strconv.Itoa(i), "agent %s does not exist or cannot receive authority", a)
		}
	}
	if err := c.Bounds.Validate(); err != nil {
		v.err(CodeLimitRange, at+"/bounds", "%v", err)
	}
	if c.Bounds.Operations == nil || len(*c.Bounds.Operations) == 0 {
		v.err(CodeCeilingUnbounded, at+"/bounds/operations", "list the operations issued grants may cover")
	} else {
		v.ops = *c.Bounds.Operations
	}
	budgeted := false
	for i, op := range v.ops {
		info, err := v.env.Operation(v.ctx, op)
		switch {
		case err != nil:
			v.lookupErr(at+"/bounds/operations/"+strconv.Itoa(i), err)
			continue
		case !info.Known:
			v.err(CodeUnsupportedCapability, at+"/bounds/operations/"+strconv.Itoa(i), "operation %q is not defined in this organization", op)
			continue
		}
		v.infos[op] = info
		budgeted = budgeted || info.ConsumesBudget
		// A prefix covering an irreversible operation would let one
		// wait_effect stand for all of them: list those exactly (K4).
		if len(info.IrreversibleUnder) > 0 {
			v.err(CodePrefixIrreversible, at+"/bounds/operations/"+strconv.Itoa(i),
				"%q covers irreversible operations; list them exactly so each is reconciled: %s", op, strings.Join(info.IrreversibleUnder, ", "))
		}
	}
	if budgeted {
		for i, op := range v.ops {
			if v.infos[op].ConsumesBudget && !c.PerGrant.Limits.CoversBudget(op) {
				v.err(CodeCeilingUnbounded, at+"/bounds/operations/"+strconv.Itoa(i),
					"operation %q spends money: a per-grant budget with an amount must cover it", op)
			}
		}
		if len(c.PerDay.Budget) == 0 {
			v.err(CodeCeilingUnbounded, at+"/per_day/budget", "a ceiling operation spends money: set a per-day budget")
		}
	}
	for i, m := range c.PerDay.Budget {
		p := at + "/per_day/budget/" + strconv.Itoa(i)
		if d, err := money.Parse(m.Amount); err != nil || d.Sign() <= 0 || !currencyCode.MatchString(m.Currency) {
			v.err(CodeLimitRange, p, "a budget is a currency code and a positive decimal amount")
		}
	}
	if ttl := c.PerGrant.TTL.D(); ttl <= 0 || ttl > MaxGrantTTL {
		v.err(CodeLimitRange, at+"/per_grant/ttl", "a grant lasts at most 24h")
	}
	if c.PerGrant.MinAttestation < 0 || c.PerGrant.MinAttestation > 2 {
		v.err(CodeLimitRange, at+"/per_grant/min_attestation", "min_attestation is 0, 1 or 2")
	}
	for _, b := range c.PerGrant.Limits.Budgets {
		if b.Grouping != "task" {
			v.err(CodeLimitRange, at+"/per_grant/limits/budgets", "per-grant budgets group by task")
			break
		}
	}
	if c.PerDay.Grants < 1 || c.PerDay.Grants > 1000 {
		v.err(CodeLimitRange, at+"/per_day/grants", "per_day.grants is 1 to 1000")
	}
	if c.PerDay.Runs < 1 || c.PerDay.Runs > 1000 {
		v.err(CodeLimitRange, at+"/per_day/runs", "per_day.runs is 1 to 1000")
	}
	if c.Delegation.Depth < 0 || c.Delegation.Depth > 1 || c.Delegation.MaxChildren < 0 || c.Delegation.MaxChildren > 10 {
		v.err(CodeLimitRange, at+"/delegation", "delegation depth is 0 or 1 and max_children 0 to 10")
	}
	if c.Concurrency < 0 || c.Concurrency > 10 {
		v.err(CodeLimitRange, at+"/concurrency", "concurrency is 1 to 10")
	}
}

func (v *validator) irreversibleCeiling() bool {
	for _, i := range v.infos {
		if i.Irreversible {
			return true
		}
	}
	return false
}

func (v *validator) budgetCeiling() bool {
	for _, i := range v.infos {
		if i.ConsumesBudget {
			return true
		}
	}
	return false
}

func dur(d Duration, lo, hi time.Duration) bool { return d.D() >= lo && d.D() <= hi }

func (v *validator) trigger() {
	w := v.d.When
	if w.Kind() == "" {
		v.err(CodeLimitRange, "/when", "declare exactly one of schedule, event, inbound, condition, threshold or manual")
		return
	}
	switch {
	case w.Schedule != nil:
		s := w.Schedule
		if len(strings.Fields(s.Cron)) != 5 {
			v.err(CodeLimitRange, "/when/schedule/cron", "a cron has five fields: minute hour day-of-month month day-of-week")
		}
		if _, err := time.LoadLocation(s.Timezone); err != nil || s.Timezone == "" || s.Timezone == "Local" {
			v.err(CodeLimitRange, "/when/schedule/timezone", "name an IANA time zone, for example Europe/Berlin")
		}
		if s.Missed != "" && s.Missed != MissedSkip && s.Missed != MissedCatchUp {
			v.err(CodeLimitRange, "/when/schedule/missed", "missed is SKIP or CATCH_UP")
		}
		if s.CatchUpWindow != 0 && !dur(s.CatchUpWindow, time.Minute, MaxCatchUpWindow) {
			v.err(CodeLimitRange, "/when/schedule/catch_up_window", "catch_up_window is at most 24h")
		}
		if s.DSTGap != "" && s.DSTGap != DSTSkip && s.DSTGap != DSTShift {
			v.err(CodeLimitRange, "/when/schedule/dst_gap", "dst_gap is SKIP or SHIFT")
		}
		switch s.Overlap {
		case "", OverlapForbid:
		case OverlapAllow:
			if v.irreversibleCeiling() {
				v.err(CodeLimitRange, "/when/schedule/overlap", "overlapping executions are refused when the ceiling has an irreversible operation")
			}
		default:
			v.err(CodeLimitRange, "/when/schedule/overlap", "overlap is FORBID or ALLOW")
		}
	case w.Event != nil:
		if !slices.Contains(Events, w.Event.On) {
			v.err(CodeUnsupportedCapability, "/when/event/on", "%q is not a platform event (one of %s)", w.Event.On, strings.Join(Events, ", "))
		}
		v.expr("/when/event/where", w.Event.Where)
	case w.Inbound != nil:
		if w.Inbound.Source.IsZero() {
			v.err(CodeLimitRange, "/when/inbound/source", "name the inbound event source")
		}
		if !eventType.MatchString(w.Inbound.Type) {
			v.err(CodeLimitRange, "/when/inbound/type", "an event type is 1 to 100 letters, digits and . _ : -")
		}
	case w.Condition != nil:
		if !slices.Contains(Probes, w.Condition.Probe) {
			v.err(CodeUnsupportedCapability, "/when/condition/probe", "%q is not a probe (one of %s)", w.Condition.Probe, strings.Join(Probes, ", "))
		}
		v.expr("/when/condition/where", w.Condition.Where)
		if !dur(w.Condition.For, time.Minute, 7*24*time.Hour) {
			v.err(CodeLimitRange, "/when/condition/for", "for is 1m to 7d")
		}
	case w.Threshold != nil:
		t := w.Threshold
		if !slices.Contains(Events, t.On) {
			v.err(CodeUnsupportedCapability, "/when/threshold/on", "%q is not a platform event", t.On)
		}
		v.expr("/when/threshold/where", t.Where)
		if !slices.Contains([]string{"", "agent", "connection", "operation", "none"}, t.GroupBy) {
			v.err(CodeLimitRange, "/when/threshold/group_by", "group_by is agent, connection, operation or none")
		}
		if !dur(t.Over, time.Minute, 24*time.Hour) {
			v.err(CodeLimitRange, "/when/threshold/over", "over is 1m to 24h")
		}
		if t.AtLeast < 1 || t.AtLeast > 100000 {
			v.err(CodeLimitRange, "/when/threshold/at_least", "at_least is 1 to 100000")
		}
	case w.Manual != nil:
		if !w.Manual.StepUp && (v.irreversibleCeiling() || v.budgetCeiling()) {
			v.err(CodeLimitRange, "/when/manual/step_up", "manual starts of an automation that spends money or has an irreversible operation need step_up: true")
		}
	}
	v.params(w.Params())
	if w.Dedupe != nil {
		if !dur(w.Dedupe.Window, time.Minute, MaxDedupeWindow) {
			v.err(CodeLimitRange, "/when/dedupe/window", "the dedupe window is at most 30d")
		}
		if strings.TrimSpace(w.Dedupe.Key) == "" {
			v.err(CodeLimitRange, "/when/dedupe/key", "the dedupe key names at least one parameter")
		}
		v.templates("/when/dedupe/key", w.Dedupe.Key)
	}
	if w.Window != nil && !w.Window.From.IsZero() && !w.Window.To.IsZero() && !w.Window.To.After(w.Window.From) {
		v.err(CodeLimitRange, "/when/window", "the window ends after it starts")
	}
}

func (v *validator) params(ps map[string]ParamSpec) {
	if len(ps) > MaxParams {
		v.err(CodeLimitRange, "/when", "at most %d parameters", MaxParams)
	} else if n := ParamsEnvelopeBytes(ps); n > MaxParamsEnvelope {
		v.err(CodeParamUnbounded, "/when/"+strings.ToLower(string(v.d.When.Kind()))+"/params",
			"the parameters can take %d bytes when stored; at most %d: lower max_len or declare fewer", n, MaxParamsEnvelope)
	}
	for _, name := range sortedKeys(ps) {
		p := ps[name]
		at := "/when/" + strings.ToLower(string(v.d.When.Kind())) + "/params/" + name
		if !paramName.MatchString(name) {
			v.err(CodeLimitRange, at, "a parameter name is a lowercase identifier")
		}
		switch p.Type {
		case ParamString:
			if p.Pattern == "" {
				v.err(CodeParamUnbounded, at+"/pattern", "a string parameter needs a pattern (or use type enum)")
			}
		case ParamEnum:
			if n := len(p.Values); n < 1 || n > MaxParamValues {
				v.err(CodeParamUnbounded, at+"/values", "an enum lists 1 to 50 values")
			}
		case ParamInt, ParamDecimal:
			for _, b := range []string{p.Min, p.Max} {
				if _, err := money.Parse(b); b != "" && err != nil {
					v.err(CodeLimitRange, at, "min and max are decimal numbers")
				}
			}
		case ParamUUID, ParamBool:
		default:
			v.err(CodeLimitRange, at+"/type", "type is string, int, decimal, enum, uuid or bool")
		}
		if p.Pattern != "" {
			if _, err := regexp.Compile(`^(?:` + p.Pattern + `)$`); err != nil || len(p.Pattern) > MaxParamPattern {
				v.err(CodeLimitRange, at+"/pattern", "the pattern is an RE2 expression of at most 200 characters")
			}
		}
		if p.MaxLen < 0 || p.MaxLen > MaxParamMaxLen {
			v.err(CodeLimitRange, at+"/max_len", "max_len is at most 256")
		}
		if v.d.When.Kind() != TriggerManual && p.From == "" {
			v.err(CodeLimitRange, at+"/from", "name where the value comes from")
		}
	}
}

func (v *validator) expr(at, e string) {
	if len(e) > MaxExpression {
		v.err(CodeLimitRange, at, "an expression is at most %d characters", MaxExpression)
	}
}

func (v *validator) conditions() {
	if len(v.d.If) > MaxConditions {
		v.err(CodeLimitRange, "/if", "at most %d conditions", MaxConditions)
	}
	for i, e := range v.d.If {
		if strings.TrimSpace(e) == "" {
			v.err(CodeLimitRange, "/if/"+strconv.Itoa(i), "an empty condition")
		}
		v.expr("/if/"+strconv.Itoa(i), e)
	}
}

// platformScopes returns the declared scopes of a step kind, and whether
// it is declared.
func (v *validator) platformScopes(kind string) ([]string, bool) {
	for _, p := range v.d.Authority.Platform {
		if p.Step == kind {
			return p.Scopes, true
		}
	}
	return nil, false
}

func (v *validator) steps() {
	do := v.d.Do
	if n := len(do); n < 1 || n > MaxSteps {
		v.err(CodeLimitRange, "/do", "declare 1 to %d steps", MaxSteps)
	}
	seen := map[string]int{}
	for i := range do {
		v.step("/do/"+strconv.Itoa(i), do[i], seen, false)
		seen[do[i].ID] = i
	}
}

func (v *validator) step(at string, s StepSpec, seen map[string]int, compensation bool) {
	if !stepIDFormat.MatchString(s.ID) {
		v.err(CodeLimitRange, at+"/id", "a step id is a lowercase slug")
	} else if _, dup := seen[s.ID]; dup {
		v.err(CodeLimitRange, at+"/id", "step id %q is used twice", s.ID)
	}
	k, ok := Catalog[s.Step]
	if !ok {
		v.err(CodeUnsupportedCapability, at+"/step", "%q is not a step kind", s.Step)
		return
	}
	if !v.env.Edition(k.Edition) {
		v.err(CodeUnsupportedCapability, at+"/step", "%s needs the %s edition", s.Step, strings.ToLower(string(k.Edition)))
	}
	scopes, declared := v.platformScopes(s.Step)
	if k.NeedsPlatformScope() && !declared {
		v.err(CodeUnsupportedCapability, at+"/step", "list %s and its scopes under authority.platform", s.Step)
	}
	if compensation && !slices.Contains([]string{KindRevokeGrant, KindNotify, KindOpenCase, KindContain}, s.Step) {
		v.err(CodeUnsupportedCapability, at+"/step", "compensation uses revoke_grant, notify, open_case or contain")
	}
	v.expr(at+"/when", s.When)
	if s.Retry != nil {
		switch {
		case !k.RetrySafe:
			v.err(CodeLimitRange, at+"/retry", "%s never retries", s.Step)
		case s.Retry.MaxAttempts < 1 || s.Retry.MaxAttempts > 5:
			v.err(CodeLimitRange, at+"/retry/max_attempts", "max_attempts is 1 to 5")
		case s.Retry.Backoff.Min != 0 && s.Retry.Backoff.Min.D() < 10*time.Second, s.Retry.Backoff.Max.D() > time.Hour:
			v.err(CodeLimitRange, at+"/retry/backoff", "backoff is at least 10s and at most 1h")
		}
	}
	switch s.OnFailure {
	case "", OnFailureStop, OnFailureEscalate:
	case OnFailureContinue:
		if k.Effectful && !k.Narrowing {
			v.err(CodeLimitRange, at+"/on_failure", "an effectful step cannot continue after a failure")
		}
	default:
		v.err(CodeLimitRange, at+"/on_failure", "on_failure is STOP, CONTINUE or ESCALATE")
	}
	if s.Timeout.D() > MaxStepTimeout || s.Timeout < 0 {
		v.err(CodeLimitRange, at+"/timeout", "a step timeout is at most 24h")
	}
	w, err := s.DecodeWith()
	if err != nil {
		v.err(CodeLimitRange, at+"/with", "%v", err)
		return
	}
	if k.Wait && s.Timeout == 0 && !slices.Contains([]string{KindWait, KindWaitCoverage, KindWaitClaim, KindGate}, s.Step) {
		v.err(CodeDeadlineMissing, at+"/timeout", "a waiting step needs a timeout")
	}
	v.withChecks(at+"/with", s, w, seen, scopes)
	v.templateFields(at+"/with", s, k)
}

func earlier(seen map[string]int, id string) bool {
	_, ok := seen[id]
	return ok
}

func (v *validator) stepKind(id string) string {
	if s := v.d.Step(id); s != nil {
		return s.Step
	}
	return ""
}

func (v *validator) withChecks(at string, s StepSpec, w any, seen map[string]int, scopes []string) {
	c := v.d.Authority.Ceiling
	refLaunch := func(p, id string) {
		if !earlier(seen, id) || v.stepKind(id) != KindLaunchRun {
			v.err(CodeLimitRange, at+p, "name an earlier launch_run step")
		}
	}
	scope := func(p, sc string, allowed ...string) {
		switch {
		case !slices.Contains(allowed, sc):
			v.err(CodeLimitRange, at+p, "%q is not one of %s", sc, strings.Join(allowed, ", "))
		case !slices.Contains(scopes, sc):
			v.err(CodeUnsupportedCapability, at+p, "list %s under authority.platform for %s", sc, s.Step)
		}
	}
	switch x := w.(type) {
	case *LaunchRunWith:
		if c == nil {
			return
		}
		if !slices.Contains(c.Agents, x.Agent) {
			v.err(CodeLimitRange, at+"/agent", "the agent must be one of the ceiling's agents")
		}
		if x.TTL != 0 && x.TTL > c.PerGrant.TTL {
			v.err(CodeLimitRange, at+"/ttl", "ttl is at most the ceiling's per-grant ttl")
		}
		if utf8.RuneCountInString(x.TaskRef) > 256 {
			v.err(CodeLimitRange, at+"/task_ref", "task_ref is at most 256 characters")
		}
		if x.Grant.Operations != nil && c.Bounds.Operations != nil {
			if op, ok := x.Grant.Operations.Within(*c.Bounds.Operations); !ok {
				v.err(CodeLimitRange, at+"/grant/operations", "operation %q is outside the ceiling", op)
			}
		}
		if x.Grant.Limits != nil {
			if _, err := gdomain.NarrowLimits(c.PerGrant.Limits, *x.Grant.Limits); err != nil {
				v.err(CodeLimitRange, at+"/grant/limits", "a launch may only lower the ceiling's per-grant limits: %v", err)
			}
		}
		if len(x.RunParams) > 16 {
			v.err(CodeLimitRange, at+"/run_params", "at most 16 run parameters")
		}
		switch x.Delivery {
		case "", DeliveryPull:
		case DeliveryWebhook:
			if x.Destination == nil || !slices.Contains(v.d.Authority.Destinations, *x.Destination) {
				v.err(CodeDestinationInvalid, at+"/destination", "a webhook launch names a declared destination")
			}
		default:
			v.err(CodeLimitRange, at+"/delivery", "delivery is PULL or WEBHOOK")
		}
		if x.ClaimWithin.D() > MaxClaimWithin || x.ClaimWithin < 0 {
			v.err(CodeLimitRange, at+"/claim_within", "claim_within is at most 1h")
		}
		if len(x.Calls) > 10 {
			v.err(CodeLimitRange, at+"/calls", "at most 10 calls")
		}
		templated := false
		for i, call := range x.Calls {
			p := at + "/calls/" + strconv.Itoa(i)
			switch call.Face {
			case FaceMCP:
				if call.Tool == "" {
					v.err(CodeLimitRange, p+"/tool", "an MCP call names its tool")
				}
			case FaceHTTP:
				if call.Method == "" || !strings.HasPrefix(call.Path, "/") {
					v.err(CodeLimitRange, p, "an HTTP call names its method and an absolute path")
				}
			default:
				v.err(CodeLimitRange, p+"/face", "face is MCP or HTTP")
			}
			for _, in := range call.Input {
				templated = templated || strings.Contains(in, "{{")
			}
		}
		// L3: a templated input may carry a value to a budget-consuming
		// operation, so each grant needs its own budget.
		if templated && v.budgetCeiling() && len(c.PerGrant.Limits.Budgets) == 0 {
			v.err(CodeCeilingUnbounded, at+"/calls", "templated call inputs reach a budget-consuming operation: set a per-grant budget")
		}
	case *WaitRunWith:
		refLaunch("/step", x.Step)
	case *WaitEffectWith:
		refLaunch("/step", x.Step)
		if strings.Contains(x.Operation, "*") {
			v.err(CodeLimitRange, at+"/operation", "wait_effect names one exact operation, not a pattern")
		}
		if c != nil && c.Bounds.Operations != nil && !c.Bounds.Operations.Matches(x.Operation) {
			v.err(CodeLimitRange, at+"/operation", "the operation must be inside the ceiling")
		}
		if x.Min < 1 || x.Min > 100 {
			v.err(CodeLimitRange, at+"/min", "min is 1 to 100")
		}
	case *GateWith:
		if !dur(x.Deadline, time.Minute, MaxGateDeadline) {
			v.err(CodeDeadlineMissing, at+"/deadline", "a gate's deadline is 1m to 72h")
		}
		if x.MinApprovals < 1 || x.MinApprovals > 2 {
			v.err(CodeLimitRange, at+"/min_approvals", "min_approvals is 1 or 2")
		}
		for i, e := range x.Exclude {
			if !slices.Contains([]string{ExcludeOwner, ExcludeConfirmers, ExcludePrincipal}, e) {
				v.err(CodeLimitRange, at+"/exclude/"+strconv.Itoa(i), "exclude OWNER, CONFIRMERS or PRINCIPAL")
			}
		}
		if utf8.RuneCountInString(x.Summary) > 1000 {
			v.err(CodeLimitRange, at+"/summary", "a summary is at most 1000 characters")
		}
		var principal ids.UUID
		if u, ok := v.d.Authority.PrincipalUser(); ok {
			principal = u.UUID()
		}
		n, err := v.env.EligibleApprovers(v.ctx, *x, v.env.Owner(), principal)
		switch {
		case err != nil:
			v.lookupErr(at+"/approvers", err)
		case n < max(x.MinApprovals, 1):
			v.err(CodeGateNoApprover, at+"/approvers", "no one could decide this gate: %d eligible, %d needed", n, max(x.MinApprovals, 1))
		}
	case *RevokeGrantWith:
		scope("/scope", x.Scope, RevokeExecution, RevokeTriggerGrant, RevokeCeilingAgents)
	case *NotifyWith:
		for i, to := range x.To {
			scope("/to/"+strconv.Itoa(i), to, ScopeOwner, ScopeConfirmers, ScopeApprovers, ScopeTriggerOwner)
		}
		if x.Destination != nil && !slices.Contains(scopes, x.Destination.String()) {
			v.err(CodeUnsupportedCapability, at+"/destination", "list the destination under authority.platform for notify")
		}
		if n := utf8.RuneCountInString(x.Message.Title); n < 1 || n > 120 {
			v.err(CodeLimitRange, at+"/message/title", "a title is 1 to 120 characters")
		}
		if utf8.RuneCountInString(x.Message.Body) > 1000 {
			v.err(CodeLimitRange, at+"/message/body", "a body is at most 1000 characters")
		}
		if len(x.To) == 0 && x.Destination == nil {
			v.err(CodeLimitRange, at+"/to", "name who is notified")
		}
	case *DeliverWith:
		if !slices.Contains(scopes, x.Destination.String()) {
			v.err(CodeUnsupportedCapability, at+"/destination", "list the destination under authority.platform for deliver")
		}
		if !earlier(seen, x.From) || v.stepKind(x.From) != KindBuildDigest {
			v.err(CodeLimitRange, at+"/from", "name an earlier build_digest step")
		}
	case *WaitWith:
		if !dur(x.Duration, time.Second, MaxStepTimeout) {
			v.err(CodeLimitRange, at+"/duration", "a wait is 1s to 24h")
		}
	case *ContainWith:
		if !slices.Contains([]string{ContainSuspendRun, ContainRevokeGrant}, x.Action) {
			v.err(CodeLimitRange, at+"/action", "action is SUSPEND_RUN or REVOKE_GRANT")
		}
		scope("/subject", x.Subject, SubjectTriggerRun, SubjectTriggerGrant)
	case *OpenCaseWith:
		if n := utf8.RuneCountInString(x.Title); n < 1 || n > 200 {
			v.err(CodeLimitRange, at+"/title", "a title is 1 to 200 characters")
		}
		if len(x.Questions) > 10 {
			v.err(CodeLimitRange, at+"/questions", "at most 10 questions")
		}
	case *PauseLaunchesWith:
		scope("/selector", x.Selector, SelectAffected, SelectList)
	case *ResumeLaunchesWith:
		if !earlier(seen, x.Step) || v.stepKind(x.Step) != KindPauseLaunches {
			v.err(CodeLimitRange, at+"/step", "name an earlier pause_launches step")
		}
	case *WaitCoverageWith:
		if x.MinState != "ENFORCED" && x.MinState != "PARTIAL" {
			v.err(CodeLimitRange, at+"/min_state", "min_state is ENFORCED or PARTIAL")
		}
		if !dur(x.Timeout, time.Minute, MaxCoverageWait) {
			v.err(CodeDeadlineMissing, at+"/timeout", "wait_coverage needs a timeout of at most 7d")
		}
		// The route is the trigger's agent, connection and operation; the
		// operation is a declared trigger parameter (D103 T6).
		if _, ok := v.d.When.Params()["operation"]; !ok {
			v.err(CodeParamUndeclared, at, "wait_coverage needs the trigger parameter operation")
		}
	case *AssignOwnerWith:
		scope("/to", x.To, ScopeAgentOwner, ScopeConnectionOwner, ScopeOwner)
		if x.Deadline.D() > 7*24*time.Hour || x.Deadline < 0 {
			v.err(CodeLimitRange, at+"/deadline", "a deadline is at most 7d")
		}
	case *ApprovalRequestWith:
		scope("/request", x.Request, ScopeTriggerRequest)
	case *DraftBaselineWith:
		if x.From != "COHORT_BASELINE" && x.From != "TEMPLATE" {
			v.err(CodeLimitRange, at+"/from", "from is COHORT_BASELINE or TEMPLATE")
		}
	case *WaitClaimWith:
		if !dur(x.Timeout, time.Minute, MaxClaimWait) {
			v.err(CodeDeadlineMissing, at+"/timeout", "wait_claim needs a timeout of at most 30d")
		}
	case *DraftRestrictionWith:
		if x.From != "UNUSED_GRANTS" || x.Days < 7 {
			v.err(CodeLimitRange, at, "draft_restriction is from UNUSED_GRANTS over at least 7 days")
		}
	case *SimulateRestrictionWith:
		if !earlier(seen, x.Step) || v.stepKind(x.Step) != KindDraftRestriction {
			v.err(CodeLimitRange, at+"/step", "name an earlier draft_restriction step")
		}
		if x.Days < 0 || x.Days > 30 {
			v.err(CodeLimitRange, at+"/days", "days is at most 30")
		}
	case *BuildDigestWith:
		scope("/scope", x.Scope, ScopeTimeRange, ScopeTriggerCase)
		if x.Scope == ScopeTimeRange && (x.Days < 1 || x.Days > 31) {
			v.err(CodeLimitRange, at+"/days", "a time range is 1 to 31 days")
		}
		v.agentScope(at+"/evidence", x.Evidence)
		for i, sec := range x.Sections {
			if !slices.Contains([]string{"decisions", "effects", "holds", "alerts", "open_items"}, sec) {
				v.err(CodeLimitRange, at+"/sections/"+strconv.Itoa(i), "sections are decisions, effects, holds, alerts or open_items")
			}
		}
	case *IntakeWith:
	}
}

// templateFields checks that templates appear only in templatable fields
// and name declared parameters or earlier steps' outputs (HR-276).
func (v *validator) templateFields(at string, s StepSpec, k KindSpec) {
	if len(s.With) == 0 {
		return
	}
	var doc any
	if err := json.Unmarshal(s.With, &doc); err != nil {
		return
	}
	walkStrings(doc, "", func(ptr, val string) {
		if !strings.Contains(val, "{{") && !strings.Contains(val, "}}") {
			return
		}
		if !slices.ContainsFunc(k.Templatable, func(p string) bool { return pointerMatch(p, ptr) }) {
			v.err(CodeTemplateField, at+ptr, "%s cannot be templated (trigger data never selects identity, agents, operations, amounts or destinations)", ptr)
			return
		}
		v.templates(at+ptr, val)
	})
}

// templates checks every {{...}} in s.
func (v *validator) templates(at, s string) {
	if strings.Count(s, "{{") != len(templateRef.FindAllString(s, -1)) {
		v.err(CodeTemplateField, at, "malformed template")
		return
	}
	params := v.d.When.Params()
	for _, m := range templateRef.FindAllStringSubmatch(s, -1) {
		ref := m[1]
		if p := paramRef.FindStringSubmatch(ref); p != nil {
			if _, ok := params[p[1]]; !ok {
				v.err(CodeParamUndeclared, at, "parameter %q is not declared by the trigger", p[1])
			}
			continue
		}
		if o := outputRef.FindStringSubmatch(ref); o != nil {
			if v.d.Step(o[1]) == nil {
				v.err(CodeTemplateField, at, "step %q does not exist", o[1])
			}
			continue
		}
		v.err(CodeTemplateField, at, "a template is {{params.<name>}} or {{steps.<id>.output.<key>}}")
	}
}

// pointerMatch matches a JSON Pointer against a pattern where "*" is any
// one segment.
func pointerMatch(pattern, ptr string) bool {
	ps, xs := strings.Split(pattern, "/"), strings.Split(ptr, "/")
	if len(ps) != len(xs) {
		return false
	}
	for i := range ps {
		if ps[i] != "*" && ps[i] != xs[i] {
			return false
		}
	}
	return true
}

func walkStrings(x any, ptr string, f func(ptr, val string)) {
	switch t := x.(type) {
	case string:
		f(ptr, t)
	case map[string]any:
		for _, k := range sortedKeys(t) {
			walkStrings(t[k], ptr+"/"+strings.NewReplacer("~", "~0", "/", "~1").Replace(k), f)
		}
	case []any:
		for i, e := range t {
			walkStrings(e, ptr+"/"+strconv.Itoa(i), f)
		}
	}
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func (v *validator) ifFails() {
	f := v.d.IfFails
	if f == nil {
		return
	}
	switch f.Default {
	case "", OnFailureStop, OnFailureEscalate:
	case OnFailureContinue:
		v.err(CodeLimitRange, "/if_fails/default", "default is STOP or ESCALATE")
	default:
		v.err(CodeLimitRange, "/if_fails/default", "default is STOP or ESCALATE")
	}
	seen := map[string]int{}
	for i, s := range v.d.Do {
		seen[s.ID] = i
	}
	for i := range f.Compensate {
		at := "/if_fails/compensate/" + strconv.Itoa(i)
		v.step(at, f.Compensate[i], seen, true)
		seen[f.Compensate[i].ID] = len(v.d.Do) + i
	}
	for i, n := range f.Notify {
		if n != ScopeOwner {
			v.err(CodeLimitRange, "/if_fails/notify/"+strconv.Itoa(i), "if_fails notifies the OWNER")
		}
	}
}

func (v *validator) finish() {
	if len(v.d.Finish) == 0 {
		v.err(CodeTerminalMissing, "/finish_when", "say what proves the work is done (finish_when)")
	}
	for i, f := range v.d.Finish {
		at := "/finish_when/" + strconv.Itoa(i)
		s := v.d.Step(f.Step)
		switch {
		case s == nil:
			v.err(CodeTerminalMissing, at+"/step", "step %q does not exist", f.Step)
		case !f.Condition.Valid():
			v.err(CodeTerminalMissing, at+"/condition", "%q is not a finish condition", f.Condition)
		case !Catalog[s.Step].Satisfies(f.Condition):
			v.err(CodeCompletionRequestOnly, at, "%s cannot prove %s: finish on the step that confirms the outcome, not the one that asks for it",
				s.Step, f.Condition)
		}
	}
}

func (v *validator) limits() {
	l := v.d.Limits
	if l.Deadline < 0 || l.Deadline.D() > MaxDeadline {
		v.err(CodeLimitRange, "/limits/deadline", "the deadline is at most 7d")
	}
	if l.PerHour < 0 || l.PerHour > 600 {
		v.err(CodeLimitRange, "/limits/per_hour", "per_hour is 1 to 600")
	}
	switch v.d.Paused {
	case "", PausedDiscard, PausedQueue, PausedExpire:
	default:
		v.err(CodeLimitRange, "/paused_triggers", "paused_triggers is DISCARD, QUEUE or EXPIRE")
	}
	if v.d.QueueMax < 0 || v.d.QueueMax > 100 {
		v.err(CodeLimitRange, "/queue_max", "queue_max is at most 100")
	}
	if v.d.QueueTTL < 0 || v.d.QueueTTL.D() > MaxQueueTTL {
		v.err(CodeLimitRange, "/queue_ttl", "queue_ttl is at most 24h")
	}
	for i, s := range v.d.Do {
		if s.Timeout.D() > v.d.Limits.DeadlineOrDefault() {
			v.err(CodeLimitRange, "/do/"+strconv.Itoa(i)+"/timeout", "a step's timeout exceeds the execution deadline")
		}
	}
}

// irreversible: every irreversible ceiling operation is reconciled by a
// wait_effect step on it (D4).
func (v *validator) irreversible() {
	for i, op := range v.ops {
		info, ok := v.infos[op]
		if !ok || !info.Irreversible {
			continue
		}
		covered := slices.ContainsFunc(v.d.Do, func(s StepSpec) bool {
			if s.Step != KindWaitEffect {
				return false
			}
			w, err := s.DecodeWith()
			if err != nil {
				return false
			}
			we := w.(*WaitEffectWith) //nolint:forcetypeassert // the catalog's type for wait_effect
			return gdomain.Ops{op}.Matches(we.Operation) || we.Operation == op
		})
		if !covered {
			v.err(CodeIrreversibleUnreconciled, "/authority/ceiling/bounds/operations/"+strconv.Itoa(i),
				"%s cannot be undone: add a wait_effect step that confirms its effect", op)
		}
	}
}

// loops warns when the trigger listens to an event the version's own
// steps can produce (D4; runtime ancestry still refuses loops).
func (v *validator) loops() {
	var on string
	switch {
	case v.d.When.Event != nil:
		on = v.d.When.Event.On
	case v.d.When.Threshold != nil:
		on = v.d.When.Threshold.On
	default:
		return
	}
	if on == EventAutomationFinished {
		v.add(SeverityWarning, CodeLoopPossible, "/when", "every execution produces automation.finished; it may trigger this automation again")
		return
	}
	check := func(at string, s StepSpec) {
		if slices.Contains(Produces(s.Step), on) {
			v.add(SeverityWarning, CodeLoopPossible, at,
				"%s can produce %s, the event this automation listens to; a loop is refused at run time", s.Step, on)
		}
	}
	for i, s := range v.d.Do {
		check("/do/"+strconv.Itoa(i), s)
	}
	if v.d.IfFails != nil {
		for i, s := range v.d.IfFails.Compensate {
			check("/if_fails/compensate/"+strconv.Itoa(i), s)
		}
	}
}

// ConfirmerScopes is what every enabling confirmer (and every approver of
// the ceiling) must hold beyond automation.publish, for the kinds and
// scopes the definition uses (D7, D65, D85, HR-272): permissions at the
// org, and permissions at each listed agent's path.
type ConfirmerScopes struct {
	Org    []string
	Agents map[ids.UUID][]string
}

func (c *ConfirmerScopes) org(ps ...string) {
	for _, p := range ps {
		if !slices.Contains(c.Org, p) {
			c.Org = append(c.Org, p)
		}
	}
}

func (c *ConfirmerScopes) agents(as []ids.UUID, ps ...string) {
	if c.Agents == nil {
		c.Agents = map[ids.UUID][]string{}
	}
	for _, a := range as {
		for _, p := range ps {
			if !slices.Contains(c.Agents[a], p) {
				c.Agents[a] = append(c.Agents[a], p)
			}
		}
	}
}

func (c *ConfirmerScopes) scope(s *AgentScope, ps ...string) {
	switch {
	case s == nil:
	case s.All:
		c.org(ps...)
	default:
		c.agents(refUUIDs(s.Agents), ps...)
	}
}

// AgentIDs lists the agents with per-path permissions, sorted.
func (c ConfirmerScopes) AgentIDs() []ids.UUID {
	out := make([]ids.UUID, 0, len(c.Agents))
	for a := range c.Agents {
		out = append(out, a)
	}
	slices.SortFunc(out, func(a, b ids.UUID) int { return strings.Compare(a.String(), b.String()) })
	return out
}

func refUUIDs(rs []RefID) []ids.UUID {
	out := make([]ids.UUID, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.UUID())
	}
	return out
}

// RevokesBeyondExecution reports whether a step's `with` revokes grants
// other than its execution's own (D65): revoke_grant TRIGGER_GRANT or
// CEILING_AGENTS, and contain REVOKE_GRANT.
func RevokesBeyondExecution(w any) bool {
	switch x := w.(type) {
	case *RevokeGrantWith:
		return x.Scope != RevokeExecution
	case *ContainWith:
		return x.Action == ContainRevokeGrant
	}
	return false
}

// RequiredConfirmerPermissions returns what each confirmer must hold. A
// step whose `with` does not decode adds nothing; Validate refuses it.
func (d *Definition) RequiredConfirmerPermissions() ConfirmerScopes {
	var out ConfirmerScopes
	all := slices.Clone(d.Do)
	if d.IfFails != nil {
		all = append(all, d.IfFails.Compensate...)
	}
	for _, s := range all {
		k, ok := Catalog[s.Step]
		if !ok {
			continue
		}
		w, err := s.DecodeWith()
		if err != nil {
			continue
		}
		at := k.ConfirmAt
		if k.ConfirmRevocable && RevokesBeyondExecution(w) {
			out.scope(d.Authority.Revocable, permGrantRevoke)
			if at == ConfirmCeilingAgents {
				continue // the revocable scope replaces the ceiling's
			}
		}
		switch at {
		case ConfirmCeilingAgents:
			out.agents(d.CeilingAgents(), k.ConfirmerPermissions...)
		case ConfirmOrg:
			out.org(k.ConfirmerPermissions...)
		case ConfirmEvidence:
			if b, ok := w.(*BuildDigestWith); ok {
				out.scope(&b.Evidence, k.ConfirmerPermissions...)
			}
		case ConfirmNone:
		}
	}
	slices.Sort(out.Org)
	for a := range out.Agents {
		slices.Sort(out.Agents[a])
	}
	return out
}

// Kinds returns the step kinds the definition uses (steps and
// compensation), sorted.
func (d *Definition) Kinds() []string {
	var out []string
	for _, s := range d.Do {
		out = append(out, s.Step)
	}
	if d.IfFails != nil {
		for _, s := range d.IfFails.Compensate {
			out = append(out, s.Step)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// CeilingAgents returns the ceiling's agents (none without a ceiling).
func (d *Definition) CeilingAgents() []ids.UUID {
	if d.Authority.Ceiling == nil {
		return nil
	}
	out := make([]ids.UUID, 0, len(d.Authority.Ceiling.Agents))
	for _, a := range d.Authority.Ceiling.Agents {
		out = append(out, a.UUID())
	}
	return out
}
