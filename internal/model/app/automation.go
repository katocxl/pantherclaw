// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	autoapp "github.com/katocxl/pantherclaw/internal/automations/app"
	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/triggers"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/model/ports"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/policy/packs/render"
	"github.com/katocxl/pantherclaw/internal/reflex/alerts"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	txdomain "github.com/katocxl/pantherclaw/internal/transactions/domain"
)

const (
	// maxDraftNodes bounds one automation draft.
	maxDraftNodes = 24
	// maxPurpose bounds an automation draft's purpose.
	maxPurpose = 500
	// maxCaseQuestion bounds one question of a drafted case.
	maxCaseQuestion = 200
	// Validation's bounds on what a person reads, in characters.
	maxGateSummary   = 1000
	maxNotifyTitle   = 120
	maxNotifyBody    = 1000
	maxCaseTitle     = 200
	maxCaseQuestions = 10
	// reviewAfter is how soon a person reviews a drafted automation again.
	reviewAfter = 30 * 24 * time.Hour
)

// Node types of a draft.
const (
	nodeGate     = "gate"
	nodeNotify   = "notify"
	nodeWait     = "wait"
	nodeOpenCase = "open_case"
	nodeBranch   = "branch"
	nodeSwitch   = "switch"
	nodeTerminal = "terminal"
)

// AutomationDrafts stores a new automation with its first DRAFT version in the
// caller's transaction (autoapp.Service). It has no publish path.
type AutomationDrafts interface {
	CreateDraftTx(ctx context.Context, tx db.TenantTx, in autoapp.Draft) (autoapp.Automation, autoapp.Version, error)
}

// AutomationDraft is a stored DRAFT. Nothing about it runs: only the M11.1 gate
// enables it (HR-544).
type AutomationDraft struct {
	Automation  ids.UUID
	Version     ids.UUID
	Name        string
	Call        ids.UUID
	Ambiguities []Ambiguity
}

// draftAutomation is the only automation a model can write (D315). No field
// holds an id, a free expression, a template or authority: Go derives the
// principal and the platform scopes from the steps.
type draftAutomation struct {
	Name        string              `json:"name"`
	Purpose     string              `json:"purpose"`
	WorkKind    autodomain.WorkKind `json:"work_kind"`
	Schedule    *draftSchedule      `json:"schedule"`
	Event       *draftEvent         `json:"event"`
	Nodes       []draftNode         `json:"nodes"`
	Ambiguities []Ambiguity         `json:"ambiguities"`
}

type draftSchedule struct {
	Cron     string `json:"cron"`
	Timezone string `json:"timezone"`
}

type draftEvent struct {
	On string `json:"on"`
}

// draftNode is one node: Type says which of its parts is set.
type draftNode struct {
	ID       string         `json:"id"`
	Type     string         `json:"type"`
	Next     string         `json:"next"`
	Gate     *draftGate     `json:"gate"`
	Notify   *draftNotify   `json:"notify"`
	Wait     *draftWait     `json:"wait"`
	OpenCase *draftOpenCase `json:"open_case"`
	Branch   *draftBranch   `json:"branch"`
	Switch   *draftSwitch   `json:"switch"`
	Terminal *draftTerminal `json:"terminal"`
}

type draftGate struct {
	Roles         []string `json:"roles"`
	MinApprovals  int      `json:"min_approvals"`
	DeadlineHours int      `json:"deadline_hours"`
	Summary       string   `json:"summary"`
}

type draftNotify struct {
	To    []string `json:"to"`
	Title string   `json:"title"`
	Body  string   `json:"body"`
}

type draftWait struct {
	Minutes int `json:"minutes"`
}

type draftOpenCase struct {
	Title     string   `json:"title"`
	Questions []string `json:"questions"`
}

type draftBranch struct {
	Conditions []guardCondition `json:"conditions"`
	Then       string           `json:"then"`
	Else       string           `json:"else"`
}

type draftSwitch struct {
	Cases   []draftCase `json:"cases"`
	Default string      `json:"default"`
}

type draftCase struct {
	Conditions []guardCondition `json:"conditions"`
	Next       string           `json:"next"`
}

type draftTerminal struct {
	Outcome    autodomain.Outcome `json:"outcome"`
	FinishWhen []draftFinish      `json:"finish_when"`
}

// draftFinish is a finish condition. Of the steps a model can write, only
// open_case satisfies one.
type draftFinish struct {
	Step      string                     `json:"step"`
	Condition autodomain.FinishCondition `json:"condition"`
}

// guardCondition compares one field of the triggering event. All of a path's
// conditions hold. There is no expression to write: Go renders the guard.
type guardCondition struct {
	Field string `json:"field"`
	Op    string `json:"op"`
	Value string `json:"value"`
}

// eventParamPattern is the declared pattern of an event field a guard reads,
// and so what a condition's value may be.
const eventParamPattern = `^[A-Za-z0-9._:/-]{1,64}$`

var eventValue = regexp.MustCompile(eventParamPattern)

// guardFields are the event fields a guard may read, none of them an
// organization's record. The environment is not one: it holds an environment's
// id, so a name a model wrote would never match and a production path would
// never be taken (D321).
var guardFields = []string{fieldActorType, fieldDecision, fieldMode, fieldOperation, fieldOutcome}

// Guard fields.
const (
	fieldActorType = "actor_type"
	fieldDecision  = "decision"
	fieldMode      = "mode"
	fieldOperation = "operation"
	fieldOutcome   = "outcome"
)

func texts[S ~string](values ...S) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, string(v))
	}
	return out
}

// eventFields are the guard fields each event always fills (reflex/feed), each
// with the values its writers can give it, built from their constants. A
// trigger param is required, so a guard on any other field would refuse every
// event, and the automation would never start (D321). A value no writer gives
// never matches, so a drafted `decision == 'DENIED'` would quietly skip a gate
// (D324). An outcome that never varies is left out: no guard can branch on it.
// `operation` has no list here: it is checked against the built-in operations.
var eventFields = func() map[string]map[string][]string {
	gateway, system := texts(reflexdomain.SubjectGateway), texts(reflexdomain.SubjectSystem)
	callers := texts(td.KindUser, td.KindServiceAccount)
	modes := []string{strings.ToUpper(pipeline.ModeEnforce), strings.ToUpper(pipeline.ModeMonitor)}
	action := func(decisions ...string) map[string][]string {
		return map[string][]string{fieldActorType: gateway, fieldDecision: decisions, fieldMode: modes, fieldOperation: nil}
	}
	actors := func(types ...[]string) map[string][]string {
		return map[string][]string{fieldActorType: slices.Concat(types...)}
	}
	return map[string]map[string][]string{
		triggers.VocabActionDecided: action(texts(
			adomain.Allow, adomain.AllowWithObligations, adomain.RequireApproval, adomain.RequireStepUp, adomain.Deny, adomain.CannotAuthorize,
		)...),
		triggers.VocabActionHeld:   action(texts(adomain.RequireApproval, adomain.RequireStepUp)...),
		triggers.VocabActionDenied: action(texts(adomain.Deny)...),
		triggers.VocabEffectRecorded: {
			fieldActorType: slices.Concat(gateway, system, texts(td.KindUser)), fieldMode: modes, fieldOperation: nil,
			fieldOutcome: texts(txdomain.EffectStates...),
		},
		triggers.VocabRunEnded:        actors(callers),
		triggers.VocabGrantIssued:     actors(callers),
		triggers.VocabGrantRevoked:    actors(callers),
		triggers.VocabAgentDiscovered: actors(callers, gateway),
		triggers.VocabApprovalExpired: actors(gateway, system),
		triggers.VocabAutomationFinished: {
			fieldActorType: texts(td.KindServiceAccount), fieldOutcome: texts(audit.Success, audit.Failure),
		},
		triggers.VocabAlertRaised:    {fieldActorType: {alerts.Actor.Type}, fieldOutcome: {alerts.StateOpen, alerts.StateSuppressed}},
		triggers.VocabIncidentOpened: {fieldActorType: {alerts.Actor.Type}},
		// coverage.lost's entries fill different fields, and case.closed's none.
		triggers.VocabCoverageLost: actors(callers, system),
		triggers.VocabCaseClosed:   actors(texts(td.KindUser)),
	}
}()

// guardValues tells a model the values of eventFields. The schema's object
// cannot vary an enum by field, so build() is what refuses any other value.
func guardValues() string {
	var b strings.Builder
	b.WriteString("the plain value the triggering event's field is compared with, written exactly as listed; " +
		"operation takes a built-in operation's full name. By event: ")
	for _, on := range slices.Sorted(maps.Keys(eventFields)) {
		for _, field := range slices.Sorted(maps.Keys(eventFields[on])) {
			if values := eventFields[on][field]; len(values) > 0 {
				b.WriteString(on + " " + field + ": " + strings.Join(values, ", ") + "; ")
			}
		}
	}
	return strings.TrimSuffix(b.String(), "; ")
}

var (
	nodeID   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,40}$`)
	cronExpr = regexp.MustCompile(`^[0-9A-Za-z*/,-]{1,16}( [0-9A-Za-z*/,-]{1,16}){4}$`)
)

// notifyScopes are the people a drafted notice may reach.
var notifyScopes = []string{autodomain.ScopeOwner, autodomain.ScopeConfirmers, autodomain.ScopeApprovers, autodomain.ScopeTriggerOwner}

// draftableSteps are the kinds a model can write (D315): those whose `with`
// holds no id and takes no authority away from running work.
func draftableSteps() []string {
	return []string{autodomain.KindGate, autodomain.KindNotify, autodomain.KindOpenCase, autodomain.KindWait}
}

// approverRoles are the built-in roles that can decide a gate. A custom role's
// name is an organization's record (HR-542).
func approverRoles() []string {
	var out []string
	for _, r := range td.Roles() {
		if r.Has(td.PermAutomationApprove) {
			out = append(out, string(r.Name))
		}
	}
	slices.Sort(out)
	return out
}

func guardSchema() ports.Schema {
	return ports.Array(ports.Object(map[string]ports.Schema{
		"field": ports.Enum(guardFields),
		"op":    ports.Enum(opNames(equalityOps)),
		"value": ports.Text(guardValues()),
	}))
}

func automationSchema() ports.Schema {
	nodeRef := func(what string) ports.Schema { return ports.Text("the id of the node " + what) }
	return ports.Object(map[string]ports.Schema{
		"name":      ports.Text("a lowercase name of letters, digits and hyphens"),
		"purpose":   ports.Text("why this automation exists, in one sentence"),
		"work_kind": ports.Enum([]string{string(autodomain.WorkAgent), string(autodomain.WorkSecurity)}),
		"schedule": ports.Nullable(ports.Object(map[string]ports.Schema{
			"cron":     ports.Text("a five-field cron expression"),
			"timezone": ports.Text("an IANA time zone"),
		})),
		"event": ports.Nullable(ports.Object(map[string]ports.Schema{"on": ports.Enum(autodomain.Events)})),
		"nodes": ports.Array(ports.Object(map[string]ports.Schema{
			"id":   ports.Text("a lowercase id of letters, digits and underscores; the first node runs first"),
			"type": ports.Enum([]string{nodeGate, nodeNotify, nodeWait, nodeOpenCase, nodeBranch, nodeSwitch, nodeTerminal}),
			"next": nodeRef("after this step; empty on a branch, switch or terminal"),
			"gate": ports.Nullable(ports.Object(map[string]ports.Schema{
				"roles":          ports.Array(ports.Enum(approverRoles())),
				"min_approvals":  ports.Integer("approvals needed, 1 or 2"),
				"deadline_hours": ports.Integer("hours to decide, 1 to 72"),
				"summary":        ports.Text("what the approvers are deciding, as literal text"),
			})),
			"notify": ports.Nullable(ports.Object(map[string]ports.Schema{
				"to":    ports.Array(ports.Enum(notifyScopes)),
				"title": ports.Text("the notice's title, as literal text"),
				"body":  ports.Text("the notice's body as literal text, or empty"),
			})),
			"wait": ports.Nullable(ports.Object(map[string]ports.Schema{"minutes": ports.Integer("minutes to wait, 1 to 1440")})),
			"open_case": ports.Nullable(ports.Object(map[string]ports.Schema{
				"title":     ports.Text("the case's title, as literal text"),
				"questions": ports.Array(ports.Text("a question for the case, as literal text")),
			})),
			"branch": ports.Nullable(ports.Object(map[string]ports.Schema{
				"conditions": guardSchema(),
				"then":       nodeRef("when every condition holds"),
				"else":       nodeRef("otherwise"),
			})),
			"switch": ports.Nullable(ports.Object(map[string]ports.Schema{
				"cases": ports.Array(ports.Object(map[string]ports.Schema{
					"conditions": guardSchema(),
					"next":       nodeRef("when every condition holds; the first case that holds wins"),
				})),
				"default": nodeRef("when no case holds"),
			})),
			"terminal": ports.Nullable(ports.Object(map[string]ports.Schema{
				"outcome": ports.Enum([]string{string(autodomain.OutcomeSucceeded), string(autodomain.OutcomePartiallyCompleted), string(autodomain.OutcomeFailed)}),
				"finish_when": ports.Array(ports.Object(map[string]ports.Schema{
					"step":      nodeRef("of an open_case step on this path"),
					"condition": ports.Enum([]string{string(autodomain.FinishCaseOpened)}),
				})),
			})),
		})),
		"ambiguities": AmbiguitySchema(),
	})
}

// literalText reports whether s is text a person reads as written: bounded,
// every character showing as written, and without template syntax. A reviewer adds
// templates in the editor (D315).
func literalText(s string, limit int) bool {
	return utf8.ValidString(s) && utf8.RuneCountInString(s) <= limit && !strings.Contains(s, "{{") && !strings.Contains(s, "}}") &&
		!strings.ContainsFunc(s, func(c rune) bool { return c != '\n' && unreadable(c) })
}

// wanted is literal text that must say something.
func wanted(s string, limit int) bool { return strings.TrimSpace(s) != "" && literalText(s, limit) }

// renderGuard is a path's guard, reading the event's fields as the trigger's
// parameters. A value only ever reaches the expression as a literal.
func renderGuard(cs []guardCondition) (string, bool) {
	if len(cs) == 0 || len(cs) > maxConditions {
		return "", false
	}
	parts := make([]string, 0, len(cs))
	for _, c := range cs {
		op, ok := equalityOps[c.Op]
		if !ok || !slices.Contains(guardFields, c.Field) {
			return "", false
		}
		parts = append(parts, "trigger.params."+c.Field+" "+op+" "+render.CELQuote(c.Value))
	}
	return strings.Join(parts, " && "), true
}

// builder turns a draft into a definition, keeping what a model does not
// choose.
type builder struct {
	// fields are the event fields the guards read.
	fields map[string]bool
	// on is the triggering event, empty when there is none.
	on string
	// operations are the built-in operations a guard may name.
	operations []string
}

// guard renders a path's guard, which only the fields its event fills can
// reach, comparing them with only the values those fields can hold.
func (b *builder) guard(cs []guardCondition) (string, bool) {
	src, ok := renderGuard(cs)
	if !ok {
		return "", false
	}
	for _, c := range cs {
		allowed, fills := eventFields[b.on][c.Field]
		if c.Field == fieldOperation {
			allowed = b.operations
		}
		if !eventValue.MatchString(c.Value) || !fills || !slices.Contains(allowed, c.Value) {
			return "", false
		}
		b.fields[c.Field] = true
	}
	return src, true
}

func with(v any) (jsontext.Value, bool) {
	raw, err := json.Marshal(v, json.Deterministic(true))
	return raw, err == nil
}

// step fills a step node's kind and `with` and reports the platform scopes it
// needs. Exactly the type's part is set, or the node is refused.
func (n draftNode) step(out *autodomain.NodeSpec) ([]string, bool) {
	var w any
	var scopes []string
	switch {
	case n.Type == nodeGate && n.Gate != nil:
		g := n.Gate
		if !subset(g.Roles, approverRoles()) || g.MinApprovals < 1 || g.MinApprovals > 2 || g.DeadlineHours < 1 || g.DeadlineHours > 72 ||
			!literalText(g.Summary, maxGateSummary) {
			return nil, false
		}
		out.Step = autodomain.KindGate
		w = autodomain.GateWith{
			Approvers: autodomain.GateApprovers{Roles: g.Roles}, MinApprovals: g.MinApprovals,
			Deadline: autodomain.Duration(time.Duration(g.DeadlineHours) * time.Hour), Summary: g.Summary,
		}
	case n.Type == nodeNotify && n.Notify != nil:
		x := n.Notify
		if !subset(x.To, notifyScopes) || !wanted(x.Title, maxNotifyTitle) || !literalText(x.Body, maxNotifyBody) {
			return nil, false
		}
		out.Step = autodomain.KindNotify
		scopes = x.To
		w = autodomain.NotifyWith{To: x.To, Message: autodomain.NotifyMessage{Title: x.Title, Body: x.Body}}
	case n.Type == nodeWait && n.Wait != nil:
		if n.Wait.Minutes < 1 || n.Wait.Minutes > 1440 {
			return nil, false
		}
		out.Step = autodomain.KindWait
		w = autodomain.WaitWith{Duration: autodomain.Duration(time.Duration(n.Wait.Minutes) * time.Minute)}
	case n.Type == nodeOpenCase && n.OpenCase != nil:
		x := n.OpenCase
		if !wanted(x.Title, maxCaseTitle) || len(x.Questions) > maxCaseQuestions {
			return nil, false
		}
		for _, q := range x.Questions {
			if !wanted(q, maxCaseQuestion) {
				return nil, false
			}
		}
		out.Step = autodomain.KindOpenCase
		w = autodomain.OpenCaseWith{Title: x.Title, Questions: x.Questions}
	default:
		return nil, false
	}
	raw, ok := with(w)
	out.With, out.Next = raw, n.Next
	return scopes, ok && n.Next != ""
}

// subset reports whether got is non-empty, has no repeat, and is all of allowed.
func subset(got, allowed []string) bool {
	seen := map[string]bool{}
	for _, v := range got {
		if seen[v] || !slices.Contains(allowed, v) {
			return false
		}
		seen[v] = true
	}
	return len(got) > 0
}

// parts counts the node's set parts: a node has one.
func (n draftNode) parts() int {
	c := 0
	for _, set := range []bool{
		n.Gate != nil, n.Notify != nil, n.Wait != nil, n.OpenCase != nil, n.Branch != nil, n.Switch != nil, n.Terminal != nil,
	} {
		if set {
			c++
		}
	}
	return c
}

func (b *builder) node(n draftNode, platform map[string][]string) (autodomain.NodeSpec, bool) {
	out := autodomain.NodeSpec{ID: n.ID}
	if n.parts() != 1 {
		return out, false
	}
	switch {
	case n.Type == nodeBranch && n.Branch != nil:
		when, ok := b.guard(n.Branch.Conditions)
		out.Branch = &autodomain.BranchSpec{When: when, Then: n.Branch.Then, Else: n.Branch.Else}
		return out, ok && n.Next == "" && n.Branch.Then != "" && n.Branch.Else != ""
	case n.Type == nodeSwitch && n.Switch != nil:
		out.Switch = &autodomain.SwitchSpec{Default: n.Switch.Default}
		for _, c := range n.Switch.Cases {
			when, ok := b.guard(c.Conditions)
			if !ok || c.Next == "" {
				return out, false
			}
			out.Switch.Cases = append(out.Switch.Cases, autodomain.CaseSpec{When: when, Next: c.Next})
		}
		return out, n.Next == "" && n.Switch.Default != "" && len(n.Switch.Cases) > 0
	case n.Type == nodeTerminal && n.Terminal != nil:
		out.Outcome = n.Terminal.Outcome
		for _, f := range n.Terminal.FinishWhen {
			out.FinishWhen = append(out.FinishWhen, autodomain.Finish{Step: f.Step, Condition: f.Condition})
		}
		return out, n.Next == "" && n.Terminal.Outcome.Valid()
	}
	scopes, ok := n.step(&out)
	if ok && (out.Step == autodomain.KindNotify || out.Step == autodomain.KindOpenCase) {
		platform[out.Step] = append(platform[out.Step], scopes...)
	}
	return out, ok
}

// checkGraph refuses repeated or malformed ids, a way out to no node, and a
// finish on anything but an open_case step. Reachability and cycles are
// validation's, as in any draft.
func checkGraph(nodes []autodomain.NodeSpec) bool {
	kind := make(map[string]autodomain.NodeSpec, len(nodes))
	terminal := false
	for _, n := range nodes {
		if _, dup := kind[n.ID]; dup || !nodeID.MatchString(n.ID) {
			return false
		}
		kind[n.ID] = n
	}
	for i := range nodes {
		n := &nodes[i]
		terminal = terminal || n.Kind() == autodomain.NodeKindTerminal
		for _, e := range n.Edges() {
			if _, ok := kind[e.To]; !ok {
				return false
			}
		}
		for _, f := range n.FinishWhen {
			if kind[f.Step].Step != autodomain.KindOpenCase || f.Condition != autodomain.FinishCaseOpened {
				return false
			}
		}
	}
	return terminal
}

// when is the trigger: a schedule, an event, or by default a person starting
// it. The event's fields that guards read are declared here, as parameters.
func (b *builder) when(d *draftAutomation) (autodomain.When, bool) {
	switch {
	case d.Schedule != nil && d.Event != nil:
		return autodomain.When{}, false
	case d.Schedule != nil:
		s := d.Schedule
		loc := s.Timezone != "" && s.Timezone != "Local" && len(s.Timezone) <= 64
		if loc {
			_, err := time.LoadLocation(s.Timezone)
			loc = err == nil
		}
		return autodomain.When{Schedule: &autodomain.Schedule{Cron: s.Cron, Timezone: s.Timezone}}, loc && cronExpr.MatchString(s.Cron)
	case d.Event != nil:
		e := &autodomain.EventWhen{On: d.Event.On}
		for _, f := range guardFields {
			if b.fields[f] {
				if e.Params == nil {
					e.Params = map[string]autodomain.ParamSpec{}
				}
				e.Params[f] = autodomain.ParamSpec{From: f, Type: autodomain.ParamString, Pattern: eventParamPattern}
			}
		}
		return autodomain.When{Event: e}, slices.Contains(autodomain.Events, d.Event.On)
	}
	return autodomain.When{Manual: &autodomain.ManualWhen{}}, true
}

// build is the definition of a draft, parsed as any definition is. Anything
// outside what a model can write refuses the whole draft (HR-543).
func (d *draftAutomation) build(now time.Time, operations []string) ([]byte, bool) {
	if !autodomain.NamePattern.MatchString(d.Name) || !wanted(d.Purpose, maxPurpose) || !d.WorkKind.Valid() ||
		len(d.Nodes) < 2 || len(d.Nodes) > maxDraftNodes {
		return nil, false
	}
	b := &builder{fields: map[string]bool{}, operations: operations}
	if d.Event != nil {
		b.on = d.Event.On
	}
	platform := map[string][]string{}
	nodes := make([]autodomain.NodeSpec, 0, len(d.Nodes))
	for _, n := range d.Nodes {
		spec, ok := b.node(n, platform)
		if !ok {
			return nil, false
		}
		nodes = append(nodes, spec)
	}
	if !checkGraph(nodes) {
		return nil, false
	}
	when, ok := b.when(d)
	if !ok {
		return nil, false
	}
	def := autodomain.Definition{
		APIVersion: autodomain.APIVersionV2, Kind: autodomain.DocKind, Purpose: d.Purpose, WorkKind: d.WorkKind,
		ReviewBy: autodomain.NewDate(now.Add(reviewAfter)), When: when, Nodes: nodes,
		Authority: autodomain.Authority{Principal: autodomain.PrincipalSelf},
	}
	for _, kind := range []string{autodomain.KindNotify, autodomain.KindOpenCase} {
		if scopes, used := platform[kind]; used {
			slices.Sort(scopes)
			def.Authority.Platform = append(def.Authority.Platform, autodomain.PlatformScope{Step: kind, Scopes: slices.Compact(scopes)})
		}
	}
	raw, err := def.Canonical()
	if err != nil {
		return nil, false
	}
	parsed, err := autodomain.Parse(raw)
	if err != nil {
		return nil, false
	}
	raw, err = parsed.Canonical()
	return raw, err == nil
}

// parseAutomation reads a model's answer strictly (HR-543).
func parseAutomation(text string, output []byte, now time.Time, operations []string) (*draftAutomation, []byte, error) {
	var d draftAutomation
	if json.Unmarshal(output, &d, json.RejectUnknownMembers(true)) != nil {
		return nil, nil, ports.ErrInvalidOutput
	}
	if err := CheckAmbiguities(text, d.Ambiguities); err != nil {
		return nil, nil, err
	}
	raw, ok := d.build(now, operations)
	if !ok {
		return nil, nil, ports.ErrInvalidOutput
	}
	return &d, raw, nil
}

// DraftAutomation turns text into a new automation with a DRAFT version,
// origin=model. Nothing runs: enabling stays with the M11.1 gate and a person
// (HR-544).
func (s *Service) DraftAutomation(ctx context.Context, text string) (AutomationDraft, error) {
	c, err := callerWith(ctx, td.PermAutomationManage)
	if err != nil {
		return AutomationDraft{}, err
	}
	if s.Automations == nil {
		return AutomationDraft{}, ErrPlatformOff
	}
	if err := CheckEnvironment(text); err != nil {
		return AutomationDraft{}, err
	}
	schema, err := automationSchema().Encode()
	if err != nil {
		return AutomationDraft{}, err
	}
	var out AutomationDraft
	res, err := s.Draft(ctx, Call{
		Task: ports.TaskAutomationDraft, Text: text, Schema: schema, Catalog: ports.Catalog{StepKinds: draftableSteps()},
		Parse: func(call ids.UUID, output []byte) error {
			d, definition, err := parseAutomation(text, output, s.now(), s.Builtin)
			if err != nil {
				return err
			}
			out.Name, out.Ambiguities = d.Name, d.Ambiguities
			err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
				a, v, err := s.Automations.CreateDraftTx(ctx, tx, autoapp.Draft{
					Name: d.Name, Purpose: d.Purpose, Kind: d.WorkKind, Owner: c.Principal.ID, Definition: definition,
				})
				if err != nil {
					return err
				}
				out.Automation, out.Version = a.ID, v.ID
				return LinkDraft(ctx, tx, c.Org, v.ID, call, automationKind, d.Ambiguities)
			})
			if errors.Is(err, autoapp.ErrName) || errors.Is(err, autoapp.ErrDefinition) || pcerr.ReasonOf(err) == "DEFINITION_INVALID" {
				return ports.ErrInvalidOutput
			}
			return err
		},
	})
	if err != nil {
		return AutomationDraft{}, err
	}
	out.Call = res.ID
	return out, nil
}
