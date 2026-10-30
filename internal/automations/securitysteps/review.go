// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package securitysteps

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/authority/replay"
	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	autoports "github.com/katocxl/pantherclaw/internal/automations/ports"
	evapp "github.com/katocxl/pantherclaw/internal/evidence/app"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	"github.com/katocxl/pantherclaw/internal/evidence/retention"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	papp "github.com/katocxl/pantherclaw/internal/policy/app"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	"github.com/katocxl/pantherclaw/internal/policy/simulation"
	"github.com/katocxl/pantherclaw/internal/policy/simulation/pgsimulation"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// Review reasons, stable codes.
const (
	ReasonNoDraft      = "DRAFT_MISSING"
	ReasonSimulation   = "SIMULATION_FAILED"
	ReasonCaseNotFound = "CASE_NOT_FOUND"
)

// Bounds of the review kinds (D31).
const (
	MinUnusedDays    = 7
	MaxUnusedDays    = 365
	MaxSimulateDays  = simulation.MaxDays
	MaxDigestDays    = 31
	DefaultDigestDay = 7
	MaxDigestTitle   = 200
	// maxUnusedGrants bounds the unused grants one draft considers, and
	// maxRestrictionRules the agents it restricts.
	maxUnusedGrants     = 500
	maxRestrictionRules = 100
	maxBodyAgents       = 40
	maxBodyOps          = 16
)

// Output keys.
const (
	OutPolicyVersion = "policy_version_id"
	OutSimulation    = "simulation_id"
	OutPack          = "pack_id"
	OutReportDigest  = "report_digest"
)

// The restriction a draft_restriction step writes: one FORBID rule per
// agent over the operations its unused grants allow, for that agent's
// runs only. A simulation shows what it would have denied; a person
// decides whether to publish it.
const (
	RestrictionReason = "UNUSED_GRANT_RESTRICTED"
	restrictionPrefix = "unused-"
	// DraftBundleID names the bundle of a draft when no policy is
	// published yet.
	DraftBundleID = "least-privilege"
)

// Digest scopes and sections (BuildDigestWith).
const (
	SectionDecisions = "decisions"
	SectionEffects   = "effects"
	SectionHolds     = "holds"
	SectionAlerts    = "alerts"
	SectionOpenItems = "open_items"
)

var digestSections = []string{SectionDecisions, SectionEffects, SectionHolds, SectionAlerts, SectionOpenItems}

// UnusedGrant is an active grant with no recorded use since a time, and
// the operation patterns its bounds allow (nil: not bounded by operation).
type UnusedGrant struct {
	ID         ids.UUID
	Agent      ids.UUID
	Operations []string
}

// UnusedGrants runs the unused_grants built-in (F310) at the org.
type UnusedGrants interface {
	Unused(ctx context.Context, tx pgx.Tx, org ids.OrgID, since time.Time, limit int) ([]UnusedGrant, error)
}

// PolicyDrafts reads the published policy and stores drafts. It has no
// way to validate, test or publish one: publication stays human (F599,
// HR-286).
type PolicyDrafts interface {
	// Published returns the published bundle and its version id, or nil.
	Published(ctx context.Context, tx pgx.Tx, org ids.OrgID) (*pdomain.Bundle, ids.UUID, error)
	// CreateDraft stores b as the next DRAFT version of its policy,
	// authored by author, and returns its id and number.
	CreateDraft(ctx context.Context, tx pgx.Tx, org ids.OrgID, b *pdomain.Bundle, author evdomain.Actor) (ids.UUID, int, error)
}

// SimulationRequest asks for a simulation of a stored version.
type SimulationRequest struct {
	Org     ids.OrgID
	Version ids.UUID
	Days    int
	Actor   evdomain.Actor
}

// SimulationStatus is a simulation's state and counts by category.
type SimulationStatus struct {
	State     simulation.State
	Evaluated int
	Counts    map[replay.Category]int
	Error     string
}

// PolicySimulations queues M11.1 simulations in the caller's transaction
// and reads them.
type PolicySimulations interface {
	Request(ctx context.Context, tx pgx.Tx, in SimulationRequest) (ids.UUID, error)
	Status(ctx context.Context, tx pgx.Tx, org ids.OrgID, id ids.UUID) (SimulationStatus, error)
}

// DigestSource counts what a digest reports: per section, counts by
// state, decision or severity over a window. It never reads payloads or
// parameter values.
type DigestSource interface {
	// Counts counts one section over [from, to) within agents (nil: the
	// whole org).
	Counts(ctx context.Context, tx pgx.Tx, org ids.OrgID, section string, from, to time.Time, agents []ids.UUID) (map[string]int64, error)
	// Case is a case's life (created to closed, or now) and its linked
	// transactions, at most limit of them.
	Case(ctx context.Context, tx pgx.Tx, org ids.OrgID, c ids.UUID, limit int) (CaseScope, error)
}

// CaseScope is what a TRIGGER_CASE digest covers.
type CaseScope struct {
	From, To     time.Time
	Transactions []ids.UUID
	// Truncated: the case links more transactions than the limit.
	Truncated bool
}

// DigestPacks records an automation's evidence pack and enqueues its
// build in the caller's transaction ((*evapp.Service).CreateForAutomationTx,
// D85): created by the automation's service account, built with
// evidence.read only, within the declared agents.
type DigestPacks interface {
	CreateForAutomationTx(ctx context.Context, tx pgx.Tx, in evapp.AutomationPack) (ids.UUID, error)
}

// ReviewDeps are the least-privilege and digest kinds' ties (D31).
type ReviewDeps struct {
	Unused      UnusedGrants
	Drafts      PolicyDrafts
	Simulations PolicySimulations
	Digests     DigestSource
	Packs       DigestPacks
	// Proposals nil is the proposals table.
	Proposals Proposals
}

func reviewSteps(d Deps) autoports.StepRegistry {
	r := d.Review
	return autoports.StepRegistry{
		autodomain.KindDraftRestriction:    &draftRestriction{d: r},
		autodomain.KindSimulateRestriction: &simulateRestriction{d: r},
		autodomain.KindBuildDigest:         &buildDigest{d: r},
	}
}

// automationAuthor is the actor of what an automation writes (D61).
func automationAuthor(sc autodomain.StepContext) evdomain.Actor {
	return evdomain.Actor{Type: string(reflexdomain.SubjectAutomation), ID: sc.Execution.Automation.String()}
}

// draftRestriction drafts a least-privilege restriction (F599): it runs
// the unused_grants built-in at the org, writes a policy DRAFT that forbids
// each agent what its unused grants allow, and proposes it. The draft is
// never validated, tested or published here.
type draftRestriction struct{ d ReviewDeps }

func (*draftRestriction) Kind() string { return autodomain.KindDraftRestriction }

func (s *draftRestriction) with(sc autodomain.StepContext) (int, string) {
	w, ok := sc.With.(*autodomain.DraftRestrictionWith)
	if !ok || w.From != "UNUSED_GRANTS" || w.Days < MinUnusedDays || w.Days > MaxUnusedDays {
		return 0, ReasonBadWith
	}
	if !inScope(sc.Def, s.Kind(), autodomain.ScopeOrg) {
		return 0, ReasonOutsideScope
	}
	return w.Days, ""
}

// restrictedAgent is one agent of a RESTRICTION proposal.
type restrictedAgent struct {
	Agent      string   `json:"agent"`
	Grants     int      `json:"unused_grants"`
	Operations []string `json:"operations"`
}

// restrictionBody is a RESTRICTION proposal's body.
type restrictionBody struct {
	PolicyVersion string            `json:"policy_version"`
	Version       int               `json:"version"`
	Base          string            `json:"base_version,omitzero"`
	Days          int               `json:"days"`
	UnusedGrants  int               `json:"unused_grants"`
	Unbounded     int               `json:"unbounded_grants"`
	Agents        []restrictedAgent `json:"agents"`
	Truncated     bool              `json:"truncated,omitzero"`
	Note          string            `json:"note"`
}

// RestrictionRuleID is the id of the FORBID rule RestrictionDraft writes
// for agent.
func RestrictionRuleID(agent ids.UUID) string { return restrictionPrefix + agent.String() }

// RestrictionDraft returns base (or a new bundle) with one FORBID rule
// per agent of byAgent, replacing an earlier rule of the same agent. It
// changes nothing in base.
func RestrictionDraft(base *pdomain.Bundle, byAgent map[ids.UUID][]string, days int) *pdomain.Bundle {
	b := &pdomain.Bundle{ID: DraftBundleID, Version: 1}
	if base != nil {
		b.ID, b.Version = base.ID, base.Version
		b.Rules, b.Tests = slices.Clone(base.Rules), slices.Clone(base.Tests)
	}
	agents := slices.SortedFunc(maps.Keys(byAgent), func(x, y ids.UUID) int { return strings.Compare(x.String(), y.String()) })
	for _, a := range agents {
		ops := slices.Clone(byAgent[a])
		slices.Sort(ops)
		ops = slices.Compact(ops)
		r := pdomain.Rule{
			ID: restrictionPrefix + a.String(), Kind: pdomain.Forbid,
			Summary:    fmt.Sprintf("Forbid agent %s what its grants unused for %d days allow", a, days),
			Operations: ops, When: `run.agent_id == "` + a.String() + `"`, Reason: RestrictionReason,
		}
		if i := slices.IndexFunc(b.Rules, func(x pdomain.Rule) bool { return x.ID == r.ID }); i >= 0 {
			b.Rules[i] = r
		} else {
			b.Rules = append(b.Rules, r)
		}
	}
	return b
}

func (s *draftRestriction) Run(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	days, reason := s.with(sc)
	if reason != "" {
		return failed(reason)
	}
	if s.d.Unused == nil || s.d.Drafts == nil {
		return unwired()
	}
	unused, err := s.d.Unused.Unused(ctx, tx, sc.Org, sc.Now.Add(-time.Duration(days)*24*time.Hour), maxUnusedGrants)
	if err != nil {
		return refusalOr(err)
	}
	byAgent, grants := map[ids.UUID][]string{}, map[ids.UUID]int{}
	unbounded := 0
	for _, g := range unused {
		if len(g.Operations) == 0 {
			unbounded++
			continue
		}
		if _, ok := byAgent[g.Agent]; !ok && len(byAgent) >= maxRestrictionRules {
			continue
		}
		byAgent[g.Agent] = append(byAgent[g.Agent], g.Operations...)
		grants[g.Agent]++
	}
	out := map[string]string{"unused_grants": strconv.Itoa(len(unused)), "agents": strconv.Itoa(len(byAgent))}
	if len(byAgent) == 0 {
		out["drafted"] = "false"
		return proposalDone(out)
	}
	base, baseID, err := s.d.Drafts.Published(ctx, tx, sc.Org)
	if err != nil {
		return autodomain.StepResult{}, err
	}
	draft := RestrictionDraft(base, byAgent, days)
	version, n, err := s.d.Drafts.CreateDraft(ctx, tx, sc.Org, draft, automationAuthor(sc))
	if err != nil {
		return refusalOr(err)
	}
	body := restrictionBody{
		PolicyVersion: version.String(), Version: n, Days: days, UnusedGrants: len(unused), Unbounded: unbounded,
		Note: "a draft only: it is never validated, tested or published by an automation; publishing stays a person's action",
	}
	if !baseID.IsZero() {
		body.Base = baseID.String()
	}
	for _, a := range slices.SortedFunc(maps.Keys(byAgent), func(x, y ids.UUID) int { return strings.Compare(x.String(), y.String()) }) {
		if len(body.Agents) == maxBodyAgents {
			body.Truncated = true
			break
		}
		ops := draft.Rules[slices.IndexFunc(draft.Rules, func(r pdomain.Rule) bool { return r.ID == restrictionPrefix+a.String() })].Operations
		if len(ops) > maxBodyOps {
			ops, body.Truncated = ops[:maxBodyOps], true
		}
		body.Agents = append(body.Agents, restrictedAgent{Agent: a.String(), Grants: grants[a], Operations: ops})
	}
	id, err := proposalsOr(s.d.Proposals).Propose(ctx, tx, sc, ProposalRestriction, ProposalAboutPolicy, version, body)
	if err != nil {
		return autodomain.StepResult{}, err
	}
	out[OutPolicyVersion], out[OutProposal], out["drafted"] = version.String(), id.String(), "true"
	out["version"] = strconv.Itoa(n)
	return proposalDone(out, ref(RefPolicyVersion, version), ref(RefProposal, id))
}

func (s *draftRestriction) Poll(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	return s.Run(ctx, tx, sc)
}

func (s *draftRestriction) Preview(_ context.Context, _ pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	days, reason := s.with(sc)
	if reason != "" {
		return previewRefused(reason)
	}
	return shadowed(map[string]string{"days": strconv.Itoa(days), "would": "DRAFT+" + ProposalRestriction})
}

// simulateRestriction simulates a draft_restriction step's draft over the
// recorded decisions (M11.1 Simulate) and waits for the result
// (SIMULATION_DONE): newly denied, held and allowed counts.
type simulateRestriction struct{ d ReviewDeps }

func (*simulateRestriction) Kind() string { return autodomain.KindSimulateRestriction }

// draftOf returns the version the named draft_restriction step drafted;
// drafted is false when it found nothing to restrict.
func (s *simulateRestriction) draftOf(sc autodomain.StepContext) (version ids.UUID, days int, drafted bool, reason string) {
	w, ok := sc.With.(*autodomain.SimulateRestrictionWith)
	if !ok || w.Step == "" || w.Days < 0 || w.Days > MaxSimulateDays {
		return ids.UUID{}, 0, false, ReasonBadWith
	}
	if !inScope(sc.Def, s.Kind(), autodomain.ScopeOrg) {
		return ids.UUID{}, 0, false, ReasonOutsideScope
	}
	days = w.Days
	if days == 0 {
		days = simulation.DefaultDays
	}
	i := slices.IndexFunc(sc.Def.Do, func(st autodomain.StepSpec) bool { return st.ID == w.Step })
	if i < 0 || i >= sc.Index || sc.Def.Do[i].Step != autodomain.KindDraftRestriction {
		return ids.UUID{}, 0, false, ReasonBadWith
	}
	o := sc.Outputs[w.Step]
	if o["drafted"] == "false" {
		return ids.UUID{}, days, false, ""
	}
	v, ok := parseID(o[OutPolicyVersion])
	if !ok {
		return ids.UUID{}, 0, false, ReasonNoDraft
	}
	return v, days, true, ""
}

func (s *simulateRestriction) Run(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	version, days, drafted, reason := s.draftOf(sc)
	if reason != "" {
		return failed(reason)
	}
	if !drafted {
		return proposalDone(map[string]string{"simulated": "false"})
	}
	if s.d.Simulations == nil {
		return unwired()
	}
	id, err := s.d.Simulations.Request(ctx, tx, SimulationRequest{Org: sc.Org, Version: version, Days: days, Actor: automationAuthor(sc)})
	if err != nil {
		return refusalOr(err)
	}
	return waiting(map[string]string{OutSimulation: id.String(), OutPolicyVersion: version.String(), "days": strconv.Itoa(days)},
		[]reflexdomain.EvidenceRef{ref(RefSimulation, id), ref(RefPolicyVersion, version)}, sc.Now.Add(pollEvery))
}

// simulationKeys are the output keys of a done simulation's counts.
var simulationKeys = map[replay.Category]string{
	replay.NewlyDenied: "newly_denied", replay.NewlyHeld: "newly_held", replay.NewlyAllowed: "newly_allowed",
	replay.NewlyConstrained: "newly_constrained", replay.ReasonChanged: "reason_changed",
	replay.Unchanged: "unchanged", replay.Unevaluable: "unevaluable",
}

func (s *simulateRestriction) Poll(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	if _, _, _, reason := s.draftOf(sc); reason != "" {
		return failed(reason)
	}
	if s.d.Simulations == nil {
		return unwired()
	}
	o := own(sc)
	id, ok := parseID(o[OutSimulation])
	version, vok := parseID(o[OutPolicyVersion])
	if !ok || !vok {
		return failed(ReasonBadWith)
	}
	st, err := s.d.Simulations.Status(ctx, tx, sc.Org, id)
	if err != nil {
		return refusalOr(err)
	}
	refs := []reflexdomain.EvidenceRef{ref(RefSimulation, id), ref(RefPolicyVersion, version)}
	switch st.State {
	case simulation.Done:
		out := map[string]string{OutSimulation: id.String(), OutPolicyVersion: version.String(), "evaluated": strconv.Itoa(st.Evaluated)}
		for c, k := range simulationKeys {
			out[k] = strconv.Itoa(st.Counts[c])
		}
		return proposalDone(out, refs...)
	case simulation.Failed, simulation.Canceled:
		return autodomain.StepResult{State: autodomain.StepFailed, Reason: ReasonSimulation, Effect: autodomain.EffectNone, Output: o, Refs: refs}, nil
	case simulation.Queued, simulation.Running:
	}
	return waiting(o, refs, sc.Now.Add(pollEvery))
}

func (s *simulateRestriction) Preview(_ context.Context, _ pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	w, ok := sc.With.(*autodomain.SimulateRestrictionWith)
	if !ok || w.Step == "" || w.Days < 0 || w.Days > MaxSimulateDays {
		return previewRefused(ReasonBadWith)
	}
	if !inScope(sc.Def, s.Kind(), autodomain.ScopeOrg) {
		return previewRefused(ReasonOutsideScope)
	}
	// A preview's draft_restriction drafted nothing, so there is nothing
	// to simulate: the would-be result names the step only (HR-288).
	return shadowed(map[string]string{"step": w.Step, "would": "SIMULATE"})
}

// buildDigest builds a digest of a time range or of the trigger's case,
// within the evidence scope the version declares (D85): a report of counts
// and links (no payloads or parameter values) and an evidence pack the
// automation's service account creates, built with evidence.read only
// within the declared agents. The deliver step sends pack_id and
// report_digest on.
type buildDigest struct{ d ReviewDeps }

func (*buildDigest) Kind() string { return autodomain.KindBuildDigest }

// digestScope returns the evidence scope a build_digest declares (D85):
// the agents of `evidence: {agents: [...]}`, or all for
// `evidence: {all: true}`. Anything but exactly one of the two is no
// scope, and the step is refused (WITH_INVALID).
func digestScope(w *autodomain.BuildDigestWith) (agents []ids.UUID, all, ok bool) {
	if !w.Evidence.Valid() {
		return nil, false, false
	}
	if w.Evidence.All {
		return nil, true, true
	}
	agents = make([]ids.UUID, 0, len(w.Evidence.Agents))
	for _, a := range w.Evidence.Agents {
		agents = append(agents, a.UUID())
	}
	return agents, false, true
}

// digestPlan is a checked build_digest.
type digestPlan struct {
	w    *autodomain.BuildDigestWith
	days int
	cse  ids.UUID
	// agents are the declared agents; nil with all.
	agents []ids.UUID
	all    bool
}

func (s *buildDigest) plan(sc autodomain.StepContext) (digestPlan, string) {
	w, ok := sc.With.(*autodomain.BuildDigestWith)
	if !ok || len(w.Sections) == 0 || len(w.Sections) > len(digestSections) || utf8.RuneCountInString(w.Title) > MaxDigestTitle {
		return digestPlan{}, ReasonBadWith
	}
	seen := map[string]bool{}
	for _, x := range w.Sections {
		if seen[x] || !slices.Contains(digestSections, x) {
			return digestPlan{}, ReasonBadWith
		}
		seen[x] = true
	}
	p := digestPlan{w: w}
	if p.agents, p.all, ok = digestScope(w); !ok || p.all != (p.agents == nil) ||
		(!p.all && (len(p.agents) == 0 || len(p.agents) > evapp.MaxAutomationPackAgents)) {
		return digestPlan{}, ReasonBadWith
	}
	switch w.Scope {
	case autodomain.ScopeTimeRange:
		p.days = w.Days
		if p.days == 0 {
			p.days = DefaultDigestDay
		}
		if p.days < 1 || p.days > MaxDigestDays {
			return digestPlan{}, ReasonBadWith
		}
	case autodomain.ScopeTriggerCase:
		if w.Days != 0 {
			return digestPlan{}, ReasonBadWith
		}
	default:
		return digestPlan{}, ReasonBadWith
	}
	if !inScope(sc.Def, s.Kind(), w.Scope) {
		return digestPlan{}, ReasonOutsideScope
	}
	if w.Scope == autodomain.ScopeTriggerCase {
		if p.cse, ok = triggerSubject(sc, reflexdomain.SubjectCase); !ok {
			return digestPlan{}, ReasonNoSubject
		}
	}
	return p, ""
}

// DigestFormat names the digest report document.
const DigestFormat = "pantherclaw.automation_digest.v1"

// OutPackNone is the pack output of a case digest whose case links no
// transaction: the report only.
const OutPackNone = "none"

// digestLink is a report's link: a kind and an id, never content.
type digestLink struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// digestReport is the report a digest's report_digest is the SHA-256 of
// (canonical JSON): counts and links only.
type digestReport struct {
	Format     string                      `json:"format"`
	Title      string                      `json:"title"`
	Org        string                      `json:"org"`
	Automation string                      `json:"automation"`
	Execution  string                      `json:"execution"`
	Scope      string                      `json:"scope"`
	From       string                      `json:"from"`
	To         string                      `json:"to"`
	Agents     []string                    `json:"agents,omitzero"` // the declared agents; absent: all
	Sections   map[string]map[string]int64 `json:"sections"`
	Links      []digestLink                `json:"links"`
}

// DigestReportDigest is the hex SHA-256 of a report's canonical JSON.
func DigestReportDigest(report any) (string, error) {
	raw, err := evdomain.CanonicalBody(report)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// digestInclude is what a digest pack holds.
var digestInclude = pack.Include{Receipts: true, Versions: true, Approvals: true, Containment: true}

func (s *buildDigest) Run(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	p, reason := s.plan(sc)
	if reason != "" {
		return failed(reason)
	}
	if s.d.Digests == nil || s.d.Packs == nil {
		return unwired()
	}
	if sc.Execution.ServiceAccount.IsZero() {
		return autodomain.StepResult{}, fmt.Errorf("securitysteps: execution %s has no service account", sc.Execution.ID)
	}
	to := sc.Now.UTC().Truncate(time.Second)
	from := to.Add(-time.Duration(p.days) * 24 * time.Hour)
	req := evapp.PackRequest{Kind: pack.ScopeTimeRange, Include: digestInclude}
	out := map[string]string{"scope": p.w.Scope}
	if !p.cse.IsZero() {
		cs, err := s.d.Digests.Case(ctx, tx, sc.Org, p.cse, evapp.MaxPackTransactions)
		if err != nil {
			return refusalOr(err)
		}
		// The report counts the case's life, at most its last MaxDigestDays.
		to = cs.To.UTC().Truncate(time.Second).Add(time.Second)
		from = cs.From.UTC().Truncate(time.Second)
		if earliest := to.Add(-MaxDigestDays * 24 * time.Hour); from.Before(earliest) {
			from = earliest
		}
		if !to.After(from) {
			to = from.Add(time.Second)
		}
		// The pack holds the case's linked transactions.
		req = evapp.PackRequest{Kind: pack.ScopeTransactions, Transactions: cs.Transactions, Include: digestInclude}
		out["transactions"] = strconv.Itoa(len(cs.Transactions))
		if cs.Truncated {
			out["truncated"] = "true"
		}
	} else {
		req.From, req.To = &from, &to
	}
	out["from"], out["to"] = rfc(from), rfc(to)
	report := digestReport{
		Format: DigestFormat, Title: p.w.Title, Org: sc.Org.String(), Automation: sc.Execution.Automation.String(),
		Execution: sc.Execution.ID.String(), Scope: p.w.Scope, From: rfc(from), To: rfc(to),
		Sections: map[string]map[string]int64{},
	}
	if report.Title == "" {
		report.Title = "Automation digest"
	}
	if p.all {
		out["agents"] = "all"
	} else {
		out["agents"] = strconv.Itoa(len(p.agents))
		for _, a := range p.agents {
			report.Agents = append(report.Agents, a.String())
		}
		slices.Sort(report.Agents)
	}
	for _, sec := range p.w.Sections {
		c, err := s.d.Digests.Counts(ctx, tx, sc.Org, sec, from, to, p.agents)
		if err != nil {
			return autodomain.StepResult{}, err
		}
		report.Sections[sec] = c
		var total int64
		for _, n := range c {
			total += n
		}
		out[sec+"_total"] = strconv.FormatInt(total, 10)
	}
	var refs []reflexdomain.EvidenceRef
	out[OutPack] = OutPackNone
	if req.Kind == pack.ScopeTimeRange || len(req.Transactions) > 0 {
		packID, err := s.d.Packs.CreateForAutomationTx(ctx, tx, evapp.AutomationPack{
			Org: sc.Org, Automation: sc.Execution.Automation, Execution: sc.Execution.ID,
			ServiceAccount: sc.Execution.ServiceAccount, Agents: p.agents, Request: req,
		})
		if err != nil {
			return refusalOr(err)
		}
		out[OutPack] = packID.String()
		report.Links = append(report.Links, digestLink{Kind: RefPack, ID: packID.String()})
		refs = append(refs, ref(RefPack, packID))
	}
	report.Links = append(report.Links, digestLink{Kind: string(reflexdomain.SubjectAutomationExecution), ID: sc.Execution.ID.String()})
	if !p.cse.IsZero() {
		report.Links = append(report.Links, digestLink{Kind: RefCase, ID: p.cse.String()})
		refs = append(refs, ref(RefCase, p.cse))
		out[OutCase] = p.cse.String()
	}
	dg, err := DigestReportDigest(report)
	if err != nil {
		return autodomain.StepResult{}, err
	}
	out[OutReportDigest] = dg
	effect := autodomain.EffectChanged
	if out[OutPack] == OutPackNone {
		effect = autodomain.EffectNone
	}
	return autodomain.StepResult{State: autodomain.StepDone, Effect: effect, Output: out, Refs: refs}, nil
}

func (s *buildDigest) Poll(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	return s.Run(ctx, tx, sc)
}

func (s *buildDigest) Preview(_ context.Context, _ pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	p, reason := s.plan(sc)
	if reason != "" {
		return previewRefused(reason)
	}
	return shadowed(map[string]string{"scope": p.w.Scope, "sections": strings.Join(p.w.Sections, ","), "would": "REPORT+PACK"})
}

// GrantSearch implements UnusedGrants over the unused_grants built-in's
// query (internal/search, F310) at the org: ACTIVE grants with no recorded
// transaction since the time. Like the built-in it cannot see use through
// routes PantherClaw does not observe.
type GrantSearch struct{}

// NewUnusedGrants returns the unused-grant search.
func NewUnusedGrants() GrantSearch { return GrantSearch{} }

// Unused implements UnusedGrants.
func (GrantSearch) Unused(ctx context.Context, tx pgx.Tx, org ids.OrgID, since time.Time, limit int) ([]UnusedGrant, error) {
	q := dbq.New(tx)
	rows, err := q.SearchGrants(ctx, dbq.SearchGrantsParams{
		OrgID: org, AllAgents: true, Agents: []ids.UUID{}, States: []string{"ACTIVE"}, UnusedSince: &since,
		PageLimit: int32(min(max(limit, 1), maxUnusedGrants)),
	})
	if err != nil {
		return nil, err
	}
	out := make([]UnusedGrant, 0, len(rows))
	for _, r := range rows {
		g, err := q.GetGrant(ctx, org, r.ID)
		if err != nil {
			return nil, err
		}
		var b gdomain.Bounds
		if err := json.Unmarshal(g.Bounds, &b); err != nil {
			return nil, fmt.Errorf("securitysteps: grant %s bounds: %w", r.ID, err)
		}
		u := UnusedGrant{ID: r.ID, Agent: r.AgentID}
		if b.Operations != nil {
			u.Operations = slices.Clone(*b.Operations)
		}
		out = append(out, u)
	}
	return out, nil
}

// PolicyStore implements PolicyDrafts in the driver's transaction, as
// the M11.1 create path stores a version (policy/app Versions.Create and
// pgstore CreateVersion): the bundle must validate and compile against
// the org's definitions and facts, and is stored as the next DRAFT with an
// audit event. It has no publish path.
type PolicyStore struct {
	facts  papp.FactCatalog
	defs   DefinitionsInTx
	limits celenv.Limits
}

// NewPolicyDrafts returns the policy draft store; facts and definitions
// compile a draft as Versions.Create does, with the server's CEL limits.
func NewPolicyDrafts(facts papp.FactCatalog, definitions DefinitionsInTx, limits celenv.Limits) *PolicyStore {
	return &PolicyStore{facts: facts, defs: definitions, limits: limits}
}

// MaxBundleBytes is the largest stored bundle (pgstore.MaxBundleBytes).
const MaxBundleBytes = 4 << 20

// Published implements PolicyDrafts.
func (p *PolicyStore) Published(ctx context.Context, tx pgx.Tx, org ids.OrgID) (*pdomain.Bundle, ids.UUID, error) {
	row, err := dbq.New(tx).GetPublishedPolicy(ctx, org)
	if db.IsNoRows(err) {
		return nil, ids.UUID{}, nil
	} else if err != nil {
		return nil, ids.UUID{}, err
	}
	var b pdomain.Bundle
	if err := json.Unmarshal(row.Bundle, &b); err != nil {
		return nil, ids.UUID{}, err
	}
	return &b, row.ID, nil
}

// errDraftInvalid is a draft that does not validate or compile.
func errDraftInvalid(reason string, err error) error {
	return pcerr.Wrap(err, pcerr.InvalidArgument, reason, err.Error())
}

// CreateDraft implements PolicyDrafts.
func (p *PolicyStore) CreateDraft(ctx context.Context, tx pgx.Tx, org ids.OrgID, b *pdomain.Bundle, author evdomain.Actor) (ids.UUID, int, error) {
	if p.facts == nil || p.defs == nil {
		return ids.UUID{}, 0, ErrUnwired
	}
	ttx, err := db.AdoptTenantTx(ctx, tx, org)
	if err != nil {
		return ids.UUID{}, 0, err
	}
	if err := b.Validate(); err != nil {
		return ids.UUID{}, 0, errDraftInvalid("POLICY_INVALID", err)
	}
	catalog, err := p.facts.Catalog(ctx, org)
	if err != nil {
		return ids.UUID{}, 0, err
	}
	ds, err := p.defs.ActiveDefinitionsInTx(ctx, ttx, org)
	if err != nil {
		return ids.UUID{}, 0, err
	}
	if _, err := (&papp.Engine{Limits: p.limits, Facts: catalog}).Compile(b, ds); err != nil {
		return ids.UUID{}, 0, errDraftInvalid("POLICY_DOES_NOT_COMPILE", err)
	}
	q := dbq.New(ttx)
	policyID, err := q.GetPolicyID(ctx, org, b.ID)
	if db.IsNoRows(err) {
		policyID = ids.NewV7()
		err = q.InsertPolicy(ctx, org, policyID, b.ID)
	}
	if err != nil {
		return ids.UUID{}, 0, err
	}
	next, err := q.NextPolicyVersion(ctx, org, policyID)
	if err != nil {
		return ids.UUID{}, 0, err
	}
	stored := *b
	stored.Version = int(next)
	raw, err := json.Marshal(stored, json.Deterministic(true))
	if err != nil {
		return ids.UUID{}, 0, err
	}
	if len(raw) > MaxBundleBytes {
		return ids.UUID{}, 0, errDraftInvalid("POLICY_INVALID", fmt.Errorf("the bundle is larger than %d bytes", MaxBundleBytes))
	}
	id, digest := ids.NewV7(), pdomain.ContentDigest(&stored)
	createdBy := author.Type + ":" + author.ID
	if err := q.InsertPolicyVersion(ctx, dbq.InsertPolicyVersionParams{
		OrgID: org, ID: id, PolicyID: policyID, Version: next, Bundle: raw, ContentDigest: digest[:], CreatedBy: createdBy,
	}); err != nil {
		return ids.UUID{}, 0, err
	}
	if _, err := audit.Record(ctx, ttx, audit.Event{
		Name: "policy.version_created", Actor: author, Outcome: audit.Success,
		Object:  &audit.Object{Type: "policy", ID: b.ID},
		Details: map[string]string{"version_id": id.String(), "version": strconv.Itoa(int(next)), "state": "DRAFT"},
	}); err != nil {
		return ids.UUID{}, 0, err
	}
	return id, int(next), nil
}

// SimulationStore implements PolicySimulations in the driver's
// transaction, as simulation.Service.Simulate queues one (Team edition,
// 1..30 days inside retention, one queued or running per org) and as
// pgsimulation stores it: the simulation row, its River job and the audit
// event. The simulation itself only reads (HR-232).
type SimulationStore struct {
	jobs     *jobs.Client
	editions simulation.Editions
}

// NewPolicySimulations returns the simulation store; jobs is the
// insert-only River client pgsimulation.Store uses.
func NewPolicySimulations(j *jobs.Client, editions simulation.Editions) *SimulationStore {
	return &SimulationStore{jobs: j, editions: editions}
}

// Request implements PolicySimulations.
func (s *SimulationStore) Request(ctx context.Context, tx pgx.Tx, in SimulationRequest) (ids.UUID, error) {
	if s.jobs == nil {
		return ids.UUID{}, simulation.ErrUnwired
	}
	if s.editions == nil {
		return ids.UUID{}, simulation.ErrEdition
	}
	ents, err := s.editions.Current(ctx)
	if err != nil {
		return ids.UUID{}, err
	}
	if !ents.PolicySimulation() {
		return ids.UUID{}, simulation.ErrEdition
	}
	if in.Days < 1 || in.Days > simulation.MaxDays {
		return ids.UUID{}, simulation.ErrWindow
	}
	ttx, err := db.AdoptTenantTx(ctx, tx, in.Org)
	if err != nil {
		return ids.UUID{}, err
	}
	q := dbq.New(ttx)
	v, err := q.GetPolicyVersion(ctx, in.Org, in.Version)
	if db.IsNoRows(err) {
		return ids.UUID{}, simulation.ErrVersionNotFound
	} else if err != nil {
		return ids.UUID{}, err
	}
	digest := v.ContentDigest
	if len(digest) != sha256.Size {
		var b pdomain.Bundle
		if err := json.Unmarshal(v.Bundle, &b); err != nil {
			return ids.UUID{}, err
		}
		d := pdomain.ContentDigest(&b)
		digest = d[:]
	}
	facts, _ := retention.BoundsOf(retention.NormalizedFacts)
	receipts, _ := retention.BoundsOf(retention.Receipts)
	keep, err := q.SimulationRetentionDays(ctx, int32(facts.Default), int32(receipts.Default)) //nolint:gosec // G115: days ≤ 3650
	if err != nil {
		return ids.UUID{}, err
	}
	if in.Days > int(keep) {
		return ids.UUID{}, simulation.ErrWindow
	}
	id := ids.NewV7()
	_, err = q.InsertPolicySimulation(ctx, dbq.InsertPolicySimulationParams{
		OrgID: in.Org, ID: id, VersionID: in.Version, ContentDigest: digest, Days: int32(in.Days),
		MaxEvaluations: simulation.DefaultMaxEvaluations, RequestedBy: in.Actor.Type + ":" + in.Actor.ID,
	})
	switch {
	case db.IsUniqueViolation(err):
		return ids.UUID{}, simulation.ErrBusy
	case db.IsForeignKeyViolation(err):
		return ids.UUID{}, simulation.ErrVersionNotFound
	case err != nil:
		return ids.UUID{}, err
	}
	sim, err := ids.FromUUID[pgsimulation.Simulation](id)
	if err != nil {
		return ids.UUID{}, err
	}
	if err := jobs.InsertTx(ctx, s.jobs, ttx, pgsimulation.SimulateArgs{Org: in.Org, Simulation: sim}, nil); err != nil {
		return ids.UUID{}, err
	}
	if _, err := audit.Record(ctx, ttx, audit.Event{
		Name: "policy.simulation_requested", Actor: in.Actor, Outcome: audit.Success,
		Object: &audit.Object{Type: "policy_simulation", ID: id.String()},
		Details: map[string]string{
			"version_id": in.Version.String(), "days": strconv.Itoa(in.Days),
			"max_evaluations": strconv.Itoa(simulation.DefaultMaxEvaluations),
		},
	}); err != nil {
		return ids.UUID{}, err
	}
	return id, nil
}

// Status implements PolicySimulations.
func (s *SimulationStore) Status(ctx context.Context, tx pgx.Tx, org ids.OrgID, id ids.UUID) (SimulationStatus, error) {
	r, err := dbq.New(tx).GetPolicySimulation(ctx, org, id)
	if db.IsNoRows(err) {
		return SimulationStatus{}, simulation.ErrNotFound
	} else if err != nil {
		return SimulationStatus{}, err
	}
	var counts map[string]int
	if err := json.Unmarshal(r.Counts, &counts); err != nil {
		return SimulationStatus{}, err
	}
	out := SimulationStatus{State: simulation.State(r.State), Evaluated: int(r.Evaluated), Counts: map[replay.Category]int{}}
	for k, n := range counts {
		out.Counts[replay.Category(k)] = n
	}
	if r.Error != nil {
		out.Error = *r.Error
	}
	return out, nil
}

// DigestCounts implements DigestSource with grouped counts over the org's
// own tables (RLS-bound), within the declared agents: decisions by
// decision, effects by effect state, holds by approval state, alerts by
// severity (test signals left out; an alert counts when one of its agent
// subjects is declared), and the open items now.
type DigestCounts struct{}

// NewDigestCounts returns the digest counts.
func NewDigestCounts() DigestCounts { return DigestCounts{} }

// digestQueries are the grouped counts by section. Windowed ones take ($1
// org, $2 from, $3 to, $4 agents), open_items ($1 org, $2 agents); NULL
// agents is the whole org.
var digestQueries = map[string]struct {
	sql      string
	windowed bool
}{
	SectionDecisions: {`SELECT t.decision, count(*) FROM pc.transactions t
JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
WHERE t.org_id = $1 AND t.created_at >= $2 AND t.created_at < $3
  AND ($4::uuid[] IS NULL OR r.agent_id = ANY ($4::uuid[])) GROUP BY t.decision`, true},
	SectionEffects: {`SELECT t.effect_state, count(*) FROM pc.transactions t
JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
WHERE t.org_id = $1 AND t.created_at >= $2 AND t.created_at < $3 AND t.effect_state IS NOT NULL
  AND ($4::uuid[] IS NULL OR r.agent_id = ANY ($4::uuid[])) GROUP BY t.effect_state`, true},
	SectionHolds: {`SELECT state, count(*) FROM pc.approval_requests
WHERE org_id = $1 AND created_at >= $2 AND created_at < $3
  AND ($4::uuid[] IS NULL OR agent_id = ANY ($4::uuid[])) GROUP BY state`, true},
	SectionAlerts: {`SELECT severity, count(*) FROM pc.alerts
WHERE org_id = $1 AND created_at >= $2 AND created_at < $3 AND NOT test
  AND ($4::uuid[] IS NULL OR EXISTS (SELECT 1 FROM jsonb_array_elements(subjects) s
       WHERE s->>'type' = 'agent' AND s->>'id' = ANY ($4::uuid[]::text[]))) GROUP BY severity`, true},
	SectionOpenItems: {`SELECT 'cases', count(*) FROM pc.cases c WHERE c.org_id = $1 AND c.state <> 'CLOSED'
  AND ($2::uuid[] IS NULL OR EXISTS (SELECT 1 FROM pc.case_agents(c.org_id, c.id) a(agent_id) WHERE a.agent_id = ANY ($2::uuid[])))
UNION ALL SELECT 'alerts', count(*) FROM pc.alerts WHERE org_id = $1 AND state IN ('OPEN', 'ACKNOWLEDGED') AND NOT test
  AND ($2::uuid[] IS NULL OR EXISTS (SELECT 1 FROM jsonb_array_elements(subjects) s
       WHERE s->>'type' = 'agent' AND s->>'id' = ANY ($2::uuid[]::text[])))
UNION ALL SELECT 'approvals', count(*) FROM pc.approval_requests WHERE org_id = $1 AND state IN ('PENDING', 'EVIDENCE_REQUESTED')
  AND ($2::uuid[] IS NULL OR agent_id = ANY ($2::uuid[]))
UNION ALL SELECT 'proposals', count(*) FROM pc.automation_proposals WHERE org_id = $1 AND state = 'PROPOSED'
  AND ($2::uuid[] IS NULL OR (subject_type = 'agent' AND subject_id = ANY ($2::uuid[])))`, false},
}

// Counts implements DigestSource.
func (DigestCounts) Counts(ctx context.Context, tx pgx.Tx, org ids.OrgID, section string, from, to time.Time, agents []ids.UUID) (map[string]int64, error) {
	dq, ok := digestQueries[section]
	if !ok {
		return nil, fmt.Errorf("securitysteps: unknown digest section %q", section)
	}
	args := []any{org}
	if dq.windowed {
		args = append(args, from, to)
	}
	args = append(args, agents)
	rows, err := tx.Query(ctx, dq.sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var k string
		var n int64
		if err := rows.Scan(&k, &n); err != nil {
			return nil, err
		}
		out[k] = n
	}
	return out, rows.Err()
}

// caseTransactionRef is a case LINK entry's ref kind of a transaction.
const caseTransactionRef = "transaction"

// Case implements DigestSource: the case's life and the transactions its
// standing LINK entries name, in link order.
func (DigestCounts) Case(ctx context.Context, tx pgx.Tx, org ids.OrgID, c ids.UUID, limit int) (CaseScope, error) {
	q := dbq.New(tx)
	r, err := q.GetCase(ctx, org, c)
	if db.IsNoRows(err) {
		return CaseScope{}, pcerr.New(pcerr.NotFound, ReasonCaseNotFound, "case not found")
	} else if err != nil {
		return CaseScope{}, err
	}
	out := CaseScope{From: r.CreatedAt, To: time.Now()}
	if r.ClosedAt != nil {
		out.To = *r.ClosedAt
	}
	links, err := q.CaseLinks(ctx, org, c)
	if err != nil {
		return CaseScope{}, err
	}
	seen := map[ids.UUID]bool{}
	for _, l := range links {
		if l.RefKind == nil || *l.RefKind != caseTransactionRef || l.RefID == nil {
			continue
		}
		id, ok := parseID(*l.RefID)
		if !ok || seen[id] {
			continue
		}
		if len(out.Transactions) == limit {
			out.Truncated = true
			break
		}
		seen[id] = true
		out.Transactions = append(out.Transactions, id)
	}
	return out, nil
}

// NewDigestPacks returns the digest packs: evidence app's
// CreateForAutomationTx (D85). A nil service leaves Packs unwired.
func NewDigestPacks(packs *evapp.Service) DigestPacks {
	if packs == nil {
		return nil
	}
	return packs
}
