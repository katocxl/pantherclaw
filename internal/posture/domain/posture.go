// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain holds posture findings (G0 M10, coordinator decision D30;
// F265, F268; HR-255): the remediation queue derived from an exposure
// snapshot, grouped by root cause, and its lifecycle. A finding is
// REMEDIATED only when a recomputation shows that none of its affected
// paths is reachable any more; temporary acceptance expires within 90
// days; nothing outside this lifecycle (an alert dismissed, a case closed)
// touches a finding. Everything here is pure.
package domain

import (
	"cmp"
	"crypto/sha256"
	"errors"
	"slices"
	"strconv"
	"time"

	exposure "github.com/katocxl/pantherclaw/internal/exposure/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Kind is a finding kind (D30).
type Kind string

// Kinds.
const (
	ExcessiveGrant          Kind = "excessive_grant"
	UncoveredPath           Kind = "uncovered_path"
	UnownedAgent            Kind = "unowned_agent"
	UnsafeDelegation        Kind = "unsafe_delegation"
	StaleCredential         Kind = "stale_credential" //nolint:gosec // G101: a finding kind, not a credential
	UnusedAuthority         Kind = "unused_authority"
	UnverifiedSensitiveTool Kind = "unverified_sensitive_tool"
	CredentialOverreach     Kind = "credential_overreach" //nolint:gosec // G101: a finding kind, not a credential
)

// Kinds lists every kind.
var Kinds = []Kind{
	ExcessiveGrant, UncoveredPath, UnownedAgent, UnsafeDelegation, StaleCredential, UnusedAuthority,
	UnverifiedSensitiveTool, CredentialOverreach,
}

// State is a finding's lifecycle state (D30).
type State string

// States.
const (
	Open                State = "OPEN"
	Assigned            State = "ASSIGNED"
	Testing             State = "TESTING"
	Remediated          State = "REMEDIATED"
	AcceptedTemporarily State = "ACCEPTED_TEMPORARILY"
	EvidenceIncomplete  State = "EVIDENCE_INCOMPLETE"
)

// Active reports a state still in the queue.
func (s State) Active() bool {
	return s == Open || s == Assigned || s == Testing || s == EvidenceIncomplete
}

// MaxAcceptance bounds a temporary acceptance (HR-255).
const MaxAcceptance = 90 * 24 * time.Hour

// Errors.
var (
	ErrTransition = errors.New("posture: transition not allowed")
	ErrAcceptance = errors.New("posture: acceptance needs a reason and an expiry within 90 days")
)

// CanMove reports whether the lifecycle allows from -> to; the database
// trigger holds to the same table.
func CanMove(from, to State) bool {
	switch {
	case from == to:
		return false
	case from.Active() && (to == Assigned || to == AcceptedTemporarily || to == EvidenceIncomplete || to == Remediated):
		return true
	case from == Assigned && to == Testing:
		return true
	case to == Open:
		return from != Open
	}
	return false
}

// CheckAcceptance validates a temporary acceptance.
func CheckAcceptance(now, until time.Time, reason string) error {
	if !until.After(now) || until.Sub(now) > MaxAcceptance || len([]rune(reason)) < 10 || len([]rune(reason)) > 1000 {
		return ErrAcceptance
	}
	return nil
}

// Candidate is a finding a snapshot shows.
type Candidate struct {
	Kind       Kind
	RootCause  string // "<type>:<uuid>"
	Agent      *ids.UUID
	Connection *ids.UUID
	Grant      *ids.UUID
	// CoverageFinding is the imported coverage finding (credential_overreach).
	CoverageFinding *ids.UUID
	Title           string
	Severity        string
	Paths           []string
	// PathsTruncated: more than MaxPaths paths; only MaxPaths are kept.
	PathsTruncated bool
	Detail         map[string]string
}

// Fingerprint identifies a candidate across snapshots: its kind, root
// cause and agent. Paths may change; the finding stays the same.
func (c Candidate) Fingerprint() []byte {
	h := sha256.New()
	h.Write([]byte(string(c.Kind) + "\x00" + c.RootCause + "\x00"))
	if c.Agent != nil {
		h.Write([]byte(c.Agent.String()))
	}
	return h.Sum(nil)
}

// Agent is what derivation reads of an agent.
type Agent struct {
	ID    ids.UUID
	Owned bool
}

// GrantInfo is what derivation reads of a grant.
type GrantInfo struct {
	ID ids.UUID
	// Unbounded lists the bounds dimensions it leaves open (operations,
	// access, targets).
	Unbounded []string
	CreatedAt time.Time
}

// CredentialInfo is what derivation reads of a connection's credential.
type CredentialInfo struct {
	Connection ids.UUID
	Name       string
	CreatedAt  time.Time
}

// CoverageFinding is an open coverage finding to import.
type CoverageFinding struct {
	ID         ids.UUID
	Connection *ids.UUID
	Agent      *ids.UUID
	Subject    string
	Excess     []string
	Severity   string
}

// Inputs are what derivation reads besides the rights.
type Inputs struct {
	Now              time.Time
	Rights           []exposure.Right
	Agents           []Agent
	Grants           []GrantInfo
	Credentials      []CredentialInfo
	CoverageFindings []CoverageFinding
	// Unverified names the operations whose definitions declare no
	// verifier.
	Unverified map[string]bool
	// Irreversible names the irreversible operations.
	Irreversible map[string]bool
}

// Thresholds.
const (
	// StaleAfter is how old an active credential gets before it is stale.
	StaleAfter = 90 * 24 * time.Hour
	// UnusedAfter is how long a grant may reach writes it never used.
	UnusedAfter = 30 * 24 * time.Hour
)

func sensitive(v exposure.Verb) bool {
	return v == exposure.VerbUpdate || v == exposure.VerbDelete || v == exposure.VerbTransfer
}

// Derive lists the candidates an exposure snapshot shows, sorted.
func Derive(in Inputs) []Candidate {
	d := deriver{by: map[string]*Candidate{}}
	// An automation's issuance ceiling is potential reach, never a finding
	// about held authority (G0 M11 D37a).
	in.Rights = exposure.HeldReach(in.Rights)
	owned := map[ids.UUID]bool{}
	for _, a := range in.Agents {
		owned[a.ID] = a.Owned
	}
	grants := map[ids.UUID]GrantInfo{}
	for _, g := range in.Grants {
		grants[g.ID] = g
	}
	used := map[string]bool{} // agent|connection|operation dispatched
	for _, r := range in.Rights {
		if r.View == exposure.Observed {
			used[r.PathKey()] = true
		}
	}
	for _, r := range in.Rights {
		if r.View == exposure.Observed || !r.Label.Current() {
			continue
		}
		path := r.PathKey()
		if r.Agent != nil && !owned[*r.Agent] {
			d.add(Candidate{
				Kind: UnownedAgent, RootCause: "agent:" + r.Agent.String(), Agent: r.Agent,
				Title: "Agent with reach has no owner", Severity: "medium",
			}, path)
		}
		if r.View == exposure.Effective && sensitive(r.Verb) && r.Agent != nil && r.Connection != nil &&
			(r.Coverage == exposure.CoverageUnknown || r.Coverage == exposure.CoverageObserveOnly) {
			d.add(Candidate{
				Kind: UncoveredPath, RootCause: "connection:" + r.Connection.String(), Agent: r.Agent,
				Connection: r.Connection, Title: "Write reach on a path that is not enforced", Severity: sev(r.Verb),
			}, path)
		}
		if r.View == exposure.Credential && r.Agent != nil && r.Connection != nil && sensitive(r.Verb) &&
			slicesContainsAny(r.Reasons, exposure.ReasonRouteOutside, exposure.ReasonAgentHeld) {
			d.add(Candidate{
				Kind: UncoveredPath, RootCause: "connection:" + r.Connection.String(), Agent: r.Agent,
				Connection: r.Connection, Title: "Write reach on a path that is not enforced", Severity: sev(r.Verb),
			}, path)
		}
		if r.Grant == nil || r.View != exposure.Effective {
			if r.View == exposure.Effective && r.Operation != "" && sensitive(r.Verb) && in.Unverified[r.Operation] &&
				(in.Irreversible[r.Operation] || r.Verb != exposure.VerbUpdate) && r.Connection != nil {
				d.add(unverified(r), path)
			}
			continue
		}
		g := grants[*r.Grant]
		root := "grant:" + r.Grant.String()
		if len(g.Unbounded) > 0 && sensitive(r.Verb) {
			c := Candidate{
				Kind: ExcessiveGrant, RootCause: root, Agent: r.Agent, Grant: r.Grant,
				Title: "Grant leaves write authority unbounded", Severity: sev(r.Verb), Detail: map[string]string{},
			}
			for _, u := range g.Unbounded {
				c.Detail["unbounded_"+u] = "true"
			}
			d.add(c, path)
		}
		if r.Verb == exposure.VerbDelegate && slicesContainsAny(r.Reasons, exposure.ReasonDelegable) &&
			r.Coverage != exposure.CoverageEnforced {
			d.add(Candidate{
				Kind: UnsafeDelegation, RootCause: root, Agent: r.Agent, Grant: r.Grant,
				Title: "Grant can be delegated over a path that is not enforced", Severity: "high",
				Detail: map[string]string{"depth": strconv.Itoa(r.Depth)},
			}, path)
		}
		if sensitive(r.Verb) && r.Operation != "" && !g.CreatedAt.IsZero() && in.Now.Sub(g.CreatedAt) >= UnusedAfter &&
			!used[r.PathKey()] {
			d.add(Candidate{
				Kind: UnusedAuthority, RootCause: root, Agent: r.Agent, Grant: r.Grant,
				Title: "Grant reaches writes it has not used in 30 days", Severity: "low",
			}, path)
		}
		if r.Operation != "" && sensitive(r.Verb) && in.Unverified[r.Operation] &&
			(in.Irreversible[r.Operation] || r.Verb != exposure.VerbUpdate) && r.Connection != nil {
			d.add(unverified(r), path)
		}
	}
	for _, c := range in.Credentials {
		if in.Now.Sub(c.CreatedAt) < StaleAfter {
			continue
		}
		conn := c.Connection
		paths := credentialPaths(in.Rights, conn)
		if len(paths) == 0 {
			paths = []string{exposure.PathKey(nil, &conn, "", "credential:"+c.Name, exposure.VerbRead)}
		}
		d.add(Candidate{
			Kind: StaleCredential, RootCause: "connection:" + conn.String(), Connection: &conn,
			Title: "Credential not rotated in 90 days", Severity: "medium",
			Detail: map[string]string{"age_days": strconv.Itoa(int(in.Now.Sub(c.CreatedAt).Hours() / 24))},
		}, paths...)
	}
	for _, f := range in.CoverageFindings {
		id := f.ID
		root := "coverage_finding:" + id.String()
		if f.Connection != nil {
			root = "connection:" + f.Connection.String()
		}
		var paths []string
		for _, x := range f.Excess {
			k, level, _ := cutLevel(x)
			for _, r := range in.Rights {
				if r.View == exposure.Credential && r.Connection != nil && f.Connection != nil && *r.Connection == *f.Connection &&
					r.ResourceGroup == "scope:"+k && verbFor(level, r.Verb) {
					paths = append(paths, r.PathKey())
				}
			}
		}
		if len(paths) == 0 {
			paths = []string{exposure.PathKey(f.Agent, f.Connection, "", "finding:"+id.String(), exposure.VerbUpdate)}
		}
		d.add(Candidate{
			Kind: CredentialOverreach, RootCause: root, Agent: f.Agent, Connection: f.Connection,
			CoverageFinding: &id, Title: "Credential holds more than its operations need", Severity: f.Severity,
			Detail: map[string]string{"subject": truncate(f.Subject, 256)},
		}, paths...)
	}
	out := make([]Candidate, 0, len(d.by))
	for _, c := range d.by {
		slices.Sort(c.Paths)
		c.Paths = slices.Compact(c.Paths)
		if len(c.Paths) > MaxPaths {
			c.Paths, c.PathsTruncated = c.Paths[:MaxPaths], true
		}
		out = append(out, *c)
	}
	slices.SortFunc(out, func(a, b Candidate) int {
		return cmp.Or(cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.RootCause, b.RootCause), cmp.Compare(agentKey(a.Agent), agentKey(b.Agent)))
	})
	return out
}

func unverified(r exposure.Right) Candidate {
	return Candidate{
		Kind: UnverifiedSensitiveTool, RootCause: "connection:" + r.Connection.String(), Agent: r.Agent,
		Connection: r.Connection, Title: "Sensitive operation has no effect verifier", Severity: sev(r.Verb),
		Detail: map[string]string{"operation": r.Operation},
	}
}

func cutLevel(s string) (string, string, bool) {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}

// verbFor reports whether a credential right's verb is part of an excess
// at level (a write excess is its update, an admin one also its delete).
func verbFor(level string, v exposure.Verb) bool {
	switch level {
	case "read":
		return v == exposure.VerbRead
	case "write":
		return v == exposure.VerbUpdate
	default:
		return v == exposure.VerbUpdate || v == exposure.VerbDelete
	}
}

func credentialPaths(rights []exposure.Right, conn ids.UUID) []string {
	var out []string
	for _, r := range rights {
		if r.View == exposure.Credential && r.Agent == nil && r.Connection != nil && *r.Connection == conn {
			out = append(out, r.PathKey())
		}
	}
	return out
}

func sev(v exposure.Verb) string {
	//exhaustive:ignore // reads, exports and delegation are low
	switch v {
	case exposure.VerbTransfer, exposure.VerbDelete:
		return "high"
	case exposure.VerbUpdate:
		return "medium"
	default:
		return "low"
	}
}

func slicesContainsAny(s []string, want ...string) bool {
	return slices.ContainsFunc(s, func(x string) bool { return slices.Contains(want, x) })
}

func agentKey(a *ids.UUID) string {
	if a == nil {
		return ""
	}
	return a.String()
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

var severities = []string{"low", "medium", "high", "critical"}

type deriver struct{ by map[string]*Candidate }

func (d *deriver) add(c Candidate, paths ...string) {
	k := string(c.Fingerprint())
	cur, ok := d.by[k]
	if !ok {
		c.Paths = slices.Clone(paths)
		d.by[k] = &c
		return
	}
	cur.Paths = append(cur.Paths, paths...)
	if slices.Index(severities, c.Severity) > slices.Index(severities, cur.Severity) {
		cur.Severity = c.Severity
	}
	for k, v := range c.Detail {
		if cur.Detail == nil {
			cur.Detail = map[string]string{}
		}
		if _, ok := cur.Detail[k]; !ok && len(cur.Detail) < 16 {
			cur.Detail[k] = v
		}
	}
}

// Finding is a stored finding as reconciliation reads it.
type Finding struct {
	ID          ids.UUID
	Kind        Kind
	Fingerprint []byte
	State       State
	Paths       []string
	// AcceptedUntil is set while ACCEPTED_TEMPORARILY.
	AcceptedUntil *time.Time
	// Connection scopes gap checks.
	Connection *ids.UUID
	// PathsTruncated: more affected paths than were kept.
	PathsTruncated bool
}

// Action is what reconciliation does to one finding.
type Action struct {
	Kind ActionKind
	// Finding is set for an existing finding; Candidate for a new or seen
	// one.
	Finding   *Finding
	Candidate *Candidate
	To        State
}

// ActionKind names a reconciliation step.
type ActionKind string

// Reconciliation steps.
const (
	ActOpen       ActionKind = "OPEN"       // insert a new OPEN finding
	ActSeen       ActionKind = "SEEN"       // still found: refresh paths and last seen
	ActReopen     ActionKind = "REOPEN"     // found again after REMEDIATED, or acceptance expired
	ActRemediate  ActionKind = "REMEDIATE"  // no affected path reachable any more (HR-255)
	ActIncomplete ActionKind = "INCOMPLETE" // gone, but the snapshot could not prove it
	ActExpire     ActionKind = "EXPIRE"     // acceptance expired while still found
)

// Snapshot is what reconciliation knows of the recomputation.
type Snapshot struct {
	Now       time.Time
	Rights    []exposure.Right
	Truncated bool
	// Gaps are the snapshot's gap codes ("PACKAGE_UNKNOWN:<connection>").
	Gaps []string
}

// reachable reports whether any of paths is current in the snapshot, in
// the effective or credential view (observed reach is history).
func (s Snapshot) reachable(paths []string) bool {
	set := map[string]bool{}
	for _, p := range paths {
		set[p] = true
	}
	for _, r := range s.Rights {
		if r.View != exposure.Observed && !r.View.Potential() && r.Label.Current() && set[r.PathKey()] {
			return true
		}
	}
	return false
}

// incomplete reports whether the snapshot cannot vouch for a finding's
// absence: it was truncated, or could not read the finding's connection
// or the policy.
func (s Snapshot) incomplete(f Finding) bool {
	if s.Truncated {
		return true
	}
	for _, g := range s.Gaps {
		if g == "POLICY_UNKNOWN" || g == "MORE_GAPS" || (f.Connection != nil && g == "PACKAGE_UNKNOWN:"+f.Connection.String()) {
			return true
		}
	}
	return false
}

// Reconcile decides what a recomputation does to the stored findings: a
// new candidate opens; a found one is seen (and a remediated one reopens);
// an accepted one whose acceptance expired reopens; an active one no
// longer found is REMEDIATED only when none of its affected paths is
// reachable and the snapshot is complete, else EVIDENCE_INCOMPLETE or
// still open (HR-255).
func Reconcile(stored []Finding, cands []Candidate, s Snapshot) []Action {
	byFP := map[string]*Finding{}
	for i := range stored {
		byFP[string(stored[i].Kind)+string(stored[i].Fingerprint)] = &stored[i]
	}
	var out []Action
	found := map[string]bool{}
	for i := range cands {
		c := &cands[i]
		k := string(c.Kind) + string(c.Fingerprint())
		found[k] = true
		f, ok := byFP[k]
		switch {
		case !ok:
			out = append(out, Action{Kind: ActOpen, Candidate: c, To: Open})
		case f.State == Remediated:
			out = append(out, Action{Kind: ActReopen, Finding: f, Candidate: c, To: Open})
		case f.State == AcceptedTemporarily && f.AcceptedUntil != nil && !s.Now.Before(*f.AcceptedUntil):
			out = append(out, Action{Kind: ActExpire, Finding: f, Candidate: c, To: Open})
		default:
			out = append(out, Action{Kind: ActSeen, Finding: f, Candidate: c, To: f.State})
		}
	}
	for i := range stored {
		f := &stored[i]
		if found[string(f.Kind)+string(f.Fingerprint)] {
			continue
		}
		switch {
		case f.State == AcceptedTemporarily && f.AcceptedUntil != nil && !s.Now.Before(*f.AcceptedUntil):
			out = append(out, Action{Kind: ActExpire, Finding: f, To: Open})
		case !f.State.Active():
			// Remediated stays remediated; an accepted finding moves only
			// when its acceptance ends, and the recomputation after that
			// remediates it.
		case s.incomplete(*f):
			if f.State != EvidenceIncomplete {
				out = append(out, Action{Kind: ActIncomplete, Finding: f, To: EvidenceIncomplete})
			}
		case f.Kind.CauseType():
			// The cause is fixed (an owner named, a credential rotated, a
			// verifier added) and a complete snapshot no longer shows it:
			// that is the proof (D63 M1). Its subject's reach may remain.
			out = append(out, Action{Kind: ActRemediate, Finding: f, To: Remediated})
		case f.PathsTruncated:
			// Paths beyond the kept ones cannot be checked (L4).
			if f.State != EvidenceIncomplete {
				out = append(out, Action{Kind: ActIncomplete, Finding: f, To: EvidenceIncomplete})
			}
		case s.reachable(f.Paths):
			// The finding's rule no longer fires, but its paths are still
			// reachable: removing the cause has not reached them yet.
		default:
			out = append(out, Action{Kind: ActRemediate, Finding: f, To: Remediated})
		}
	}
	return out
}

// MaxPaths is how many affected paths a finding keeps.
const MaxPaths = 256

// CauseType reports a kind whose cause is a fact about its subject (no
// owner, an old credential, no verifier) rather than reach: it is
// remediated when a complete recomputation no longer shows the cause,
// whatever reach the subject keeps. The other kinds are reach-type: they
// are remediated only when none of their affected paths is reachable
// (HR-255, D63 M1).
func (k Kind) CauseType() bool {
	return k == UnownedAgent || k == UnverifiedSensitiveTool || k == StaleCredential
}
