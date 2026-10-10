// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package recording

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	bdomain "github.com/katocxl/pantherclaw/internal/budgets/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// ErrNotRecorded is what a replayed read returns when the recording does
// not hold it. The pipeline treats it as missing evidence, and the replay
// lists it as a gap: incomplete, never guessed (HR-197, F507).
var ErrNotRecorded = errors.New("recording: the read was not recorded")

// Gap is a read a replay needed that the recording does not hold, with the
// pipeline step that made it.
type Gap struct {
	Read   string `json:"read"`
	Step   int    `json:"step"`
	Detail string `json:"detail"`
}

// Served is what a replay serves by reference.
type Served struct {
	// Definitions are the recorded definitions, loaded again by their pins,
	// by digest.
	Definitions map[string]*defs.Definition
	// Policy is the recorded policy, compiled again, or a proposed one (nil:
	// none applies).
	Policy *pipeline.Policy
	// Proposed: Policy replaces whatever policy the evaluation read (F505).
	Proposed bool
}

// Reader serves a recording to the pipeline. It reads nothing else and
// writes nothing.
type Reader struct {
	org    ids.OrgID
	rec    *Recording
	served Served

	mu   sync.Mutex
	gaps []Gap
}

var _ pipeline.Reader = (*Reader)(nil)

// NewReader returns a Reader of rec, recorded in org.
func NewReader(org ids.OrgID, rec *Recording, served Served) *Reader {
	return &Reader{org: org, rec: rec, served: served}
}

// Request returns the request the recording decided.
func (r *Reader) Request() (pipeline.Request, error) {
	act, err := actionir.Parse(bytes.Clone(r.rec.Request.Action))
	if err != nil {
		return pipeline.Request{}, err
	}
	id, err := r.rec.identity()
	if err != nil {
		return pipeline.Request{}, err
	}
	return pipeline.Request{Org: r.org, Action: act, Identity: id, Gateway: r.rec.Request.Gateway}, nil
}

// Gaps returns the reads the replay needed and the recording did not hold.
func (r *Reader) Gaps() []Gap {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.gaps)
}

func (r *Reader) gap(read string, step int, detail string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	g := Gap{Read: read, Step: step, Detail: detail}
	if !slices.Contains(r.gaps, g) {
		r.gaps = append(r.gaps, g)
	}
	return ErrNotRecorded
}

func (r *Reader) otherOrg(org ids.OrgID, read string, step int) error {
	if org == r.org {
		return nil
	}
	return r.gap(read, step, "a read of another org")
}

// Containment implements pipeline.Reader.
func (r *Reader) Containment(_ context.Context, org ids.OrgID) (pipeline.Containment, error) {
	c := r.rec.Reads.Containment
	if err := r.otherOrg(org, "containment", pipeline.StepContainment); err != nil || c == nil {
		return pipeline.Containment{}, r.gap("containment", pipeline.StepContainment, "the containment state was not recorded")
	}
	return c.value()
}

// Definition implements pipeline.Reader.
func (r *Reader) Definition(_ context.Context, org ids.OrgID, pin actionir.Definition) (pipeline.Pinned, error) {
	if err := r.otherOrg(org, "definition", pipeline.StepScope); err != nil {
		return pipeline.Pinned{}, err
	}
	i := slices.IndexFunc(r.rec.Reads.Definitions, func(d Definition) bool { return d.Pin == pin })
	if i < 0 {
		return pipeline.Pinned{}, r.gap("definition", pipeline.StepScope, "definition "+pin.Digest+" was not recorded")
	}
	d := r.rec.Reads.Definitions[i]
	if err := errOf(d.Err); err != nil {
		return pipeline.Pinned{}, err
	}
	def := r.served.Definitions[d.Digest]
	if def == nil {
		return pipeline.Pinned{}, r.gap("definition", pipeline.StepScope, "definition "+d.Digest+" no longer exists")
	}
	return pipeline.Pinned{Definition: def, State: defs.State(d.State)}, nil
}

// Policy implements pipeline.Reader.
func (r *Reader) Policy(_ context.Context, org ids.OrgID) (*pipeline.Policy, error) {
	if err := r.otherOrg(org, "policy", pipeline.StepFacts); err != nil {
		return nil, err
	}
	if r.served.Proposed {
		return r.served.Policy, nil
	}
	p := r.rec.Reads.Policy
	switch {
	case p == nil:
		return nil, r.gap("policy", pipeline.StepFacts, "the policy was not recorded")
	case p.Err != "":
		return nil, errOf(p.Err)
	case p.None:
		return nil, nil //nolint:nilnil // no policy was published
	case r.served.Policy == nil:
		return nil, r.gap("policy", pipeline.StepFacts, "policy "+p.Ref+" no longer exists")
	}
	return r.served.Policy, nil
}

// Run implements pipeline.Reader.
func (r *Reader) Run(_ context.Context, org ids.OrgID, id ids.UUID) (pipeline.Run, error) {
	i := slices.IndexFunc(r.rec.Reads.Runs, func(x Run) bool { return x.ID == id.String() })
	if err := r.otherOrg(org, "run", pipeline.StepIdentity); err != nil || i < 0 {
		return pipeline.Run{}, r.gap("run", pipeline.StepIdentity, "run "+id.String()+" was not recorded")
	}
	return r.rec.Reads.Runs[i].value()
}

// Agent implements pipeline.Reader.
func (r *Reader) Agent(_ context.Context, org ids.OrgID, id ids.UUID) (pipeline.Agent, error) {
	i := slices.IndexFunc(r.rec.Reads.Agents, func(x Agent) bool { return x.ID == id.String() })
	if err := r.otherOrg(org, "agent", pipeline.StepIdentity); err != nil || i < 0 {
		return pipeline.Agent{}, r.gap("agent", pipeline.StepIdentity, "agent "+id.String()+" was not recorded")
	}
	return r.rec.Reads.Agents[i].value()
}

// Chain implements pipeline.Reader.
func (r *Reader) Chain(_ context.Context, org ids.OrgID, id gdomain.GrantID) ([]gdomain.Grant, error) {
	i := slices.IndexFunc(r.rec.Reads.Chains, func(x Chain) bool { return x.Grant == id.String() })
	if err := r.otherOrg(org, "chain", pipeline.StepAuthority); err != nil || i < 0 {
		return nil, r.gap("chain", pipeline.StepAuthority, "the chain of grant "+id.String()+" was not recorded")
	}
	c := r.rec.Reads.Chains[i]
	if err := errOf(c.Err); err != nil {
		return nil, err
	}
	out := make([]gdomain.Grant, 0, len(c.Grants))
	for _, g := range c.Grants {
		v, err := g.value(r.org)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// Envelopes implements pipeline.Reader.
func (r *Reader) Envelopes(_ context.Context, org ids.OrgID, scopes []gdomain.Scope) ([]gdomain.Envelope, error) {
	want := scopesOf(scopes)
	i := slices.IndexFunc(r.rec.Reads.Envelopes, func(x Envelopes) bool { return slices.Equal(x.Scopes, want) })
	if err := r.otherOrg(org, "envelopes", pipeline.StepAuthority); err != nil || i < 0 {
		return nil, r.gap("envelopes", pipeline.StepAuthority, "the guardrails of these scopes were not recorded")
	}
	e := r.rec.Reads.Envelopes[i]
	if err := errOf(e.Err); err != nil {
		return nil, err
	}
	var out []gdomain.Envelope
	for _, x := range e.Envelopes {
		v, err := x.value(r.org)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// Facts implements pipeline.Reader: a read of the same subject that asked
// for every name serves it, so a proposed policy that needs fewer facts
// replays exactly; a name never asked for is a gap.
func (r *Reader) Facts(_ context.Context, org ids.OrgID, subjectType, subjectID string, names []string) (map[string]fdomain.Fact, error) {
	if err := r.otherOrg(org, "facts", pipeline.StepFacts); err != nil {
		return nil, err
	}
	var missing []string
	for _, f := range r.rec.Reads.Facts {
		if f.SubjectType != subjectType || f.SubjectID != subjectID {
			continue
		}
		missing = missing[:0]
		for _, n := range names {
			if !slices.Contains(f.Names, n) {
				missing = append(missing, n)
			}
		}
		if len(missing) > 0 {
			continue
		}
		all, err := f.value()
		if err != nil {
			return nil, err
		}
		out := make(map[string]fdomain.Fact, len(names))
		for _, n := range names {
			if v, ok := all[n]; ok {
				out[n] = v
			}
		}
		return out, nil
	}
	if missing == nil {
		missing = names
	}
	return nil, r.gap("facts", pipeline.StepFacts, "facts "+strings.Join(missing, ", ")+" about "+subjectType+" "+subjectID+" were not recorded")
}

// Usage implements pipeline.Reader: a read that covered every ref of the
// plan serves it, keyed by the plan's own refs.
func (r *Reader) Usage(_ context.Context, org ids.OrgID, plan gdomain.Plan) (pipeline.Usage, error) {
	if err := r.otherOrg(org, "usage", pipeline.StepBoundaries); err != nil {
		return pipeline.Usage{}, err
	}
	for _, u := range r.rec.Reads.Usage {
		out, ok, err := u.serve(plan)
		if ok {
			return out, err
		}
	}
	return pipeline.Usage{}, r.gap("usage", pipeline.StepBoundaries, "the budgets and counters of this plan were not recorded")
}

func (u Usage) serve(plan gdomain.Plan) (pipeline.Usage, bool, error) {
	refs := func(dtos []Ref) ([]bdomain.Ref, error) {
		out := make([]bdomain.Ref, 0, len(dtos))
		for _, d := range dtos {
			v, err := d.value()
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	}
	budgets, err1 := refs(u.Budgets)
	counters, err2 := refs(u.Counters)
	if err := errors.Join(err1, err2); err != nil {
		return pipeline.Usage{}, true, err
	}
	has := func(set []bdomain.Ref, ref bdomain.Ref) bool {
		return slices.ContainsFunc(set, func(x bdomain.Ref) bool { return sameRef(x, ref) })
	}
	for _, d := range plan.Budgets {
		if !has(budgets, d.Ref) {
			return pipeline.Usage{}, false, nil
		}
	}
	for _, d := range plan.Counters {
		if !has(counters, d.Ref) {
			return pipeline.Usage{}, false, nil
		}
	}
	if err := errOf(u.Err); err != nil {
		return pipeline.Usage{}, true, err
	}
	out := pipeline.Usage{Accounts: map[bdomain.Ref]bdomain.Account{}, Counters: map[bdomain.Ref]bdomain.Counter{}, CounterRows: map[bdomain.Ref]int{}}
	for _, d := range plan.Budgets {
		for _, a := range u.Accounts {
			ref, err := a.Ref.value()
			if err != nil {
				return pipeline.Usage{}, true, err
			}
			if sameRef(ref, d.Ref) {
				if out.Accounts[d.Ref], err = a.value(); err != nil {
					return pipeline.Usage{}, true, err
				}
			}
		}
	}
	for _, d := range plan.Counters {
		capRef := d.Ref
		capRef.Key = [32]byte{}
		for _, c := range u.CounterUse {
			ref, err := c.Ref.value()
			if err != nil {
				return pipeline.Usage{}, true, err
			}
			if sameRef(ref, d.Ref) {
				if out.Counters[d.Ref], err = c.value(); err != nil {
					return pipeline.Usage{}, true, err
				}
			}
		}
		for _, n := range u.CounterRows {
			ref, err := n.Ref.value()
			if err != nil {
				return pipeline.Usage{}, true, err
			}
			if sameRef(ref, capRef) {
				out.CounterRows[capRef] = n.Rows
			}
		}
	}
	return out, true, nil
}

// Claim implements pipeline.Reader.
func (r *Reader) Claim(_ context.Context, org ids.OrgID, key string) (*pipeline.Claim, error) {
	i := slices.IndexFunc(r.rec.Reads.Claims, func(x Claim) bool { return x.Key == key })
	if err := r.otherOrg(org, "claim", pipeline.StepBoundaries); err != nil || i < 0 {
		return nil, r.gap("claim", pipeline.StepBoundaries, "earlier attempts on the dedupe key were not recorded")
	}
	return r.rec.Reads.Claims[i].value()
}

// Connection implements pipeline.Reader.
func (r *Reader) Connection(_ context.Context, org ids.OrgID, id ids.UUID) (pipeline.Connection, error) {
	i := slices.IndexFunc(r.rec.Reads.Connections, func(x Connection) bool { return x.ID == id.String() })
	if err := r.otherOrg(org, "connection", pipeline.StepScope); err != nil || i < 0 {
		return pipeline.Connection{}, r.gap("connection", pipeline.StepScope, "connection "+id.String()+" was not recorded")
	}
	return r.rec.Reads.Connections[i].value()
}

// Hold implements pipeline.Reader.
func (r *Reader) Hold(_ context.Context, org ids.OrgID, run, action ids.UUID) (*pipeline.HoldRequest, error) {
	i := slices.IndexFunc(r.rec.Reads.Holds, func(x Hold) bool { return x.Run == run.String() && x.Action == action.String() })
	if err := r.otherOrg(org, "hold", pipeline.StepRequirements); err != nil || i < 0 {
		return nil, r.gap("hold", pipeline.StepRequirements, "the transaction's approval request was not recorded")
	}
	return r.rec.Reads.Holds[i].value()
}

// Variants implements pipeline.Reader.
func (r *Reader) Variants(_ context.Context, org ids.OrgID, key [32]byte, operation string, target actionir.Target, now time.Time) (
	[]apdomain.VariantLine, []apdomain.ContextLine, error,
) {
	k := hex.EncodeToString(key[:])
	i := slices.IndexFunc(r.rec.Reads.Variants, func(x Variants) bool {
		return x.Key == k && x.Operation == operation && x.Target == target && x.Now.Equal(now)
	})
	if err := r.otherOrg(org, "variants", pipeline.StepRequirements); err != nil || i < 0 {
		return nil, nil, r.gap("variants", pipeline.StepRequirements, "earlier and approved requests for this action were not recorded")
	}
	v := r.rec.Reads.Variants[i]
	if err := errOf(v.Err); err != nil {
		return nil, nil, err
	}
	return slices.Clone(v.Variants), slices.Clone(v.Context), nil
}

// HoldSettings implements pipeline.Reader.
func (r *Reader) HoldSettings(_ context.Context, org ids.OrgID) (pipeline.HoldSettings, error) {
	h := r.rec.Reads.HoldSettings
	if err := r.otherOrg(org, "hold_settings", pipeline.StepRequirements); err != nil || h == nil {
		return pipeline.HoldSettings{}, r.gap("hold_settings", pipeline.StepRequirements, "the org's hold settings were not recorded")
	}
	if err := errOf(h.Err); err != nil {
		return pipeline.HoldSettings{}, err
	}
	return pipeline.HoldSettings{HoldDeadline: time.Duration(h.HoldDeadlineNS)}, nil
}

// String names a gap for an explanation.
func (g Gap) String() string { return fmt.Sprintf("step %d: %s", g.Step, g.Detail) }
