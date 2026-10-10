// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package recording

import (
	"context"
	"encoding/hex"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Recorder is a pipeline.Reader that passes every read to the Reader it
// wraps, unchanged, and keeps its arguments and result. It records one
// evaluation of one request.
type Recorder struct {
	r   pipeline.Reader
	req pipeline.Request

	mu    sync.Mutex
	reads Reads
	err   error
}

var _ pipeline.Reader = (*Recorder)(nil)

// NewRecorder returns a Recorder of req's evaluation over r.
func NewRecorder(r pipeline.Reader, req pipeline.Request) *Recorder {
	return &Recorder{r: r, req: req}
}

// Recording returns what the evaluation read, or the first result that
// could not be recorded.
func (r *Recorder) Recording() (*Recording, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return nil, r.err
	}
	return &Recording{Format: FormatVersion, Pipeline: pipeline.Version, Request: request(r.req), Reads: r.reads}, nil
}

// NewTampered returns the recording of a request the finalization answered
// before the pipeline ran: the run and action ids were used for another
// action, whose hash was storedHash (HR-006).
func NewTampered(req pipeline.Request, storedHash string) *Recording {
	return &Recording{
		Format: FormatVersion, Pipeline: pipeline.Version, Request: request(req),
		Tampered: &Tampered{StoredActionHash: storedHash},
	}
}

func request(req pipeline.Request) Request {
	id := req.Identity
	return Request{
		Action: slices.Clone(req.Action.Canonical), Instance: uid(id.InstanceID), Agent: uid(id.AgentID),
		Attestation: id.AttestationLevel, JKT: id.JKT, Gateway: req.Gateway,
	}
}

func (r *Recorder) keep(fn func(*Reads) error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := fn(&r.reads); err != nil && r.err == nil {
		r.err = err
	}
}

// Containment implements pipeline.Reader.
func (r *Recorder) Containment(ctx context.Context, org ids.OrgID) (pipeline.Containment, error) {
	c, err := r.r.Containment(ctx, org)
	r.keep(func(x *Reads) error { x.Containment = fromContainment(c, err); return nil })
	return c, err
}

// Definition implements pipeline.Reader.
func (r *Recorder) Definition(ctx context.Context, org ids.OrgID, pin actionir.Definition) (pipeline.Pinned, error) {
	p, err := r.r.Definition(ctx, org, pin)
	r.keep(func(x *Reads) error {
		d := Definition{Pin: pin, Err: errKind(err)}
		if err == nil {
			if p.Definition == nil {
				return errors.New("recording: a definition read returned no definition")
			}
			d.Digest, d.State = p.Definition.Digest, string(p.State)
		}
		x.Definitions = append(x.Definitions, d)
		return nil
	})
	return p, err
}

// Policy implements pipeline.Reader.
func (r *Recorder) Policy(ctx context.Context, org ids.OrgID) (*pipeline.Policy, error) {
	p, err := r.r.Policy(ctx, org)
	r.keep(func(x *Reads) error { x.Policy = fromPolicy(p, err); return nil })
	return p, err
}

// Run implements pipeline.Reader.
func (r *Recorder) Run(ctx context.Context, org ids.OrgID, id ids.UUID) (pipeline.Run, error) {
	run, err := r.r.Run(ctx, org, id)
	r.keep(func(x *Reads) error { x.Runs = append(x.Runs, fromRun(id, run, err)); return nil })
	return run, err
}

// Agent implements pipeline.Reader.
func (r *Recorder) Agent(ctx context.Context, org ids.OrgID, id ids.UUID) (pipeline.Agent, error) {
	a, err := r.r.Agent(ctx, org, id)
	r.keep(func(x *Reads) error { x.Agents = append(x.Agents, fromAgent(id, a, err)); return nil })
	return a, err
}

// Chain implements pipeline.Reader.
func (r *Recorder) Chain(ctx context.Context, org ids.OrgID, id gdomain.GrantID) ([]gdomain.Grant, error) {
	grants, err := r.r.Chain(ctx, org, id)
	r.keep(func(x *Reads) error {
		c := Chain{Grant: id.String(), Err: errKind(err)}
		read := grants
		if c.Err != "" {
			read = nil // the read failed: nothing to keep
		}
		for _, g := range read {
			dto, cerr := fromGrant(g)
			if cerr != nil {
				return cerr
			}
			c.Grants = append(c.Grants, dto)
		}
		x.Chains = append(x.Chains, c)
		return nil
	})
	return grants, err
}

// Envelopes implements pipeline.Reader.
func (r *Recorder) Envelopes(ctx context.Context, org ids.OrgID, scopes []gdomain.Scope) ([]gdomain.Envelope, error) {
	envs, err := r.r.Envelopes(ctx, org, scopes)
	r.keep(func(x *Reads) error {
		e := Envelopes{Scopes: scopesOf(scopes), Err: errKind(err)}
		read := envs
		if e.Err != "" {
			read = nil // the read failed: nothing to keep
		}
		for _, env := range read {
			dto, cerr := fromEnvelope(env)
			if cerr != nil {
				return cerr
			}
			e.Envelopes = append(e.Envelopes, dto)
		}
		x.Envelopes = append(x.Envelopes, e)
		return nil
	})
	return envs, err
}

func scopesOf(scopes []gdomain.Scope) []Scope {
	out := make([]Scope, 0, len(scopes))
	for _, s := range scopes {
		out = append(out, fromScope(s))
	}
	return out
}

// Facts implements pipeline.Reader.
func (r *Recorder) Facts(ctx context.Context, org ids.OrgID, subjectType, subjectID string, names []string) (map[string]fdomain.Fact, error) {
	found, err := r.r.Facts(ctx, org, subjectType, subjectID, names)
	r.keep(func(x *Reads) error {
		f, cerr := fromFacts(subjectType, subjectID, names, found, err)
		if cerr != nil {
			return cerr
		}
		x.Facts = append(x.Facts, f)
		return nil
	})
	return found, err
}

// Usage implements pipeline.Reader.
func (r *Recorder) Usage(ctx context.Context, org ids.OrgID, plan gdomain.Plan) (pipeline.Usage, error) {
	u, err := r.r.Usage(ctx, org, plan)
	r.keep(func(x *Reads) error { x.Usage = append(x.Usage, fromUsage(plan, u, err)); return nil })
	return u, err
}

// Claim implements pipeline.Reader.
func (r *Recorder) Claim(ctx context.Context, org ids.OrgID, key string) (*pipeline.Claim, error) {
	c, err := r.r.Claim(ctx, org, key)
	r.keep(func(x *Reads) error { x.Claims = append(x.Claims, fromClaim(key, c, err)); return nil })
	return c, err
}

// Connection implements pipeline.Reader.
func (r *Recorder) Connection(ctx context.Context, org ids.OrgID, id ids.UUID) (pipeline.Connection, error) {
	c, err := r.r.Connection(ctx, org, id)
	r.keep(func(x *Reads) error { x.Connections = append(x.Connections, fromConnection(id, c, err)); return nil })
	return c, err
}

// Hold implements pipeline.Reader.
func (r *Recorder) Hold(ctx context.Context, org ids.OrgID, run, action ids.UUID) (*pipeline.HoldRequest, error) {
	h, err := r.r.Hold(ctx, org, run, action)
	r.keep(func(x *Reads) error { x.Holds = append(x.Holds, fromHold(run, action, h, err)); return nil })
	return h, err
}

// Variants implements pipeline.Reader.
func (r *Recorder) Variants(ctx context.Context, org ids.OrgID, key [32]byte, operation string, target actionir.Target, now time.Time) (
	[]apdomain.VariantLine, []apdomain.ContextLine, error,
) {
	variants, approved, err := r.r.Variants(ctx, org, key, operation, target, now)
	r.keep(func(x *Reads) error {
		v := Variants{Key: hex.EncodeToString(key[:]), Operation: operation, Target: target, Now: now, Err: errKind(err)}
		if err == nil {
			v.Variants, v.Context = slices.Clone(variants), slices.Clone(approved)
		}
		x.Variants = append(x.Variants, v)
		return nil
	})
	return variants, approved, err
}

// HoldSettings implements pipeline.Reader.
func (r *Recorder) HoldSettings(ctx context.Context, org ids.OrgID) (pipeline.HoldSettings, error) {
	s, err := r.r.HoldSettings(ctx, org)
	r.keep(func(x *Reads) error {
		x.HoldSettings = &HoldSettings{HoldDeadlineNS: int64(s.HoldDeadline), Err: errKind(err)}
		return nil
	})
	return s, err
}

// any reports whether any read is recorded.
func (r *Reads) any() bool {
	return r.Containment != nil || r.Policy != nil || r.HoldSettings != nil || len(r.Definitions)+len(r.Runs)+len(r.Agents)+
		len(r.Chains)+len(r.Envelopes)+len(r.Facts)+len(r.Usage)+len(r.Claims)+len(r.Connections)+len(r.Holds)+len(r.Variants) > 0
}
