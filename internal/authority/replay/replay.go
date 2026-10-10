// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package replay runs the decision pipeline again on an evaluation's
// recorded inputs (G0 M7 design decision 11, HR-197, F504–F508): unchanged,
// to show whether the decision reproduces, or under a proposed policy
// version, to show what that version would have decided and why. It
// explains every check that differs and reports a replay it cannot run
// exactly as incomplete, with the reasons, never as a guess.
//
// An Engine holds only read ports: it has no store, no finalization, no
// signer and no gateway client, so a replay cannot write a transaction,
// receipt, reservation or permit, or reach a target. The PostgreSQL source
// reads in READ ONLY transactions besides.
package replay

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"

	"github.com/katocxl/pantherclaw/internal/actionir"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/recording"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// ErrNotFound is returned by a Source for a record that does not exist in
// the org; Replay returns it for an evaluation without a decision receipt
// and for a proposed policy version that does not exist (T-037: another
// org's ids look the same).
var ErrNotFound = errors.New("replay: not found")

// Source is everything a replay reads. Every method reads, none writes
// (HR-197).
type Source interface {
	// Receipt returns the decision receipt (compact JWS) of an evaluation.
	Receipt(ctx context.Context, org ids.OrgID, txn ids.UUID, evaluation int) (string, error)
	// Inputs returns the sealed inputs of an evaluation.
	Inputs(ctx context.Context, org ids.OrgID, txn ids.UUID, evaluation int) (recording.Sealed, error)
	// Definition returns a definition of a package version the org
	// imported, by its pin, whatever its state now.
	Definition(ctx context.Context, org ids.OrgID, pin actionir.Definition) (*defs.Definition, error)
	// Bundle returns a stored policy bundle by its id and version number.
	Bundle(ctx context.Context, org ids.OrgID, bundle string, version int) (*pdomain.Bundle, error)
	// PolicyVersion returns a stored policy version (a draft, the published
	// one or an earlier one) by its id.
	PolicyVersion(ctx context.Context, org ids.OrgID, id ids.UUID) (*pdomain.Bundle, error)
	// Catalog returns the org's current fact types.
	Catalog(ctx context.Context, org ids.OrgID) (map[string]fdomain.Type, error)
}

// Opener opens sealed inputs; recording.Sealer implements it.
type Opener interface {
	Open(ctx context.Context, org ids.OrgID, txn ids.UUID, evaluation int, row recording.Sealed) (*recording.Recording, error)
}

// Engine replays recorded evaluations. It holds read ports only (HR-197).
type Engine struct {
	Source Source
	Inputs Opener
}

// Reasons a replay is incomplete (F507).
const (
	IncompleteInputsMissing      = "INPUTS_MISSING"
	IncompleteInputsTruncated    = "INPUTS_TRUNCATED"
	IncompleteInputsUnreadable   = "INPUTS_UNREADABLE"
	IncompleteFormatUnsupported  = "FORMAT_UNSUPPORTED"
	IncompletePipelineVersion    = "PIPELINE_VERSION_UNSUPPORTED"
	IncompletePolicyUncompilable = "POLICY_UNCOMPILABLE"
	IncompleteInputUnavailable   = "INPUT_UNAVAILABLE"
)

// Outcome is what a replay found. It carries decisions and checklists,
// never the input values themselves (those need evidence.read_restricted,
// design decision 11).
type Outcome struct {
	// Transaction is not in the JSON form: ids.UUID has no text form; the
	// RPC that returns an outcome names it.
	Transaction ids.UUID `json:"-"`
	Evaluation  int      `json:"evaluation"`
	// Policy is the policy version replayed (id@version, or "none"), and
	// Proposed whether it replaced the recorded one (F505).
	Policy   string `json:"policy"`
	Proposed bool   `json:"proposed"`
	// Complete is false when the replay could not run exactly; Incomplete
	// then says why (F507). Decision and Checklist are empty when it could
	// not run at all.
	Complete    bool             `json:"complete"`
	Incomplete  []Limitation     `json:"incomplete,omitzero"`
	Decision    adomain.Decision `json:"decision,omitzero"`
	Reason      string           `json:"reason,omitzero"`
	BasisDigest string           `json:"basis_digest,omitzero"`
	Checklist   []pipeline.Item  `json:"checklist,omitzero"`
	Original    Original         `json:"original"`
	// SameDecision: the decision and its decisive reason are the original's.
	// Reproduced: a complete replay with the recorded policy gave the same
	// decision, decisive reason and decision basis (F504).
	SameDecision bool `json:"same_decision"`
	Reproduced   bool `json:"reproduced"`
	// Differences are the checks whose items differ, with the policy rules
	// and the inputs that explain them (F506).
	Differences []Difference `json:"differences,omitzero"`
	// Notes are limits of a complete replay worth knowing.
	Notes []string `json:"notes,omitzero"`
}

// Original is the recorded decision, from its receipt.
type Original struct {
	Decision    adomain.Decision `json:"decision"`
	Reason      string           `json:"reason"`
	BasisDigest string           `json:"basis_digest"`
	Checklist   []pipeline.Item  `json:"checklist"`
	// Omitted counts checklist items the receipt left out to fit.
	Omitted int `json:"omitted,omitzero"`
}

// Limitation is why a replay is incomplete.
type Limitation struct {
	Code   string `json:"code"`
	Step   int    `json:"step,omitzero"`
	Detail string `json:"detail"`
}

// Difference is one check whose items differ between the original and the
// replay.
type Difference struct {
	Step     int             `json:"step"`
	Check    string          `json:"check"`
	Original []pipeline.Item `json:"original"`
	Replayed []pipeline.Item `json:"replayed"`
	// Rules are the policy rules among the differing items.
	Rules []string `json:"rules,omitzero"`
	// Inputs are what differed in the inputs: the policy version, or reads
	// the replay needed and could not have.
	Inputs []string `json:"inputs,omitzero"`
}

// Replay runs evaluation of txn again on its recorded inputs, at the
// recorded time: with the recorded policy, or with the stored policy
// version proposed when it is not nil. It never calls the finalization and
// reaches nothing but its read ports (HR-197, F508).
func (e *Engine) Replay(ctx context.Context, org ids.OrgID, txn ids.UUID, evaluation int, proposed *ids.UUID) (*Outcome, error) {
	jws, err := e.Source.Receipt(ctx, org, txn, evaluation)
	if err != nil {
		return nil, fmt.Errorf("replay: the decision receipt: %w", err)
	}
	orig, err := original(jws)
	if err != nil {
		return nil, err
	}
	out := &Outcome{Transaction: txn, Evaluation: evaluation, Original: orig, Proposed: proposed != nil}
	var bundle *pdomain.Bundle
	if proposed != nil {
		if bundle, err = e.Source.PolicyVersion(ctx, org, *proposed); err != nil {
			return nil, fmt.Errorf("replay: the proposed policy version: %w", err)
		}
		out.Policy = fmt.Sprintf("%s@%d", bundle.ID, bundle.Version)
	}
	rec, lim := e.open(ctx, org, txn, evaluation)
	if lim != nil {
		return out.incomplete(*lim), nil
	}
	if rec.Tampered != nil {
		return out.tampered(rec), nil
	}
	served, lims, err := e.served(ctx, org, rec, bundle, out)
	if err != nil {
		return nil, err
	}
	if len(lims) > 0 {
		return out.incomplete(lims...), nil
	}
	rd := recording.NewReader(org, rec, served)
	req, err := rd.Request()
	if err != nil {
		return out.incomplete(Limitation{Code: IncompleteInputsUnreadable, Detail: "the recorded request does not parse"}), nil //nolint:nilerr // incomplete, not a failure
	}
	ev, err := (&pipeline.Pipeline{}).EvaluateWith(ctx, rd, req)
	if err != nil {
		return out.incomplete(gaps(rd.Gaps())...), nil //nolint:nilerr // incomplete, not a failure
	}
	out.Decision, out.Reason, out.BasisDigest, out.Checklist = ev.Decision, ev.Decisive().Code, ev.Basis.Digest(), ev.Checklist
	out.Incomplete = gaps(rd.Gaps())
	out.Complete = len(out.Incomplete) == 0
	out.SameDecision = out.Decision == orig.Decision && out.Reason == orig.Reason
	out.Reproduced = !out.Proposed && out.Complete && out.SameDecision && out.BasisDigest == orig.BasisDigest
	out.Differences = differences(orig, ev.Checklist, out.Incomplete, policyChange(rec, out))
	return out, nil
}

// RecordedInputs returns an evaluation's recorded inputs themselves: the
// values it read. Callers return them only to holders of
// evidence.read_restricted (design decision 11). Missing inputs are
// ErrNotFound; truncated or unreadable ones are the recording package's
// errors.
func (e *Engine) RecordedInputs(ctx context.Context, org ids.OrgID, txn ids.UUID, evaluation int) (*recording.Recording, error) {
	row, err := e.Source.Inputs(ctx, org, txn, evaluation)
	if err != nil {
		return nil, fmt.Errorf("replay: the inputs: %w", err)
	}
	return e.Inputs.Open(ctx, org, txn, evaluation, row)
}

// open loads and opens the inputs; a limitation says why it cannot.
func (e *Engine) open(ctx context.Context, org ids.OrgID, txn ids.UUID, evaluation int) (*recording.Recording, *Limitation) {
	row, err := e.Source.Inputs(ctx, org, txn, evaluation)
	switch {
	case errors.Is(err, ErrNotFound):
		return nil, &Limitation{
			Code:   IncompleteInputsMissing,
			Detail: "no inputs are stored for this evaluation: it was decided before inputs were kept, or they were removed",
		}
	case err != nil:
		return nil, &Limitation{Code: IncompleteInputsUnreadable, Detail: "the inputs could not be read"}
	case row.Truncated:
		return nil, &Limitation{Code: IncompleteInputsTruncated, Detail: "the inputs were larger than 32 KiB compressed and only their digest was kept"}
	case row.Format != recording.FormatVersion:
		return nil, &Limitation{Code: IncompleteFormatUnsupported, Detail: fmt.Sprintf("the inputs use format %d; this server reads format %d", row.Format, recording.FormatVersion)}
	case row.Pipeline != pipeline.Version:
		return nil, &Limitation{
			Code:   IncompletePipelineVersion,
			Detail: fmt.Sprintf("the evaluation ran pipeline version %d; this server replays version %d", row.Pipeline, pipeline.Version),
		}
	}
	rec, err := e.Inputs.Open(ctx, org, txn, evaluation, row)
	if err != nil {
		return nil, &Limitation{Code: IncompleteInputsUnreadable, Detail: "the inputs could not be opened"}
	}
	return rec, nil
}

// served loads what the recording names by reference: each definition by
// its pin, and the recorded policy's bundle or the proposed one, compiled
// as the evaluation compiled its policy.
func (e *Engine) served(ctx context.Context, org ids.OrgID, rec *recording.Recording, proposed *pdomain.Bundle, out *Outcome) (
	recording.Served, []Limitation, error,
) {
	s := recording.Served{Definitions: map[string]*defs.Definition{}, Proposed: proposed != nil}
	for _, d := range rec.Reads.Definitions {
		if d.Err != "" {
			continue
		}
		def, err := e.Source.Definition(ctx, org, d.Pin)
		switch {
		case errors.Is(err, ErrNotFound):
			continue // the reader reports it as a gap
		case err != nil:
			return s, nil, fmt.Errorf("replay: definition %s: %w", d.Digest, err)
		}
		s.Definitions[d.Digest] = def
	}
	p := rec.Reads.Policy
	if proposed != nil {
		var catalog map[string]fdomain.Type
		if p == nil || p.None || p.Err != "" {
			var err error
			if catalog, err = e.Source.Catalog(ctx, org); err != nil {
				return s, nil, fmt.Errorf("replay: the fact catalog: %w", err)
			}
			out.Notes = append(out.Notes, "the evaluation read no policy, so the proposed one is compiled with the org's current fact types")
		}
		compiled, err := p.Proposed(proposed, catalog)
		if err != nil {
			return s, []Limitation{{ //nolint:nilerr // incomplete, not a failure
				Code: IncompletePolicyUncompilable, Step: pipeline.StepFacts, Detail: "the proposed policy does not compile for this action",
			}}, nil
		}
		s.Policy = compiled
		return s, nil, nil
	}
	switch {
	case p == nil:
		out.Policy = "unknown"
	case p.None:
		out.Policy = "none"
	case p.Err != "":
		out.Policy = "unreadable"
	default:
		out.Policy = p.Ref
		b, err := e.Source.Bundle(ctx, org, p.Bundle, p.Version)
		switch {
		case errors.Is(err, ErrNotFound):
			return s, nil, nil // the reader reports it as a gap
		case err != nil:
			return s, nil, fmt.Errorf("replay: policy %s: %w", p.Ref, err)
		}
		if s.Policy, err = p.Compile(b); err != nil {
			return s, []Limitation{{ //nolint:nilerr // incomplete, not a failure
				Code: IncompletePolicyUncompilable, Step: pipeline.StepFacts, Detail: "policy " + p.Ref + " no longer compiles",
			}}, nil
		}
	}
	return s, nil, nil
}

func (o *Outcome) incomplete(l ...Limitation) *Outcome {
	o.Complete, o.Incomplete = false, append(o.Incomplete, l...)
	return o
}

// tampered replays a tampering denial: the finalization compared the
// request's action hash with the one stored for its ids (HR-006); no
// policy or other input takes part.
func (o *Outcome) tampered(rec *recording.Recording) *Outcome {
	act, err := actionir.Parse(rec.Request.Action)
	if err != nil {
		return o.incomplete(Limitation{Code: IncompleteInputsUnreadable, Detail: "the recorded request does not parse"})
	}
	if act.HashHex() == rec.Tampered.StoredActionHash {
		return o.incomplete(Limitation{Code: IncompleteInputsUnreadable, Detail: "the recorded request is the stored action"})
	}
	o.Complete, o.Decision, o.Reason = true, adomain.Deny, adomain.ReasonActionTampered
	o.Checklist = []pipeline.Item{{
		Step: pipeline.StepFinalBinding, Check: "final_binding", Status: pipeline.StatusFailed, Code: adomain.ReasonActionTampered,
		Detail: "this run and action id were already used for another action", Decisive: true,
	}}
	o.SameDecision = o.Decision == o.Original.Decision && o.Reason == o.Original.Reason
	o.Reproduced = !o.Proposed && o.SameDecision
	o.Notes = append(o.Notes, "the finalization decided this evaluation before the pipeline ran: the run and action ids were already used for another action, so no policy takes part")
	return o
}

func gaps(gs []recording.Gap) []Limitation {
	var out []Limitation
	for _, g := range gs {
		out = append(out, Limitation{Code: IncompleteInputUnavailable, Step: g.Step, Detail: g.Detail})
	}
	return out
}

// policyChange describes a proposed policy against the recorded one.
func policyChange(rec *recording.Recording, o *Outcome) string {
	if !o.Proposed {
		return ""
	}
	from := "no policy"
	if p := rec.Reads.Policy; p != nil && !p.None && p.Err == "" {
		from = "policy " + p.Ref
	}
	return from + " replaced by proposed policy " + o.Policy
}

// original decodes the receipt's claims. It reads the receipt as stored;
// `pclaw verify` checks its signature.
func original(jws string) (Original, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return Original{}, errors.New("replay: the decision receipt is not a compact JWS")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Original{}, fmt.Errorf("replay: the decision receipt: %w", err)
	}
	var r finalize.DecisionReceipt
	if err := json.Unmarshal(raw, &r); err != nil {
		return Original{}, fmt.Errorf("replay: the decision receipt: %w", err)
	}
	o := Original{Decision: r.Pap.Decision, BasisDigest: r.Pap.BasisDigest, Checklist: r.Pap.Checklist, Omitted: r.Pap.Omitted}
	for _, it := range r.Pap.Checklist {
		if it.Decisive {
			o.Reason = it.Code
			break
		}
	}
	return o, nil
}
