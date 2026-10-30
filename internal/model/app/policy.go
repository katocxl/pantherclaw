// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"
	"slices"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/model/ports"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

const (
	// policyKind is a model_drafts row's kind for a policy version.
	policyKind = "POLICY"
	// firstBundleID names the bundle when the organization has none published.
	firstBundleID = "model-draft"
	// maxDraftRules bounds what one call adds to a policy.
	maxDraftRules = 16
	// approverRole is the default role that holds approval.respond.
	approverRole = "approver"
)

// PolicyDrafts stores policy drafts in the caller's transaction
// (securitysteps.PolicyStore). It has no publish path.
type PolicyDrafts interface {
	Published(ctx context.Context, tx pgx.Tx, org ids.OrgID) (*pdomain.Bundle, ids.UUID, error)
	CreateDraft(ctx context.Context, tx pgx.Tx, org ids.OrgID, b *pdomain.Bundle, author evdomain.Actor) (ids.UUID, int, error)
}

// Operations lists the operations the caller may read (search.Drafter).
type Operations interface {
	VisibleOperations(ctx context.Context) ([]string, error)
}

// PolicyDraft is a stored DRAFT version. Nothing about it is in force: only
// the M11.1 gate publishes (HR-544).
type PolicyDraft struct {
	Version ids.UUID
	Number  int
	Call    ids.UUID
	// Summaries are the added rules', in words.
	Summaries   []string
	Ambiguities []Ambiguity
}

// draftRule is the only rule a model can write. Exceptions, emergency marks,
// labels and facts have no field here.
type draftRule struct {
	Kind       pdomain.Kind     `json:"kind"`
	Summary    string           `json:"summary"`
	Operations []string         `json:"operations"`
	When       string           `json:"when"`
	Reason     string           `json:"reason"`
	Approval   *draftApproval   `json:"approval"`
	StepUp     *draftStepUp     `json:"step_up"`
	Constraint *draftConstraint `json:"constraint"`
}

type draftApproval struct {
	Count int `json:"count"`
}

type draftStepUp struct {
	Subject string `json:"subject"`
}

type draftConstraint struct {
	Kind     pdomain.ConstraintKind `json:"kind"`
	Param    string                 `json:"param"`
	Max      string                 `json:"max"`
	Currency string                 `json:"currency"`
	Values   []string               `json:"values"`
}

// policyOutput is the whole answer to a policy draft.
type policyOutput struct {
	Rules       []draftRule `json:"rules"`
	Ambiguities []Ambiguity `json:"ambiguities"`
}

func policySchema() ports.Schema {
	return ports.Object(map[string]ports.Schema{
		"rules": ports.Array(ports.Object(map[string]ports.Schema{
			"kind":       ports.Enum([]string{string(pdomain.Forbid), string(pdomain.RequireApproval), string(pdomain.RequireStepUp), string(pdomain.Constrain)}),
			"summary":    ports.Text("the rule as one readable line"),
			"operations": ports.Array(ports.Text("a catalog operation, or a prefix ending in .*")),
			"when":       ports.Text("a CEL condition over action; true when the rule always applies"),
			"reason":     ports.Text("a stable reason code in UPPER_SNAKE"),
			"approval":   ports.Nullable(ports.Object(map[string]ports.Schema{"count": ports.Integer("approvers needed, 1 or 2")})),
			"step_up":    ports.Nullable(ports.Object(map[string]ports.Schema{"subject": ports.Enum([]string{"launcher", "principal"})})),
			"constraint": ports.Nullable(ports.Object(map[string]ports.Schema{
				"kind":     ports.Enum([]string{string(pdomain.AmountMax), string(pdomain.CountMax), string(pdomain.AllowedValues)}),
				"param":    ports.Text("the parameter limited"),
				"max":      ports.Text("a decimal limit, empty for allowed_values"),
				"currency": ports.Text("the currency of a money limit, or empty"),
				"values":   ports.Array(ports.Text("an allowed value")),
			})),
		})),
		"ambiguities": AmbiguitySchema(),
	})
}

// rule turns a draft rule into a policy rule, with the fixed values a model
// does not choose. It is checked by Rule.Validate.
func (d draftRule) rule(id string) pdomain.Rule {
	r := pdomain.Rule{
		ID: id, Kind: d.Kind, Summary: d.Summary, Operations: d.Operations, When: d.When, Reason: d.Reason,
	}
	if d.Approval != nil {
		r.Approval = &pdomain.ApprovalRequirement{Role: approverRole, Count: d.Approval.Count}
	}
	if d.StepUp != nil {
		r.StepUp = &pdomain.StepUpRequirement{Subject: d.StepUp.Subject, Method: "webauthn"}
	}
	if c := d.Constraint; c != nil {
		r.Constraint = &pdomain.Constraint{Kind: c.Kind, Param: c.Param, Max: c.Max, Currency: c.Currency, Values: c.Values}
	}
	return r
}

// covered reports whether op, exact or a prefix, reaches an operation the
// person may read: a draft names nothing else.
func covered(op string, visible []string) bool {
	if prefix, ok := strings.CutSuffix(op, "*"); ok {
		return slices.ContainsFunc(visible, func(v string) bool { return strings.HasPrefix(v, prefix) })
	}
	return slices.Contains(visible, op)
}

// parsePolicy reads a model's answer strictly. Anything unknown, malformed or
// outside what the person may read refuses the whole draft (HR-543).
func parsePolicy(text string, output []byte, call ids.UUID, visible []string) ([]pdomain.Rule, []Ambiguity, error) {
	var o policyOutput
	if json.Unmarshal(output, &o, json.RejectUnknownMembers(true)) != nil {
		return nil, nil, ports.ErrInvalidOutput
	}
	if len(o.Rules) == 0 || len(o.Rules) > maxDraftRules {
		return nil, nil, ports.ErrInvalidOutput
	}
	if err := CheckAmbiguities(text, o.Ambiguities); err != nil {
		return nil, nil, err
	}
	out := make([]pdomain.Rule, 0, len(o.Rules))
	for i, d := range o.Rules {
		r := d.rule("model-" + call.String() + "-" + strconv.Itoa(i))
		if r.Validate() != nil {
			return nil, nil, ports.ErrInvalidOutput
		}
		for _, op := range r.Operations {
			if !covered(op, visible) {
				return nil, nil, ports.ErrInvalidOutput
			}
		}
		out = append(out, r)
	}
	return out, o.Ambiguities, nil
}

// storeDraft adds rules to the published policy, or starts one, as the next
// DRAFT: a draft that left the rest out would read as removing it. It is
// marked origin=model in the same transaction.
func (s *Service) storeDraft(ctx context.Context, c tenancy.Caller, call ids.UUID, rules []pdomain.Rule) (version ids.UUID, number int, err error) {
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		base, _, err := s.Policies.Published(ctx, tx.Pgx(), c.Org)
		if err != nil {
			return err
		}
		b := &pdomain.Bundle{ID: firstBundleID, Version: 1}
		if base != nil {
			b.ID, b.Version, b.Rules, b.Tests = base.ID, base.Version, slices.Clone(base.Rules), slices.Clone(base.Tests)
		}
		b.Rules = append(b.Rules, rules...)
		if version, number, err = s.Policies.CreateDraft(ctx, tx.Pgx(), c.Org, b, c.Actor()); err != nil {
			return err
		}
		return LinkDraft(ctx, tx, c.Org, version, call, policyKind)
	})
	switch pcerr.ReasonOf(err) {
	case "POLICY_INVALID", "POLICY_DOES_NOT_COMPILE":
		return ids.UUID{}, 0, ports.ErrInvalidOutput
	}
	return version, number, err
}

// DraftPolicy turns text into a DRAFT policy version, origin=model. It only
// ever stores a draft: publishing stays with the M11.1 gate and a person
// (HR-544).
func (s *Service) DraftPolicy(ctx context.Context, text string) (PolicyDraft, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return PolicyDraft{}, err
	}
	if err := c.Require(td.PermPolicyAuthor, td.OrgPath(c.Org)); err != nil {
		return PolicyDraft{}, err
	}
	if s.Policies == nil || s.Operations == nil {
		return PolicyDraft{}, ErrPlatformOff
	}
	visible, err := s.Operations.VisibleOperations(ctx)
	if err != nil {
		return PolicyDraft{}, err
	}
	schema, err := policySchema().Encode()
	if err != nil {
		return PolicyDraft{}, err
	}
	var out PolicyDraft
	res, err := s.Draft(ctx, Call{
		Task: ports.TaskPolicyDraft, Text: text, Schema: schema,
		Catalog: ports.Catalog{OperationGroups: OperationGroups(visible)},
		Parse: func(call ids.UUID, output []byte) error {
			rules, ambiguities, err := parsePolicy(text, output, call, visible)
			if err != nil {
				return err
			}
			out.Ambiguities = ambiguities
			for _, r := range rules {
				out.Summaries = append(out.Summaries, r.Summary)
			}
			out.Version, out.Number, err = s.storeDraft(ctx, c, call, rules)
			return err
		},
	})
	if err != nil {
		return PolicyDraft{}, err
	}
	out.Call = res.ID
	return out, nil
}
