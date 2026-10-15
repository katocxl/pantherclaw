// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package policiesrpc

import (
	"context"
	"errors"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connectproto"
	"google.golang.org/protobuf/proto"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/rpc"
	"github.com/katocxl/pantherclaw/internal/policy/app"
	"github.com/katocxl/pantherclaw/internal/policy/domain"
)

// The publish gate's RPCs (G0 M11.1 design decisions 6, 9 and 11; HR-230,
// HR-231, HR-236). Confirming or declining a change request happens only
// on its page, with a security key; these RPCs only read requests.

// gateError returns a refused validation or test run as the wire error
// with its report as an error detail.
func gateError(err error) error {
	var ge *app.GateError
	if !errors.As(err, &ge) {
		return err
	}
	ce := connect.NewError(rpc.ConnectCode(pcerr.CodeOf(err)), pcerr.ReasonOf(err)+": "+pcerr.PublicMessage(err)).WithCause(err)
	var detail proto.Message
	switch {
	case ge.Validation != nil:
		detail = validationProto(*ge.Validation)
	case ge.Tests != nil:
		detail = testsProto(*ge.Tests)
	}
	if detail != nil {
		if d, derr := connectproto.NewErrorDetail(detail); derr == nil {
			ce = ce.WithDetail(d)
		}
	}
	return ce
}

func validationProto(r domain.ValidationResult) *pantherclawv1.ValidationReport {
	out := &pantherclawv1.ValidationReport{
		Passed: r.Passed, DefinitionsDigest: r.DefinitionsDigest[:], CatalogDigest: r.CatalogDigest[:],
	}
	for _, f := range r.Findings {
		out.Findings = append(out.Findings, &pantherclawv1.PolicyFinding{
			Code: f.Code, Severity: f.Severity, Rules: f.Rules, Detail: f.Detail, Example: f.Example, SampleBased: f.SampleBased,
		})
	}
	return out
}

func testsProto(r domain.TestResult) *pantherclawv1.TestReport {
	out := &pantherclawv1.TestReport{
		Passed: r.Passed, Mutants: int32(r.Mutants), Survivors: int32(r.Survivors), Error: r.Error, //nolint:gosec // bounded runs
		DefinitionsDigest: r.DefinitionsDigest[:], CatalogDigest: r.CatalogDigest[:],
	}
	for _, c := range r.Cases {
		out.Cases = append(out.Cases, &pantherclawv1.TestCaseResult{
			Id: c.ID, Passed: c.Passed, Decision: c.Decision, Reason: c.Reason, Rule: c.Rule, Detail: c.Detail,
		})
	}
	for _, m := range r.Surviving {
		out.Surviving = append(out.Surviving, &pantherclawv1.SurvivingMutant{Rule: m.Rule, Mutation: m.Mutation})
	}
	return out
}

func diffProto(d domain.Diff) *pantherclawv1.PolicyDiff {
	out := &pantherclawv1.PolicyDiff{Direction: string(d.Direction)}
	for _, c := range d.Changes {
		out.Changes = append(out.Changes, &pantherclawv1.PolicyRuleChange{
			RuleId: c.RuleID, Kind: c.Kind, Field: c.Field, Before: c.Before, After: c.After,
			Direction: string(c.Direction), Sentence: c.Sentence,
		})
	}
	return out
}

// ChangeRequestProto renders a change request (nil: none).
func ChangeRequestProto(r *app.ChangeRequest) *pantherclawv1.PolicyChangeRequest {
	if r == nil {
		return nil
	}
	out := &pantherclawv1.PolicyChangeRequest{
		Id: r.ID.String(), Kind: string(r.Kind), SubjectId: r.Subject.String(), State: r.State,
		Required: int32(r.Required), RequestedBy: r.RequestedBy, CreateTime: ts(r.CreatedAt), //nolint:gosec // 1 or 2
		ExpireTime: ts(r.ExpiresAt), DecidedReason: r.DecidedReason, Summary: r.Summary, Binding: r.Binding[:], Url: r.URL,
	}
	if !r.Base.IsZero() {
		out.BaseVersionId = r.Base.String()
	}
	if r.DecidedAt != nil {
		out.DecideTime = ts(*r.DecidedAt)
	}
	for _, c := range r.Confirmations {
		out.Confirmations = append(out.Confirmations, &pantherclawv1.PolicyChangeConfirmation{
			UserId: c.Principal.String(), CredentialId: c.Credential.String(), CreateTime: ts(c.At),
		})
	}
	return out
}

// ValidatePolicyVersion implements PolicyServiceHandler.
func (s *Policies) ValidatePolicyVersion(ctx context.Context, req *pantherclawv1.ValidatePolicyVersionRequest) (*pantherclawv1.ValidatePolicyVersionResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	v, r, err := s.svc.Validate(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ValidatePolicyVersionResponse{Version: VersionProto(v, false), Validation: validationProto(r)}, nil
}

// TestPolicyVersion implements PolicyServiceHandler.
func (s *Policies) TestPolicyVersion(ctx context.Context, req *pantherclawv1.TestPolicyVersionRequest) (*pantherclawv1.TestPolicyVersionResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	v, r, err := s.svc.Test(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.TestPolicyVersionResponse{Version: VersionProto(v, false), Tests: testsProto(r)}, nil
}

// DiffPolicyVersions implements PolicyServiceHandler.
func (s *Policies) DiffPolicyVersions(ctx context.Context, req *pantherclawv1.DiffPolicyVersionsRequest) (*pantherclawv1.DiffPolicyVersionsResponse, error) {
	to, err := parseID(req.GetToId())
	if err != nil {
		return nil, err
	}
	var from *ids.UUID
	if req.FromId != nil {
		f, err := parseID(req.GetFromId())
		if err != nil {
			return nil, err
		}
		from = &f
	}
	d, outcomes, err := s.svc.Diff(ctx, from, to)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.DiffPolicyVersionsResponse{Diff: diffProto(d), Outcomes: outcomes}, nil
}

// RollbackPolicy implements PolicyServiceHandler.
func (s *Policies) RollbackPolicy(ctx context.Context, req *pantherclawv1.RollbackPolicyRequest) (*pantherclawv1.RollbackPolicyResponse, error) {
	to, err := parseID(req.GetToVersionId())
	if err != nil {
		return nil, err
	}
	expected, err := expectedVersion(req.ExpectedCurrentVersion)
	if err != nil {
		return nil, err
	}
	out, err := s.svc.Rollback(ctx, to, expected)
	if err != nil {
		return nil, gateError(err)
	}
	return &pantherclawv1.RollbackPolicyResponse{
		Version: VersionProto(out.Version, false), ChangeRequest: ChangeRequestProto(out.ChangeRequest),
		CarriedRuleIds: out.Carried, Diff: diffProto(out.Diff),
	}, nil
}

// ListPolicyChangeRequests implements PolicyServiceHandler.
func (s *Policies) ListPolicyChangeRequests(ctx context.Context, req *pantherclawv1.ListPolicyChangeRequestsRequest) (*pantherclawv1.ListPolicyChangeRequestsResponse, error) {
	if s.svc.Changes == nil {
		return nil, app.ErrGateUnavailable
	}
	limit := int(req.GetPageSize())
	if limit == 0 {
		limit = 50
	}
	rs, err := s.svc.Changes.List(ctx, req.GetState(), limit)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListPolicyChangeRequestsResponse{}
	for i := range rs {
		out.Requests = append(out.Requests, ChangeRequestProto(&rs[i]))
	}
	return out, nil
}

// GetPolicyChangeRequest implements PolicyServiceHandler.
func (s *Policies) GetPolicyChangeRequest(ctx context.Context, req *pantherclawv1.GetPolicyChangeRequestRequest) (*pantherclawv1.GetPolicyChangeRequestResponse, error) {
	if s.svc.Changes == nil {
		return nil, app.ErrGateUnavailable
	}
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	r, err := s.svc.Changes.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetPolicyChangeRequestResponse{Request: ChangeRequestProto(&r)}, nil
}
