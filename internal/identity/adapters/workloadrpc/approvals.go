// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package workloadrpc

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	approvals "github.com/katocxl/pantherclaw/internal/approvals/app"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/runs/adapters/runsrpc"
	waitlist "github.com/katocxl/pantherclaw/internal/waitlist/app"
)

// The workload's side of approvals (G0 M5 part 2): waiting on a held
// transaction, giving evidence and asking for access. Each call is
// authenticated by PAP/1 and serves only the caller's own run (HR-174).

var errNoApprovals = pcerr.New(pcerr.Unimplemented, "UNIMPLEMENTED", "this server does not serve approvals to workloads")

// WithApprovals adds evidence and access requests from workloads.
func (s *Workload) WithApprovals(svc *approvals.Service, access *waitlist.Writer) *Workload {
	s.approvals, s.access = svc, access
	return s
}

// authenticate checks the call's PAP/1 credentials and consumes the proof
// (PAP-1 §4); it returns the caller's org and instance.
func (s *Workload) authenticate(ctx context.Context, info *connect.CallInfo) (ids.OrgID, ids.UUID, error) {
	token, _ := strings.CutPrefix(info.RequestHeader().Get("Authorization"), "PAP ")
	org := tokenOrg(token)
	c, _, err := s.verify(ctx, info)
	if err != nil {
		return org, ids.UUID{}, s.papError(ctx, info, org, err)
	}
	tok, ok := c.Token()
	if !ok {
		return org, ids.UUID{}, s.papError(ctx, info, org, pap.Err(pap.CodeInvalidToken))
	}
	org = tok.Instance.Org
	if err := s.svc.Consume(ctx, org, c); err != nil {
		return org, ids.UUID{}, s.papError(ctx, info, org, err)
	}
	return org, tok.Instance.Instance, nil
}

// WaitInfo maps a wait handle (states, codes and times only, HR-174).
func WaitInfo(v approvals.WaitView) *pantherclawv1.WaitInfo {
	out := &pantherclawv1.WaitInfo{
		Handle: v.Handle.String(), RetryAfterSeconds: int32(v.RetryAfter / time.Second), //nolint:gosec // seconds
		State: pantherclawv1.WaitState(pantherclawv1.WaitState_value["WAIT_STATE_"+v.State]), Code: v.Code,
		ProposedParams: v.ProposedParams,
	}
	if !v.Deadline.IsZero() {
		out.DeadlineTime = timestamppb.New(v.Deadline)
	}
	if v.ConsumeBy != nil {
		out.ConsumeByTime = timestamppb.New(*v.ConsumeBy)
	}
	if v.EvidenceDeadline != nil {
		out.EvidenceDeadlineTime = timestamppb.New(*v.EvidenceDeadline)
	}
	if !v.RequestID.IsZero() {
		out.ApprovalRequestId = v.RequestID.String()
	}
	return out
}

// Wait implements WorkloadServiceHandler: a long poll of at most 30
// seconds on a held transaction of the caller's run (HR-174). Beyond the
// wait limits it answers ResourceExhausted with a Retry-After header.
func (s *Workload) Wait(ctx context.Context, req *pantherclawv1.WaitRequest) (*pantherclawv1.WaitResponse, error) {
	if s.waits == nil {
		return nil, errNoApprovals
	}
	info, err := callInfo(ctx)
	if err != nil {
		return nil, err
	}
	org, inst, err := s.authenticate(ctx, info)
	if err != nil {
		return nil, err
	}
	run, handle, err := runAndHandle(req.GetRunId(), req.GetHandle())
	if err != nil {
		return nil, err
	}
	known := ""
	if req.GetKnownState() != pantherclawv1.WaitState_WAIT_STATE_UNSPECIFIED {
		known = strings.TrimPrefix(req.GetKnownState().String(), "WAIT_STATE_")
	}
	v, timedOut, err := s.waits.Wait(ctx, org, inst, run, handle, known, time.Duration(req.GetTimeoutSeconds())*time.Second)
	if errors.Is(err, approvals.ErrTooManyWaits) {
		info.ResponseHeader().Set("Retry-After", strconv.Itoa(int(approvals.RetryAfter/time.Second)))
	}
	if err != nil {
		return nil, err
	}
	s.setNonce(ctx, info, org)
	return &pantherclawv1.WaitResponse{Wait: WaitInfo(v), TimedOut: timedOut}, nil
}

func runAndHandle(run, handle string) (ids.UUID, ids.UUID, error) {
	r, err := runsrpc.ParseID(run)
	if err != nil {
		return ids.UUID{}, ids.UUID{}, err
	}
	h, err := runsrpc.ParseID(handle)
	return r, h, err
}

// SubmitEvidence implements WorkloadServiceHandler: an UNTRUSTED note on
// the open approval request of a held transaction of the caller's run
// (HR-172). It returns the handle's state after it.
func (s *Workload) SubmitEvidence(ctx context.Context, req *pantherclawv1.SubmitEvidenceRequest) (*pantherclawv1.SubmitEvidenceResponse, error) {
	if s.approvals == nil {
		return nil, errNoApprovals
	}
	info, err := callInfo(ctx)
	if err != nil {
		return nil, err
	}
	org, inst, err := s.authenticate(ctx, info)
	if err != nil {
		return nil, err
	}
	run, handle, err := runAndHandle(req.GetRunId(), req.GetHandle())
	if err != nil {
		return nil, err
	}
	_, evidence, err := s.approvals.SubmitWorkloadEvidence(ctx, org, inst, run, handle, req.GetNote())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.SubmitEvidenceResponse{EvidenceId: evidence.String()}
	if s.waits != nil {
		if v, err := s.waits.Read(ctx, org, inst, run, handle); err == nil {
			out.Wait = WaitInfo(v)
		}
	}
	s.setNonce(ctx, info, org)
	return out, nil
}

// RequestAccess implements WorkloadServiceHandler: an access request for
// the caller's run's grant, citing one of its run's scope denials, at most
// 3 per run (decision 10). It grants nothing.
func (s *Workload) RequestAccess(ctx context.Context, req *pantherclawv1.WorkloadServiceRequestAccessRequest) (*pantherclawv1.WorkloadServiceRequestAccessResponse, error) {
	if s.access == nil {
		return nil, errNoApprovals
	}
	info, err := callInfo(ctx)
	if err != nil {
		return nil, err
	}
	org, inst, err := s.authenticate(ctx, info)
	if err != nil {
		return nil, err
	}
	run, txn, err := runAndHandle(req.GetRunId(), req.GetTransactionId())
	if err != nil {
		return nil, err
	}
	e, err := s.access.RequestWorkloadAccess(ctx, org, inst, run, txn, req.GetNote())
	if err != nil {
		return nil, err
	}
	s.setNonce(ctx, info, org)
	return &pantherclawv1.WorkloadServiceRequestAccessResponse{EntryId: e.ID.String(), DeadlineTime: timestamppb.New(e.DeadlineAt)}, nil
}
