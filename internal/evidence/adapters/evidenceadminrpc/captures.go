// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package evidenceadminrpc

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/evidence/capture"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

var profileStates = map[string]pantherclawv1.CaptureProfileState{
	capture.StateActive:   pantherclawv1.CaptureProfileState_CAPTURE_PROFILE_STATE_ACTIVE,
	capture.StateDisabled: pantherclawv1.CaptureProfileState_CAPTURE_PROFILE_STATE_DISABLED,
	capture.StateExpired:  pantherclawv1.CaptureProfileState_CAPTURE_PROFILE_STATE_EXPIRED,
}

var captureDirections = map[capture.Direction]pantherclawv1.CaptureDirection{
	capture.Request:  pantherclawv1.CaptureDirection_CAPTURE_DIRECTION_REQUEST,
	capture.Response: pantherclawv1.CaptureDirection_CAPTURE_DIRECTION_RESPONSE,
}

func profileProto(p capture.Profile) *pantherclawv1.CaptureProfile {
	out := &pantherclawv1.CaptureProfile{
		Id: p.ID.String(), Purpose: p.Purpose, Operations: p.Operations, CaptureRequest: p.CaptureRequest,
		CaptureResponse: p.CaptureResponse, ByteCap: p.ByteCap, RetentionDays: p.RetentionDays, ExpireTime: ts(p.ExpiresAt),
		State: profileStates[p.EffectiveState], CreatedBy: p.CreatedBy.String(), CreateTime: ts(p.CreatedAt),
		DisabledBy: idString(p.DisabledBy), DisableTime: tsp(p.DisabledAt),
	}
	for _, c := range p.Connections {
		out.ConnectionIds = append(out.ConnectionIds, c.String())
	}
	return out
}

// CreateCaptureProfile implements EvidenceAdminServiceHandler.
func (a *Admin) CreateCaptureProfile(ctx context.Context, req *pantherclawv1.CreateCaptureProfileRequest) (*pantherclawv1.CreateCaptureProfileResponse, error) {
	r := capture.ProfileRequest{
		Purpose: req.GetPurpose(), Operations: req.GetOperations(), Request: req.GetCaptureRequest(), Response: req.GetCaptureResponse(),
		ByteCap: int(req.GetByteCap()), RetentionDays: int(req.GetRetentionDays()), ExpiresInDays: int(req.GetExpiresInDays()),
	}
	for _, s := range req.GetConnectionIds() {
		id, err := ids.ParseUUID(s)
		if err != nil {
			return nil, errInvalidID
		}
		r.Connections = append(r.Connections, id)
	}
	p, err := a.capture.CreateProfile(ctx, r)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.CreateCaptureProfileResponse{Profile: profileProto(p)}, nil
}

// ListCaptureProfiles implements EvidenceAdminServiceHandler.
func (a *Admin) ListCaptureProfiles(ctx context.Context, req *pantherclawv1.ListCaptureProfilesRequest) (*pantherclawv1.ListCaptureProfilesResponse, error) {
	state := ""
	for k, v := range profileStates {
		if v == req.GetState() {
			state = k
		}
	}
	p, err := a.capture.ListProfiles(ctx, state, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListCaptureProfilesResponse{NextPageToken: p.Next}
	for _, x := range p.Items {
		out.Profiles = append(out.Profiles, profileProto(x))
	}
	return out, nil
}

// DisableCaptureProfile implements EvidenceAdminServiceHandler.
func (a *Admin) DisableCaptureProfile(ctx context.Context, req *pantherclawv1.DisableCaptureProfileRequest) (*pantherclawv1.DisableCaptureProfileResponse, error) {
	id, err := ids.ParseUUID(req.GetId())
	if err != nil {
		return nil, errInvalidID
	}
	p, err := a.capture.DisableProfile(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.DisableCaptureProfileResponse{Profile: profileProto(p)}, nil
}

// ReadPayloadCapture implements EvidenceAdminServiceHandler. The read is
// audited before the content leaves the use case.
func (a *Admin) ReadPayloadCapture(ctx context.Context, req *pantherclawv1.ReadPayloadCaptureRequest) (*pantherclawv1.ReadPayloadCaptureResponse, error) {
	txn, err := ids.ParseUUID(req.GetTransactionId())
	if err != nil {
		return nil, errInvalidID
	}
	var dir capture.Direction
	for k, v := range captureDirections {
		if v == req.GetDirection() {
			dir = k
		}
	}
	r, err := a.capture.ReadCapture(ctx, txn, dir, req.GetReason())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ReadPayloadCaptureResponse{
		Id: r.ID.String(), TransactionId: r.Transaction.String(), ProfileId: r.Profile.String(), Direction: captureDirections[r.Direction],
		Size: int64(r.Size), Truncated: r.Truncated, CreateTime: ts(r.Created), RemoveTime: ts(r.RemoveAt), Content: r.Content,
	}, nil
}
