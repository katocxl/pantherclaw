// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gatewaysrpc

import (
	"context"

	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
)

// errNoSecurityKeys answers ListApproverKeys on a server without security
// keys (no WebAuthn relying party): there is nothing a gateway could pin.
var errNoSecurityKeys = pcerr.New(pcerr.FailedPrecondition, "SECURITY_KEYS_OFF", "this server has no security keys configured")

// WithRPID sets the WebAuthn relying party id ListApproverKeys reports,
// and returns h. Without one, ListApproverKeys is refused.
func (h *AdminHandler) WithRPID(rpID string) *AdminHandler {
	h.rpID = rpID
	return h
}

// ListApproverKeys implements GatewayAdminServiceHandler (HR-038).
func (h *AdminHandler) ListApproverKeys(ctx context.Context, req *pantherclawv1.ListApproverKeysRequest) (*pantherclawv1.ListApproverKeysResponse, error) {
	keys, org, next, err := h.s.ListApproverKeys(ctx, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	if h.rpID == "" {
		return nil, errNoSecurityKeys
	}
	out := &pantherclawv1.ListApproverKeysResponse{OrgId: org.String(), RpId: h.rpID, NextPageToken: next}
	for _, k := range keys {
		out.Keys = append(out.Keys, &pantherclawv1.ApproverKey{
			Id: k.ID.String(), UserId: k.User.String(), UserEmail: k.Email, UserDisplayName: k.DisplayName, Name: k.Name,
			CredentialId: k.CredentialID, Algorithm: int32(k.Algorithm), PublicKey: k.PublicKey, Fingerprint: k.Fingerprint, //nolint:gosec // a COSE id
			CreateTime: timestamppb.New(k.CreatedAt),
		})
	}
	return out, nil
}
