// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package workloadrpc

import (
	"context"
	"strings"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
)

// KubernetesPrefix is the URL path prefix of KubernetesService procedures,
// which RawBody covers like WorkloadService's (PAP/1 proofs sign the body;
// G0 M32 D970).
const KubernetesPrefix = "/" + pantherclawv1connect.KubernetesServiceName + "/"

// Authenticate checks a call's PAP/1 token and proof exactly like
// WorkloadService and consumes the proof, for another service an enrolled
// instance calls (KubernetesService, G0 M32 D970). It returns the
// instance, and sets a fresh PAP-Nonce on a failure.
func (s *Workload) Authenticate(ctx context.Context) (pap.Instance, error) {
	info, err := callInfo(ctx)
	if err != nil {
		return pap.Instance{}, err
	}
	token, _ := strings.CutPrefix(info.RequestHeader().Get("Authorization"), "PAP ")
	org := tokenOrg(token)
	c, _, err := s.verify(ctx, info)
	if err != nil {
		return pap.Instance{}, s.papError(ctx, info, org, err)
	}
	tok, ok := c.Token()
	if !ok {
		return pap.Instance{}, s.papError(ctx, info, org, pap.Err(pap.CodeInvalidToken))
	}
	if err := s.svc.Consume(ctx, tok.Instance.Org, c); err != nil {
		return pap.Instance{}, s.papError(ctx, info, tok.Instance.Org, err)
	}
	return tok.Instance, nil
}

// SetNonce sets a fresh PAP-Nonce on a successful call's response.
func (s *Workload) SetNonce(ctx context.Context, in pap.Instance) {
	if info, err := callInfo(ctx); err == nil {
		s.setNonce(ctx, info, in.Org)
	}
}
