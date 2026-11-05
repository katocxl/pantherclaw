// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package fedface

import (
	"context"
	"crypto/sha256"
	"encoding/json/jsontext"
	"errors"
	"net/http"
	"strings"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// admitCodes are the refusals of StartFederatedCall a peer may see: they
// say what to fix on its side, nothing of our policy (D1025).
var admitCodes = []string{
	"FEDERATION_NOT_TRUSTED", "FEDERATION_PEER_STALE", "FEDERATION_TOKEN_INVALID", "FEDERATION_REPLAY",
	"FEDERATION_LISTING_UNKNOWN", "FEDERATION_EDITION",
}

// call authenticates a peer's call, decides it under our cross-org grants
// and, on an allow, forwards the exact body to the listed agent through
// the listing's a2a connection (G0 M35 D1024, D1024b, D1024c).
func (h *Handler) call(ctx context.Context, c *call) answer {
	scheme, token, _ := strings.Cut(c.r.Header.Get("Authorization"), " ")
	token = strings.TrimSpace(token)
	if !strings.EqualFold(scheme, AuthScheme) || token == "" {
		return answer{err: &faceError{
			status: http.StatusUnauthorized, rpc: codeAuthenticate, reason: "FEDERATION_TOKEN_INVALID",
			message: "a federated call carries Authorization: " + AuthScheme + " <token>",
		}}
	}
	sum := sha256.Sum256(c.body)
	adm, err := h.admit.StartFederatedCall(ctx, &pb.StartFederatedCallRequest{
		Credential: token, BodySha256: sum[:], Htu: h.URL(c.listing), Listing: c.listing,
	})
	if err != nil {
		return h.admitRefused(ctx, err)
	}
	cfg := h.config.Current()
	if cfg == nil {
		return unavailable("the gateway has no configuration yet")
	}
	conn := cfg.ByID[adm.GetConnectionId()]
	if conn == nil {
		// The listing's a2a connection is not served by this gateway.
		return answer{err: &faceError{status: http.StatusNotFound, rpc: wire404, reason: CodeListingUnknown, message: "unknown listing"}}
	}
	// The listing's connection, decided through the built-in pc.federation
	// package: the definitions and mappings are its, the egress the
	// connection's.
	fc := *conn
	fc.Package, fc.Mapper = h.pkg, h.mapper
	parsed, err := h.mapper.Federation(ctx, mapping.Context{
		Org: cfg.Org, Env: adm.GetEnv(), RunID: adm.GetRunId(), ActionID: ids.NewV7().String(),
		AgentInstance: adm.GetInstanceId(), Connection: conn.GetId(),
	}, c.listing, c.method, c.params)
	if err != nil {
		why := "the message does not match what a federated " + c.method + " may carry"
		if errors.Is(err, mapping.ErrUnmapped) {
			why = "this method is not taken through federation"
		}
		return answer{err: &faceError{status: http.StatusBadRequest, rpc: wireInvalidParams, reason: CodeBadRequest, message: why}}
	}
	res := h.engine.Dispatch(dispatch.WithFederationBody(ctx, c.body), dispatch.Call{
		Connection: &fc, Action: parsed, FederationCallID: adm.GetCallId(),
		// The peer agent's trace context, correlation only (G0 M36 D1060).
		Trace: dispatch.ParseTraceContext(c.r.Header.Values(dispatch.HeaderTraceparent), c.r.Header.Values(dispatch.HeaderTracestate)),
	})
	h.log.InfoContext(ctx, "federation.decided", "listing", c.listing, "class", string(res.Class), "code", res.Code,
		"transaction", res.TransactionID)
	// Our minimal signed receipt goes with every answer to a decided call
	// (D1024d, FQ35-2).
	a := h.answerOf(res)
	a.receipt = res.FederationReceipt
	return a
}

// answerOf is the answer for a dispatched federated call.
func (h *Handler) answerOf(res dispatch.Result) answer {
	switch {
	case res.Class == "" && res.Response != nil:
		return answer{result: jsontext.Value(res.Response.Body)}
	case res.Class == dispatch.AuthenticationFailed:
		return answer{err: &faceError{status: http.StatusUnauthorized, rpc: codeAuthenticate, reason: CodeAuthentication, message: "the federated call was not admitted"}}
	case res.Class == dispatch.Held:
		return answer{err: &faceError{status: http.StatusOK, rpc: codeDecided, reason: CodeHeld, message: textHeld}}
	case res.Class == dispatch.PolicyDenied || res.Class == dispatch.CannotAuthorize:
		return answer{err: &faceError{status: http.StatusOK, rpc: codeDecided, reason: CodeRefused, message: textRefused}}
	default:
		// Allowed, but the listed agent did not answer: nothing of why.
		return unavailable("the listed agent did not answer; ask again later")
	}
}

// JSON-RPC codes the face answers.
const (
	wire404           = -32001
	wireInvalidParams = -32602
)

// admitRefused answers a call StartFederatedCall did not admit.
func (h *Handler) admitRefused(ctx context.Context, err error) answer {
	for _, code := range admitCodes {
		if strings.Contains(err.Error(), code) {
			status := http.StatusUnauthorized
			if code == "FEDERATION_LISTING_UNKNOWN" {
				status = http.StatusNotFound
			}
			return answer{err: &faceError{status: status, rpc: codeAuthenticate, reason: code, message: "the federated call was not admitted: " + code}}
		}
	}
	switch connect.CodeOf(err) {
	case connect.CodeUnauthenticated, connect.CodePermissionDenied, connect.CodeInvalidArgument, connect.CodeFailedPrecondition:
		return answer{err: &faceError{status: http.StatusUnauthorized, rpc: codeAuthenticate, reason: CodeAuthentication, message: "the federated call was not admitted"}}
	}
	h.log.ErrorContext(ctx, "gateway.authority_unavailable", pclog.Err(err))
	return unavailable("federation is not available now; ask again later")
}

func unavailable(msg string) answer {
	return answer{err: &faceError{status: http.StatusServiceUnavailable, rpc: codeUnavailable, reason: CodeUnavailable, message: msg}}
}
