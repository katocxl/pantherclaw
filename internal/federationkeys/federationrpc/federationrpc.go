// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package federationrpc serves FederationService over Connect (G0 M35
// D1020–D1025).
package federationrpc

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/federationkeys"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/grants/adapters/grantsrpc"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/keystore"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Handler implements FederationServiceHandler.
type Handler struct{ svc *federationkeys.Service }

// New returns the handler.
func New(svc *federationkeys.Service) *Handler { return &Handler{svc: svc} }

var _ pantherclawv1connect.FederationServiceHandler = (*Handler)(nil)

var errID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "the id must be a UUID")

func parseID(s string) (ids.UUID, error) {
	id, err := ids.ParseUUID(s)
	if err != nil {
		return ids.UUID{}, errID
	}
	return id, nil
}

func ts(t *time.Time) *timestamppb.Timestamp {
	if t == nil || t.IsZero() {
		return nil
	}
	return timestamppb.New(*t)
}

func keyProto(k keystore.FederationKey) *pantherclawv1.FederationKey {
	out := &pantherclawv1.FederationKey{
		Kid: k.KID, State: k.State, PublicKey: base64.RawURLEncoding.EncodeToString(k.Public), CreateTime: timestamppb.New(k.CreatedAt),
	}
	out.RetireTime = ts(&k.RetiresAt)
	return out
}

var trustStates = map[string]pantherclawv1.FederationTrustState{
	federationkeys.StateProposed:       pantherclawv1.FederationTrustState_FEDERATION_TRUST_STATE_PROPOSED,
	federationkeys.StateConfirmedLocal: pantherclawv1.FederationTrustState_FEDERATION_TRUST_STATE_CONFIRMED_LOCAL,
	federationkeys.StateActive:         pantherclawv1.FederationTrustState_FEDERATION_TRUST_STATE_ACTIVE,
	federationkeys.StateStale:          pantherclawv1.FederationTrustState_FEDERATION_TRUST_STATE_STALE,
	federationkeys.StateRevoked:        pantherclawv1.FederationTrustState_FEDERATION_TRUST_STATE_REVOKED,
}

func trustProto(t dbq.PcFederationTrust) *pantherclawv1.FederationTrust {
	out := &pantherclawv1.FederationTrust{
		Id: t.ID.String(), PeerOrgId: t.PeerOrgID.String(), PeerName: t.PeerName, PeerDocUrl: t.PeerDocUrl,
		PeerServerUrl: t.PeerServerUrl, State: trustStates[t.State], SafetyCode: t.SafetyCode,
		PinnedKeysDigest: hex.EncodeToString(t.PinnedKeysDigest), CreateTime: timestamppb.New(t.CreatedAt), CreatedBy: t.CreatedBy,
		ConfirmTime: ts(t.ConfirmedAt), PeerConfirmTime: ts(t.PeerConfirmedAt), LastRefreshTime: ts(t.LastRefreshedAt),
		PeerDocumentExpireTime: ts(&t.PeerDocExpiresAt), RevokeTime: ts(t.RevokedAt),
	}
	if t.PeerFederationUrl != nil {
		out.PeerFederationUrl = *t.PeerFederationUrl
	}
	if t.ConfirmedBy != nil {
		out.ConfirmedBy = "user:" + t.ConfirmedBy.String()
	}
	var set federationkeys.JWKS
	if json.Unmarshal(t.PinnedJwks, &set) == nil {
		for _, k := range set.Keys {
			out.PinnedKids = append(out.PinnedKids, k.Kid)
		}
	}
	return out
}

func listingProto(l federationkeys.Listing) *pantherclawv1.FederationListing {
	return &pantherclawv1.FederationListing{
		Id: l.ID.String(), Name: l.Name, AgentId: l.AgentID.String(), ConnectionId: l.ConnectionID.String(), Skills: l.Skills,
		State: l.State, CreateTime: timestamppb.New(l.CreatedAt), CreatedBy: l.CreatedBy, CardUrl: l.CardURL,
	}
}

// GetFederationDocument implements FederationServiceHandler.
func (h *Handler) GetFederationDocument(ctx context.Context, _ *pantherclawv1.GetFederationDocumentRequest) (*pantherclawv1.GetFederationDocumentResponse, error) {
	d, err := h.svc.Document(ctx)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.GetFederationDocumentResponse{Document: d.Document, DocumentUrl: d.DocumentURL, FederationUrl: d.FederationURL}
	for _, k := range d.Keys {
		out.Keys = append(out.Keys, keyProto(k))
	}
	return out, nil
}

// SetFederationEndpoint implements FederationServiceHandler.
func (h *Handler) SetFederationEndpoint(ctx context.Context, req *pantherclawv1.SetFederationEndpointRequest) (*pantherclawv1.SetFederationEndpointResponse, error) {
	u, err := h.svc.SetEndpoint(ctx, req.GetFederationUrl())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.SetFederationEndpointResponse{FederationUrl: u}, nil
}

// RotateFederationKey implements FederationServiceHandler.
func (h *Handler) RotateFederationKey(ctx context.Context, _ *pantherclawv1.RotateFederationKeyRequest) (*pantherclawv1.RotateFederationKeyResponse, error) {
	k, retiring, err := h.svc.RotateKey(ctx)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RotateFederationKeyResponse{Key: keyProto(k), RetiringKid: retiring}, nil
}

// ProposeFederationTrust implements FederationServiceHandler.
func (h *Handler) ProposeFederationTrust(ctx context.Context, req *pantherclawv1.ProposeFederationTrustRequest) (*pantherclawv1.ProposeFederationTrustResponse, error) {
	t, err := h.svc.Propose(ctx, req.GetPeerDocUrl())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ProposeFederationTrustResponse{Trust: trustProto(t)}, nil
}

// ConfirmFederationTrust implements FederationServiceHandler.
func (h *Handler) ConfirmFederationTrust(ctx context.Context, req *pantherclawv1.ConfirmFederationTrustRequest) (*pantherclawv1.ConfirmFederationTrustResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	t, err := h.svc.Confirm(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ConfirmFederationTrustResponse{Trust: trustProto(t)}, nil
}

// RefreshFederationTrust implements FederationServiceHandler.
func (h *Handler) RefreshFederationTrust(ctx context.Context, req *pantherclawv1.RefreshFederationTrustRequest) (*pantherclawv1.RefreshFederationTrustResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	t, err := h.svc.Refresh(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RefreshFederationTrustResponse{Trust: trustProto(t)}, nil
}

// RevokeFederationTrust implements FederationServiceHandler.
func (h *Handler) RevokeFederationTrust(ctx context.Context, req *pantherclawv1.RevokeFederationTrustRequest) (*pantherclawv1.RevokeFederationTrustResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	t, err := h.svc.Revoke(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RevokeFederationTrustResponse{Trust: trustProto(t)}, nil
}

// ListFederationTrusts implements FederationServiceHandler.
func (h *Handler) ListFederationTrusts(ctx context.Context, req *pantherclawv1.ListFederationTrustsRequest) (*pantherclawv1.ListFederationTrustsResponse, error) {
	ts, err := h.svc.Trusts(ctx, req.GetIncludeRevoked())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListFederationTrustsResponse{}
	for _, t := range ts {
		out.Trusts = append(out.Trusts, trustProto(t))
	}
	return out, nil
}

// GetFederationTrust implements FederationServiceHandler.
func (h *Handler) GetFederationTrust(ctx context.Context, req *pantherclawv1.GetFederationTrustRequest) (*pantherclawv1.GetFederationTrustResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	t, err := h.svc.Trust(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetFederationTrustResponse{Trust: trustProto(t)}, nil
}

// CreateFederationListing implements FederationServiceHandler.
func (h *Handler) CreateFederationListing(ctx context.Context, req *pantherclawv1.CreateFederationListingRequest) (*pantherclawv1.CreateFederationListingResponse, error) {
	agent, err := parseID(req.GetAgentId())
	if err != nil {
		return nil, err
	}
	conn, err := parseID(req.GetConnectionId())
	if err != nil {
		return nil, err
	}
	l, err := h.svc.CreateListing(ctx, req.GetName(), agent, conn, req.GetSkills())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.CreateFederationListingResponse{Listing: listingProto(l)}, nil
}

// RetireFederationListing implements FederationServiceHandler.
func (h *Handler) RetireFederationListing(ctx context.Context, req *pantherclawv1.RetireFederationListingRequest) (*pantherclawv1.RetireFederationListingResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	l, err := h.svc.RetireListing(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RetireFederationListingResponse{Listing: listingProto(l)}, nil
}

// ListFederationListings implements FederationServiceHandler.
func (h *Handler) ListFederationListings(ctx context.Context, req *pantherclawv1.ListFederationListingsRequest) (*pantherclawv1.ListFederationListingsResponse, error) {
	ls, err := h.svc.ListListings(ctx, req.GetIncludeRetired())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListFederationListingsResponse{}
	for _, l := range ls {
		out.Listings = append(out.Listings, listingProto(l))
	}
	return out, nil
}

// ListFederatedPeerAgents implements FederationServiceHandler.
func (h *Handler) ListFederatedPeerAgents(ctx context.Context, req *pantherclawv1.ListFederatedPeerAgentsRequest) (*pantherclawv1.ListFederatedPeerAgentsResponse, error) {
	id, err := parseID(req.GetTrustId())
	if err != nil {
		return nil, err
	}
	as, err := h.svc.PeerAgents(ctx, id)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListFederatedPeerAgentsResponse{}
	for _, a := range as {
		out.Agents = append(out.Agents, &pantherclawv1.FederatedPeerAgent{
			Listing: a.Listing, AgentName: a.AgentName, CardUrl: a.CardURL, CardDigest: a.CardDigest, Verified: a.Verified, Reason: a.Reason,
		})
	}
	return out, nil
}

// IssueCrossOrgGrant implements FederationServiceHandler.
func (h *Handler) IssueCrossOrgGrant(ctx context.Context, req *pantherclawv1.IssueCrossOrgGrantRequest) (*pantherclawv1.IssueCrossOrgGrantResponse, error) {
	trust, err := parseID(req.GetTrustId())
	if err != nil {
		return nil, err
	}
	g, err := h.svc.IssueCrossOrgGrant(ctx, federationkeys.CrossOrgGrantRequest{
		TrustID: trust, PeerAgent: req.GetPeerAgent(), Listing: req.GetListing(), Operations: req.GetOperations(),
		Limits: req.GetLimits(), MinAttestation: int(req.GetMinAttestationLevel()), ExpiresAt: req.GetExpireTime().AsTime(),
	})
	if err != nil {
		return nil, err
	}
	pg, err := grantsrpc.GrantProto(g)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.IssueCrossOrgGrantResponse{Grant: pg}, nil
}

// RevokeCrossOrgGrant implements FederationServiceHandler.
func (h *Handler) RevokeCrossOrgGrant(ctx context.Context, req *pantherclawv1.RevokeCrossOrgGrantRequest) (*pantherclawv1.RevokeCrossOrgGrantResponse, error) {
	id, err := gdomain.ParseGrantID(req.GetGrantId())
	if err != nil {
		return nil, errID
	}
	if err := h.svc.RevokeCrossOrgGrant(ctx, id, req.GetReason()); err != nil {
		return nil, err
	}
	return &pantherclawv1.RevokeCrossOrgGrantResponse{}, nil
}

// ListFederationReceipts implements FederationServiceHandler.
func (h *Handler) ListFederationReceipts(ctx context.Context, req *pantherclawv1.ListFederationReceiptsRequest) (*pantherclawv1.ListFederationReceiptsResponse, error) {
	var trust, action *ids.UUID
	if s := req.GetTrustId(); s != "" {
		id, err := parseID(s)
		if err != nil {
			return nil, err
		}
		trust = &id
	}
	if s := req.GetActionId(); s != "" {
		id, err := parseID(s)
		if err != nil {
			return nil, err
		}
		action = &id
	}
	p, err := h.svc.Receipts(ctx, trust, action, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListFederationReceiptsResponse{NextPageToken: p.Next}
	for _, r := range p.Receipts {
		pr := &pantherclawv1.FederationReceipt{
			Id: r.ID.String(), Direction: r.Direction, TrustId: r.TrustID.String(), PeerOrgId: r.PeerOrgID.String(),
			State: r.State, ReceiveTime: timestamppb.New(r.ReceivedAt),
		}
		if r.ActionID != nil {
			pr.ActionId = r.ActionID.String()
		}
		if r.PeerActionID != nil {
			pr.PeerActionId = *r.PeerActionID
		}
		if r.Decision != nil {
			pr.Decision = *r.Decision
		}
		if r.ReceiptJws != nil {
			pr.ReceiptJws = *r.ReceiptJws
		}
		out.Receipts = append(out.Receipts, pr)
	}
	return out, nil
}

// SignListingCard implements FederationServiceHandler.
func (h *Handler) SignListingCard(ctx context.Context, req *pantherclawv1.SignListingCardRequest) (*pantherclawv1.SignListingCardResponse, error) {
	c, err := h.svc.SignListingCard(ctx, req.GetListing())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.SignListingCardResponse{Card: c.Card, CardDigest: c.Digest, ExpireTime: timestamppb.New(c.Expires)}, nil
}
