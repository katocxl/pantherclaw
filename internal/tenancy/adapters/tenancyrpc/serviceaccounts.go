// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package tenancyrpc

import (
	"context"
	"net/netip"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/assertion"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// ServiceAccounts serves ServiceAccountService.
type ServiceAccounts struct {
	pantherclawv1connect.UnimplementedServiceAccountServiceHandler
	s *app.ServiceAccounts
}

// NewServiceAccounts returns the ServiceAccountService handler.
func NewServiceAccounts(s *app.ServiceAccounts) *ServiceAccounts { return &ServiceAccounts{s: s} }

var keyAlgFromProto = map[pantherclawv1.KeyAlgorithm]assertion.Alg{
	pantherclawv1.KeyAlgorithm_KEY_ALGORITHM_EDDSA: assertion.EdDSA,
	pantherclawv1.KeyAlgorithm_KEY_ALGORITHM_ES256: assertion.ES256,
}

var keyAlgToProto = map[assertion.Alg]pantherclawv1.KeyAlgorithm{
	assertion.EdDSA: pantherclawv1.KeyAlgorithm_KEY_ALGORITHM_EDDSA,
	assertion.ES256: pantherclawv1.KeyAlgorithm_KEY_ALGORITHM_ES256,
}

var credentialState = map[app.CredentialState]pantherclawv1.CredentialState{
	app.CredentialActive:  pantherclawv1.CredentialState_CREDENTIAL_STATE_ACTIVE,
	app.CredentialRevoked: pantherclawv1.CredentialState_CREDENTIAL_STATE_REVOKED,
	app.CredentialExpired: pantherclawv1.CredentialState_CREDENTIAL_STATE_EXPIRED,
}

func serviceAccountProto(s app.ServiceAccount) *pantherclawv1.ServiceAccount {
	return &pantherclawv1.ServiceAccount{
		Id: s.ID.String(), Name: s.Name, Description: s.Description, State: accountState[s.State], ClientId: s.ClientID,
		CreatedBy: s.CreatedBy, CreateTime: ts(s.CreatedAt), UpdateTime: ts(s.UpdatedAt),
	}
}

func keyProto(k app.ServiceAccountKey) *pantherclawv1.ServiceAccountKey {
	return &pantherclawv1.ServiceAccountKey{
		Id: k.ID.String(), ServiceAccountId: k.ServiceAccount.String(), Kid: k.KID, Algorithm: keyAlgToProto[k.Alg],
		PublicJwk: k.PublicJWK, State: credentialState[k.State], CreatedBy: k.CreatedBy, CreateTime: ts(k.CreatedAt),
		ExpireTime: ts(k.ExpiresAt), RevokeTime: tsp(k.RevokedAt),
	}
}

func apiKeyProto(k app.APIKey) *pantherclawv1.ApiKey {
	out := &pantherclawv1.ApiKey{
		Id: k.ID.String(), ServiceAccountId: k.ServiceAccount.String(), Name: k.Name, Hint: k.Hint,
		State: credentialState[k.State], CreatedBy: k.CreatedBy, CreateTime: ts(k.CreatedAt), ExpireTime: ts(k.ExpiresAt),
		RevokeTime: tsp(k.RevokedAt), LastUseTime: tsp(k.LastUsed),
	}
	for _, s := range k.Scopes {
		out.Scopes = append(out.Scopes, string(s))
	}
	for _, p := range k.AllowedCIDRs {
		out.AllowedCidrs = append(out.AllowedCidrs, p.String())
	}
	return out
}

// CreateServiceAccount implements ServiceAccountServiceHandler.
func (h *ServiceAccounts) CreateServiceAccount(ctx context.Context, req *pantherclawv1.CreateServiceAccountRequest) (*pantherclawv1.CreateServiceAccountResponse, error) {
	sa, err := h.s.Create(ctx, req.GetName(), req.GetDescription())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.CreateServiceAccountResponse{ServiceAccount: serviceAccountProto(sa)}, nil
}

// GetServiceAccount implements ServiceAccountServiceHandler.
func (h *ServiceAccounts) GetServiceAccount(ctx context.Context, req *pantherclawv1.GetServiceAccountRequest) (*pantherclawv1.GetServiceAccountResponse, error) {
	id, err := parseID[td.ServiceAccount](req.GetId())
	if err != nil {
		return nil, err
	}
	sa, err := h.s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetServiceAccountResponse{ServiceAccount: serviceAccountProto(sa)}, nil
}

// ListServiceAccounts implements ServiceAccountServiceHandler.
func (h *ServiceAccounts) ListServiceAccounts(ctx context.Context, req *pantherclawv1.ListServiceAccountsRequest) (*pantherclawv1.ListServiceAccountsResponse, error) {
	pr, err := pageOf(req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	p, err := h.s.List(ctx, pr)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListServiceAccountsResponse{NextPageToken: p.Next}
	for _, sa := range p.Items {
		out.ServiceAccounts = append(out.ServiceAccounts, serviceAccountProto(sa))
	}
	return out, nil
}

// UpdateServiceAccount implements ServiceAccountServiceHandler.
func (h *ServiceAccounts) UpdateServiceAccount(ctx context.Context, req *pantherclawv1.UpdateServiceAccountRequest) (*pantherclawv1.UpdateServiceAccountResponse, error) {
	id, err := parseID[td.ServiceAccount](req.GetId())
	if err != nil {
		return nil, err
	}
	sa, err := h.s.Update(ctx, id, req.Description)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.UpdateServiceAccountResponse{ServiceAccount: serviceAccountProto(sa)}, nil
}

// SetServiceAccountState implements ServiceAccountServiceHandler.
func (h *ServiceAccounts) SetServiceAccountState(ctx context.Context, req *pantherclawv1.SetServiceAccountStateRequest) (*pantherclawv1.SetServiceAccountStateResponse, error) {
	id, err := parseID[td.ServiceAccount](req.GetId())
	if err != nil {
		return nil, err
	}
	sa, err := h.s.SetState(ctx, id, accountStateFromProto[req.GetState()])
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.SetServiceAccountStateResponse{ServiceAccount: serviceAccountProto(sa)}, nil
}

// AddServiceAccountKey implements ServiceAccountServiceHandler.
func (h *ServiceAccounts) AddServiceAccountKey(ctx context.Context, req *pantherclawv1.AddServiceAccountKeyRequest) (*pantherclawv1.AddServiceAccountKeyResponse, error) {
	id, err := parseID[td.ServiceAccount](req.GetServiceAccountId())
	if err != nil {
		return nil, err
	}
	k, err := h.s.AddKey(ctx, id, keyAlgFromProto[req.GetAlgorithm()], req.GetPublicJwk(), time.Duration(req.GetTtlDays())*24*time.Hour)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.AddServiceAccountKeyResponse{Key: keyProto(k)}, nil
}

// ListServiceAccountKeys implements ServiceAccountServiceHandler.
func (h *ServiceAccounts) ListServiceAccountKeys(ctx context.Context, req *pantherclawv1.ListServiceAccountKeysRequest) (*pantherclawv1.ListServiceAccountKeysResponse, error) {
	id, err := parseID[td.ServiceAccount](req.GetServiceAccountId())
	if err != nil {
		return nil, err
	}
	pr, err := pageOf(req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	p, err := h.s.ListKeys(ctx, id, pr)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListServiceAccountKeysResponse{NextPageToken: p.Next}
	for _, k := range p.Items {
		out.Keys = append(out.Keys, keyProto(k))
	}
	return out, nil
}

// RevokeServiceAccountKey implements ServiceAccountServiceHandler.
func (h *ServiceAccounts) RevokeServiceAccountKey(ctx context.Context, req *pantherclawv1.RevokeServiceAccountKeyRequest) (*pantherclawv1.RevokeServiceAccountKeyResponse, error) {
	id, err := parseID[td.ServiceAccount](req.GetServiceAccountId())
	if err != nil {
		return nil, err
	}
	key, err := parseID[anyID](req.GetKeyId())
	if err != nil {
		return nil, err
	}
	k, err := h.s.RevokeKey(ctx, id, key.UUID())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RevokeServiceAccountKeyResponse{Key: keyProto(k)}, nil
}

// CreateApiKey implements ServiceAccountServiceHandler.
func (h *ServiceAccounts) CreateApiKey(ctx context.Context, req *pantherclawv1.CreateApiKeyRequest) (*pantherclawv1.CreateApiKeyResponse, error) {
	id, err := parseID[td.ServiceAccount](req.GetServiceAccountId())
	if err != nil {
		return nil, err
	}
	scopes := make([]td.Permission, len(req.GetScopes()))
	for i, s := range req.GetScopes() {
		scopes[i] = td.Permission(s)
	}
	cidrs := make([]netip.Prefix, len(req.GetAllowedCidrs()))
	for i, s := range req.GetAllowedCidrs() {
		if cidrs[i], err = netip.ParsePrefix(s); err != nil {
			return nil, app.ErrInvalidCIDRs
		}
	}
	k, tok, err := h.s.CreateLimitedAPIKey(ctx, id, req.GetName(), scopes, time.Duration(req.GetTtlDays())*24*time.Hour, cidrs)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.CreateApiKeyResponse{ApiKey: apiKeyProto(k), Secret: tok.Reveal()}, nil
}

// ListApiKeys implements ServiceAccountServiceHandler.
func (h *ServiceAccounts) ListApiKeys(ctx context.Context, req *pantherclawv1.ListApiKeysRequest) (*pantherclawv1.ListApiKeysResponse, error) {
	id, err := parseOptID[td.ServiceAccount](req.GetServiceAccountId())
	if err != nil {
		return nil, err
	}
	pr, err := pageOf(req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	p, err := h.s.ListAPIKeys(ctx, id, pr)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListApiKeysResponse{NextPageToken: p.Next}
	for _, k := range p.Items {
		out.ApiKeys = append(out.ApiKeys, apiKeyProto(k))
	}
	return out, nil
}

// RevokeApiKey implements ServiceAccountServiceHandler.
func (h *ServiceAccounts) RevokeApiKey(ctx context.Context, req *pantherclawv1.RevokeApiKeyRequest) (*pantherclawv1.RevokeApiKeyResponse, error) {
	id, err := parseID[anyID](req.GetId())
	if err != nil {
		return nil, err
	}
	k, err := h.s.RevokeAPIKey(ctx, id.UUID())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RevokeApiKeyResponse{ApiKey: apiKeyProto(k)}, nil
}
