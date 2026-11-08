// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package federationkeys

import (
	"context"
	"encoding/base64"
	"strconv"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	gapp "github.com/katocxl/pantherclaw/internal/grants/app"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// ExecutionContextFederation is a federated agent's execution context.
const ExecutionContextFederation = "federation"

// TargetTypeListing is the target type of a pc.federation action.
const TargetTypeListing = "federation_listing"

// CrossOrgGrantRequest asks for a cross-org grant.
type CrossOrgGrantRequest struct {
	TrustID        ids.UUID
	PeerAgent      string
	Listing        string
	Operations     []string
	Limits         []byte
	MinAttestation int
	ExpiresAt      time.Time
}

// IssueCrossOrgGrant grants a peer org's agent the listed operations on
// one listing (grant.issue and federation.read; D1024c). It ensures the
// peer agent's federated agent in this org, with one ADMITTED instance
// that has no key, on the listed agent's team and environment, owned by the
// first person who issues to it; the grant represents the federated
// principal (peer org, peer agent).
func (s *Service) IssueCrossOrgGrant(ctx context.Context, req CrossOrgGrantRequest) (gdomain.Grant, error) {
	c, err := s.person(ctx, td.PermFederationRead)
	if err != nil {
		return gdomain.Grant{}, err
	}
	now := s.now()
	if req.ExpiresAt.IsZero() || !req.ExpiresAt.After(now) || req.ExpiresAt.Sub(now) > MaxGrantTTL {
		return gdomain.Grant{}, ErrGrantInvalid
	}
	var (
		trust dbq.PcFederationTrust
		fa    dbq.GetFederationAgentRow
	)
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		var err error
		trust, err = q.GetFederationTrust(ctx, c.Org, req.TrustID)
		if db.IsNoRows(err) {
			return ErrTrustNotFound
		} else if err != nil {
			return err
		}
		if trust.State != StateActive {
			return ErrNotTrusted
		}
		if !strings.HasPrefix(req.PeerAgent, orgSubject(trust.PeerOrgID)+"/agent/") {
			return ErrGrantInvalid
		}
		l, err := q.GetActiveFederationListingByName(ctx, c.Org, req.Listing)
		if db.IsNoRows(err) {
			return ErrListingUnknown
		} else if err != nil {
			return err
		}
		fa, err = q.GetFederationAgent(ctx, c.Org, trust.ID, req.PeerAgent)
		if err == nil {
			return nil
		} else if !db.IsNoRows(err) {
			return err
		}
		listed, err := q.GetAgent(ctx, c.Org, l.AgentID)
		if err != nil {
			return err
		}
		agent, inst, user := ids.NewV7(), ids.NewV7(), c.Principal.ID
		ec, by := ExecutionContextFederation, actorString(c.Actor())
		if _, err := q.InsertAgent(ctx, dbq.InsertAgentParams{
			OrgID: c.Org, ID: agent, Name: federatedName(trust.PeerName, req.PeerAgent),
			Purpose: "A peer organization's agent, reaching listed agents through federation",
			TeamID:  listed.TeamID, EnvironmentID: listed.EnvironmentID, OwnerUserID: &user, ExecutionContext: &ec, CreatedBy: by,
		}); err != nil {
			return err
		}
		if err := q.InsertFederatedInstance(ctx, dbq.InsertFederatedInstanceParams{
			OrgID: c.Org, ID: inst, AgentID: agent, Jkt: syntheticJKT(trust.ID, req.PeerAgent), DecidedBy: &by,
		}); err != nil {
			return err
		}
		if err := q.InsertFederationAgent(ctx, dbq.InsertFederationAgentParams{
			OrgID: c.Org, TrustID: trust.ID, PeerAgent: req.PeerAgent, AgentID: agent, InstanceID: inst, CreatedBy: by,
		}); err != nil {
			return err
		}
		fa, err = q.GetFederationAgent(ctx, c.Org, trust.ID, req.PeerAgent)
		return err
	})
	if err != nil {
		return gdomain.Grant{}, err
	}
	targets := map[string]gdomain.Match{TargetTypeListing: {IDs: []string{req.Listing}}}
	ops := gdomain.Ops(req.Operations)
	var limits gdomain.Limits
	if len(req.Limits) > 0 {
		if limits, err = gdomain.DecodeLimits(req.Limits); err != nil {
			return gdomain.Grant{}, ErrGrantInvalid
		}
	}
	g, err := s.grants.Issue(ctx, gapp.IssueRequest{
		AgentID: fa.AgentID, InstanceID: fa.InstanceID,
		Principal: gdomain.Principal{Kind: gdomain.PrincipalFederated, ID: trust.PeerOrgID, Peer: req.PeerAgent},
		TaskRef:   "federation:" + req.Listing, ExpiresAt: req.ExpiresAt,
		Bounds: gdomain.Bounds{Operations: &ops, Targets: &targets},
		Limits: limits, MinAttestation: req.MinAttestation,
	})
	if err != nil {
		return gdomain.Grant{}, err
	}
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		return record(ctx, tx, auditkind.FederationGrantIssued, c.Actor(), "grant", g.ID.String(), map[string]string{
			"trust_id": trust.ID.String(), "peer_org_id": trust.PeerOrgID.String(), "peer_agent": req.PeerAgent, "listing": req.Listing,
		})
	})
	return g, err
}

// federatedName is a federated agent's name, <peer org name>/<peer agent>
// (D1024c); the peer document names no agent but by id, so the peer
// agent is its id.
func federatedName(peerName, peerAgent string) string {
	a := agentPart(peerAgent)
	name := peerName + "/" + a[strings.LastIndex(a, "/")+1:]
	if len(name) > 200 {
		name = name[len(name)-200:]
	}
	return name
}

// RevokeCrossOrgGrant revokes a cross-org grant (grant.revoke); any other
// grant is not found here.
func (s *Service) RevokeCrossOrgGrant(ctx context.Context, id gdomain.GrantID, reason string) error {
	c, err := s.caller(ctx, td.PermFederationRead)
	if err != nil && err != ErrEdition { //nolint:errorlint // sentinel; revoking only narrows
		return err
	}
	if !c.Human() {
		return ErrPersonOnly
	}
	v, err := s.grants.Get(ctx, id)
	if err != nil {
		return err
	}
	if v.Grant.Principal.Kind != gdomain.PrincipalFederated {
		return gapp.ErrGrantNotFound
	}
	if _, err := s.grants.Revoke(ctx, id, reason); err != nil {
		return err
	}
	return s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		return record(ctx, tx, auditkind.FederationGrantRevoked, c.Actor(), "grant", id.String(), map[string]string{
			"peer_org_id": v.Grant.Principal.ID.String(), "peer_agent": v.Grant.Principal.Peer,
		})
	})
}

// ReceiptPage is one page of receipts.
type ReceiptPage struct {
	Receipts []dbq.PcFederationReceipt
	Next     string
}

// Receipts lists federation receipts, newest first (federation.read).
func (s *Service) Receipts(ctx context.Context, trust, action *ids.UUID, size int32, token string) (ReceiptPage, error) {
	c, err := s.caller(ctx, td.PermFederationRead)
	if err != nil && err != ErrEdition { //nolint:errorlint // sentinel; reading stays allowed
		return ReceiptPage{}, err
	}
	if size <= 0 || size > 200 {
		size = 50
	}
	p := dbq.ListFederationReceiptsParams{OrgID: c.Org, TrustID: trust, ActionID: action, RowLimit: size}
	if token != "" {
		at, id, ok := parsePageToken(token)
		if !ok {
			return ReceiptPage{}, ErrGrantInvalid
		}
		p.BeforeAt, p.BeforeID = &at, &id
	}
	var out ReceiptPage
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		out.Receipts, err = dbq.New(tx).ListFederationReceipts(ctx, p)
		return err
	}, db.ReadOnly())
	if err == nil && int32(len(out.Receipts)) == size { //nolint:gosec // ≤ 200
		last := out.Receipts[len(out.Receipts)-1]
		out.Next = base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(last.ReceivedAt.UnixNano(), 10) + "|" + last.ID.String()))
	}
	return out, err
}

func parsePageToken(tok string) (time.Time, ids.UUID, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		return time.Time{}, ids.UUID{}, false
	}
	ns, idStr, ok := strings.Cut(string(raw), "|")
	if !ok {
		return time.Time{}, ids.UUID{}, false
	}
	n, err := strconv.ParseInt(ns, 10, 64)
	if err != nil {
		return time.Time{}, ids.UUID{}, false
	}
	id, err := ids.ParseUUID(idStr)
	return time.Unix(0, n), id, err == nil
}
