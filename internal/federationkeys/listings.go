// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package federationkeys

import (
	"context"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"regexp"
	"slices"
	"time"

	"github.com/katocxl/pantherclaw/internal/a2a"
	"github.com/katocxl/pantherclaw/internal/a2a/a2astore"
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// CardTTL is how long a signed listing card is served before the gateway
// asks again.
const CardTTL = time.Hour

var listingName = regexp.MustCompile(`^[a-z0-9-]{1,63}$`)

// signedCard is a listing's card as the federation face serves it.
type signedCard struct {
	raw    []byte
	name   string
	digest string
}

// listingCard rewrites the listing's pinned card for the federation face
// (its URL, the listing's skills) and signs it with the org's ACTIVE
// federation key, so a peer verifies it with the keys it pinned (D1023).
func (s *Service) listingCard(ctx context.Context, q *dbq.Queries, org ids.OrgID, l dbq.PcFederationListing, federationURL string) (signedCard, error) {
	pin, err := pinOf(ctx, q, org, l.ConnectionID)
	if err != nil {
		return signedCard{}, err
	}
	if pin.DriftedAt != nil || pin.Config.GetPeerAgentId() != l.AgentID.String() {
		return signedCard{}, ErrListingInvalid
	}
	binding := pin.Config.GetInterface().GetProtocol()
	if binding == "" {
		binding = a2a.BindingJSONRPC
	}
	rewritten, err := a2a.Rewrite(pin.Config.GetPinnedCard(), binding, FaceURL(federationURL, l.Name), l.Skills)
	if err != nil {
		return signedCard{}, err
	}
	kid, key, err := s.keys.FederationCardKey(ctx, org)
	if err != nil {
		return signedCard{}, err
	}
	raw, err := a2a.Sign(rewritten, kid, key)
	if err != nil {
		return signedCard{}, err
	}
	card, err := a2a.ParseCard(raw)
	if err != nil {
		return signedCard{}, err
	}
	d, err := a2a.Digest(raw)
	if err != nil {
		return signedCard{}, err
	}
	return signedCard{raw: raw, name: card.Name, digest: hex.EncodeToString(d[:])}, nil
}

// Listing is a listing with its card URL.
type Listing struct {
	dbq.PcFederationListing
	CardURL string
}

// CreateListing lists one of the org's agents for its peers
// (federation.manage): the connection must be an ACTIVE a2a connection to
// that agent, and the skills the connection's.
func (s *Service) CreateListing(ctx context.Context, name string, agent, conn ids.UUID, skills []string) (Listing, error) {
	c, err := s.person(ctx, td.PermFederationManage)
	if err != nil {
		return Listing{}, err
	}
	if !listingName.MatchString(name) || len(skills) == 0 {
		return Listing{}, ErrListingInvalid
	}
	var out Listing
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		pin, err := pinOf(ctx, q, c.Org, conn)
		if errors.Is(err, a2astore.ErrNotFound) {
			return ErrListingInvalid
		} else if err != nil {
			return err
		}
		if pin.DriftedAt != nil || pin.Config.GetPeerAgentId() != agent.String() {
			return ErrListingInvalid
		}
		allowed := pin.Config.GetSkills()
		if len(allowed) == 0 {
			card, err := a2a.ParseCard(pin.Config.GetPinnedCard())
			if err != nil {
				return ErrListingInvalid
			}
			allowed = card.SkillIDs()
		}
		for _, sk := range skills {
			if !slices.Contains(allowed, sk) {
				return ErrListingInvalid
			}
		}
		l, err := q.InsertFederationListing(ctx, dbq.InsertFederationListingParams{
			OrgID: c.Org, ID: ids.NewV7(), Name: name, AgentID: agent, ConnectionID: conn, Skills: skills,
			CreatedBy: actorString(c.Actor()),
		})
		if db.IsUniqueViolation(err) {
			return ErrListingInvalid
		} else if err != nil {
			return err
		}
		fu, err := s.federationURL(ctx, q, c.Org)
		if err != nil {
			return err
		}
		out = Listing{PcFederationListing: l}
		if fu != "" {
			out.CardURL = CardURL(fu, l.Name)
		}
		return record(ctx, tx, auditkind.FederationListingCreated, c.Actor(), "federation_listing", l.ID.String(),
			map[string]string{"name": name, "agent_id": agent.String(), "connection_id": conn.String()})
	})
	return out, err
}

// RetireListing retires a listing (federation.manage); peers reach it no
// more.
func (s *Service) RetireListing(ctx context.Context, id ids.UUID) (Listing, error) {
	c, err := s.personNarrowing(ctx, td.PermFederationManage)
	if err != nil {
		return Listing{}, err
	}
	var out Listing
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		by := actorString(c.Actor())
		l, err := dbq.New(tx).RetireFederationListing(ctx, &by, c.Org, id)
		if db.IsNoRows(err) {
			return ErrListingUnknown
		} else if err != nil {
			return err
		}
		out = Listing{PcFederationListing: l}
		return record(ctx, tx, auditkind.FederationListingRetired, c.Actor(), "federation_listing", id.String(), map[string]string{"name": l.Name})
	})
	return out, err
}

// ListListings lists the org's listings (federation.read).
func (s *Service) ListListings(ctx context.Context, includeRetired bool) ([]Listing, error) {
	c, err := s.caller(ctx, td.PermFederationRead)
	if err != nil {
		return nil, err
	}
	var out []Listing
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		rows, err := q.ListFederationListings(ctx, c.Org, includeRetired)
		if err != nil {
			return err
		}
		fu, err := s.federationURL(ctx, q, c.Org)
		if err != nil {
			return err
		}
		for _, l := range rows {
			li := Listing{PcFederationListing: l}
			if fu != "" && l.State == "ACTIVE" {
				li.CardURL = CardURL(fu, l.Name)
			}
			out = append(out, li)
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// SignedListingCard is the card the federation face serves.
type SignedListingCard struct {
	Card    []byte
	Digest  string
	Expires time.Time
}

// SignListingCard returns a listing's card for the calling gateway's
// federation face (gateway.authorize): the server rewrites and signs it
// itself, so the gateway chooses nothing (D1023).
func (s *Service) SignListingCard(ctx context.Context, listing string) (SignedListingCard, error) {
	c, err := s.caller(ctx, td.PermGatewayAuthorize)
	if err != nil {
		return SignedListingCard{}, err
	}
	var out SignedListingCard
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		l, err := q.GetActiveFederationListingByName(ctx, c.Org, listing)
		if db.IsNoRows(err) {
			return ErrListingUnknown
		} else if err != nil {
			return err
		}
		fu, err := s.federationURL(ctx, q, c.Org)
		if err != nil {
			return err
		}
		if fu == "" {
			return ErrNoEndpoint
		}
		card, err := s.listingCard(ctx, q, c.Org, l, fu)
		if err != nil {
			return err
		}
		out = SignedListingCard{Card: card.raw, Digest: card.digest, Expires: s.now().Add(CardTTL)}
		return nil
	}, db.ReadOnly())
	return out, err
}

// PeerAgent is one agent a peer lists, as this org sees it.
type PeerAgent struct {
	DocAgent
	Verified bool
	Reason   string
}

// PeerAgents lists the agents in a trust's pinned peer document
// (federation.read). One is verified only when the trust is ACTIVE, the
// document verified with the pinned keys, and the card fetched from its
// URL has the listed digest and a signature by a pinned key.
func (s *Service) PeerAgents(ctx context.Context, trustID ids.UUID) ([]PeerAgent, error) {
	c, err := s.caller(ctx, td.PermFederationRead)
	if err != nil {
		return nil, err
	}
	var t dbq.PcFederationTrust
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		t, err = dbq.New(tx).GetFederationTrust(ctx, c.Org, trustID)
		if db.IsNoRows(err) {
			return ErrTrustNotFound
		}
		return err
	}, db.ReadOnly())
	if err != nil {
		return nil, err
	}
	vd, err := verifyDocument(t.PeerDocument, s.now())
	if err != nil {
		return nil, err
	}
	pinned, err := a2a.ParseKeys(t.PinnedJwks)
	if err != nil {
		return nil, ErrKeyUnverified
	}
	var out []PeerAgent
	for _, a := range vd.Doc.Agents {
		p := PeerAgent{DocAgent: a}
		switch {
		case t.State != "ACTIVE":
			p.Reason = "the trust is " + t.State
		case !slices.ContainsFunc(vd.SignedBy, func(kid string) bool { _, ok := pinned[kid]; return ok }):
			p.Reason = "the document is not signed by a pinned key"
		default:
			p.Verified, p.Reason = s.verifyCard(ctx, a, pinned)
		}
		out = append(out, p)
	}
	return out, nil
}

func (s *Service) verifyCard(ctx context.Context, a DocAgent, pinned a2a.Keys) (bool, string) {
	raw, err := a2a.FetchCard(ctx, s.client, a.CardURL)
	if err != nil {
		return false, "the card could not be fetched"
	}
	d, err := a2a.Digest(raw)
	if err != nil || hex.EncodeToString(d[:]) != a.CardDigest {
		return false, "the card is not the listed one"
	}
	if err := a2a.VerifySignatures(raw, pinned); err != nil {
		return false, "the card is not signed by a pinned key"
	}
	var card struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(raw, &card) != nil {
		return false, "the card is not valid"
	}
	return true, ""
}
