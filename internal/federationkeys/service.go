// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package federationkeys

import (
	"context"
	"encoding/json/v2"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/a2a/a2astore"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	gapp "github.com/katocxl/pantherclaw/internal/grants/app"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// StepUpWithin is how fresh a person's step-up must be to rotate a key or
// confirm a trust.
const StepUpWithin = 5 * time.Minute

// systemActor is the actor of what the server does on its own: peer
// messages and the daily refresh.
var systemActor = evdomain.Actor{Type: "system", ID: "federation"}

// Editions says an org's edition (entitlements.Service).
type Editions interface {
	For(ctx context.Context, org ids.OrgID) (billing.Entitlements, error)
}

// Config configures the Service.
type Config struct {
	Pool *db.Pool
	Keys *keystore.FederationKeys
	// Grants issues and revokes the cross-org grants.
	Grants *gapp.Service
	// Editions gates federation to the Enterprise edition; nil refuses.
	Editions Editions
	// ServerURL is this server's public URL (the document's server_url).
	ServerURL string
	// Client fetches peer documents and cards and posts peer messages;
	// nil is an outbound HTTPS egress client.
	Client *http.Client
	Logger *slog.Logger
}

// Service is the federation service.
type Service struct {
	pool      *db.Pool
	keys      *keystore.FederationKeys
	grants    *gapp.Service
	editions  Editions
	serverURL string
	client    *http.Client
	log       *slog.Logger
	now       func() time.Time
}

// New returns the service.
func New(cfg Config) *Service {
	client := cfg.Client
	if client == nil {
		client = httpx.NewEgressClient(httpx.EgressConfig{Timeout: 10 * time.Second})
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Service{
		pool: cfg.Pool, keys: cfg.Keys, grants: cfg.Grants, editions: cfg.Editions,
		serverURL: strings.TrimSuffix(cfg.ServerURL, "/"), client: client, log: log, now: time.Now,
	}
}

// enterprise refuses an org without the Enterprise edition (fail closed).
func (s *Service) enterprise(ctx context.Context, org ids.OrgID) error {
	if s.editions == nil {
		return ErrEdition
	}
	e, err := s.editions.For(ctx, org)
	if err != nil {
		return err
	}
	if e.Edition != billing.Enterprise {
		return ErrEdition
	}
	return nil
}

// caller returns the caller holding perm, in an Enterprise org.
func (s *Service) caller(ctx context.Context, perm td.Permission) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	if err := c.Require(perm, td.OrgPath(c.Org)); err != nil {
		return c, err
	}
	return c, s.enterprise(ctx, c.Org)
}

// person is caller for a person only.
func (s *Service) person(ctx context.Context, perm td.Permission) (tenancy.Caller, error) {
	c, err := s.caller(ctx, perm)
	if err != nil {
		return c, err
	}
	if !c.Human() {
		return c, ErrPersonOnly
	}
	return c, nil
}

// personNarrowing is person for a change that only narrows: a lapsed org
// can still make it.
func (s *Service) personNarrowing(ctx context.Context, perm td.Permission) (tenancy.Caller, error) {
	c, err := s.caller(ctx, perm)
	if errors.Is(err, ErrEdition) {
		err = nil
	}
	if err != nil {
		return c, err
	}
	if !c.Human() {
		return c, ErrPersonOnly
	}
	return c, nil
}

// stepUp checks, in tx, that c's browser session stepped up within
// StepUpWithin; it returns the security key used.
func stepUp(ctx context.Context, tx db.TenantTx, c tenancy.Caller) (ids.UUID, error) {
	if !c.Human() || c.Credential != tenancy.CredBrowserSession || c.Session.IsZero() {
		return ids.UUID{}, ErrStepUp
	}
	su, err := dbq.New(tx).SessionStepUp(ctx, c.Org, c.Session, c.Principal.ID)
	if db.IsNoRows(err) {
		return ids.UUID{}, ErrStepUp
	} else if err != nil {
		return ids.UUID{}, err
	}
	if su.DbNow.Sub(su.StepUpAt) > StepUpWithin || su.StepUpAt.After(su.DbNow.Add(time.Minute)) {
		return ids.UUID{}, ErrStepUp
	}
	return su.CredentialID, nil
}

func actorString(a evdomain.Actor) string { return a.Type + ":" + a.ID }

func record(ctx context.Context, tx db.TenantTx, name string, actor evdomain.Actor, objType, objID string, details map[string]string) error {
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: actor, Outcome: audit.Success, Object: &audit.Object{Type: objType, ID: objID}, Details: details,
	})
	return err
}

// Settings is the org's federation face URL.
func (s *Service) federationURL(ctx context.Context, q *dbq.Queries, org ids.OrgID) (string, error) {
	st, err := q.GetFederationSettings(ctx, org)
	if db.IsNoRows(err) {
		return "", nil
	}
	return st.FederationUrl, err
}

// SetEndpoint stores the org's federation face URL (federation.manage).
func (s *Service) SetEndpoint(ctx context.Context, url string) (string, error) {
	c, err := s.person(ctx, td.PermFederationManage)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(url, "https://") || strings.ContainsAny(url, "?# ") {
		return "", ErrNoEndpoint
	}
	url = strings.TrimSuffix(url, "/")
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		if _, err := dbq.New(tx).PutFederationSettings(ctx, c.Org, url, actorString(c.Actor())); err != nil {
			return err
		}
		return record(ctx, tx, auditkind.FederationEndpointSet, c.Actor(), "federation_settings", c.Org.String(), map[string]string{"federation_url": url})
	})
	return url, err
}

// DocumentInfo is the org's signed document and its keys.
type DocumentInfo struct {
	Document      []byte
	DocumentURL   string
	FederationURL string
	Keys          []keystore.FederationKey
}

// Document returns the caller's org's document (federation.read).
func (s *Service) Document(ctx context.Context) (DocumentInfo, error) {
	c, err := s.caller(ctx, td.PermFederationRead)
	if err != nil {
		return DocumentInfo{}, err
	}
	return s.document(ctx, c.Org)
}

// PublicDocument is the document served at the well-known URL; an org
// without the Enterprise edition serves none.
func (s *Service) PublicDocument(ctx context.Context, org ids.OrgID) ([]byte, error) {
	if err := s.enterprise(ctx, org); err != nil {
		return nil, err
	}
	d, err := s.document(ctx, org)
	return d.Document, err
}

// document builds and signs org's document with every live key (D1020).
func (s *Service) document(ctx context.Context, org ids.OrgID) (DocumentInfo, error) {
	signers, err := s.keys.FederationSigners(ctx, org)
	if err != nil {
		return DocumentInfo{}, err
	}
	live, err := s.keys.ListFederationKeys(ctx, org)
	if err != nil {
		return DocumentInfo{}, err
	}
	now := s.now().UTC().Truncate(time.Second)
	d := Document{V: DocumentVersion, OrgID: org.String(), ServerURL: s.serverURL, IssuedAt: now.Unix(), ExpiresAt: now.Add(DocumentTTL).Unix()}
	for _, k := range live {
		d.Keys.Keys = append(d.Keys.Keys, jws.PublicJWK(k.Public, k.KID))
	}
	err = s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		var err error
		if d.OrgName, err = q.GetOrgName(ctx, org); err != nil {
			return err
		}
		if d.FederationURL, err = s.federationURL(ctx, q, org); err != nil {
			return err
		}
		listings, err := q.ListFederationListings(ctx, org, false)
		if err != nil {
			return err
		}
		for _, l := range listings {
			if d.FederationURL == "" {
				break
			}
			card, err := s.listingCard(ctx, q, org, l, d.FederationURL)
			if err != nil {
				s.log.WarnContext(ctx, "federation.listing_card_unavailable", slog.String("listing", l.Name))
				continue
			}
			d.Agents = append(d.Agents, DocAgent{
				Listing: l.Name, AgentName: card.name, CardURL: CardURL(d.FederationURL, l.Name), CardDigest: card.digest,
			})
		}
		return nil
	}, db.ReadOnly())
	if err != nil {
		return DocumentInfo{}, err
	}
	if d.Agents == nil {
		d.Agents = []DocAgent{}
	}
	payload, err := json.Marshal(d, json.Deterministic(true))
	if err != nil {
		return DocumentInfo{}, err
	}
	raw, err := signDocument(signers, payload)
	if err != nil {
		return DocumentInfo{}, err
	}
	return DocumentInfo{Document: raw, DocumentURL: DocumentURL(s.serverURL, org), FederationURL: d.FederationURL, Keys: live}, nil
}

// RotateKey rotates the org's federation key with a fresh step-up
// (federation.manage); the RETIRING key keeps co-signing the document for
// keystore.FederationKeyOverlap.
func (s *Service) RotateKey(ctx context.Context) (keystore.FederationKey, string, error) {
	c, err := s.person(ctx, td.PermFederationManage)
	if err != nil {
		return keystore.FederationKey{}, "", err
	}
	newKID, retiring, err := s.keys.RotateFederationKey(ctx, c.Org, c.Actor(), func(ctx context.Context, tx db.TenantTx, newKID, retiring string) error {
		key, err := stepUp(ctx, tx, c)
		if err != nil {
			return err
		}
		return record(ctx, tx, auditkind.FederationKeyRotated, c.Actor(), "federation_key", newKID,
			map[string]string{"retiring_kid": retiring, "security_key": key.String()})
	})
	if err != nil {
		return keystore.FederationKey{}, "", err
	}
	live, err := s.keys.ListFederationKeys(ctx, c.Org)
	if err != nil {
		return keystore.FederationKey{}, "", err
	}
	for _, k := range live {
		if k.KID == newKID {
			return k, retiring, nil
		}
	}
	return keystore.FederationKey{KID: newKID, State: keystore.FederationKeyActive}, retiring, nil
}

// pinOf is the listing connection's ACTIVE pin.
func pinOf(ctx context.Context, q *dbq.Queries, org ids.OrgID, conn ids.UUID) (a2astore.Pin, error) {
	return a2astore.Get(ctx, q, org, conn, "ACTIVE")
}
