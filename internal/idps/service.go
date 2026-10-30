// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package idps

import (
	"context"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/oidcrp"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/protect"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// More errors.
var (
	ErrHuman   = pcerr.New(pcerr.PermissionDenied, "HUMAN_ONLY", "only a person can change identity providers")
	ErrEdition = pcerr.New(pcerr.PermissionDenied, "EDITION_REQUIRED",
		"organization identity providers need the Enterprise edition")
	// ErrDiscovery: the issuer's discovery document could not be read or
	// is not acceptable. It says no more, so it is no probe of what the
	// server can reach (HR-483).
	ErrDiscovery = pcerr.New(pcerr.InvalidArgument, "IDENTITY_PROVIDER_DISCOVERY",
		"the issuer's OpenID discovery document could not be read over HTTPS or is not acceptable")
)

// The change codes a request and its notifications name.
const (
	ChangeActivate   = "activate"
	ChangeUpdate     = "change"
	ChangeDisable    = "disable"
	ChangeOwnOnlyOn  = "own_providers_only_on"
	ChangeOwnOnlyOff = "own_providers_only_off"
)

// Editions reports the licence's entitlements.
type Editions interface {
	Current(ctx context.Context) (billing.Entitlements, error)
}

// Notifier enqueues a notification in the producer's transaction.
type Notifier interface {
	Enqueue(ctx context.Context, tx db.TenantTx, m napp.Message) (napp.Enqueued, error)
}

// Service is the organization identity provider use cases (D155, D161,
// D162). Every write is filed as a two-person protected change, whatever
// the CUSTODY mode, by a person holding identity_provider.manage; every
// org admin is notified when it is filed and when it applies. Creating,
// activating and changing a provider need the Enterprise edition;
// disabling one, the own-providers-only setting and reads work in every
// edition.
type Service struct {
	Pool     *db.Pool
	Store    *Store
	Gate     *protect.Gate
	Editions Editions
	// Notify tells the org's admins; nil sends nothing (tests).
	Notify Notifier
	// Probe reads a provider's discovery document before a create or
	// change is filed; nil: no probe.
	Probe func(ctx context.Context, in Input) error
}

// Filed is the protected change a write filed.
type Filed struct {
	Change, Request ids.UUID
	// Stranded are the active admins who would lose their last provider.
	Stranded []ids.UUID
}

// Register sets the Gate's appliers for the identity provider surfaces.
func (s *Service) Register(g *protect.Gate) {
	g.Register(protect.SurfaceIdentityProviderPut, s.ApplyPut, s.providerState)
	g.Register(protect.SurfaceIdentityProviderDisable, s.ApplyDisable, s.providerState)
	g.Register(protect.SurfaceIdentityProviderOwnOnly, s.ApplyOwnOnly, s.settingsState)
	g.OnClose(protect.SurfaceIdentityProviderPut, s.Store.ClosePut)
}

// DiscoveryProbe reads an organization provider's discovery document
// through the egress client (client nil) or client (tests).
func DiscoveryProbe(client *http.Client) func(context.Context, Input) error {
	return func(ctx context.Context, in Input) error {
		secret := in.ClientSecret
		if !secret.IsSet() || len(secret.Reveal()) == 0 {
			secret = pclog.NewSecret([]byte("probe")) // discovery uses no secret
		}
		p, err := oidcrp.New(oidcrp.Config{
			Name: in.Name, Issuer: in.Issuer, ClientID: in.ClientID, ClientSecret: secret, HTTPClient: client, Org: true,
		})
		if err != nil {
			return ErrInvalid
		}
		ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		if err := p.Discover(ctx); err != nil {
			return ErrDiscovery
		}
		return nil
	}
}

// manager is the caller of a write: a person holding
// identity_provider.manage at the org. The permission is not human-only
// (Org Admin stays bindable to service accounts, D161), so a service
// account, an API key or a support session is refused here.
func manager(ctx context.Context) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return tenancy.Caller{}, err
	}
	if err := c.Require(td.PermIdentityProviderManage, td.OrgPath(c.Org)); err != nil {
		return tenancy.Caller{}, err
	}
	if !c.Human() || c.Credential == tenancy.CredAPIKey || c.Credential == tenancy.CredSupportSession {
		return tenancy.Caller{}, ErrHuman
	}
	return c, nil
}

func (s *Service) entitled(ctx context.Context) error {
	if s.Editions == nil {
		return ErrEdition
	}
	e, err := s.Editions.Current(ctx)
	if err != nil {
		return err
	}
	if !e.OrgIdentityProviders() {
		return ErrEdition
	}
	return nil
}

func (s *Service) probe(ctx context.Context, in Input) error {
	if s.Probe == nil {
		return nil
	}
	return s.Probe(ctx, in)
}

// putPayload is a stored put: the provider and its new settings. The
// secret stays sealed in it.
type putPayload struct {
	ID         ids.UUID `json:"id"`
	Name       string   `json:"name"`
	Issuer     string   `json:"issuer"`
	ClientID   string   `json:"client_id"`
	Secret     []byte   `json:"sealed_secret,omitzero"`
	TrustEmail bool     `json:"trust_email"`
	Change     string   `json:"change"`
}

type disablePayload struct {
	ID ids.UUID `json:"id"`
}

type ownOnlyPayload struct {
	On bool `json:"own_providers_only"`
}

// Create stores a PENDING provider with its secret sealed and files its
// activation.
func (s *Service) Create(ctx context.Context, in Input) (Provider, Filed, error) {
	c, err := manager(ctx)
	if err != nil {
		return Provider{}, Filed{}, err
	}
	if err := s.entitled(ctx); err != nil {
		return Provider{}, Filed{}, err
	}
	if err := in.validate(true); err != nil {
		return Provider{}, Filed{}, err
	}
	if err := s.probe(ctx, in); err != nil {
		return Provider{}, Filed{}, err
	}
	var (
		p Provider
		f Filed
	)
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		if p, err = s.Store.Create(ctx, tx, c.Actor(), c.Principal.ID, ids.NewV7(), in); err != nil {
			return err
		}
		f, err = s.file(ctx, tx, c, protect.SurfaceIdentityProviderPut, p.ID, put(p.ID, in, nil, ChangeActivate), nil)
		return err
	})
	return p, f, err
}

func put(id ids.UUID, in Input, sealed []byte, change string) putPayload {
	return putPayload{
		ID: id, Name: in.Name, Issuer: in.Issuer, ClientID: in.ClientID, Secret: sealed, TrustEmail: in.TrustEmail, Change: change,
	}
}

// Update files a change of provider id, which also activates it when it is
// not ACTIVE. An unset secret keeps the stored one. The issuer can't
// change once the provider has been active (T-207).
func (s *Service) Update(ctx context.Context, id ids.UUID, in Input) (Filed, error) {
	c, err := manager(ctx)
	if err != nil {
		return Filed{}, err
	}
	if err := s.entitled(ctx); err != nil {
		return Filed{}, err
	}
	if err := in.validate(false); err != nil {
		return Filed{}, err
	}
	if s.Store.deploymentName(in.Name) {
		return Filed{}, ErrNameTaken
	}
	var cur Provider
	if err := s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		cur, err = s.Store.Get(ctx, tx, id)
		return err
	}, db.ReadOnly()); err != nil {
		return Filed{}, err
	}
	if cur.ActivatedAt != nil && cur.Issuer != in.Issuer {
		return Filed{}, ErrIssuerFixed
	}
	if err := s.probe(ctx, in); err != nil {
		return Filed{}, err
	}
	var f Filed
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		var sealed []byte
		if len(in.ClientSecret.Reveal()) > 0 {
			if sealed, err = s.Store.Seal(ctx, c.Org, id, in.ClientSecret); err != nil {
				return err
			}
		}
		change := ChangeUpdate
		if cur.State != StateActive {
			if err := s.Store.underLimit(ctx, tx, id); err != nil {
				return err
			}
			change = ChangeActivate
		}
		f, err = s.file(ctx, tx, c, protect.SurfaceIdentityProviderPut, id, put(id, in, sealed, change), nil)
		return err
	})
	return f, err
}

// Disable files turning provider id off. It is refused at once when no
// active admin would have a provider left (HR-484); otherwise the request
// lists the admins who would lose their last one (D162).
func (s *Service) Disable(ctx context.Context, id ids.UUID) (Filed, error) {
	c, err := manager(ctx)
	if err != nil {
		return Filed{}, err
	}
	var f Filed
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		p, err := s.Store.Get(ctx, tx, id)
		if err != nil {
			return err
		}
		if p.State == StateDisabled {
			return ErrState
		}
		stranded, err := s.Store.StrandedByDisable(ctx, tx, id)
		if err != nil {
			return err
		}
		f, err = s.file(ctx, tx, c, protect.SurfaceIdentityProviderDisable, id, disablePayload{ID: id}, stranded)
		return err
	})
	return f, err
}

// SetOwnOnly files the org's "own providers only" setting; turning it on
// is checked for lock-out like Disable.
func (s *Service) SetOwnOnly(ctx context.Context, on bool) (Filed, error) {
	c, err := manager(ctx)
	if err != nil {
		return Filed{}, err
	}
	var f Filed
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		stranded, err := s.Store.StrandedByOwnOnly(ctx, tx, on)
		if err != nil {
			return err
		}
		f, err = s.file(ctx, tx, c, protect.SurfaceIdentityProviderOwnOnly, ownOnlySubject, ownOnlyPayload{On: on}, stranded)
		return err
	})
	return f, err
}

// ownOnlySubject is the subject of the setting's changes.
var ownOnlySubject = protect.SubjectID(protect.SurfaceIdentityProviderOwnOnly, "own_providers_only")

// file holds a change for a second person in every mode (HR-481) and
// tells every org admin.
func (s *Service) file(ctx context.Context, tx db.TenantTx, c tenancy.Caller, surface protect.Surface, subject ids.UUID,
	payload any, stranded []ids.UUID,
) (Filed, error) {
	summary, change := map[string]string{}, ""
	switch p := payload.(type) {
	case putPayload:
		change = p.Change
		summary["name"], summary["issuer"], summary["client_id"] = p.Name, p.Issuer, p.ClientID
		summary["trust_email"], summary["client_auth_changed"] = fmt.Sprint(p.TrustEmail), fmt.Sprint(p.Secret != nil)
	case disablePayload:
		change = ChangeDisable
	case ownOnlyPayload:
		change = ChangeOwnOnlyOff
		if p.On {
			change = ChangeOwnOnlyOn
		}
	}
	summary["change"], summary["stranded_admins"] = change, joinIDs(stranded, ",")
	held, err := s.Gate.Hold(ctx, tx, c, protect.Change{
		Category: protect.Custody, Surface: surface, Subject: subject.String(), SubjectID: subject,
		Summary: summary, Widening: []string{"identity_provider"}, Payload: payload,
	}, func(context.Context) error { return protect.ErrUnavailable })
	if err != nil {
		return Filed{}, err
	}
	if held == nil {
		return Filed{}, protect.ErrUnavailable // an identity provider change never applies at once
	}
	f := Filed{Change: held.Change, Request: held.Request, Stranded: stranded}
	return f, s.tellAdmins(ctx, tx, "identity_provider.change_requested", map[string]string{
		"request": held.Request.String(), "change": change, "user": c.Principal.ID.String(), "stranded": strandedParam(stranded),
	})
}

// joinIDs joins ids with sep; "" for none.
func joinIDs(us []ids.UUID, sep string) string {
	ss := make([]string, len(us))
	for i, u := range us {
		ss[i] = u.String()
	}
	return strings.Join(ss, sep)
}

// strandedParam fits the stranded admins in a template parameter (at most
// 200 characters): every id that fits, then how many more.
func strandedParam(us []ids.UUID) string {
	if len(us) == 0 {
		return "none"
	}
	var b strings.Builder
	for i, u := range us {
		more := fmt.Sprintf(" and %d more", len(us)-i)
		if b.Len() > 0 && b.Len()+2+36+len(more) > 200 {
			b.WriteString(more)
			break
		}
		if b.Len() > 0 {
			b.WriteString(", ")
		}
		b.WriteString(u.String())
	}
	return b.String()
}

func (s *Service) tellAdmins(ctx context.Context, tx db.TenantTx, typ string, params map[string]string) error {
	if s.Notify == nil {
		return nil
	}
	admins, err := dbq.New(tx).OrgUsersWithRoles(ctx, tx.OrgID(), []string{string(td.RoleOrgAdmin)})
	if err != nil {
		return err
	}
	_, err = s.Notify.Enqueue(ctx, tx, napp.Message{Org: tx.OrgID(), Type: typ, Params: params, Personal: admins})
	return err
}

func (s *Service) applied(ctx context.Context, tx db.TenantTx, author tenancy.Caller, change string) error {
	publisher, _ := protect.Publisher(ctx)
	return s.tellAdmins(ctx, tx, "identity_provider.change_applied", map[string]string{
		"change": change, "user": author.Principal.ID.String(), "publisher": publisher.String(),
	})
}

// ApplyPut is the confirmed re-run of a put (protect.Applier). Activating
// or changing still needs the Enterprise edition when it applies.
func (s *Service) ApplyPut(ctx context.Context, tx db.TenantTx, author tenancy.Caller, payload []byte) error {
	var p putPayload
	if err := json.Unmarshal(payload, &p); err != nil || p.ID.IsZero() {
		return protect.ErrInvalid
	}
	if err := s.entitled(ctx); err != nil {
		return err
	}
	if err := s.Store.Put(ctx, tx, author.Actor(), author.Principal.ID, p.ID, Change{
		Name: p.Name, Issuer: p.Issuer, ClientID: p.ClientID, SealedSecret: p.Secret, TrustEmail: p.TrustEmail,
	}); err != nil {
		return err
	}
	return s.applied(ctx, tx, author, p.Change)
}

// ApplyDisable is the confirmed re-run of a disable; the lock-out guard
// runs again (HR-484).
func (s *Service) ApplyDisable(ctx context.Context, tx db.TenantTx, author tenancy.Caller, payload []byte) error {
	var p disablePayload
	if err := json.Unmarshal(payload, &p); err != nil || p.ID.IsZero() {
		return protect.ErrInvalid
	}
	if err := s.Store.Disable(ctx, tx, author.Actor(), author.Principal.ID, p.ID); err != nil {
		return err
	}
	return s.applied(ctx, tx, author, ChangeDisable)
}

// ApplyOwnOnly is the confirmed re-run of the setting; the lock-out guard
// runs again when it turns on (HR-484).
func (s *Service) ApplyOwnOnly(ctx context.Context, tx db.TenantTx, author tenancy.Caller, payload []byte) error {
	var p ownOnlyPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return protect.ErrInvalid
	}
	if err := s.Store.SetOwnOnly(ctx, tx, author.Actor(), author.Principal.ID, p.On); err != nil {
		return err
	}
	change := ChangeOwnOnlyOff
	if p.On {
		change = ChangeOwnOnlyOn
	}
	return s.applied(ctx, tx, author, change)
}

// providerState is a provider's state now (protect.State): a confirmation
// applies only to the provider as it was when the change was asked.
func (s *Service) providerState(ctx context.Context, tx db.TenantTx, payload []byte) ([]byte, error) {
	var p struct {
		ID ids.UUID `json:"id"`
	}
	if err := json.Unmarshal(payload, &p); err != nil || p.ID.IsZero() {
		return nil, protect.ErrInvalid
	}
	row, err := dbq.New(tx).LockOrgIdentityProvider(ctx, tx.OrgID(), p.ID)
	if db.IsNoRows(err) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	return fmt.Appendf(nil, "%s|%s|%s|%s|%s|%t|%s", row.State, row.Name, row.Issuer, row.ClientID,
		hex.EncodeToString(row.SecretDigest), row.TrustEmail, row.UpdatedAt.UTC().Format(time.RFC3339Nano)), nil
}

// settingsState is the own-providers-only setting now.
func (s *Service) settingsState(ctx context.Context, tx db.TenantTx, _ []byte) ([]byte, error) {
	row, err := dbq.New(tx).OrgIdentityProviderSettings(ctx, tx.OrgID())
	if db.IsNoRows(err) {
		return []byte("unset"), nil
	} else if err != nil {
		return nil, err
	}
	return fmt.Appendf(nil, "%t|%s", row.OwnProvidersOnly, row.UpdatedAt.UTC().Format(time.RFC3339Nano)), nil
}

// List returns the org's providers and its own-providers-only setting.
func (s *Service) List(ctx context.Context) ([]Provider, bool, error) {
	c, err := reader(ctx)
	if err != nil {
		return nil, false, err
	}
	var (
		out  []Provider
		only bool
	)
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		if out, err = s.Store.List(ctx, tx); err != nil {
			return err
		}
		only, err = s.Store.OwnOnly(ctx, tx)
		return err
	}, db.ReadOnly())
	return out, only, err
}

// Get returns provider id.
func (s *Service) Get(ctx context.Context, id ids.UUID) (Provider, error) {
	c, err := reader(ctx)
	if err != nil {
		return Provider{}, err
	}
	var p Provider
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		p, err = s.Store.Get(ctx, tx, id)
		return err
	}, db.ReadOnly())
	return p, err
}

func reader(ctx context.Context) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return tenancy.Caller{}, err
	}
	return c, c.Require(td.PermIdentityProviderRead, td.OrgPath(c.Org))
}
