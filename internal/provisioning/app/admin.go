// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/credential"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/idps"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/protect"
	"github.com/katocxl/pantherclaw/internal/provisioning/domain"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The change codes a request and its notifications name.
const (
	ChangeTokenActivate = "scim_token_activate"
	ChangeSAMLActivate  = "saml_activate"
	ChangeSAMLChange    = "saml_change"
	ChangeSAMLDisable   = "saml_disable"
	ChangeMappingAdd    = "group_role_mapping_add"
	ChangeMappingRemove = "group_role_mapping_remove"
)

// Filed is the protected change a write filed.
type Filed = idps.Filed

// Register sets the Gate's appliers and closers for the provisioning
// surfaces.
func (s *Service) Register(g *protect.Gate) {
	g.Register(protect.SurfaceSCIMTokenActivate, s.ApplyTokenActivate, tokenState)
	g.Register(protect.SurfaceSAMLConnectionPut, s.ApplySAMLPut, connectionState)
	g.Register(protect.SurfaceSAMLDisable, s.ApplySAMLDisable, connectionState)
	g.Register(protect.SurfaceGroupMappingAdd, s.ApplyMappingAdd, groupState)
	g.Register(protect.SurfaceGroupMappingRemove, s.ApplyMappingRemove, mappingState)
	RegisterClosers(g)
}

// RegisterClosers lets the Gate lapse a token or a connection whose
// activation was declined or expired, in every role: the jobs role expires
// requests.
func RegisterClosers(g *protect.Gate) {
	g.OnClose(protect.SurfaceSCIMTokenActivate, CloseToken)
	g.OnClose(protect.SurfaceSAMLConnectionPut, CloseConnection)
}

// manager is the caller of a write: a person holding
// identity_provider.manage at the org, never an API key or a support
// session (as for identity providers, D161).
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

func reader(ctx context.Context) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return tenancy.Caller{}, err
	}
	return c, c.Require(td.PermIdentityProviderRead, td.OrgPath(c.Org))
}

// payloadID is the id of a stored change's payload.
type payloadID struct {
	ID ids.UUID `json:"id"`
}

func idOf(payload []byte) (ids.UUID, error) {
	var p payloadID
	if err := json.Unmarshal(payload, &p); err != nil || p.ID.IsZero() {
		return ids.UUID{}, protect.ErrInvalid
	}
	return p.ID, nil
}

// file holds a change for a second person in every mode and tells every
// org admin.
func (s *Service) file(ctx context.Context, tx db.TenantTx, c tenancy.Caller, surface protect.Surface, subject ids.UUID,
	change string, summary map[string]string, widening string, payload any, stranded []ids.UUID,
) (Filed, error) {
	if summary == nil {
		summary = map[string]string{}
	}
	summary["change"], summary["stranded_admins"] = change, strings.Join(idStrings(stranded), ",")
	if s.Gate == nil {
		return Filed{}, protect.ErrUnavailable
	}
	held, err := s.Gate.Hold(ctx, tx, c, protect.Change{
		Category: protect.Custody, Surface: surface, Subject: subject.String(), SubjectID: subject,
		Summary: summary, Widening: []string{widening}, Payload: payload,
	}, func(context.Context) error { return protect.ErrUnavailable })
	if err != nil {
		return Filed{}, err
	}
	if held == nil {
		return Filed{}, protect.ErrUnavailable // a provisioning change never applies at once
	}
	f := Filed{Change: held.Change, Request: held.Request, Stranded: stranded}
	return f, s.tellAdmins(ctx, tx, "identity_provider.change_requested", map[string]string{
		"request": held.Request.String(), "change": change, "user": c.Principal.ID.String(), "stranded": strandedParam(stranded),
	})
}

func idStrings(us []ids.UUID) []string {
	out := make([]string, len(us))
	for i, u := range us {
		out[i] = u.String()
	}
	return out
}

// strandedParam fits the stranded admins in a template parameter (at most
// 200 characters).
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

func recordBy(ctx context.Context, tx db.TenantTx, c tenancy.Caller, name, objType string, obj ids.UUID, details map[string]string) error {
	if details == nil {
		details = map[string]string{}
	}
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: c.Actor(), Outcome: audit.Success, Object: &audit.Object{Type: objType, ID: obj.String()}, Details: details,
	})
	return err
}

// --- SCIM tokens (HR-629, D409 point 5) ---

// Token is a SCIM token as people see it: never its secret.
type Token struct {
	ID                                   ids.UUID
	Name, Issuer, SubjectAttribute, Hint string
	State, CreatedBy                     string
	CreatedAt, ExpiresAt                 time.Time
	ActivatedAt, RevokedAt, LastUsedAt   *time.Time
}

func tokenView(r dbq.PcScimToken) Token {
	return Token{
		ID: r.ID, Name: r.Name, Issuer: r.Issuer, SubjectAttribute: r.SubjectAttribute, Hint: r.Hint, State: r.State,
		CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt, ActivatedAt: r.ActivatedAt, RevokedAt: r.RevokedAt,
		LastUsedAt: r.LastUsedAt,
	}
}

// TokenInput names a new SCIM token.
type TokenInput struct {
	Name, Issuer, SubjectAttribute string
	TTLDays                        int
}

// knownIssuer reports whether issuer is one of the deployment's providers
// or one of the org's own that is not turned off.
func (s *Service) knownIssuer(ctx context.Context, q *dbq.Queries, org ids.OrgID, issuer string) error {
	if s.IdPs != nil {
		for _, d := range s.IdPs.Deployment {
			if d.Issuer == issuer {
				return nil
			}
		}
	}
	ok, err := q.IssuerInUse(ctx, org, issuer)
	if err != nil {
		return err
	}
	if !ok {
		return ErrIssuer
	}
	return nil
}

// CreateToken stores a PENDING token and files its activation (D409): the
// secret is returned once and does nothing until a different person
// confirms. It needs the Enterprise edition.
func (s *Service) CreateToken(ctx context.Context, in TokenInput) (Token, string, Filed, error) {
	c, err := manager(ctx)
	if err != nil {
		return Token{}, "", Filed{}, err
	}
	if err := s.entitled(ctx, scim); err != nil {
		return Token{}, "", Filed{}, err
	}
	if !domain.ValidTokenName(in.Name) || in.SubjectAttribute != domain.SubjectUserName && in.SubjectAttribute != domain.SubjectExternalID ||
		in.TTLDays < 1 || in.TTLDays > domain.MaxTokenDays || in.Issuer == "" || len(in.Issuer) > 512 {
		return Token{}, "", Filed{}, ErrInvalid
	}
	secret, err := credential.New(credential.SCIMToken, "", c.Org)
	if err != nil {
		return Token{}, "", Filed{}, err
	}
	var (
		t Token
		f Filed
	)
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := s.knownIssuer(ctx, q, c.Org, in.Issuer); err != nil {
			return err
		}
		r, err := q.InsertSCIMToken(ctx, dbq.InsertSCIMTokenParams{
			OrgID: c.Org, ID: ids.NewV7(), Name: in.Name, Issuer: in.Issuer, SubjectAttribute: in.SubjectAttribute,
			SecretHash: secret.Hash(), Hint: secret.Hint(), CreatedBy: c.Principal.String(), TtlDays: int32(in.TTLDays),
		})
		if db.IsUniqueViolation(err) {
			return ErrNameTaken
		} else if err != nil {
			return err
		}
		t = tokenView(r)
		if err := recordBy(ctx, tx, c, "scim.token_created", "scim_token", r.ID, map[string]string{
			"name": r.Name, "issuer": trimDetail(r.Issuer), "subject_attribute": r.SubjectAttribute,
		}); err != nil {
			return err
		}
		f, err = s.file(ctx, tx, c, protect.SurfaceSCIMTokenActivate, r.ID, ChangeTokenActivate, map[string]string{
			"name": r.Name, "issuer": r.Issuer, "subject_attribute": r.SubjectAttribute, "hint": r.Hint,
			"expires": r.ExpiresAt.UTC().Format(time.RFC3339),
		}, "scim_token", payloadID{ID: r.ID}, nil)
		return err
	})
	if err != nil {
		return Token{}, "", Filed{}, err
	}
	return t, secret.Reveal(), f, nil
}

// ApplyTokenActivate is the confirmed activation of a token.
func (s *Service) ApplyTokenActivate(ctx context.Context, tx db.TenantTx, author tenancy.Caller, payload []byte) error {
	id, err := idOf(payload)
	if err != nil {
		return err
	}
	if err := s.entitled(ctx, scim); err != nil {
		return err
	}
	q := dbq.New(tx)
	// The provider may have been turned off since the token was filed: a
	// token activates only for an issuer that is still known (D528).
	tok, err := q.LockSCIMToken(ctx, tx.OrgID(), id)
	if db.IsNoRows(err) {
		return ErrState
	} else if err != nil {
		return err
	}
	if err := s.knownIssuer(ctx, q, tx.OrgID(), tok.Issuer); err != nil {
		return err
	}
	n, err := q.ActivateSCIMToken(ctx, tx.OrgID(), id)
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrState
	}
	if err := recordBy(ctx, tx, author, "scim.token_activated", "scim_token", id, nil); err != nil {
		return err
	}
	return s.applied(ctx, tx, author, ChangeTokenActivate)
}

// tokenState is a token's state now (protect.State).
func tokenState(ctx context.Context, tx db.TenantTx, payload []byte) ([]byte, error) {
	id, err := idOf(payload)
	if err != nil {
		return nil, err
	}
	r, err := dbq.New(tx).LockSCIMToken(ctx, tx.OrgID(), id)
	if db.IsNoRows(err) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	return fmt.Appendf(nil, "%s|%s|%s|%s", r.State, r.Issuer, r.SubjectAttribute, r.ExpiresAt.UTC().Format(time.RFC3339Nano)), nil
}

// CloseToken lapses a PENDING token whose activation was declined or
// expired (protect.Closer).
func CloseToken(ctx context.Context, tx db.TenantTx, _ ids.UUID, payload []byte) error {
	id, err := idOf(payload)
	if err != nil {
		return nil // nothing of ours to lapse
	}
	_, err = dbq.New(tx).LapseSCIMToken(ctx, tx.OrgID(), id)
	return err
}

// RevokeToken ends a token at once, in every edition.
func (s *Service) RevokeToken(ctx context.Context, id ids.UUID) (Token, error) {
	c, err := manager(ctx)
	if err != nil {
		return Token{}, err
	}
	var t Token
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		r, err := q.LockSCIMToken(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		n, err := q.RevokeSCIMToken(ctx, c.Org, id)
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrState
		}
		if err := recordBy(ctx, tx, c, "scim.token_revoked", "scim_token", id, map[string]string{"previous_state": r.State}); err != nil {
			return err
		}
		r, err = q.LockSCIMToken(ctx, c.Org, id)
		t = tokenView(r)
		return err
	})
	return t, err
}

// ListTokens lists the org's tokens.
func (s *Service) ListTokens(ctx context.Context) ([]Token, error) {
	c, err := reader(ctx)
	if err != nil {
		return nil, err
	}
	var out []Token
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListSCIMTokens(ctx, c.Org)
		for _, r := range rows {
			out = append(out, tokenView(r))
		}
		return err
	}, db.ReadOnly())
	return out, err
}

// --- SAML connections (HR-633) ---

// Connection is a SAML connection as people see it.
type Connection struct {
	ID                                    ids.UUID
	Name, EntityID, Issuer, SSOURL, State string
	Certificates                          []string
	CreatedBy                             string
	CreatedAt, UpdatedAt                  time.Time
	ActivatedAt, DisabledAt               *time.Time
}

func connectionView(r dbq.PcSamlConnection) Connection {
	return Connection{
		ID: r.ID, Name: r.Name, EntityID: r.IdpEntityID, Issuer: deref(r.Issuer), SSOURL: r.SsoUrl, State: r.State,
		Certificates: slices.Clone(r.Certificates), CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
		ActivatedAt: r.ActivatedAt, DisabledAt: r.DisabledAt,
	}
}

// samlPut is a stored connection put.
type samlPut struct {
	ID           ids.UUID `json:"id"`
	SSOURL       string   `json:"sso_url"`
	Certificates []string `json:"certificates"`
	Change       string   `json:"change"`
}

func (s *Service) checkURL(u string) error {
	if s.CheckURL == nil {
		return fmt.Errorf("no URL check is configured")
	}
	return s.CheckURL(u)
}

// CreateConnection stores a PENDING connection and files its activation. It
// needs the Enterprise edition.
func (s *Service) CreateConnection(ctx context.Context, in domain.Connection) (Connection, Filed, error) {
	c, err := manager(ctx)
	if err != nil {
		return Connection{}, Filed{}, err
	}
	if err := s.entitled(ctx, saml); err != nil {
		return Connection{}, Filed{}, err
	}
	if err := in.Validate(s.checkURL, s.now().Now()); err != nil {
		return Connection{}, Filed{}, err
	}
	var (
		out Connection
		f   Filed
	)
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		n, err := q.CountSAMLConnections(ctx, c.Org)
		if err != nil {
			return err
		}
		if n >= domain.MaxConnections {
			return ErrTooMany
		}
		r, err := q.InsertSAMLConnection(ctx, dbq.InsertSAMLConnectionParams{
			OrgID: c.Org, ID: ids.NewV7(), Name: in.Name, IdpEntityID: in.EntityID, SsoUrl: in.SSOURL, Certificates: in.Certificates,
			CreatedBy: c.Principal.String(),
		})
		if db.IsUniqueViolation(err) {
			return ErrNameTaken
		} else if err != nil {
			return err
		}
		out = connectionView(r)
		f, err = s.fileSAMLPut(ctx, tx, c, r, samlPut{ID: r.ID, SSOURL: in.SSOURL, Certificates: in.Certificates, Change: ChangeSAMLActivate})
		return err
	})
	return out, f, err
}

func (s *Service) fileSAMLPut(ctx context.Context, tx db.TenantTx, c tenancy.Caller, r dbq.PcSamlConnection, p samlPut) (Filed, error) {
	return s.file(ctx, tx, c, protect.SurfaceSAMLConnectionPut, r.ID, p.Change, map[string]string{
		"name": r.Name, "idp_entity_id": r.IdpEntityID, "sso_url": p.SSOURL, "certificates": certPrints(p.Certificates),
	}, "saml_connection", p, nil)
}

// certPrints are the certificates' SHA-256 fingerprints, for the
// confirming person to compare with the provider's.
func certPrints(certs []string) string {
	out := make([]string, 0, len(certs))
	for _, c := range certs {
		out = append(out, domain.Fingerprint(c))
	}
	return strings.Join(out, ",")
}

// UpdateConnection files a change of sign-in URL and certificates; it also
// activates a connection that is not ACTIVE. The entity id never changes.
func (s *Service) UpdateConnection(ctx context.Context, id ids.UUID, ssoURL string, certs []string) (Filed, error) {
	c, err := manager(ctx)
	if err != nil {
		return Filed{}, err
	}
	if err := s.entitled(ctx, saml); err != nil {
		return Filed{}, err
	}
	var f Filed
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		r, err := q.LockSAMLConnection(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		in := domain.Connection{Name: r.Name, EntityID: r.IdpEntityID, SSOURL: ssoURL, Certificates: certs}
		if err := in.Validate(s.checkURL, s.now().Now()); err != nil {
			return err
		}
		change := ChangeSAMLChange
		if r.State != domain.StateActive {
			change = ChangeSAMLActivate
			n, err := q.CountSAMLConnections(ctx, c.Org)
			if err != nil {
				return err
			}
			if r.State != domain.StatePending && n >= domain.MaxConnections {
				return ErrTooMany
			}
		}
		f, err = s.fileSAMLPut(ctx, tx, c, r, samlPut{ID: id, SSOURL: ssoURL, Certificates: certs, Change: change})
		return err
	})
	return f, err
}

// ApplySAMLPut is the confirmed put: the settings are checked again, and an
// expired certificate refuses it.
func (s *Service) ApplySAMLPut(ctx context.Context, tx db.TenantTx, author tenancy.Caller, payload []byte) error {
	var p samlPut
	if err := json.Unmarshal(payload, &p); err != nil || p.ID.IsZero() {
		return protect.ErrInvalid
	}
	if err := s.entitled(ctx, saml); err != nil {
		return err
	}
	q := dbq.New(tx)
	r, err := q.LockSAMLConnection(ctx, tx.OrgID(), p.ID)
	if db.IsNoRows(err) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	in := domain.Connection{Name: r.Name, EntityID: r.IdpEntityID, SSOURL: p.SSOURL, Certificates: p.Certificates}
	if err := in.Validate(s.checkURL, s.now().Now()); err != nil {
		return err
	}
	n, err := q.PutSAMLConnection(ctx, dbq.PutSAMLConnectionParams{SsoUrl: p.SSOURL, Certificates: p.Certificates, OrgID: tx.OrgID(), ID: p.ID})
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrState
	}
	if err := recordBy(ctx, tx, author, "saml.connection_put", "saml_connection", p.ID, map[string]string{
		"change": p.Change, "name": r.Name, "certificates": certPrints(p.Certificates),
	}); err != nil {
		return err
	}
	return s.applied(ctx, tx, author, p.Change)
}

// DisableConnection files turning a connection off. It is refused at once
// when no active admin would have a way left to sign in (HR-484); the
// request lists the admins who would lose theirs.
func (s *Service) DisableConnection(ctx context.Context, id ids.UUID) (Filed, error) {
	c, err := manager(ctx)
	if err != nil {
		return Filed{}, err
	}
	var f Filed
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		r, err := dbq.New(tx).LockSAMLConnection(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if r.State == domain.StateDisabled {
			return ErrState
		}
		stranded, err := s.stranded(ctx, tx, id)
		if err != nil {
			return err
		}
		f, err = s.file(ctx, tx, c, protect.SurfaceSAMLDisable, id, ChangeSAMLDisable, map[string]string{
			"name": r.Name, "idp_entity_id": r.IdpEntityID,
		}, "saml_connection", payloadID{ID: id}, stranded)
		return err
	})
	return f, err
}

func (s *Service) stranded(ctx context.Context, tx db.TenantTx, id ids.UUID) ([]ids.UUID, error) {
	if s.IdPs == nil {
		return nil, nil
	}
	return s.IdPs.StrandedByDisable(ctx, tx, id)
}

// ApplySAMLDisable is the confirmed disable; the lock-out guard runs again
// (HR-484).
func (s *Service) ApplySAMLDisable(ctx context.Context, tx db.TenantTx, author tenancy.Caller, payload []byte) error {
	id, err := idOf(payload)
	if err != nil {
		return err
	}
	q := dbq.New(tx)
	if err := q.LockOrgIdentityProviderSettings(ctx, tx.OrgID().UUID()); err != nil {
		return err
	}
	if _, err := s.stranded(ctx, tx, id); err != nil {
		return err
	}
	n, err := q.DisableSAMLConnection(ctx, tx.OrgID(), id)
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrState
	}
	if err := recordBy(ctx, tx, author, "saml.connection_disabled", "saml_connection", id, nil); err != nil {
		return err
	}
	return s.applied(ctx, tx, author, ChangeSAMLDisable)
}

// connectionState is a connection's state now (protect.State).
func connectionState(ctx context.Context, tx db.TenantTx, payload []byte) ([]byte, error) {
	id, err := idOf(payload)
	if err != nil {
		return nil, err
	}
	r, err := dbq.New(tx).LockSAMLConnection(ctx, tx.OrgID(), id)
	if db.IsNoRows(err) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	return fmt.Appendf(nil, "%s|%s|%s|%s|%s", r.State, r.IdpEntityID, r.SsoUrl, strings.Join(r.Certificates, ","),
		r.UpdatedAt.UTC().Format(time.RFC3339Nano)), nil
}

// CloseConnection lapses a PENDING connection whose activation was
// declined or expired (protect.Closer).
func CloseConnection(ctx context.Context, tx db.TenantTx, _ ids.UUID, payload []byte) error {
	id, err := idOf(payload)
	if err != nil {
		return nil
	}
	_, err = dbq.New(tx).LapseSAMLConnection(ctx, tx.OrgID(), id)
	return err
}

// ListConnections lists the org's connections.
func (s *Service) ListConnections(ctx context.Context) ([]Connection, error) {
	c, err := reader(ctx)
	if err != nil {
		return nil, err
	}
	var out []Connection
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListSAMLConnections(ctx, c.Org)
		for _, r := range rows {
			out = append(out, connectionView(r))
		}
		return err
	}, db.ReadOnly())
	return out, err
}
