// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app is IdP-native agent access (G0 M26 D400-D403, D408; H8): the
// org's assertion issuers, client bindings and allow-listed MCP clients, and
// the token grants that use them. Nothing here creates authority: an
// assertion or a sign-in uses or narrows an existing grant (HR-620).
package app

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/oidcrp"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/idaccess/domain"
	"github.com/katocxl/pantherclaw/internal/idaccess/ports"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/protect"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Errors of the admin calls.
var (
	ErrHuman   = pcerr.New(pcerr.PermissionDenied, "HUMAN_ONLY", "only a person can change identity provider access")
	ErrEdition = pcerr.New(pcerr.PermissionDenied, "EDITION_REQUIRED", "IdP-native agent access needs a paid edition")
	ErrInvalid = pcerr.New(pcerr.InvalidArgument, "IDACCESS_INVALID", "the request is not valid")
	ErrURL     = pcerr.New(pcerr.InvalidArgument, "IDACCESS_URL", "the URL must be HTTPS on a public host, without query or fragment")
	ErrState   = pcerr.New(pcerr.FailedPrecondition, "IDACCESS_STATE", "the entry is not in a state that allows this")
	ErrFound   = pcerr.New(pcerr.NotFound, "IDACCESS_NOT_FOUND", "not found")
	// ErrDiscovery says only that the issuer could not be used, so it is no
	// probe of what the server can reach (HR-483).
	ErrDiscovery = pcerr.New(pcerr.InvalidArgument, "ASSERTION_ISSUER_DISCOVERY",
		"the issuer's metadata and keys could not be read over HTTPS or are not acceptable")
)

// Editions reports the licence's entitlements.
type Editions interface {
	Current(ctx context.Context) (billing.Entitlements, error)
}

// Notifier enqueues a notification in the producer's transaction.
type Notifier interface {
	Enqueue(ctx context.Context, tx db.TenantTx, m napp.Message) (napp.Enqueued, error)
}

// Admin is the IdpAccessService use cases. Every addition is a two-person
// protected change in every protect mode, filed by a person holding
// identity_provider.manage, with every org admin told (HR-623); every
// removal applies at once (HR-141). Filing and applying an addition need a
// paid edition; nothing on the token path checks the edition (HR-357).
type Admin struct {
	Pool     *db.Pool
	Gate     *protect.Gate
	Editions Editions
	// Notify tells the org's admins; nil sends nothing (tests).
	Notify Notifier
	// Discovery checks an issuer before it is filed; nil checks nothing.
	Discovery ports.Discovery
	// PublicURL is the server's public URL: the org's issuer identifier, and
	// so every assertion's audience, is under it.
	PublicURL string
	// CheckURL checks an issuer or gateway URL; nil is oidcrp.CheckOrgURL.
	CheckURL func(string) error
}

// Filed is a held addition.
type Filed struct{ Change, Request ids.UUID }

// Register sets the Gate's appliers, states and closers for the surfaces.
// Closers run in every role (the jobs role expires requests), so the server
// calls RegisterClosers there too.
func (s *Admin) Register(g *protect.Gate) {
	g.Register(protect.SurfaceAssertionIssuer, s.applyIssuer, issuerState)
	g.Register(protect.SurfaceAssertionClient, s.applyClient, clientState)
	g.Register(protect.SurfaceMcpAccess, s.applyMcpAccess, mcpAccessState)
	g.Register(protect.SurfaceMcpClient, s.applyMcpClient, mcpClientState)
	RegisterClosers(g)
}

// RegisterClosers lets the Gate lapse an addition that was declined or
// expired.
func RegisterClosers(g *protect.Gate) {
	g.OnClose(protect.SurfaceAssertionIssuer, closeIssuer)
	g.OnClose(protect.SurfaceAssertionClient, closeClient)
	g.OnClose(protect.SurfaceMcpClient, closeMcpClient)
}

// manager is the caller of a write: a person holding
// identity_provider.manage, never a service account, API key or support
// session.
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

func (s *Admin) entitled(ctx context.Context) error {
	if s.Editions == nil {
		return ErrEdition
	}
	e, err := s.Editions.Current(ctx)
	if err != nil {
		return err
	}
	if !e.IdpAccess() {
		return ErrEdition
	}
	return nil
}

func (s *Admin) checkURL(raw string) error {
	check := s.CheckURL
	if check == nil {
		check = oidcrp.CheckOrgURL
	}
	u, err := url.Parse(raw)
	if err != nil || check(raw) != nil || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return ErrURL
	}
	return nil
}

// IssuerInput adds an issuer.
type IssuerInput struct {
	Name, Issuer, Tenant string
	Algorithms           []string
}

func (in IssuerInput) validate() error {
	if len(in.Algorithms) == 0 || len(in.Algorithms) > 3 || len(in.Tenant) > 256 || len(in.Issuer) > 512 {
		return ErrInvalid
	}
	for i, a := range in.Algorithms {
		if !slices.Contains([]string{"RS256", "ES256", "EdDSA"}, a) || slices.Contains(in.Algorithms[:i], a) {
			return ErrInvalid
		}
	}
	return nil
}

// CreateIssuer stores a PENDING issuer, after reading its metadata and
// keys, and files its activation. The issuer pins the org's issuer
// identifier as the only audience an assertion may name.
func (s *Admin) CreateIssuer(ctx context.Context, in IssuerInput) (dbq.PcOrgAssertionIssuer, Filed, error) {
	c, err := manager(ctx)
	if err != nil {
		return dbq.PcOrgAssertionIssuer{}, Filed{}, err
	}
	if err := s.entitled(ctx); err != nil {
		return dbq.PcOrgAssertionIssuer{}, Filed{}, err
	}
	if err := in.validate(); err != nil {
		return dbq.PcOrgAssertionIssuer{}, Filed{}, err
	}
	if err := s.checkURL(in.Issuer); err != nil {
		return dbq.PcOrgAssertionIssuer{}, Filed{}, err
	}
	if s.Discovery != nil {
		if err := s.Discovery.Check(ctx, in.Issuer); err != nil {
			return dbq.PcOrgAssertionIssuer{}, Filed{}, ErrDiscovery
		}
	}
	var (
		row dbq.PcOrgAssertionIssuer
		f   Filed
	)
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		var tenant *string
		if in.Tenant != "" {
			tenant = &in.Tenant
		}
		var err error
		row, err = dbq.New(tx).InsertAssertionIssuer(ctx, dbq.InsertAssertionIssuerParams{
			OrgID: c.Org, ID: ids.NewV7(), Name: in.Name, Issuer: in.Issuer, Audience: domain.IssuerID(s.PublicURL, c.Org),
			Tenant: tenant, Algorithms: in.Algorithms, CreatedBy: c.Principal.ID,
		})
		if db.IsUniqueViolation(err) {
			return ErrState
		} else if err != nil {
			return err
		}
		f, err = s.file(ctx, tx, c, protect.SurfaceAssertionIssuer, row.ID, idPayload{ID: row.ID}, map[string]string{
			"name": in.Name, "issuer": in.Issuer, "tenant": in.Tenant, "algorithms": strings.Join(in.Algorithms, ","),
		})
		return err
	})
	return row, f, err
}

// DisableIssuer turns an issuer off at once (HR-141): its assertions stop
// on their next use, and its pending activation can't apply.
func (s *Admin) DisableIssuer(ctx context.Context, id ids.UUID) (dbq.PcOrgAssertionIssuer, error) {
	c, err := manager(ctx)
	if err != nil {
		return dbq.PcOrgAssertionIssuer{}, err
	}
	var row dbq.PcOrgAssertionIssuer
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		by := c.Principal.ID
		var err error
		if row, err = dbq.New(tx).DisableAssertionIssuer(ctx, &by, c.Org, id); err != nil {
			return notFound(err)
		}
		return s.removed(ctx, tx, c.Actor(), "idaccess.issuer_disabled", "assertion_issuer", id)
	})
	return row, err
}

// ListIssuers lists the org's issuers.
func (s *Admin) ListIssuers(ctx context.Context) ([]dbq.PcOrgAssertionIssuer, error) {
	c, err := reader(ctx)
	if err != nil {
		return nil, err
	}
	var out []dbq.PcOrgAssertionIssuer
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		out, err = dbq.New(tx).ListAssertionIssuers(ctx, c.Org)
		return err
	}, db.ReadOnly())
	return out, err
}

// BindClient files that a client id of an issuer acts as one agent. The
// binding is never re-pointed: remove it and bind again.
func (s *Admin) BindClient(ctx context.Context, issuer ids.UUID, clientID string, agent ids.UUID) (dbq.PcOrgAssertionClient, Filed, error) {
	c, err := manager(ctx)
	if err != nil {
		return dbq.PcOrgAssertionClient{}, Filed{}, err
	}
	if err := s.entitled(ctx); err != nil {
		return dbq.PcOrgAssertionClient{}, Filed{}, err
	}
	if clientID == "" || len(clientID) > 512 {
		return dbq.PcOrgAssertionClient{}, Filed{}, ErrInvalid
	}
	var (
		row dbq.PcOrgAssertionClient
		f   Filed
	)
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		iss, err := q.GetAssertionIssuer(ctx, c.Org, issuer)
		if err != nil {
			return notFound(err)
		}
		if iss.State == domain.StateDisabled {
			return ErrState
		}
		if _, err := q.GetAgent(ctx, c.Org, agent); err != nil {
			return notFound(err)
		}
		row, err = q.InsertAssertionClient(ctx, dbq.InsertAssertionClientParams{
			OrgID: c.Org, ID: ids.NewV7(), IssuerID: issuer, ClientID: clientID, AgentID: agent, CreatedBy: c.Principal.ID,
		})
		if db.IsUniqueViolation(err) {
			return ErrState
		} else if err != nil {
			return err
		}
		f, err = s.file(ctx, tx, c, protect.SurfaceAssertionClient, row.ID, idPayload{ID: row.ID}, map[string]string{
			"issuer": iss.Issuer, "client_id": clientID, "agent": agent.String(),
		})
		return err
	})
	return row, f, err
}

// RemoveClient removes a binding at once.
func (s *Admin) RemoveClient(ctx context.Context, id ids.UUID) (dbq.PcOrgAssertionClient, error) {
	c, err := manager(ctx)
	if err != nil {
		return dbq.PcOrgAssertionClient{}, err
	}
	var row dbq.PcOrgAssertionClient
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		by := c.Principal.ID
		var err error
		if row, err = dbq.New(tx).RemoveAssertionClient(ctx, &by, c.Org, id); err != nil {
			return notFound(err)
		}
		return s.removed(ctx, tx, c.Actor(), "idaccess.client_removed", "assertion_client", id)
	})
	return row, err
}

// ListClients lists an issuer's bindings.
func (s *Admin) ListClients(ctx context.Context, issuer ids.UUID) ([]dbq.PcOrgAssertionClient, error) {
	c, err := reader(ctx)
	if err != nil {
		return nil, err
	}
	var out []dbq.PcOrgAssertionClient
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		out, err = dbq.New(tx).ListAssertionClients(ctx, c.Org, issuer)
		return err
	}, db.ReadOnly())
	return out, err
}

// McpAccess is the org's MCP authorization setting.
type McpAccess struct {
	Enabled    bool
	GatewayURL string
	Issuer     string
}

// GetMcpAccess returns the setting; it is off until a person turns it on.
func (s *Admin) GetMcpAccess(ctx context.Context) (McpAccess, error) {
	c, err := reader(ctx)
	if err != nil {
		return McpAccess{}, err
	}
	out := McpAccess{Issuer: domain.IssuerID(s.PublicURL, c.Org)}
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		row, err := dbq.New(tx).GetOrgMcpAccess(ctx, c.Org)
		if db.IsNoRows(err) {
			return nil
		} else if err != nil {
			return err
		}
		out.Enabled = row.Enabled
		if row.GatewayUrl != nil {
			out.GatewayURL = *row.GatewayUrl
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

type mcpAccessPayload struct {
	GatewayURL string `json:"gateway_url"`
}

// EnableMcpAccess files turning MCP authorization on for gatewayURL.
func (s *Admin) EnableMcpAccess(ctx context.Context, gatewayURL string) (Filed, error) {
	c, err := manager(ctx)
	if err != nil {
		return Filed{}, err
	}
	if err := s.entitled(ctx); err != nil {
		return Filed{}, err
	}
	gatewayURL = strings.TrimSuffix(gatewayURL, "/")
	if err := s.checkURL(gatewayURL); err != nil || len(gatewayURL) > 512 {
		return Filed{}, ErrURL
	}
	var f Filed
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		f, err = s.file(ctx, tx, c, protect.SurfaceMcpAccess, mcpAccessSubject, mcpAccessPayload{GatewayURL: gatewayURL},
			map[string]string{"gateway_url": gatewayURL})
		return err
	})
	return f, err
}

var mcpAccessSubject = protect.SubjectID(protect.SurfaceMcpAccess, "mcp_access")

// DisableMcpAccess turns MCP authorization off at once.
func (s *Admin) DisableMcpAccess(ctx context.Context) (McpAccess, error) {
	c, err := manager(ctx)
	if err != nil {
		return McpAccess{}, err
	}
	out := McpAccess{Issuer: domain.IssuerID(s.PublicURL, c.Org)}
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		row, err := dbq.New(tx).DisableOrgMcpAccess(ctx, c.Principal.ID, c.Org)
		if db.IsNoRows(err) {
			return nil // already off
		} else if err != nil {
			return err
		}
		if row.GatewayUrl != nil {
			out.GatewayURL = *row.GatewayUrl
		}
		if err := dbq.New(tx).BumpOrgGatewaysConfig(ctx, c.Org); err != nil {
			return err
		}
		return s.removed(ctx, tx, c.Actor(), "idaccess.mcp_access_disabled", "org", c.Org.UUID())
	})
	return out, err
}

// AllowMcpClient files that a client, named by the URL of its Client ID
// Metadata Document, acts as one enrolled agent through its own mcp_client
// instance. That instance holds no key anyone has, so no PAP/1 proof can
// use it, and only the confirmation admits it (HR-625).
func (s *Admin) AllowMcpClient(ctx context.Context, clientURL string, agent ids.UUID) (dbq.PcMcpClient, Filed, error) {
	c, err := manager(ctx)
	if err != nil {
		return dbq.PcMcpClient{}, Filed{}, err
	}
	if err := s.entitled(ctx); err != nil {
		return dbq.PcMcpClient{}, Filed{}, err
	}
	if !ValidClientURL(clientURL) || s.checkURL(clientURL) != nil {
		return dbq.PcMcpClient{}, Filed{}, ErrURL
	}
	var (
		row dbq.PcMcpClient
		f   Filed
	)
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if _, err := q.GetAgent(ctx, c.Org, agent); err != nil {
			return notFound(err)
		}
		inst, err := q.InsertMcpClientInstance(ctx, dbq.InsertMcpClientInstanceParams{
			OrgID: c.Org, ID: ids.NewV7(), AgentID: agent, Jkt: unheldKey(), PublicJwk: []byte("{}"),
		})
		if err != nil {
			return err
		}
		row, err = q.InsertMcpClient(ctx, dbq.InsertMcpClientParams{
			OrgID: c.Org, ID: ids.NewV7(), ClientUrl: clientURL, AgentID: agent, InstanceID: inst.ID, CreatedBy: c.Principal.ID,
		})
		if db.IsUniqueViolation(err) {
			return ErrState
		} else if err != nil {
			return err
		}
		f, err = s.file(ctx, tx, c, protect.SurfaceMcpClient, row.ID, idPayload{ID: row.ID}, map[string]string{
			"client_url": clientURL, "agent": agent.String(), "instance": inst.ID.String(),
		})
		return err
	})
	return row, f, err
}

// ValidClientURL reports whether raw can name a client by its metadata
// document: HTTPS with a path, no query, fragment or userinfo.
func ValidClientURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" &&
		len(u.Path) > 1 && len(raw) <= 1024 && !strings.Contains(u.Path, "/./") && !strings.Contains(u.Path, "/../")
}

// unheldKey is a key thumbprint no key has: the client's instance is never
// authenticated by a key (D408.1, D408.2).
func unheldKey() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// RemoveMcpClient removes a client at once and revokes its instance: its
// tokens stop on their next use (HR-141).
func (s *Admin) RemoveMcpClient(ctx context.Context, id ids.UUID) (dbq.PcMcpClient, error) {
	c, err := manager(ctx)
	if err != nil {
		return dbq.PcMcpClient{}, err
	}
	var row dbq.PcMcpClient
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		by := c.Principal.ID
		var err error
		if row, err = q.RemoveMcpClient(ctx, &by, c.Org, id); err != nil {
			return notFound(err)
		}
		if _, err := q.RevokeMcpClientInstance(ctx, dbq.RevokeMcpClientInstanceParams{
			OrgID: c.Org, ID: row.InstanceID, DecidedBy: new(by.String()), Reason: new("mcp client removed"),
		}); err != nil {
			return err
		}
		return s.removed(ctx, tx, c.Actor(), "idaccess.mcp_client_removed", "mcp_client", id)
	})
	return row, err
}

// ListMcpClients lists the allow-list.
func (s *Admin) ListMcpClients(ctx context.Context) ([]dbq.PcMcpClient, error) {
	c, err := reader(ctx)
	if err != nil {
		return nil, err
	}
	var out []dbq.PcMcpClient
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		out, err = dbq.New(tx).ListMcpClients(ctx, c.Org)
		return err
	}, db.ReadOnly())
	return out, err
}

type idPayload struct {
	ID ids.UUID `json:"id"`
}

func payloadID(payload []byte) (ids.UUID, error) {
	var p idPayload
	if err := json.Unmarshal(payload, &p); err != nil || p.ID.IsZero() {
		return ids.UUID{}, protect.ErrInvalid
	}
	return p.ID, nil
}

// file holds an addition for a second person in every mode (HR-623) and
// tells every org admin.
func (s *Admin) file(ctx context.Context, tx db.TenantTx, c tenancy.Caller, surface protect.Surface, subject ids.UUID,
	payload any, summary map[string]string,
) (Filed, error) {
	held, err := s.Gate.Hold(ctx, tx, c, protect.Change{
		Category: protect.Custody, Surface: surface, Subject: subject.String(), SubjectID: subject,
		Summary: summary, Widening: []string{"idp_access"}, Payload: payload,
	}, func(context.Context) error { return protect.ErrUnavailable })
	if err != nil {
		return Filed{}, err
	}
	if held == nil {
		return Filed{}, protect.ErrUnavailable // an addition never applies at once
	}
	return Filed{Change: held.Change, Request: held.Request}, s.tellAdmins(ctx, tx, "idaccess.change_requested", map[string]string{
		"request": held.Request.String(), "change": string(surface), "user": c.Principal.ID.String(),
	})
}

func (s *Admin) tellAdmins(ctx context.Context, tx db.TenantTx, typ string, params map[string]string) error {
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

// removed records a removal and tells every org admin.
func (s *Admin) removed(ctx context.Context, tx db.TenantTx, actor evdomain.Actor, name, objType string, id ids.UUID) error {
	if _, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: actor, Outcome: audit.Success, Object: &audit.Object{Type: objType, ID: id.String()},
	}); err != nil {
		return err
	}
	return s.tellAdmins(ctx, tx, "idaccess.removed", map[string]string{"change": name, "user": actor.ID})
}

func (s *Admin) applied(ctx context.Context, tx db.TenantTx, author tenancy.Caller, surface protect.Surface) error {
	publisher, _ := protect.Publisher(ctx)
	return s.tellAdmins(ctx, tx, "idaccess.change_applied", map[string]string{
		"change": string(surface), "user": author.Principal.ID.String(), "publisher": publisher.String(),
	})
}

func one(n int64, err error) error {
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrState
	}
	return nil
}

func notFound(err error) error {
	if db.IsNoRows(err) {
		return ErrFound
	}
	return err
}

// The appliers: each is the confirmed re-run of an addition, and needs the
// edition again when it applies.

func (s *Admin) applyIssuer(ctx context.Context, tx db.TenantTx, author tenancy.Caller, payload []byte) error {
	id, err := payloadID(payload)
	if err != nil {
		return err
	}
	if err := s.entitled(ctx); err != nil {
		return err
	}
	if err := one(dbq.New(tx).ActivateAssertionIssuer(ctx, author.Principal.ID, tx.OrgID(), id)); err != nil {
		return err
	}
	return s.applied(ctx, tx, author, protect.SurfaceAssertionIssuer)
}

func (s *Admin) applyClient(ctx context.Context, tx db.TenantTx, author tenancy.Caller, payload []byte) error {
	id, err := payloadID(payload)
	if err != nil {
		return err
	}
	if err := s.entitled(ctx); err != nil {
		return err
	}
	if err := one(dbq.New(tx).ActivateAssertionClient(ctx, tx.OrgID(), id)); err != nil {
		return err
	}
	return s.applied(ctx, tx, author, protect.SurfaceAssertionClient)
}

func (s *Admin) applyMcpAccess(ctx context.Context, tx db.TenantTx, author tenancy.Caller, payload []byte) error {
	var p mcpAccessPayload
	if err := json.Unmarshal(payload, &p); err != nil || p.GatewayURL == "" {
		return protect.ErrInvalid
	}
	if err := s.entitled(ctx); err != nil {
		return err
	}
	if err := dbq.New(tx).EnableOrgMcpAccess(ctx, tx.OrgID(), &p.GatewayURL, author.Principal.ID); err != nil {
		return err
	}
	if err := dbq.New(tx).BumpOrgGatewaysConfig(ctx, tx.OrgID()); err != nil {
		return err
	}
	return s.applied(ctx, tx, author, protect.SurfaceMcpAccess)
}

func (s *Admin) applyMcpClient(ctx context.Context, tx db.TenantTx, author tenancy.Caller, payload []byte) error {
	id, err := payloadID(payload)
	if err != nil {
		return err
	}
	if err := s.entitled(ctx); err != nil {
		return err
	}
	q := dbq.New(tx)
	row, err := q.GetMcpClient(ctx, tx.OrgID(), id)
	if err != nil {
		return notFound(err)
	}
	if err := one(q.ActivateMcpClient(ctx, tx.OrgID(), id)); err != nil {
		return err
	}
	if err := one(q.AdmitMcpClientInstance(ctx, new(author.Principal.ID.String()), tx.OrgID(), row.InstanceID)); err != nil {
		return err
	}
	return s.applied(ctx, tx, author, protect.SurfaceMcpClient)
}

// The states: a confirmation applies only to the entry as it was when the
// change was asked.

func issuerState(ctx context.Context, tx db.TenantTx, payload []byte) ([]byte, error) {
	id, err := payloadID(payload)
	if err != nil {
		return nil, err
	}
	r, err := dbq.New(tx).LockAssertionIssuer(ctx, tx.OrgID(), id)
	if err != nil {
		return nil, notFound(err)
	}
	return fmt.Appendf(nil, "%s|%s|%s|%s|%v|%s", r.State, r.Issuer, r.Audience, deref(r.Tenant), r.Algorithms,
		r.UpdatedAt.UTC().Format(time.RFC3339Nano)), nil
}

func clientState(ctx context.Context, tx db.TenantTx, payload []byte) ([]byte, error) {
	id, err := payloadID(payload)
	if err != nil {
		return nil, err
	}
	q := dbq.New(tx)
	r, err := q.LockAssertionClient(ctx, tx.OrgID(), id)
	if err != nil {
		return nil, notFound(err)
	}
	iss, err := q.LockAssertionIssuer(ctx, tx.OrgID(), r.IssuerID)
	if err != nil {
		return nil, err
	}
	return fmt.Appendf(nil, "%s|%s|%s|%s|%s", r.State, r.ClientID, r.AgentID, iss.State, iss.Issuer), nil
}

func mcpAccessState(ctx context.Context, tx db.TenantTx, _ []byte) ([]byte, error) {
	r, err := dbq.New(tx).GetOrgMcpAccess(ctx, tx.OrgID())
	if db.IsNoRows(err) {
		return []byte("unset"), nil
	} else if err != nil {
		return nil, err
	}
	return fmt.Appendf(nil, "%t|%s|%s", r.Enabled, deref(r.GatewayUrl), r.UpdatedAt.UTC().Format(time.RFC3339Nano)), nil
}

func mcpClientState(ctx context.Context, tx db.TenantTx, payload []byte) ([]byte, error) {
	id, err := payloadID(payload)
	if err != nil {
		return nil, err
	}
	r, err := dbq.New(tx).LockMcpClient(ctx, tx.OrgID(), id)
	if err != nil {
		return nil, notFound(err)
	}
	return fmt.Appendf(nil, "%s|%s|%s|%s", r.State, r.ClientUrl, r.AgentID, r.InstanceID), nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// The closers: an addition that was declined or expired stops waiting.

var lapseActor = evdomain.Actor{Type: "system", ID: "idaccess"}

func closeIssuer(ctx context.Context, tx db.TenantTx, author ids.UUID, payload []byte) error {
	id, err := payloadID(payload)
	if err != nil {
		return nil //nolint:nilerr // nothing of ours to lapse
	}
	n, err := dbq.New(tx).LapseAssertionIssuer(ctx, &author, tx.OrgID(), id)
	if err != nil || n == 0 {
		return err
	}
	return lapsed(ctx, tx, "assertion_issuer", id)
}

func closeClient(ctx context.Context, tx db.TenantTx, author ids.UUID, payload []byte) error {
	id, err := payloadID(payload)
	if err != nil {
		return nil //nolint:nilerr // nothing of ours to lapse
	}
	n, err := dbq.New(tx).LapseAssertionClient(ctx, &author, tx.OrgID(), id)
	if err != nil || n == 0 {
		return err
	}
	return lapsed(ctx, tx, "assertion_client", id)
}

func closeMcpClient(ctx context.Context, tx db.TenantTx, author ids.UUID, payload []byte) error {
	id, err := payloadID(payload)
	if err != nil {
		return nil //nolint:nilerr // nothing of ours to lapse
	}
	q := dbq.New(tx)
	row, err := q.LapseMcpClient(ctx, &author, tx.OrgID(), id)
	if db.IsNoRows(err) {
		return nil
	} else if err != nil {
		return err
	}
	if _, err := q.RevokeMcpClientInstance(ctx, dbq.RevokeMcpClientInstanceParams{
		OrgID: tx.OrgID(), ID: row.InstanceID, DecidedBy: new(author.String()), Reason: new("mcp client not confirmed"),
	}); err != nil {
		return err
	}
	return lapsed(ctx, tx, "mcp_client", id)
}

func lapsed(ctx context.Context, tx db.TenantTx, objType string, id ids.UUID) error {
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: "idaccess.lapsed", Actor: lapseActor, Outcome: audit.Success, Object: &audit.Object{Type: objType, ID: id.String()},
	})
	return err
}
