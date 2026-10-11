// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app holds the connection use cases (G0 M6 design decision 7,
// HR-077, HR-183, HR-184). A connection is one target (an HTTP API, a
// remote MCP server, or the developer's machine for the hook) served by one
// gateway through one tool package; each route of the package has a mode on
// it, monitor by default (PN-013).
//
// Every change needs connection.manage, which only people hold. Changes
// that weaken enforcement (a route to monitor; the base URL, allowed hosts,
// gateway, access mode or destination class; restoring a quarantined
// connection) are audited with the old and new values and notified.
// Changes that strengthen it (a route to enforce, quarantine, retire) raise
// the containment epoch in the same transaction, so outstanding permits
// fail BeginDispatch. Every change bumps the gateway's configuration
// version, so it refetches its configuration (decision 19).
package app

import (
	"context"
	"slices"
	"strconv"
	"strings"

	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Defaults and limits (G0 M6 design decisions 7 and 11).
const (
	DefaultMaxResponseBytes = 1 << 20
	DefaultTimeoutMs        = 10_000
	maxAllowedHosts         = 16
	maxReason               = 500
)

// Kinds, modes, states and access modes, as stored.
const (
	KindHTTP  = "http"
	KindMCP   = "mcp"
	KindLocal = "local"

	ModeMonitor = "monitor"
	ModeEnforce = "enforce"

	StateActive      = "ACTIVE"
	StateQuarantined = "QUARANTINED"
	StateRetired     = "RETIRED"

	AccessHeld           = "pantherclaw_held"
	AccessAgentHeld      = "agent_held"
	AccessTargetEnforced = "target_enforced"
	AccessNone           = "none"

	ClassPublic   = "public"
	ClassInternal = "internal"
)

// Errors.
var (
	ErrNotFound        = pcerr.New(pcerr.NotFound, "CONNECTION_NOT_FOUND", "connection not found")
	ErrNameTaken       = pcerr.New(pcerr.AlreadyExists, "CONNECTION_NAME_TAKEN", "a connection already has this name")
	ErrGatewayNotFound = pcerr.New(pcerr.NotFound, "GATEWAY_NOT_FOUND", "gateway not found")
	ErrGatewayRevoked  = pcerr.New(pcerr.FailedPrecondition, "GATEWAY_REVOKED", "the gateway is revoked")
	ErrPackage         = pcerr.New(pcerr.FailedPrecondition, "PACKAGE_NOT_PINNED", "the org has no usable pinned version of this package")
	ErrNoRoutes        = pcerr.New(pcerr.FailedPrecondition, "PACKAGE_HAS_NO_ROUTES", "the package has no routes this kind of connection can serve")
	ErrRoute           = pcerr.New(pcerr.NotFound, "ROUTE_NOT_FOUND", "the connection's package has no such route")
	ErrBaseURL         = pcerr.New(pcerr.InvalidArgument, "BASE_URL_INVALID", "the base URL must be https://host[:port][/path] or http:// for a private address")
	ErrPlainHTTP       = pcerr.New(pcerr.InvalidArgument, "PLAIN_HTTP_PUBLIC", "plain http is allowed only for a private address literal")
	ErrOwnHost         = pcerr.New(pcerr.InvalidArgument, "OWN_HOST", "a connection cannot target PantherClaw itself")
	ErrAllowedHosts    = pcerr.New(pcerr.InvalidArgument, "ALLOWED_HOSTS_INVALID", "allowed hosts are up to 16 distinct host or host:port entries")
	ErrShape           = pcerr.New(pcerr.InvalidArgument, "CONNECTION_INVALID", "the connection's fields do not fit its kind and access mode")
	ErrStale           = pcerr.New(pcerr.FailedPrecondition, "CONNECTION_REVISION_STALE", "the connection changed since it was read")
	ErrState           = pcerr.New(pcerr.FailedPrecondition, "CONNECTION_STATE", "the connection is not in a state that allows this")
	ErrReason          = pcerr.New(pcerr.InvalidArgument, "REASON_REQUIRED", "a reason of 1 to 500 characters is required")
	ErrNameReserved    = pcerr.New(pcerr.InvalidArgument, "CONNECTION_NAME_RESERVED", "this name is a path of the gateway itself")
)

// reservedNames are the gateway's own first path segments: a connection's
// name is the first segment of its HTTP routes (/{connection}/…), so it
// can never shadow them.
var reservedNames = []string{"mcp", "hook", "sdk", "healthz", "readyz", "metrics"}

// Notifier queues a notification in the caller's transaction (M5).
type Notifier interface {
	Enqueue(ctx context.Context, tx db.TenantTx, m napp.Message) (napp.Enqueued, error)
}

// Service serves connections.
type Service struct {
	pool   *db.Pool
	notify Notifier
	own    []endpoint
}

// New returns the connection use cases. publicURL and gatewayAPIURL are
// PantherClaw's own endpoints, which no connection may target; n may be nil.
func New(pool *db.Pool, n Notifier, publicURL, gatewayAPIURL string) *Service {
	return &Service{pool: pool, notify: n, own: ownEndpoints(publicURL, gatewayAPIURL)}
}

// Connection is a connection with its routes.
type Connection struct {
	dbq.PcConnection
	Routes []dbq.PcConnectionRoute
}

// CreateInput is a new connection. Zero values take the defaults.
type CreateInput struct {
	Name, Kind, Package, BaseURL                    string
	Gateway                                         ids.UUID
	AllowedHosts                                    []string
	DestinationClass, AccessMode                    string
	CredentialHeader, CredentialScheme, DefaultMode string
	MaxResponseBytes, TimeoutMs                     int32
}

// actor is who makes a change: a person holding the permission, or the
// operator seeding a development org (Seed).
type actor struct {
	Org ids.OrgID
	// By is recorded in created_by, updated_by and changed_by.
	By    string
	Audit evdomain.Actor
}

func (s *Service) caller(ctx context.Context, p td.Permission) (actor, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return actor{}, err
	}
	if err := c.Require(p, td.OrgPath(c.Org)); err != nil {
		return actor{}, err
	}
	return actor{Org: c.Org, By: c.Principal.String(), Audit: c.Actor()}, nil
}

func record(ctx context.Context, tx db.TenantTx, c actor, name string, conn ids.UUID, details map[string]string) error {
	for k, v := range details {
		details[k] = clip(v)
	}
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: c.Audit, Outcome: audit.Success, Object: &audit.Object{Type: "connection", ID: conn.String()}, Details: details,
	})
	return err
}

// clip cuts a detail at the ledger's 512-byte limit on a rune boundary.
func clip(s string) string {
	const limit = 512
	if len(s) <= limit {
		return s
	}
	cut := limit
	for cut > 0 && (s[cut]&0xC0) == 0x80 {
		cut--
	}
	return s[:cut]
}

func (s *Service) notifyWeakened(ctx context.Context, tx db.TenantTx, c actor, conn dbq.PcConnection, changes []string) error {
	if s.notify == nil {
		return nil
	}
	_, err := s.notify.Enqueue(ctx, tx, napp.Message{Org: c.Org, Type: "security.connection_weakened", Params: map[string]string{
		"connection": conn.Name, "user": c.By, "change": strings.Join(changes, ", "),
	}})
	return err
}

func (s *Service) notifyQuarantined(ctx context.Context, tx db.TenantTx, c actor, conn dbq.PcConnection, code string) error {
	if s.notify == nil {
		return nil
	}
	_, err := s.notify.Enqueue(ctx, tx, napp.Message{Org: c.Org, Type: "security.connection_quarantined", Params: map[string]string{
		"connection": conn.Name, "reason": code,
	}})
	return err
}

func bumpEpoch(ctx context.Context, q *dbq.Queries, org ids.OrgID) error {
	if err := q.InsertContainment(ctx, org); err != nil {
		return err
	}
	_, err := q.BumpEpoch(ctx, org)
	return err
}

// activeGateway checks that a gateway of the caller's org is active.
func activeGateway(ctx context.Context, q *dbq.Queries, org ids.OrgID, id ids.UUID) error {
	g, err := q.GetGateway(ctx, org, id)
	if db.IsNoRows(err) {
		return ErrGatewayNotFound
	} else if err != nil {
		return err
	}
	if g.State != "ACTIVE" {
		return ErrGatewayRevoked
	}
	return nil
}

// routes returns the routes of the org's pinned version of a package that a
// connection of this kind serves: for http and mcp, the mappings of
// definitions with a dispatch template of that kind; for local, the hook
// mappings.
func routes(ctx context.Context, q *dbq.Queries, org ids.OrgID, pkg, kind string) ([]string, error) {
	pin, err := q.PinnedPackageRaw(ctx, org, pkg)
	if db.IsNoRows(err) {
		return nil, ErrPackage
	} else if err != nil {
		return nil, err
	}
	if slices.Contains([]string{"QUARANTINED", "RETIRED"}, pin.State) {
		return nil, ErrPackage
	}
	p, err := manifest.Decode(pin.Raw)
	if err != nil {
		return nil, ErrPackage
	}
	var out []string
	for _, d := range p.Definitions {
		for _, m := range d.Mappings {
			serves := false
			switch kind {
			case KindHTTP:
				serves = d.Dispatch != nil && d.Dispatch.HTTP != nil && m.Channel != domain.ChannelHook
			case KindMCP:
				serves = d.Dispatch != nil && d.Dispatch.MCP != nil && m.Channel != domain.ChannelHook
			case KindLocal:
				serves = m.Channel == domain.ChannelHook
			}
			if serves && !slices.Contains(out, m.Route) {
				out = append(out, m.Route)
			}
		}
	}
	if len(out) == 0 {
		return nil, ErrNoRoutes
	}
	slices.Sort(out)
	return out, nil
}

// shape checks the fields that depend on the kind and access mode, and
// normalizes the base URL and allowed hosts.
func (s *Service) shape(kind, baseURL string, hosts []string, access, header, scheme string) (*string, []string, error) {
	switch {
	case !slices.Contains([]string{AccessHeld, AccessAgentHeld, AccessTargetEnforced, AccessNone}, access):
		return nil, nil, ErrShape
	case (header != "") != (access == AccessHeld), scheme != "" && header == "":
		return nil, nil, ErrShape
	}
	if kind == KindLocal {
		if baseURL != "" || len(hosts) > 0 || access != AccessNone {
			return nil, nil, ErrShape
		}
		return nil, []string{}, nil
	}
	if kind != KindHTTP && kind != KindMCP {
		return nil, nil, ErrShape
	}
	norm, ep, err := checkBaseURL(baseURL, s.own)
	if err != nil {
		return nil, nil, err
	}
	allowed, err := checkAllowedHosts(hosts, ep, norm, s.own)
	if err != nil {
		return nil, nil, err
	}
	return &norm, allowed, nil
}

func orDefault[T comparable](v, def T) T {
	var zero T
	if v == zero {
		return def
	}
	return v
}

func ptr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// Create registers a connection and gives every route of its package the
// default mode (monitor unless set).
func (s *Service) Create(ctx context.Context, in CreateInput) (Connection, error) {
	c, err := s.caller(ctx, td.PermConnectionManage)
	if err != nil {
		return Connection{}, err
	}
	return s.create(ctx, c, in)
}

// Seed creates a connection as the operator, for `pantherclaw-server dev
// seed` and `dev connection`, with every check Create makes. DEVELOPMENT
// ONLY: in production a person holding connection.manage creates
// connections (HR-183).
func (s *Service) Seed(ctx context.Context, org ids.OrgID, operator string, in CreateInput) (Connection, error) {
	return s.create(ctx, actor{Org: org, By: "operator:" + operator, Audit: evdomain.Actor{Type: "operator", ID: operator}}, in)
}

func (s *Service) create(ctx context.Context, c actor, in CreateInput) (Connection, error) {
	if slices.Contains(reservedNames, in.Name) {
		return Connection{}, ErrNameReserved
	}
	in.DestinationClass = orDefault(in.DestinationClass, ClassPublic)
	in.DefaultMode = orDefault(in.DefaultMode, ModeMonitor)
	in.MaxResponseBytes = orDefault(in.MaxResponseBytes, DefaultMaxResponseBytes)
	in.TimeoutMs = orDefault(in.TimeoutMs, DefaultTimeoutMs)
	if !slices.Contains([]string{ClassPublic, ClassInternal}, in.DestinationClass) ||
		!slices.Contains([]string{ModeMonitor, ModeEnforce}, in.DefaultMode) ||
		in.MaxResponseBytes < 1024 || in.MaxResponseBytes > 8<<20 || in.TimeoutMs < 100 || in.TimeoutMs > 60_000 {
		return Connection{}, ErrShape
	}
	base, hosts, err := s.shape(in.Kind, in.BaseURL, in.AllowedHosts, in.AccessMode, in.CredentialHeader, in.CredentialScheme)
	if err != nil {
		return Connection{}, err
	}
	var out Connection
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := activeGateway(ctx, q, c.Org, in.Gateway); err != nil {
			return err
		}
		rs, err := routes(ctx, q, c.Org, in.Package, in.Kind)
		if err != nil {
			return err
		}
		conn, err := q.InsertConnection(ctx, dbq.InsertConnectionParams{
			OrgID: c.Org, ID: ids.NewV7(), Name: in.Name, Kind: in.Kind, GatewayID: in.Gateway, Package: in.Package,
			BaseUrl: base, AllowedHosts: hosts, DestinationClass: in.DestinationClass, AccessMode: in.AccessMode,
			CredentialHeader: ptr(in.CredentialHeader), CredentialScheme: ptr(in.CredentialScheme), DefaultMode: in.DefaultMode,
			MaxResponseBytes: in.MaxResponseBytes, TimeoutMs: in.TimeoutMs, CreatedBy: c.By,
		})
		if db.IsUniqueViolation(err) {
			return ErrNameTaken
		} else if err != nil {
			return err
		}
		for _, r := range rs {
			if err := q.InsertConnectionRoute(ctx, dbq.InsertConnectionRouteParams{
				OrgID: c.Org, ConnectionID: conn.ID, Route: r, Mode: in.DefaultMode, ChangedBy: c.By,
			}); err != nil {
				return err
			}
		}
		if _, err := q.BumpGatewayConfig(ctx, c.Org, conn.GatewayID); err != nil {
			return err
		}
		if err := record(ctx, tx, c, "connection.created", conn.ID, map[string]string{
			"name": conn.Name, "kind": conn.Kind, "gateway_id": conn.GatewayID.String(), "package": conn.Package,
			"base_url": deref(conn.BaseUrl), "allowed_hosts": strings.Join(conn.AllowedHosts, ","), "access_mode": conn.AccessMode,
			"default_mode": conn.DefaultMode, "routes": strconv.Itoa(len(rs)),
		}); err != nil {
			return err
		}
		out, err = load(ctx, q, conn)
		return err
	})
	return out, err
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func load(ctx context.Context, q *dbq.Queries, conn dbq.PcConnection) (Connection, error) {
	rs, err := q.ListConnectionRoutes(ctx, conn.OrgID, conn.ID)
	return Connection{PcConnection: conn, Routes: rs}, err
}

// Get returns one connection (connection.read); another org's is NotFound.
func (s *Service) Get(ctx context.Context, id ids.UUID) (Connection, error) {
	c, err := s.caller(ctx, td.PermConnectionRead)
	if err != nil {
		return Connection{}, err
	}
	var out Connection
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		conn, err := q.GetConnection(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		out, err = load(ctx, q, conn)
		return err
	})
	return out, err
}

// List pages through connections (connection.read).
func (s *Service) List(ctx context.Context, size int32, token string, gateway *ids.UUID, includeRetired bool) ([]Connection, string, error) {
	c, err := s.caller(ctx, td.PermConnectionRead)
	if err != nil {
		return nil, "", err
	}
	pr, err := page.Parse(size, token)
	if err != nil {
		return nil, "", err
	}
	var out []Connection
	var next string
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		rows, err := q.ListConnections(ctx, dbq.ListConnectionsParams{
			OrgID: c.Org, IncludeRetired: includeRetired, GatewayID: gateway, AfterID: pr.After, MaxRows: pr.Limit(),
		})
		if err != nil {
			return err
		}
		rows, next = page.Finish(pr, rows, func(r dbq.PcConnection) ids.UUID { return r.ID })
		for _, r := range rows {
			conn, err := load(ctx, q, r)
			if err != nil {
				return err
			}
			out = append(out, conn)
		}
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	return out, next, nil
}
