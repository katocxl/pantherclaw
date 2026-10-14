// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// UpdateInput changes the fields that are set. Revision is the revision the
// caller read.
type UpdateInput struct {
	ID       ids.UUID
	Revision int32
	Gateway  *ids.UUID
	BaseURL  *string
	// AllowedHosts replaces the list when SetAllowedHosts (an empty list
	// means "the base URL's host").
	AllowedHosts    []string
	SetAllowedHosts bool
	// AgentHosts replaces the agent hosts when SetAgentHosts; any change
	// weakens (HR-183).
	AgentHosts    []string
	SetAgentHosts bool
	// Connector replaces a connector connection's spec, which weakens
	// enforcement (HR-183); moving a connector to another gateway needs it,
	// so its egress connection is checked on the new gateway.
	Connector        *ConnectorSpec
	DestinationClass *string
	AccessMode       *string
	DefaultMode      *string
	MaxResponseBytes *int32
	TimeoutMs        *int32
}

// change is one changed field with its old and new values and whether it
// weakens enforcement (HR-183).
type change struct {
	field, from, to string
	weakens         bool
}

// apply runs a change to a locked connection: the update itself, the epoch
// for strengthening changes, the gateway configuration versions, the audit
// with old and new values, and the notification for weakening ones.
func (s *Service) apply(ctx context.Context, tx db.TenantTx, c actor, before dbq.PcConnection, p dbq.UpdateConnectionParams,
	changes []change, event string, extra map[string]string,
) (dbq.PcConnection, error) {
	q := dbq.New(tx)
	after, err := q.UpdateConnection(ctx, p)
	if db.IsNoRows(err) {
		return dbq.PcConnection{}, ErrStale
	} else if err != nil {
		return dbq.PcConnection{}, err
	}
	return after, s.after(ctx, tx, c, before, after, changes, event, extra)
}

// disableMovedProviders disables the fact providers bound to the gateway
// a connection moved away from, so their facts stop counting and the new
// gateway can be registered (#299 review follow-up).
func disableMovedProviders(ctx context.Context, tx db.TenantTx, q *dbq.Queries, c actor, conn dbq.PcConnection) error {
	moved, err := q.DisableMovedGatewayProviders(ctx, c.Org, &conn.ID, &conn.GatewayID)
	if err != nil {
		return err
	}
	for _, p := range moved {
		if err := q.DeactivateFactDeclarations(ctx, c.Org, p.ID); err != nil {
			return err
		}
		details := map[string]string{"reason": "connection_moved", "connection": conn.ID.String()}
		if p.GatewayID != nil {
			details["gateway"] = p.GatewayID.String()
		}
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: "facts.provider_disabled", Actor: c.Audit, Outcome: audit.Success,
			Object: &audit.Object{Type: "fact_provider", ID: p.ID.String()}, Details: details,
		}); err != nil {
			return err
		}
	}
	return nil
}

// after is everything a change does besides writing it.
func (s *Service) after(ctx context.Context, tx db.TenantTx, c actor, before, after dbq.PcConnection, changes []change,
	event string, extra map[string]string,
) error {
	q := dbq.New(tx)
	strengthens, weakened := false, []string{}
	details := map[string]string{}
	for k, v := range extra {
		details[k] = v
	}
	for _, ch := range changes {
		details[ch.field+"_old"], details[ch.field+"_new"] = ch.from, ch.to
		if ch.weakens {
			weakened = append(weakened, ch.field)
		} else {
			strengthens = true
		}
	}
	if len(weakened) > 0 {
		details["weakening"] = strings.Join(weakened, ",")
	}
	if strengthens {
		if err := bumpEpoch(ctx, q, c.Org); err != nil {
			return err
		}
	}
	for _, g := range slices.Compact([]ids.UUID{before.GatewayID, after.GatewayID}) {
		if _, err := q.BumpGatewayConfig(ctx, c.Org, g); err != nil {
			return err
		}
	}
	if before.GatewayID != after.GatewayID {
		if err := disableMovedProviders(ctx, tx, q, c, after); err != nil {
			return err
		}
	}
	if len(details) > 16 {
		// More changes than the ledger takes in one entry: keep the field
		// names, which say what weakened.
		details = map[string]string{"weakening": details["weakening"], "fields": fieldNames(changes)}
	}
	if err := record(ctx, tx, c, event, after.ID, details); err != nil {
		return err
	}
	if len(weakened) > 0 {
		return s.notifyWeakened(ctx, tx, c, after, weakened)
	}
	return nil
}

func fieldNames(changes []change) string {
	names := make([]string, len(changes))
	for i, ch := range changes {
		names[i] = ch.field
	}
	return strings.Join(names, ",")
}

// params starts an update that keeps every field.
func params(c actor, conn dbq.PcConnection) dbq.UpdateConnectionParams {
	return dbq.UpdateConnectionParams{
		GatewayID: conn.GatewayID, BaseUrl: conn.BaseUrl, AllowedHosts: conn.AllowedHosts, DestinationClass: conn.DestinationClass,
		AccessMode: conn.AccessMode, DefaultMode: conn.DefaultMode, MaxResponseBytes: conn.MaxResponseBytes, TimeoutMs: conn.TimeoutMs,
		AgentHosts: conn.AgentHosts,
		State:      conn.State, QuarantineReason: conn.QuarantineReason, UpdatedBy: c.By, OrgID: c.Org, ID: conn.ID,
		Revision: conn.Revision,
	}
}

// lock locks a connection that is not retired.
func lock(ctx context.Context, q *dbq.Queries, org ids.OrgID, id ids.UUID) (dbq.PcConnection, error) {
	conn, err := q.LockConnection(ctx, org, id)
	if db.IsNoRows(err) {
		return conn, ErrNotFound
	} else if err != nil {
		return conn, err
	}
	if conn.State == StateRetired {
		return conn, ErrState
	}
	return conn, nil
}

// Update changes a connection's settings. Changing the gateway, base URL,
// allowed hosts, access mode or destination class weakens enforcement, as
// does a default mode of monitor; a default mode of enforce strengthens it.
// The response cap and timeout are neither.
func (s *Service) Update(ctx context.Context, in UpdateInput) (Connection, error) {
	c, err := s.caller(ctx, td.PermConnectionManage)
	if err != nil {
		return Connection{}, err
	}
	var out Connection
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		conn, err := lock(ctx, q, c.Org, in.ID)
		if err != nil {
			return err
		}
		if conn.Revision != in.Revision {
			return ErrStale
		}
		p := params(c, conn)
		var changes []change
		set := func(field, from, to string, weakens bool) {
			if from != to {
				changes = append(changes, change{field: field, from: from, to: to, weakens: weakens})
			}
		}
		if in.Gateway != nil {
			if err := activeGateway(ctx, q, c.Org, *in.Gateway); err != nil {
				return err
			}
			if conn.Kind == KindMCPContainer && s.hosted[*in.Gateway] {
				return ErrHostedGateway
			}
			if conn.Kind == KindMCPContainer && in.Connector == nil {
				return ErrConnector
			}
			p.GatewayID = *in.Gateway
			set("gateway_id", conn.GatewayID.String(), p.GatewayID.String(), true)
		}
		if in.AccessMode != nil {
			p.AccessMode = *in.AccessMode
			set("access_mode", conn.AccessMode, p.AccessMode, true)
		}
		if in.BaseURL != nil || in.SetAllowedHosts || in.AccessMode != nil {
			base, hosts := deref(conn.BaseUrl), conn.AllowedHosts
			if in.BaseURL != nil {
				base = *in.BaseURL
			}
			if in.SetAllowedHosts {
				hosts = in.AllowedHosts
			} else if in.BaseURL != nil {
				hosts = nil // a new base URL defaults its own host again
			}
			nb, nh, err := s.shape(conn.Kind, base, hosts, p.AccessMode, deref(conn.CredentialHeader), deref(conn.CredentialScheme))
			if err != nil {
				return err
			}
			p.BaseUrl, p.AllowedHosts = nb, nh
			set("base_url", deref(conn.BaseUrl), deref(nb), true)
			set("allowed_hosts", strings.Join(conn.AllowedHosts, ","), strings.Join(nh, ","), true)
		}
		if in.SetAgentHosts {
			if p.AgentHosts, err = checkAgentHosts(conn.Kind, in.AgentHosts); err != nil {
				return err
			}
			set("agent_hosts", strings.Join(conn.AgentHosts, ","), strings.Join(p.AgentHosts, ","), true)
		}
		if in.DestinationClass != nil {
			if !slices.Contains([]string{ClassPublic, ClassInternal}, *in.DestinationClass) {
				return ErrShape
			}
			p.DestinationClass = *in.DestinationClass
			set("destination_class", conn.DestinationClass, p.DestinationClass, true)
		}
		if in.DefaultMode != nil {
			if !slices.Contains([]string{ModeMonitor, ModeEnforce}, *in.DefaultMode) {
				return ErrShape
			}
			p.DefaultMode = *in.DefaultMode
			set("default_mode", conn.DefaultMode, p.DefaultMode, p.DefaultMode == ModeMonitor)
		}
		limits := map[string]string{}
		if in.MaxResponseBytes != nil {
			if *in.MaxResponseBytes < 1024 || *in.MaxResponseBytes > 8<<20 {
				return ErrShape
			}
			p.MaxResponseBytes = *in.MaxResponseBytes
			limits["max_response_bytes"] = strconv.Itoa(int(p.MaxResponseBytes))
		}
		if in.TimeoutMs != nil {
			if *in.TimeoutMs < 100 || *in.TimeoutMs > 60_000 {
				return ErrShape
			}
			p.TimeoutMs = *in.TimeoutMs
			limits["timeout_ms"] = strconv.Itoa(int(p.TimeoutMs))
		}
		var spec ConnectorSpec
		if in.Connector != nil {
			if conn.Kind != KindMCPContainer {
				return ErrConnector
			}
			if spec, err = in.Connector.check(); err != nil {
				return err
			}
			cur, err := q.CurrentConnectorSpec(ctx, c.Org, conn.ID)
			if err != nil {
				return err
			}
			set("connector", connectorSummary(&cur), specView(spec), true)
		}
		after, err := s.apply(ctx, tx, c, conn, p, changes, "connection.updated", limits)
		if err != nil {
			return err
		}
		if in.Connector != nil {
			if _, err := putConnector(ctx, q, c, after, spec); err != nil {
				return err
			}
		}
		out, err = load(ctx, q, after)
		return err
	})
	return out, err
}

// SetRouteMode sets one route's mode: monitor weakens enforcement, enforce
// strengthens it (HR-183, HR-184). A route of the pinned package that has no
// mode yet gets one.
func (s *Service) SetRouteMode(ctx context.Context, id ids.UUID, route, mode string) (Connection, error) {
	c, err := s.caller(ctx, td.PermConnectionManage)
	if err != nil {
		return Connection{}, err
	}
	if mode != ModeMonitor && mode != ModeEnforce {
		return Connection{}, ErrShape
	}
	var out Connection
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		conn, err := lock(ctx, q, c.Org, id)
		if err != nil {
			return err
		}
		current, err := q.ListConnectionRoutes(ctx, c.Org, id)
		if err != nil {
			return err
		}
		from := ""
		for _, r := range current {
			if r.Route == route {
				from = r.Mode
			}
		}
		if from == "" {
			rs, err := routes(ctx, q, c.Org, conn.Package, conn.Kind)
			if err != nil {
				return err
			}
			if !slices.Contains(rs, route) {
				return ErrRoute
			}
			from = conn.DefaultMode
			if err := q.InsertConnectionRoute(ctx, dbq.InsertConnectionRouteParams{
				OrgID: c.Org, ConnectionID: id, Route: route, Mode: from, ChangedBy: c.By,
			}); err != nil {
				return err
			}
		}
		if from != mode {
			if _, err := q.SetConnectionRouteMode(ctx, dbq.SetConnectionRouteModeParams{
				Mode: mode, ChangedBy: c.By, OrgID: c.Org, ConnectionID: id, Route: route,
			}); err != nil {
				return err
			}
			if err := q.TouchConnection(ctx, c.By, c.Org, id); err != nil {
				return err
			}
			after, err := q.GetConnection(ctx, c.Org, id)
			if err != nil {
				return err
			}
			if err := s.after(ctx, tx, c, conn, after, []change{{field: "route_mode", from: from, to: mode, weakens: mode == ModeMonitor}},
				"connection.route_mode_changed", map[string]string{"route": route}); err != nil {
				return err
			}
			conn = after
		}
		out, err = load(ctx, q, conn)
		return err
	})
	return out, err
}

// Quarantine stops every action through a connection at once (strengthens).
// The reason is stored in the ledger as untrusted text; the connection
// records reason code manual.
func (s *Service) Quarantine(ctx context.Context, id ids.UUID, reason string) (Connection, error) {
	if n := utf8.RuneCountInString(reason); n < 1 || n > maxReason || !utf8.ValidString(reason) {
		return Connection{}, ErrReason
	}
	return s.transition(ctx, id, []string{StateActive}, StateQuarantined, ptr("manual"), false, "connection.quarantined",
		map[string]string{"reason": reason})
}

// Restore lifts a quarantine (weakens).
func (s *Service) Restore(ctx context.Context, id ids.UUID) (Connection, error) {
	return s.transition(ctx, id, []string{StateQuarantined}, StateActive, nil, true, "connection.restored", nil)
}

// Retire ends a connection and revokes its credentials (strengthens).
func (s *Service) Retire(ctx context.Context, id ids.UUID) error {
	_, err := s.transition(ctx, id, []string{StateActive, StateQuarantined}, StateRetired, nil, false, "connection.retired", nil)
	return err
}

func (s *Service) transition(ctx context.Context, id ids.UUID, from []string, to string, reasonCode *string, weakens bool,
	event string, extra map[string]string,
) (Connection, error) {
	c, err := s.caller(ctx, td.PermConnectionManage)
	if err != nil {
		return Connection{}, err
	}
	var out Connection
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		conn, err := lock(ctx, q, c.Org, id)
		if err != nil {
			return err
		}
		if !slices.Contains(from, conn.State) {
			return ErrState
		}
		p := params(c, conn)
		p.State, p.QuarantineReason = to, reasonCode
		details := map[string]string{}
		for k, v := range extra {
			details[k] = v
		}
		if to == StateRetired {
			n, err := q.RevokeConnectionCredentials(ctx, ptr(c.By), c.Org, id)
			if err != nil {
				return err
			}
			details["sealed_revoked"] = strconv.FormatInt(n, 10)
		}
		if conn.State == StateQuarantined {
			// Lifting a quarantine (or retiring) closes the circuits that a
			// gateway opened (HR-078): only a person gets here.
			n, err := q.CloseCircuits(ctx, c.Org, id)
			if err != nil {
				return err
			}
			if n > 0 {
				details["circuits_closed"] = strconv.FormatInt(n, 10)
			}
		}
		after, err := s.apply(ctx, tx, c, conn, p, []change{{field: "state", from: conn.State, to: to, weakens: weakens}}, event, details)
		if err != nil {
			return err
		}
		if to == StateQuarantined && s.notify != nil {
			if err := s.notifyQuarantined(ctx, tx, c, after, "manual"); err != nil {
				return err
			}
		}
		out, err = load(ctx, q, after)
		return err
	})
	return out, err
}
