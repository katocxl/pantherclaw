// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"time"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Shared MCP state (G0 M15 D12, HR-411..413): a gateway's MCP holds, tasks,
// sessions and relayed elicitations (D39), so that every replica of the
// gateway sees them and a restart loses nothing. Rows belong to the calling gateway alone: the org
// and gateway come from the certificate, and no call names another
// gateway. Each entry is bound to (connection, run, instance), a session
// also to its key thumbprint; the gateway checks the binding on every read
// (HR-412). A task's or elicitation's body is sealed to the gateway's broker key and the
// server never opens it (HR-411). Writes are compare-and-set on version.
//
// The bounds are the gateway's memory bounds before M15: beyond them an
// entry is not kept, which only costs the agent a new action (HR-412).
const (
	MaxMCPEntriesPerInstance  = 32
	MaxMCPEntries             = 2000
	MaxMCPSessions            = 10_000
	MaxMCPSessionsPerInstance = 16
	MaxMCPBodyBytes           = 64 << 20
	// Lifetimes (D42): how far ahead an entry may expire, a minute for
	// clock skew included. 00187's CHECK matches.
	MaxMCPHoldTTL        = time.Hour + time.Minute
	MaxMCPSessionTTL     = 8*time.Hour + time.Minute
	MaxMCPElicitationTTL = 10*time.Minute + time.Minute
)

// MCP state kinds, as stored.
const (
	MCPHold    = "HOLD"
	MCPTask    = "TASK"
	MCPSession = "SESSION"
	// MCPElicitation is an elicitation relayed to the agent (D39): kept like
	// a task, with a sealed body, within the same bounds.
	MCPElicitation = "ELICITATION"
)

// Errors (D12).
var (
	ErrMCPStateConflict = pcerr.New(pcerr.FailedPrecondition, "MCP_STATE_CONFLICT", "the MCP state entry changed or exists")
	ErrMCPStateFull     = pcerr.New(pcerr.ResourceExhausted, "MCP_STATE_FULL", "the gateway keeps as much MCP state as it may")
	ErrMCPStateNotFound = pcerr.New(pcerr.NotFound, "MCP_STATE_NOT_FOUND", "no such MCP state entry")
	ErrMCPStateInvalid  = pcerr.New(pcerr.InvalidArgument, "MCP_STATE_INVALID", "the MCP state entry does not fit its kind")
	// ErrMCPStateConnection: the connection is not one the calling gateway
	// serves (D42, as ReportStatus and HR-418).
	ErrMCPStateConnection = pcerr.New(pcerr.PermissionDenied, "MCP_STATE_CONNECTION", "the gateway does not serve this connection")
)

// MCPEntry is one entry to write.
type MCPEntry struct {
	Kind          string
	Key           []byte
	Connection    ids.UUID
	Run, Instance *ids.UUID
	JKT, ActionID string
	Status        string
	Busy          bool
	SealedBody    []byte
	ExpireTime    time.Time
}

func optString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// valid reports whether the entry carries only what its kind may, and
// expires within its kind's lifetime (D42).
func (e MCPEntry) valid(now time.Time) bool {
	if len(e.Key) != 32 || !e.ExpireTime.After(now) {
		return false
	}
	ttl, ok := false, false
	switch e.Kind {
	case MCPHold:
		ttl = !e.ExpireTime.After(now.Add(MaxMCPHoldTTL))
		ok = e.ActionID != "" && e.JKT == "" && e.Status == "" && !e.Busy && len(e.SealedBody) == 0
	case MCPTask:
		ttl = !e.ExpireTime.After(now.Add(MaxMCPHoldTTL))
		ok = e.ActionID != "" && e.JKT == "" && e.Status != ""
	case MCPSession:
		ttl = !e.ExpireTime.After(now.Add(MaxMCPSessionTTL))
		ok = e.ActionID == "" && e.Status == "" && !e.Busy && len(e.SealedBody) == 0
	case MCPElicitation:
		ttl = !e.ExpireTime.After(now.Add(MaxMCPElicitationTTL))
		ok = e.ActionID == "" && e.JKT == "" && e.Status == "" && !e.Busy && len(e.SealedBody) > 0
	}
	return ttl && ok
}

// sameBinding reports whether an update keeps the stored entry's binding,
// which never changes once written (D42).
func (e MCPEntry) sameBinding(cur dbq.PcGatewayMcpState) bool {
	return e.Connection == cur.ConnectionID && sameUUID(e.Run, cur.RunID) && sameUUID(e.Instance, cur.InstanceID) &&
		e.JKT == derefString(cur.Jkt)
}

func sameUUID(a, b *ids.UUID) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// PutMCPState writes an entry of the calling gateway and returns its new
// version. ifVersion 0: the entry must not exist (an expired one does not);
// otherwise it must be the stored version. A new hold or task past the
// bounds is refused with ErrMCPStateFull; a new session past its
// instance's bound ends that instance's least recently updated session.
func (s *Service) PutMCPState(ctx context.Context, id Identity, e MCPEntry, ifVersion int64) (int64, error) {
	now := s.clk.Now()
	if !e.valid(now) {
		return 0, ErrMCPStateInvalid
	}
	var version int64
	err := s.pool.InTenantTx(ctx, id.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		conn, err := q.GetConnection(ctx, id.Org, e.Connection)
		if db.IsNoRows(err) || (err == nil && (conn.GatewayID != id.Gateway || conn.State == "RETIRED")) {
			return ErrMCPStateConnection
		} else if err != nil {
			return err
		}
		// One writer per gateway at a time, so the bounds hold.
		if err := q.LockGatewayMCPState(ctx, id.Gateway); err != nil {
			return err
		}
		cur, err := q.GetGatewayMCPState(ctx, dbq.GetGatewayMCPStateParams{OrgID: id.Org, GatewayID: id.Gateway, Kind: e.Kind, Key: e.Key})
		if err != nil && !db.IsNoRows(err) {
			return err
		}
		exists := err == nil
		live := exists && cur.ExpireTime.After(now)
		if (ifVersion == 0 && live) || (ifVersion != 0 && (!live || cur.Version != ifVersion || !e.sameBinding(cur))) {
			return ErrMCPStateConflict
		}
		oldBytes := 0
		if live {
			oldBytes = len(cur.SealedBody)
		}
		if err := s.makeRoom(ctx, q, id, e, !live, len(e.SealedBody)-oldBytes, now); err != nil {
			return err
		}
		if ifVersion != 0 {
			n, err := q.UpdateGatewayMCPState(ctx, dbq.UpdateGatewayMCPStateParams{
				OrgID: id.Org, GatewayID: id.Gateway, Kind: e.Kind, Key: e.Key, ActionID: optString(e.ActionID), Status: optString(e.Status),
				Busy: e.Busy, SealedBody: e.SealedBody, ExpireTime: e.ExpireTime, UpdateTime: now, IfVersion: ifVersion,
			})
			if err != nil {
				return err
			} else if n != 1 {
				return ErrMCPStateConflict
			}
			version = ifVersion + 1
			return nil
		}
		if exists {
			// An expired row under the same key no longer counts.
			if _, err := q.DeleteGatewayMCPState(ctx, dbq.DeleteGatewayMCPStateParams{
				OrgID: id.Org, GatewayID: id.Gateway, Kind: e.Kind, Key: e.Key,
			}); err != nil {
				return err
			}
		}
		version = 1
		return q.InsertGatewayMCPState(ctx, dbq.InsertGatewayMCPStateParams{
			OrgID: id.Org, GatewayID: id.Gateway, Kind: e.Kind, Key: e.Key, ConnectionID: e.Connection, RunID: e.Run,
			InstanceID: e.Instance, Jkt: optString(e.JKT), ActionID: optString(e.ActionID), Status: optString(e.Status),
			Busy: e.Busy, SealedBody: e.SealedBody, ExpireTime: e.ExpireTime, UpdateTime: now,
		})
	})
	return version, err
}

// makeRoom checks the bounds for a write that adds an entry (isNew) or
// extra bytes of sealed body.
func (s *Service) makeRoom(ctx context.Context, q *dbq.Queries, id Identity, e MCPEntry, isNew bool, extra int, now time.Time) error {
	if !isNew && extra <= 0 {
		return nil
	}
	if isNew && e.Kind == MCPSession {
		mine, err := q.ListInstanceMCPSessions(ctx, dbq.ListInstanceMCPSessionsParams{
			OrgID: id.Org, GatewayID: id.Gateway, InstanceID: e.Instance, Now: now,
		})
		if err != nil {
			return err
		}
		for i := 0; len(mine)-i >= MaxMCPSessionsPerInstance; i++ {
			if _, err := q.DeleteGatewayMCPState(ctx, dbq.DeleteGatewayMCPStateParams{
				OrgID: id.Org, GatewayID: id.Gateway, Kind: MCPSession, Key: mine[i],
			}); err != nil {
				return err
			}
		}
	}
	c, err := q.CountGatewayMCPState(ctx, dbq.CountGatewayMCPStateParams{OrgID: id.Org, GatewayID: id.Gateway, InstanceID: e.Instance, Now: now})
	if err != nil {
		return err
	}
	switch {
	case e.Kind == MCPSession:
		if c.Sessions >= MaxMCPSessions {
			return ErrMCPStateFull
		}
	case isNew && (c.Entries >= MaxMCPEntries || c.InstanceEntries >= MaxMCPEntriesPerInstance):
		return ErrMCPStateFull
	case c.BodyBytes+int64(extra) > MaxMCPBodyBytes:
		return ErrMCPStateFull
	}
	return nil
}

// GetMCPState returns a live entry of the calling gateway.
func (s *Service) GetMCPState(ctx context.Context, id Identity, kind string, key []byte) (dbq.PcGatewayMcpState, error) {
	var out dbq.PcGatewayMcpState
	err := s.pool.InTenantTx(ctx, id.Org, func(ctx context.Context, tx db.TenantTx) error {
		r, err := dbq.New(tx).GetGatewayMCPState(ctx, dbq.GetGatewayMCPStateParams{OrgID: id.Org, GatewayID: id.Gateway, Kind: kind, Key: key})
		if db.IsNoRows(err) || (err == nil && !r.ExpireTime.After(s.clk.Now())) {
			return ErrMCPStateNotFound
		}
		out = r
		return err
	})
	return out, err
}

// DeleteMCPState deletes an entry of the calling gateway; ifVersion 0
// deletes whatever version. A missing entry is no error (false); a stored
// live entry of another version is ErrMCPStateConflict.
func (s *Service) DeleteMCPState(ctx context.Context, id Identity, kind string, key []byte, ifVersion int64) (bool, error) {
	var deleted bool
	err := s.pool.InTenantTx(ctx, id.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		n, err := q.DeleteGatewayMCPState(ctx, dbq.DeleteGatewayMCPStateParams{
			OrgID: id.Org, GatewayID: id.Gateway, Kind: kind, Key: key, IfVersion: ifVersion, Now: s.clk.Now(),
		})
		if err != nil {
			return err
		}
		if deleted = n == 1; deleted || ifVersion == 0 {
			return nil
		}
		cur, err := q.GetGatewayMCPState(ctx, dbq.GetGatewayMCPStateParams{OrgID: id.Org, GatewayID: id.Gateway, Kind: kind, Key: key})
		if db.IsNoRows(err) || (err == nil && !cur.ExpireTime.After(s.clk.Now())) {
			return nil
		} else if err != nil {
			return err
		}
		return ErrMCPStateConflict
	})
	return deleted, err
}

// PurgeMCPState deletes one org's expired MCP state.
func (s *Service) PurgeMCPState(ctx context.Context, org ids.OrgID) (int64, error) {
	var n int64
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		n, err = dbq.New(tx).PurgeGatewayMCPState(ctx, org, s.clk.Now())
		return err
	})
	return n, err
}
