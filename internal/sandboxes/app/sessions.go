// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app serves the containment sandbox's sessions on the server (G0
// M9 track B; PN-008, F454, F457; HR-121, HR-215, HR-218; T-087): opening a
// session for an agent and the connections it maps, verifying the signed
// probe, control and canary reports against the session's probe key and
// single-use nonces, and recording each mapped connection's closure through
// the coverage closure contract (internal/coverage/app).
package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"maps"
	"slices"
	"time"

	agents "github.com/katocxl/pantherclaw/internal/agents/app"
	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	"github.com/katocxl/pantherclaw/internal/authn/credential"
	coverage "github.com/katocxl/pantherclaw/internal/coverage/app"
	covdomain "github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Limits of a session (G0 M9 design decision 9).
const (
	MaxSessionTTL = 24 * time.Hour
	// enrollmentTTL is the life of the sandbox instance's enrollment token
	// (PAP-1 §3.2).
	enrollmentTTL = 15 * time.Minute
)

// Report kinds as stored.
const (
	KindSandbox = "SANDBOX"
	KindControl = "CONTROL"
	KindCanary  = "CANARY"
)

// Errors of the sandbox use cases.
var (
	ErrNotFound    = pcerr.New(pcerr.NotFound, "SANDBOX_SESSION_NOT_FOUND", "sandbox session not found")
	ErrAgent       = pcerr.New(pcerr.FailedPrecondition, "AGENT_UNUSABLE", "the agent is not usable or has no environment")
	ErrConnections = pcerr.New(pcerr.FailedPrecondition, "SANDBOX_CONNECTIONS",
		"every mapped connection must be active with a pinned package, name agent hosts no other mapped connection names, and be served by one gateway")
	ErrNotOpen = pcerr.New(pcerr.FailedPrecondition, "SANDBOX_SESSION_CLOSED", "the sandbox session has ended or expired")
	ErrKeys    = pcerr.New(pcerr.InvalidArgument, "SANDBOX_KEYS", "the probe and host keys must be two different Ed25519 keys")
	// ErrReport is every rejected report (HR-215); the reason is recorded,
	// never returned.
	ErrReport = pcerr.New(pcerr.InvalidArgument, "PROBE_REPORT_REJECTED", "the probe report was rejected")
)

// Service serves sandbox sessions as pc_app.
type Service struct {
	Pool     *db.Pool
	Coverage *coverage.Service
	// Clock is the wall clock when nil.
	Clock clock.Clock
}

// StartInput opens a session.
type StartInput struct {
	Agent        ids.UUID
	Connections  []ids.UUID
	AgentImage   string
	EdgeImage    string
	ProbeImage   string
	ConfigDigest string
	// ProbeKey verifies the sandbox report and HostKey the control and
	// canary reports; they differ (HR-215).
	ProbeKey      ed25519.PublicKey
	HostKey       ed25519.PublicKey
	EngineVersion string
	EngineAPI     string
	Runtime       string
	TTL           time.Duration
}

// Started is an opened session: its enrollment token (shown once), its
// first nonces and the edge's host mapping.
type Started struct {
	Session         dbq.PcSandboxSession
	Connections     []ids.UUID
	EnrollmentToken credential.Token
	Nonces          Nonces
	// AgentHosts maps each agent host to its connection's name.
	AgentHosts map[string]string
}

// Nonces are one probe run's server nonces.
type Nonces struct {
	Sandbox, Control, Canary string
	ExpiresAt                time.Time
}

// StartSession opens a sandbox session for an agent and the connections
// it maps (sandbox.run over the agent). It mints the enrollment of a new
// sandbox instance, which the launcher admits (HR-094), and the first
// nonces. A session that runs other images or another configuration than
// the agent's last closure invalidates that closure's scopes at once
// (sandbox_image, sandbox_config; HR-211).
func (s *Service) StartSession(ctx context.Context, in StartInput) (Started, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Started{}, err
	}
	if len(in.ProbeKey) != ed25519.PublicKeySize || len(in.HostKey) != ed25519.PublicKeySize || in.ProbeKey.Equal(in.HostKey) {
		return Started{}, ErrKeys
	}
	ttl := in.TTL
	if ttl <= 0 || ttl > MaxSessionTTL {
		ttl = MaxSessionTTL
	}
	var out Started
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		a, err := agentFor(ctx, c, q, in.Agent)
		if err != nil {
			return err
		}
		if !adomain.State(a.State).Usable() || a.EnvironmentID == nil {
			return ErrAgent
		}
		hosts, err := mappedHosts(ctx, q, c.Org, in.Connections)
		if err != nil {
			return err
		}
		tok, err := credential.New(credential.EnrollmentToken, "", c.Org)
		if err != nil {
			return err
		}
		et, err := q.InsertEnrollmentToken(ctx, dbq.InsertEnrollmentTokenParams{
			OrgID: c.Org, ID: ids.NewV7(), AgentID: a.ID, EnvironmentID: *a.EnvironmentID, TokenHash: tok.Hash(),
			CreatedBy: c.Principal.String(), TtlMinutes: int32(enrollmentTTL / time.Minute),
		})
		if err != nil {
			return err
		}
		sess, err := q.InsertSandboxSession(ctx, dbq.InsertSandboxSessionParams{
			OrgID: c.Org, ID: ids.NewV7(), AgentID: a.ID, Launcher: c.Principal.String(), EnrollmentTokenID: et.ID,
			AgentImage: in.AgentImage, EdgeImage: in.EdgeImage, ProbeImage: in.ProbeImage, ConfigDigest: in.ConfigDigest,
			ProbeJkt: jws.Thumbprint(in.ProbeKey), ProbePublicKey: in.ProbeKey, HostJkt: jws.Thumbprint(in.HostKey), HostPublicKey: in.HostKey,
			EngineVersion: in.EngineVersion,
			ApiVersion:    in.EngineAPI, Runtime: in.Runtime, TtlSeconds: int32(ttl / time.Second), //nolint:gosec // G115: at most 86400
		})
		if err != nil {
			return err
		}
		// Each connection's bindings as the session opens: its closure is
		// recorded only while they still hold (the closure contract's Bound).
		for _, conn := range in.Connections {
			b, err := q.CoverageBinding(ctx, c.Org, conn)
			if db.IsNoRows(err) {
				return ErrConnections
			} else if err != nil {
				return err
			}
			if err := q.InsertSandboxSessionConnection(ctx, dbq.InsertSandboxSessionConnectionParams{
				OrgID: c.Org, SessionID: sess.ID, ConnectionID: conn, ConnectionRevision: b.Revision, GatewayID: b.GatewayID,
				PackageVersionID: b.PackageVersionID, CredentialVersion: b.CredentialVersion,
			}); err != nil {
				return err
			}
		}
		if err := s.invalidateChanged(ctx, tx, q, sess, in.Connections); err != nil {
			return err
		}
		nonces, err := issueNonces(ctx, q, c.Org, sess.ID)
		if err != nil {
			return err
		}
		out = Started{Session: sess, Connections: in.Connections, EnrollmentToken: tok, Nonces: nonces, AgentHosts: hosts}
		return record(ctx, tx, c, "sandbox.session_started", sess.ID, map[string]string{
			"agent_id": a.ID.String(), "config_digest": in.ConfigDigest, "runtime": in.Runtime,
		})
	})
	return out, err
}

// agentFor loads an agent the caller may run in a sandbox (sandbox.run);
// another org's or an unreadable agent is NotFound.
func agentFor(ctx context.Context, c tenancy.Caller, q *dbq.Queries, id ids.UUID) (dbq.PcAgent, error) {
	a, err := q.LockAgent(ctx, c.Org, id)
	if db.IsNoRows(err) {
		return a, ErrNotFound
	} else if err != nil {
		return a, err
	}
	path, err := agents.PathOf(ctx, q, a)
	if err != nil {
		return a, err
	}
	if err := c.Require(td.PermSandboxRun, path); err != nil {
		return a, err
	}
	return a, nil
}

// mappedHosts checks the mapped connections (active, one gateway, no host
// named twice) and returns the edge's mapping: agent host → connection
// name.
func mappedHosts(ctx context.Context, q *dbq.Queries, org ids.OrgID, conns []ids.UUID) (map[string]string, error) {
	hosts := map[string]string{}
	var gateway ids.UUID
	for i, id := range conns {
		conn, err := q.GetConnection(ctx, org, id)
		if db.IsNoRows(err) {
			return nil, ErrConnections
		} else if err != nil {
			return nil, err
		}
		if conn.State != "ACTIVE" || len(conn.AgentHosts) == 0 || (i > 0 && conn.GatewayID != gateway) {
			return nil, ErrConnections
		}
		gateway = conn.GatewayID
		for _, h := range conn.AgentHosts {
			if _, dup := hosts[h]; dup {
				return nil, ErrConnections
			}
			hosts[h] = conn.Name
		}
	}
	return hosts, nil
}

// invalidateChanged records sandbox_image or sandbox_config for each
// mapped connection whose last closure for the agent was taken with other
// images or another configuration.
func (s *Service) invalidateChanged(ctx context.Context, tx db.TenantTx, q *dbq.Queries, sess dbq.PcSandboxSession, conns []ids.UUID) error {
	images := []string{sess.AgentImage, sess.EdgeImage, sess.ProbeImage}
	for _, conn := range conns {
		last, err := q.LastSandboxClosure(ctx, sess.OrgID, sess.AgentID, conn)
		if db.IsNoRows(err) {
			continue
		} else if err != nil {
			return err
		}
		agent := sess.AgentID
		if !slices.Equal(slices.Sorted(slices.Values(last.ImageDigests)), slices.Sorted(slices.Values(images))) {
			if err := s.Coverage.RecordInvalidation(ctx, tx, covdomain.Invalidation{Kind: covdomain.InvSandboxImage, Connection: conn, Agent: &agent, Subject: &sess.ID}); err != nil {
				return err
			}
		}
		if "sha256:"+hex.EncodeToString(last.ConfigSha256) != sess.ConfigDigest {
			if err := s.Coverage.RecordInvalidation(ctx, tx, covdomain.Invalidation{Kind: covdomain.InvSandboxConfig, Connection: conn, Agent: &agent, Subject: &sess.ID}); err != nil {
				return err
			}
		}
	}
	return nil
}

// issueNonces mints one probe run's nonces, valid 15 minutes; only their
// SHA-256 is stored.
func issueNonces(ctx context.Context, q *dbq.Queries, org ids.OrgID, session ids.UUID) (Nonces, error) {
	var out Nonces
	for _, k := range []struct {
		kind string
		dst  *string
	}{{KindSandbox, &out.Sandbox}, {KindControl, &out.Control}, {KindCanary, &out.Canary}} {
		var b [32]byte
		if _, err := rand.Read(b[:]); err != nil {
			return Nonces{}, err
		}
		*k.dst = base64.RawURLEncoding.EncodeToString(b[:])
		sum := sha256.Sum256([]byte(*k.dst))
		n, err := q.InsertProbeNonce(ctx, dbq.InsertProbeNonceParams{
			OrgID: org, ID: ids.NewV7(), SessionID: session, Kind: k.kind, NonceSha256: sum[:],
		})
		if err != nil {
			return Nonces{}, err
		}
		out.ExpiresAt = n.ExpiresAt
	}
	return out, nil
}

// GetSession returns a session (coverage.read over its agent).
func (s *Service) GetSession(ctx context.Context, id ids.UUID) (dbq.PcSandboxSession, []ids.UUID, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return dbq.PcSandboxSession{}, nil, err
	}
	var sess dbq.PcSandboxSession
	var conns []ids.UUID
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		var err error
		if sess, err = q.GetSandboxSession(ctx, c.Org, id); db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if err := readableAgent(ctx, c, q, sess.AgentID); err != nil {
			return err
		}
		conns, err = sessionConnections(ctx, q, sess)
		return err
	}, db.ReadOnly())
	return sess, conns, err
}

// ListSessions lists sessions, newest first, of the agents the caller may
// read coverage of.
func (s *Service) ListSessions(ctx context.Context, agent, after *ids.UUID, limit int32) ([]dbq.PcSandboxSession, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return nil, err
	}
	var out []dbq.PcSandboxSession
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		rows, err := q.ListSandboxSessionsPage(ctx, dbq.ListSandboxSessionsPageParams{OrgID: c.Org, AgentID: agent, After: after, MaxRows: limit})
		if err != nil {
			return err
		}
		readable := map[ids.UUID]bool{}
		for _, r := range rows {
			ok, seen := readable[r.AgentID]
			if !seen {
				err := readableAgent(ctx, c, q, r.AgentID)
				ok = err == nil
				readable[r.AgentID] = ok
			}
			if ok {
				out = append(out, r)
			}
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// readableAgent loads an agent whose coverage the caller may read.
func readableAgent(ctx context.Context, c tenancy.Caller, q *dbq.Queries, id ids.UUID) error {
	a, err := q.GetAgent(ctx, c.Org, id)
	if db.IsNoRows(err) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	path, err := agents.PathOf(ctx, q, a)
	if err != nil {
		return err
	}
	if c.Require(td.PermCoverageRead, path) != nil {
		return ErrNotFound
	}
	return nil
}

func sessionConnections(ctx context.Context, q *dbq.Queries, sess dbq.PcSandboxSession) ([]ids.UUID, error) {
	rows, err := q.SandboxSessionConnections(ctx, sess.OrgID, sess.ID)
	if err != nil {
		return nil, err
	}
	out := make([]ids.UUID, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.ID)
	}
	return out, nil
}

// record audits an event of a session by its caller.
func record(ctx context.Context, tx db.TenantTx, c tenancy.Caller, name string, session ids.UUID, details map[string]string) error {
	d := maps.Clone(details)
	if d == nil {
		d = map[string]string{}
	}
	if c.Credential != "" {
		d["via"] = string(c.Credential)
	}
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: c.Actor(), Outcome: audit.Success, Object: &audit.Object{Type: "sandbox_session", ID: session.String()}, Details: d,
	})
	return err
}
