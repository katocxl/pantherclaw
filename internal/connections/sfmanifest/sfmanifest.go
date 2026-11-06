// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package sfmanifest keeps snowflake connection configurations (G0 M31
// D962) as pgmanifest keeps postgres ones (G0 M14 D84): the account,
// warehouse, database and schema, fixed once the connection exists, and
// the manifest a gateway serves, with a proposed one that waits for a
// person with connection.manage to confirm it with a fresh security-key
// step-up. A first manifest and every widening change are proposed; a
// narrowing change applies at once. The current manifest keeps serving
// while a proposal waits.
package sfmanifest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/connections/pgmanifest"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Errors.
var (
	// ErrType: the store was given another kind's configuration.
	ErrType = errors.New("sfmanifest: not a snowflake configuration")
	// ErrNotFound: no such snowflake connection.
	ErrNotFound = pcerr.New(pcerr.NotFound, "NOT_FOUND", "no such snowflake connection")
	// ErrNothing: nothing waits for confirmation.
	ErrNothing = pcerr.New(pcerr.FailedPrecondition, "NOTHING_PROPOSED", "this connection has no proposed configuration")
	// ErrHuman: only a person confirms.
	ErrHuman = pcerr.New(pcerr.PermissionDenied, "HUMAN_REQUIRED", "only a person can confirm a snowflake manifest")
	// ErrChanged: the proposal changed while the page was open.
	ErrChanged = pcerr.New(pcerr.FailedPrecondition, "PROPOSAL_CHANGED", "the proposed configuration changed; reload the page")
)

// Store is the snowflake kind's configuration store (ports.KindConfig). A
// snowflake connection depends on no gateway's network: it may move.
type Store struct{}

// encode is a configuration's canonical JSON and its digest.
func encode(c *capp.SnowflakeConfig) ([]byte, []byte, error) {
	raw, err := json.Marshal(c, json.Deterministic(true))
	if err != nil {
		return nil, nil, err
	}
	sum := sha256.Sum256(raw)
	return raw, sum[:], nil
}

// Save stores a validated configuration in the transaction that creates or
// updates the connection: the first one, and a widening change, as
// proposed; a narrowing change at once, voiding a pending proposal. The
// account, warehouse, database and schema never change.
func (Store) Save(ctx context.Context, tx db.TenantTx, org ids.OrgID, connection ids.UUID, _ int32, cfg any) (string, error) {
	sc, ok := cfg.(*capp.SnowflakeConfig)
	if !ok || sc == nil {
		return "", ErrType
	}
	raw, digest, err := encode(sc)
	if err != nil {
		return "", err
	}
	q := dbq.New(tx)
	row, err := q.LockSnowflakeConnection(ctx, org, connection)
	if db.IsNoRows(err) {
		return "", q.ProposeSnowflakeConnection(ctx, dbq.ProposeSnowflakeConnectionParams{
			OrgID: org, ConnectionID: connection, Account: sc.Account, Warehouse: sc.Warehouse, DatabaseName: sc.Database,
			SchemaName: sc.Schema, Proposed: raw, ProposedDigest: digest,
		})
	} else if err != nil {
		return "", err
	}
	if row.Account != sc.Account || row.Warehouse != sc.Warehouse || row.DatabaseName != sc.Database || row.SchemaName != sc.Schema {
		return "", capp.ErrSnowflakeEndpointImmutable
	}
	current, err := capp.DecodeSnowflake(row.Config)
	if err != nil {
		return "", err
	}
	if current == nil || len(Widening(*current, *sc)) > 0 {
		return "", q.ProposeSnowflakeChange(ctx, dbq.ProposeSnowflakeChangeParams{
			OrgID: org, ConnectionID: connection, Proposed: raw, ProposedDigest: digest,
		})
	}
	return "", q.ApplySnowflakeConnection(ctx, dbq.ApplySnowflakeConnectionParams{OrgID: org, ConnectionID: connection, Config: raw, Digest: digest})
}

// Load returns the configuration the gateway serves, or nil before a first
// manifest is confirmed: the gateway then dispatches nothing.
func (Store) Load(ctx context.Context, tx db.TenantTx, org ids.OrgID, connection ids.UUID) (proto.Message, error) {
	row, err := dbq.New(tx).GetSnowflakeConnection(ctx, org, connection)
	if db.IsNoRows(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	c, err := capp.DecodeSnowflake(row.Config)
	if err != nil || c == nil {
		return nil, err
	}
	return Proto(*c), nil
}

// Proto is a configuration as the gateway and a read get it.
func Proto(c capp.SnowflakeConfig) *pb.SnowflakeConfig {
	pg := pgmanifest.Proto(capp.PostgresConfig{Tables: c.Tables})
	return &pb.SnowflakeConfig{
		Account: c.Account, Warehouse: c.Warehouse, Database: c.Database, Schema: c.Schema, Tables: pg.GetTables(),
		MaxRows: c.MaxRows, StatementTimeoutMs: c.StatementTimeoutMs, MaxResultBytes: c.MaxResultBytes, MinGroupSize: c.MinGroupSize,
	}
}

// FromProto is a request's configuration; nil for none.
func FromProto(p *pb.SnowflakeConfig) *capp.SnowflakeConfig {
	if p == nil {
		return nil
	}
	out := &capp.SnowflakeConfig{
		Account: p.GetAccount(), Warehouse: p.GetWarehouse(), Database: p.GetDatabase(), Schema: p.GetSchema(),
		MaxRows: p.GetMaxRows(), StatementTimeoutMs: p.GetStatementTimeoutMs(), MaxResultBytes: p.GetMaxResultBytes(),
		MinGroupSize: p.GetMinGroupSize(),
	}
	for _, t := range p.GetTables() {
		ct := capp.PostgresTable{Schema: t.GetSchema(), Name: t.GetName(), ScopeKey: t.GetScopeKey(), ScopeColumn: t.GetScopeColumn(), MaxRows: t.GetMaxRows()}
		for _, col := range t.GetColumns() {
			ct.Columns = append(ct.Columns, capp.PostgresColumn{Name: col.GetName(), Type: col.GetType(), Class: col.GetClass()})
		}
		out.Tables = append(out.Tables, ct)
	}
	return out
}

// Widening lists how next reaches further than current: the postgres rules
// (a new table or column, a class lowered or a type changed, a scope
// changed, a limit raised, the minimum group size lowered), on the
// manifest; the endpoint never changes.
func Widening(current, next capp.SnowflakeConfig) []string {
	view := func(c capp.SnowflakeConfig) capp.PostgresConfig {
		return capp.PostgresConfig{
			Tables: c.Tables, MaxRows: c.MaxRows, StatementTimeoutMs: c.StatementTimeoutMs, MaxResultBytes: c.MaxResultBytes,
			MinGroupSize: c.MinGroupSize,
		}
	}
	return pgmanifest.Widening(view(current), view(next))
}

// Service is the confirmation's use cases.
type Service struct {
	pool *db.Pool
}

// New returns a Service.
func New(pool *db.Pool) *Service { return &Service{pool: pool} }

// Manifest is a snowflake connection's configurations, for a page.
type Manifest struct {
	Connection  ids.UUID
	Name        string
	State       string
	Current     *capp.SnowflakeConfig
	Proposed    *capp.SnowflakeConfig
	ProposedAt  *time.Time
	ConfirmedAt *time.Time
	// Widening is how the proposal widens the current manifest (all of it
	// for a first one).
	Widening []string
	// Digest is the proposal's digest, which the confirmation names.
	Digest string
}

func caller(ctx context.Context) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	return c, c.Require(td.PermConnectionManage, td.OrgPath(c.Org))
}

// Get returns a snowflake connection's current and proposed configuration.
func (s *Service) Get(ctx context.Context, id ids.UUID) (Manifest, error) {
	c, err := caller(ctx)
	if err != nil {
		return Manifest{}, err
	}
	var out Manifest
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		conn, err := q.GetConnection(ctx, c.Org, id)
		if db.IsNoRows(err) || (err == nil && conn.Kind != capp.KindSnowflake) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		row, err := q.GetSnowflakeConnection(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		out = Manifest{Connection: id, Name: conn.Name, State: conn.State, ProposedAt: row.ProposedAt, ConfirmedAt: row.ConfirmedAt}
		if out.Current, err = capp.DecodeSnowflake(row.Config); err != nil {
			return err
		}
		if out.Proposed, err = capp.DecodeSnowflake(row.Proposed); err != nil {
			return err
		}
		if out.Proposed != nil {
			out.Digest = hex.EncodeToString(row.ProposedDigest)
			if out.Current == nil {
				out.Widening = []string{"a first configuration: the connection serves nothing until it is confirmed"}
			} else {
				out.Widening = Widening(*out.Current, *out.Proposed)
			}
		}
		return nil
	})
	return out, err
}

// Serves reports whether id is a snowflake connection the caller (with
// connection.manage) can see, so one confirm path serves both kinds
// (G0 M31 D962a). It changes nothing.
func (s *Service) Serves(ctx context.Context, id ids.UUID) (bool, error) {
	c, err := caller(ctx)
	if err != nil {
		return false, err
	}
	var ok bool
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		conn, err := dbq.New(tx).GetConnection(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return nil
		} else if err != nil {
			return err
		}
		ok = conn.Kind == capp.KindSnowflake
		return nil
	})
	return ok, err
}

// Confirm applies the proposed configuration a page showed (digest): a
// person with connection.manage and a fresh security-key step-up. The
// connection's gateway reloads its configuration.
func (s *Service) Confirm(ctx context.Context, id ids.UUID, digest string, su *stepup.StepUp) error {
	c, err := caller(ctx)
	if err != nil {
		return err
	}
	if !c.Human() {
		return ErrHuman
	}
	if su == nil {
		return stepup.ErrStepUp
	}
	want, err := hex.DecodeString(digest)
	if err != nil || len(want) != sha256.Size {
		return ErrChanged
	}
	return s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		if err := stepup.Check(ctx, tx, c, *su, now); err != nil {
			return err
		}
		conn, err := q.GetConnection(ctx, c.Org, id)
		if db.IsNoRows(err) || (err == nil && conn.Kind != capp.KindSnowflake) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		row, err := q.LockSnowflakeConnection(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if row.Proposed == nil {
			return ErrNothing
		}
		current, err := capp.DecodeSnowflake(row.Config)
		if err != nil {
			return err
		}
		proposed, err := capp.DecodeSnowflake(row.Proposed)
		if err != nil {
			return err
		}
		widening := []string{"first configuration"}
		if current != nil {
			widening = Widening(*current, *proposed)
		}
		n, err := q.ConfirmSnowflakeConnection(ctx, dbq.ConfirmSnowflakeConnectionParams{
			ConfirmedBy: &c.Principal.ID, ConfirmedCredential: &su.Credential, OrgID: c.Org, ConnectionID: id, ProposedDigest: want,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrChanged
		}
		if _, err := q.BumpGatewayConfig(ctx, c.Org, conn.GatewayID); err != nil {
			return err
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: auditkind.ConnectionPostgresManifestConfirmed, Actor: c.Actor(), Outcome: audit.Success,
			Object: &audit.Object{Type: "connection", ID: id.String()},
			Details: map[string]string{
				"kind": capp.KindSnowflake, "digest": digest, "previous_digest": hex.EncodeToString(row.Digest),
				"widening": strings.Join(widening, "; "), "security_key": su.Credential.String(),
			},
		})
		return err
	})
}
