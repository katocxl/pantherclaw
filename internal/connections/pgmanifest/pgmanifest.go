// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pgmanifest keeps postgres connection configurations (G0 M14 D15,
// D64, D84): the endpoint and manifest a gateway serves, and a proposed
// one that waits for a person with connection.manage to confirm it with a
// fresh security-key step-up. A new connection's first configuration and
// every widening change are proposed; a narrowing change applies at once.
// The current configuration keeps serving while a proposal waits.
package pgmanifest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
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
	ErrType = errors.New("pgmanifest: not a postgres configuration")
	// ErrNotFound: no such postgres connection.
	ErrNotFound = pcerr.New(pcerr.NotFound, "NOT_FOUND", "no such postgres connection")
	// ErrNothing: nothing waits for confirmation.
	ErrNothing = pcerr.New(pcerr.FailedPrecondition, "NOTHING_PROPOSED", "this connection has no proposed configuration")
	// ErrHuman: only a person confirms.
	ErrHuman = pcerr.New(pcerr.PermissionDenied, "HUMAN_REQUIRED", "only a person can confirm a postgres manifest")
	// ErrChanged: the proposal changed while the page was open.
	ErrChanged = pcerr.New(pcerr.FailedPrecondition, "PROPOSAL_CHANGED", "the proposed configuration changed; reload the page")
)

// Store is the postgres kind's configuration store (ports.KindConfig).
type Store struct{}

// encode is a configuration's canonical JSON and its digest.
func encode(c *capp.PostgresConfig) ([]byte, []byte, error) {
	raw, err := json.Marshal(c, json.Deterministic(true))
	if err != nil {
		return nil, nil, err
	}
	sum := sha256.Sum256(raw)
	return raw, sum[:], nil
}

func decode(raw []byte) (*capp.PostgresConfig, error) {
	if raw == nil {
		return nil, nil
	}
	var c capp.PostgresConfig
	if err := json.Unmarshal(raw, &c, json.RejectUnknownMembers(true)); err != nil {
		return nil, err
	}
	return &c, nil
}

// Save stores a validated configuration in the transaction that creates or
// updates the connection: the first one, and a widening change, as
// proposed; a narrowing change at once, voiding a pending proposal. A
// postgres connection has no base URL.
func (Store) Save(ctx context.Context, tx db.TenantTx, org ids.OrgID, connection ids.UUID, _ int32, cfg any) (string, error) {
	pc, ok := cfg.(*capp.PostgresConfig)
	if !ok || pc == nil {
		return "", ErrType
	}
	raw, digest, err := encode(pc)
	if err != nil {
		return "", err
	}
	q := dbq.New(tx)
	row, err := q.LockPostgresConnection(ctx, org, connection)
	if db.IsNoRows(err) {
		return "", q.ProposePostgresConnection(ctx, dbq.ProposePostgresConnectionParams{
			OrgID: org, ConnectionID: connection, Proposed: raw, ProposedDigest: digest,
		})
	} else if err != nil {
		return "", err
	}
	current, err := decode(row.Config)
	if err != nil {
		return "", err
	}
	if current == nil || len(Widening(*current, *pc)) > 0 {
		return "", q.ProposePostgresChange(ctx, dbq.ProposePostgresChangeParams{
			OrgID: org, ConnectionID: connection, Proposed: raw, ProposedDigest: digest,
		})
	}
	return "", q.ApplyPostgresConnection(ctx, dbq.ApplyPostgresConnectionParams{OrgID: org, ConnectionID: connection, Config: raw, Digest: digest})
}

// Load returns the configuration the gateway serves, or nil before a first
// configuration is confirmed: the gateway then dispatches nothing.
func (Store) Load(ctx context.Context, tx db.TenantTx, org ids.OrgID, connection ids.UUID) (proto.Message, error) {
	row, err := dbq.New(tx).GetPostgresConnection(ctx, org, connection)
	if db.IsNoRows(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	c, err := decode(row.Config)
	if err != nil || c == nil {
		return nil, err
	}
	return Proto(*c), nil
}

// Proto is a configuration as the gateway gets it.
func Proto(c capp.PostgresConfig) *pb.PostgresConfig {
	out := &pb.PostgresConfig{
		Host: c.Host, Port: c.Port, Database: c.Database, User: c.User, Sslmode: c.SSLMode, CaPem: c.CAPEM, Internal: c.Internal,
		MaxRows: c.MaxRows, StatementTimeoutMs: c.StatementTimeoutMs, MaxResultBytes: c.MaxResultBytes, MinGroupSize: c.MinGroupSize,
	}
	for _, t := range c.Tables {
		pt := &pb.PostgresTable{Schema: t.Schema, Name: t.Name, ScopeKey: t.ScopeKey, ScopeColumn: t.ScopeColumn, MaxRows: t.MaxRows}
		for _, col := range t.Columns {
			pt.Columns = append(pt.Columns, &pb.PostgresColumn{Name: col.Name, Type: col.Type, Class: col.Class})
		}
		out.Tables = append(out.Tables, pt)
	}
	return out
}

// classRank orders the data classes from least to most protected.
var classRank = map[string]int{"public": 0, "internal": 1, "pii": 2, "secret": 3}

// Widening lists how next reaches further than current (D84): a new table
// or column, a column class lowered or its type changed, a record scope
// removed or changed, a limit raised (rows, timeout, answer size) or the
// minimum group size lowered, internal turned on, or another endpoint
// (host, port, database, role, TLS mode, CA). None means next only
// narrows and applies at once.
func Widening(current, next capp.PostgresConfig) []string {
	var out []string
	add := func(format string, args ...any) { out = append(out, fmt.Sprintf(format, args...)) }
	if next.Internal && !current.Internal {
		add("internal turned on")
	}
	if next.Host != current.Host || next.Port != current.Port || next.Database != current.Database || next.User != current.User {
		add("another endpoint: %s:%d/%s as %s", next.Host, next.Port, next.Database, next.User)
	}
	if next.SSLMode != current.SSLMode || next.CAPEM != current.CAPEM {
		add("TLS changed: %s", next.SSLMode)
	}
	if next.MaxRows > current.MaxRows {
		add("max_rows raised to %d", next.MaxRows)
	}
	if next.StatementTimeoutMs > current.StatementTimeoutMs {
		add("statement_timeout_ms raised to %d", next.StatementTimeoutMs)
	}
	if next.MaxResultBytes > current.MaxResultBytes {
		add("max_result_bytes raised to %d", next.MaxResultBytes)
	}
	if next.MinGroupSize < current.MinGroupSize {
		add("min_group_size lowered to %d", next.MinGroupSize)
	}
	limit := func(c capp.PostgresConfig, t capp.PostgresTable) int32 {
		if t.MaxRows > 0 {
			return min(t.MaxRows, c.MaxRows)
		}
		return c.MaxRows
	}
	for _, nt := range next.Tables {
		ref := nt.Schema + "." + nt.Name
		i := slices.IndexFunc(current.Tables, func(t capp.PostgresTable) bool { return t.Schema == nt.Schema && t.Name == nt.Name })
		if i < 0 {
			add("new table %s", ref)
			continue
		}
		ct := current.Tables[i]
		if ct.ScopeKey != "" && (nt.ScopeKey != ct.ScopeKey || nt.ScopeColumn != ct.ScopeColumn) {
			add("record scope of %s changed", ref)
		}
		if limit(next, nt) > limit(current, ct) {
			add("max_rows of %s raised", ref)
		}
		for _, nc := range nt.Columns {
			j := slices.IndexFunc(ct.Columns, func(c capp.PostgresColumn) bool { return c.Name == nc.Name })
			switch {
			case j < 0:
				add("new column %s.%s (%s)", ref, nc.Name, nc.Class)
			case nc.Type != ct.Columns[j].Type:
				add("column %s.%s is now %s", ref, nc.Name, nc.Type)
			case classRank[nc.Class] < classRank[ct.Columns[j].Class]:
				add("column %s.%s lowered from %s to %s", ref, nc.Name, ct.Columns[j].Class, nc.Class)
			}
		}
	}
	return out
}

// Service is the confirm page's use cases.
type Service struct {
	pool *db.Pool
}

// New returns a Service.
func New(pool *db.Pool) *Service { return &Service{pool: pool} }

// Manifest is a postgres connection's configurations, for the page.
type Manifest struct {
	Connection  ids.UUID
	Name        string
	State       string
	Current     *capp.PostgresConfig
	Proposed    *capp.PostgresConfig
	ProposedAt  *time.Time
	ConfirmedAt *time.Time
	// Widening is how the proposal widens the current configuration (all
	// of it for a first one).
	Widening []string
	// Digest is the proposal's digest, which the confirmation names.
	Digest string
}

// caller holds connection.manage (D92).
func caller(ctx context.Context) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	return c, c.Require(td.PermConnectionManage, td.OrgPath(c.Org))
}

// Get returns a postgres connection's current and proposed configuration.
func (s *Service) Get(ctx context.Context, id ids.UUID) (Manifest, error) {
	c, err := caller(ctx)
	if err != nil {
		return Manifest{}, err
	}
	var out Manifest
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		conn, err := q.GetConnection(ctx, c.Org, id)
		if db.IsNoRows(err) || (err == nil && conn.Kind != capp.KindPostgres) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		row, err := q.GetPostgresConnection(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		out = Manifest{Connection: id, Name: conn.Name, State: conn.State, ProposedAt: row.ProposedAt, ConfirmedAt: row.ConfirmedAt}
		if out.Current, err = decode(row.Config); err != nil {
			return err
		}
		if out.Proposed, err = decode(row.Proposed); err != nil {
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

// Confirm applies the proposed configuration the page showed (digest): a
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
		if db.IsNoRows(err) || (err == nil && conn.Kind != capp.KindPostgres) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		row, err := q.LockPostgresConnection(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if row.Proposed == nil {
			return ErrNothing
		}
		current, err := decode(row.Config)
		if err != nil {
			return err
		}
		proposed, err := decode(row.Proposed)
		if err != nil {
			return err
		}
		widening := []string{"first configuration"}
		if current != nil {
			widening = Widening(*current, *proposed)
		}
		n, err := q.ConfirmPostgresConnection(ctx, dbq.ConfirmPostgresConnectionParams{
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
			Name: "connection.postgres_manifest_confirmed", Actor: c.Actor(), Outcome: audit.Success,
			Object: &audit.Object{Type: "connection", ID: id.String()},
			Details: map[string]string{
				"digest": digest, "previous_digest": hex.EncodeToString(row.Digest), "widening": strings.Join(widening, "; "),
				"security_key": su.Credential.String(),
			},
		})
		return err
	})
}
