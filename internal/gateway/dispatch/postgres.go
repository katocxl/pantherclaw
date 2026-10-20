// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect/v2"
	"google.golang.org/protobuf/proto"

	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	"github.com/katocxl/pantherclaw/internal/gateway/pgdispatch"
	"github.com/katocxl/pantherclaw/internal/gateway/pgtarget"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Codes of a postgres dispatch (G0 M14 D16, D18, D20). A query the
// manifest or the decision does not allow is refused with the pgdispatch
// code, in lower case, before any statement is sent.
const (
	// CodeRoleNotReadOnly: the connection's role failed the HR-309 check;
	// the connection dispatches nothing until it passes.
	CodeRoleNotReadOnly = "role_not_read_only"
	// CodeStatementTimeout: the statement ran past its timeout.
	CodeStatementTimeout = "statement_timeout"
	// CodeTargetMismatch: postgres.tables.read named a pg_database other than
	// the connection's database (D79).
	CodeTargetMismatch = "target_mismatch"
	// CodeKindConfigMissing: the gateway has no postgres configuration for
	// the connection (D85).
	CodeKindConfigMissing = "kind_config_missing"
)

// roleRecheck is how long a passed role check holds before the pool checks
// again.
const roleRecheck = 10 * time.Minute

// pgEntry is one connection revision's pool and its role check.
type pgEntry struct {
	key  string
	pool *pgtarget.Pool
	db   string

	mu      sync.Mutex
	checked time.Time
	// used is when a dispatch last took the pool (under pgPools).
	used time.Time
}

// pgIdle is how long a pool nobody takes stays open: a deleted or retired
// connection's pool closes once it has gone unused this long (D98); a
// changed configuration closes it at once.
const pgIdle = 15 * time.Minute

// pgPools are the open pools of each engine, by connection id.
var pgPools = struct {
	sync.Mutex
	m map[*Engine]map[string]*pgEntry
}{m: map[*Engine]map[string]*pgEntry{}}

// sendPostgres builds, commits, runs and records a read of a postgres
// connection (G0 M14 D16). The statement is built from the permitted
// action alone (HR-307); BeginDispatch commits it; the pool for this
// connection revision and credential runs it in a read-only transaction
// (HR-308) after the role check passed (HR-309). A refused query, a failed
// check, a timeout or a database error is FAILED: a read has no effect to
// be uncertain about.
func (e *Engine) sendPostgres(ctx context.Context, r Result, conn *control.Connection, def *defs.Definition, a actionir.Parsed, want permitWant,
	t *timer,
) Result {
	pc := postgresOf(conn)
	if pc == nil {
		// The configuration never reached this gateway: nothing is committed
		// or sent (D85).
		return r.fail(CannotAuthorize, CodeKindConfigMissing)
	}
	query, buildErr := pgQuery(pc, def, a.Action)
	// A postgres connection is pantherclaw_held only: no action token, and
	// no HTTP request to bind.
	_, err := e.authority.BeginDispatch(ctx, &pb.BeginDispatchRequest{PermitId: want.PermitID, Epoch: want.Epoch})
	t.lap("begin")
	if err != nil {
		r.Reasons = append(r.Reasons, strings.ToUpper(connect.CodeOf(err).String()))
		return r.fail(EnforcementFailed, CodeDispatchRefused)
	}
	ctx = context.WithoutCancel(ctx)
	if buildErr != nil {
		code := CodeRequest
		if c := pgdispatch.CodeOf(buildErr); c != "" {
			code = strings.ToLower(c)
		} else if errors.Is(buildErr, errDatabaseMismatch) {
			code = CodeTargetMismatch
		}
		e.log.WarnContext(ctx, "gateway.request_not_built", slog.String("transaction_id", want.Txn), pclog.Err(buildErr))
		return e.record(ctx, r, want, pb.Outcome_OUTCOME_FAILED, 0, nil, 0, EnforcementFailed, code, t)
	}
	start := time.Now()
	var res pgtarget.Result
	if query.statement == nil {
		// postgres.tables.read answers from the manifest alone.
		body, err := pgdispatch.Describe(query.manifest, query.access)
		if err != nil {
			return e.record(ctx, r, want, pb.Outcome_OUTCOME_FAILED, 0, nil, 0, EnforcementFailed, CodeRequest, t)
		}
		res.Body = body
	} else {
		ent, err := e.pgPool(ctx, conn, def, pc)
		if err != nil {
			return e.credentialFailed(ctx, r, conn, want, err, t)
		}
		runCtx, cancel := context.WithTimeout(ctx, time.Duration(query.manifest.StatementTimeoutMS)*time.Millisecond+pgtarget.ConnectTimeout+5*time.Second)
		defer cancel()
		if findings, err := ent.check(runCtx); err != nil || len(findings) > 0 {
			class, code := pgClassify(err)
			if err == nil {
				class, code = EnforcementFailed, CodeRoleNotReadOnly
				e.log.ErrorContext(ctx, "security.postgres_role_not_read_only", slog.String("connection_id", conn.GetId()),
					slog.Any("findings", findings))
			}
			e.breaker.record(ctx, conn, pb.Outcome_OUTCOME_FAILED)
			return e.record(ctx, r, want, pb.Outcome_OUTCOME_FAILED, 0, nil, time.Since(start), class, code, t)
		}
		res, err = ent.pool.Run(runCtx, query.statement)
		if err != nil {
			class, code := pgClassify(err)
			e.breaker.record(ctx, conn, pb.Outcome_OUTCOME_FAILED)
			e.log.WarnContext(ctx, "gateway.target_error", slog.String("transaction_id", want.Txn), pclog.Err(err))
			return e.record(ctx, r, want, pb.Outcome_OUTCOME_FAILED, 0, nil, time.Since(start), class, code, t)
		}
		e.breaker.record(ctx, conn, pb.Outcome_OUTCOME_ACCEPTED)
	}
	elapsed := time.Since(start)
	t.lap("target")
	sum := sha256.Sum256(res.Body)
	r.Response = &egress.Response{Status: 200, Body: res.Body, ContentType: "application/json"}
	return e.record(ctx, r, want, pb.Outcome_OUTCOME_ACCEPTED, 200, sum[:], elapsed, "", "", t)
}

// pgClassify is the class and code of a failed check or run: a timeout,
// an address the egress checks refused, or another database error. Each
// is FAILED, since a read changes nothing.
func pgClassify(err error) (Class, string) {
	switch {
	case errors.Is(err, pgtarget.ErrTimeout), errors.Is(err, context.DeadlineExceeded):
		return ToolFailed, CodeStatementTimeout
	case errors.Is(err, httpx.ErrDestinationDenied):
		return EnforcementFailed, CodeEgressDenied
	}
	return ToolFailed, CodeTargetRefused
}

// pgPlan is a built query: a statement, or none for the description.
type pgPlan struct {
	manifest  pgdispatch.Manifest
	statement *pgdispatch.Statement
	access    pgdispatch.Access
}

var errDatabaseMismatch = errors.New("dispatch: the target names another database")

// errNoPostgresConfig: the gateway's configuration carries no postgres
// configuration for the connection.
var errNoPostgresConfig = errors.New("dispatch: the connection has no postgres configuration")

// pgQuery builds the statement of a postgres read from the permitted
// action: the target and the typed params only (HR-307).
func pgQuery(pc *pb.PostgresConfig, def *defs.Definition, a actionir.ActionIR) (pgPlan, error) {
	if pc == nil {
		return pgPlan{}, errNoPostgresConfig
	}
	if def.Dispatch == nil || def.Dispatch.SQL == nil {
		return pgPlan{}, fmt.Errorf("%w: no sql dispatch", egress.ErrBuild)
	}
	m, err := pgManifest(pc).Normalized()
	if err != nil {
		return pgPlan{}, err
	}
	vals, err := def.DecodeParams(a.Params)
	if err != nil {
		return pgPlan{}, err
	}
	plan := pgPlan{manifest: m}
	limit := 0
	if v, ok := vals["limit"]; ok {
		if v.Int < 1 {
			// A limit, the clamped one included, is at least one row (D98).
			return pgPlan{}, &pgdispatch.Error{Code: pgdispatch.CodeQueryInvalid, Detail: "limit must be at least 1"}
		}
		limit = int(min(v.Int, int64(pgdispatch.MaxRowsLimit)))
	}
	filters := pgFilters(vals["filters"].Filter)
	switch def.Dispatch.SQL.Operation {
	case "rows":
		var order []pgdispatch.Order
		for _, s := range vals["order_by"].List {
			o, err := pgdispatch.ParseOrder(s)
			if err != nil {
				return pgPlan{}, err
			}
			order = append(order, o)
		}
		plan.statement, err = pgdispatch.BuildRows(m, pgdispatch.Rows{
			Table: a.Target.ID, Columns: vals["columns"].List, Filters: filters, OrderBy: order, Limit: limit, Access: plan.access,
		})
	case "aggregate":
		var measures []pgdispatch.Measure
		for _, s := range vals["measures"].List {
			ms, err := pgdispatch.ParseMeasure(s)
			if err != nil {
				return pgPlan{}, err
			}
			measures = append(measures, ms)
		}
		plan.statement, err = pgdispatch.BuildAggregate(m, pgdispatch.Aggregate{
			Table: a.Target.ID, GroupBy: vals["group_by"].List, Measures: measures, Filters: filters, Limit: limit, Access: plan.access,
		})
	case "tables":
		if a.Target.ID != pc.GetDatabase() {
			return pgPlan{}, errDatabaseMismatch
		}
	default:
		return pgPlan{}, fmt.Errorf("%w: sql operation %q", egress.ErrBuild, def.Dispatch.SQL.Operation)
	}
	return plan, err
}

func pgFilters(ps []defs.Predicate) []pgdispatch.Filter {
	out := make([]pgdispatch.Filter, len(ps))
	for i, p := range ps {
		out[i] = pgdispatch.Filter{Column: p.Column, Op: pgdispatch.Op(p.Op), Value: p.Value, Values: p.Values}
	}
	return out
}

// pgManifest is the connection's manifest as pgdispatch reads it.
func pgManifest(pc *pb.PostgresConfig) pgdispatch.Manifest {
	m := pgdispatch.Manifest{
		MaxRows: int(pc.GetMaxRows()), StatementTimeoutMS: int(pc.GetStatementTimeoutMs()),
		MaxResultBytes: int(pc.GetMaxResultBytes()), MinGroupSize: int(pc.GetMinGroupSize()),
	}
	for _, t := range pc.GetTables() {
		tb := pgdispatch.Table{Schema: t.GetSchema(), Name: t.GetName(), ScopeKey: t.GetScopeKey(), ScopeColumn: t.GetScopeColumn(), MaxRows: int(t.GetMaxRows())}
		for _, c := range t.GetColumns() {
			tb.Columns = append(tb.Columns, pgdispatch.Column{Name: c.GetName(), Type: pgdispatch.ColumnType(c.GetType()), Class: pgdispatch.Class(c.GetClass())})
		}
		m.Tables = append(m.Tables, tb)
	}
	return m
}

// pgPool returns the pool of this connection revision and credential,
// opening it with the sealed password, which must match the definition's
// credential pattern if it declares one.
func (e *Engine) pgPool(ctx context.Context, conn *control.Connection, def *defs.Definition, pc *pb.PostgresConfig) (*pgEntry, error) {
	// A confirmed manifest changes the configuration, not the revision.
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(pc)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	key := fmt.Sprintf("%d/%s/%d/%x", conn.GetRevision(), conn.Credential.GetId(), conn.Credential.GetVersion(), sum)
	pgPools.Lock()
	defer pgPools.Unlock()
	pools := pgPools.m[e]
	if pools == nil {
		pools = map[string]*pgEntry{}
		pgPools.m[e] = pools
	}
	now := time.Now()
	for id, ent := range pools {
		if id != conn.GetId() && now.Sub(ent.used) > pgIdle {
			ent.pool.Close()
			delete(pools, id)
		}
	}
	if ent, ok := pools[conn.GetId()]; ok {
		if ent.key == key {
			ent.used = now
			return ent, nil
		}
		ent.pool.Close()
		delete(pools, conn.GetId())
	}
	plain, err := e.openStatic(ctx, conn)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	if err := CheckCredentialPattern(def, conn.Credential.GetKind(), plain); err != nil {
		return nil, err
	}
	p, err := pgtarget.Open(ctx, pgtarget.Config{
		Endpoint: pgtarget.Endpoint{
			Host: pc.GetHost(), Port: int(pc.GetPort()), Database: pc.GetDatabase(), User: pc.GetUser(), SSLMode: pc.GetSslmode(),
			CAPEM: pc.GetCaPem(), Internal: pc.GetInternal(),
		},
		Manifest: pgManifest(pc),
		Password: string(plain),
		Allowed:  e.allowed,
	})
	if err != nil {
		return nil, err
	}
	ent := &pgEntry{key: key, pool: p, db: pc.GetDatabase(), used: now}
	pools[conn.GetId()] = ent
	return ent, nil
}

// check runs the role check when it has not passed within roleRecheck. A
// failed check is not cached: it runs again on the next dispatch.
func (ent *pgEntry) check(ctx context.Context) ([]string, error) {
	ent.mu.Lock()
	defer ent.mu.Unlock()
	if !ent.checked.IsZero() && time.Since(ent.checked) < roleRecheck {
		return nil, nil
	}
	findings, err := ent.pool.Check(ctx)
	if err == nil && len(findings) == 0 {
		ent.checked = time.Now()
	}
	return findings, err
}

// PostgresCheck runs the HR-309 role check for a postgres connection's
// test (D18): the findings, none when the role passes.
func (e *Engine) PostgresCheck(ctx context.Context, conn *control.Connection) ([]string, error) {
	pc := postgresOf(conn)
	if pc == nil {
		return nil, errNoPostgresConfig
	}
	ent, err := e.pgPool(ctx, conn, &defs.Definition{Dispatch: &defs.Dispatch{}}, pc)
	if err != nil {
		return nil, err
	}
	ent.mu.Lock()
	defer ent.mu.Unlock()
	findings, err := ent.pool.Check(ctx)
	if err == nil && len(findings) == 0 {
		ent.checked = time.Now()
	} else {
		ent.checked = time.Time{}
	}
	return findings, err
}

// postgresTest is a postgres connection's read test (D18): the HR-309 role
// check instead of a read. It reports 200 when the role passes and 403
// when it does not, with the digest of the findings; a check that could
// not run reports nothing, and the test is tried again.
func (e *Engine) postgresTest(ctx context.Context, conn *control.Connection, operation string) (Observation, error) {
	if operation != "postgres.tables.read" {
		return Observation{}, ErrNotReviewedRead
	}
	findings, err := e.PostgresCheck(ctx, conn)
	if errors.Is(err, httpx.ErrDestinationDenied) {
		// The address is outside what this gateway may reach (D98): the test
		// fails, as every dispatch would.
		findings, err = []string{"the database address is outside this gateway's egress allow-list"}, nil
	}
	if err != nil {
		e.log.WarnContext(ctx, "gateway.postgres_test_inconclusive", slog.String("connection_id", conn.GetId()), pclog.Err(err))
		return Observation{}, nil
	}
	status := 200
	if len(findings) > 0 {
		status = 403
		e.log.ErrorContext(ctx, "security.postgres_role_not_read_only", slog.String("connection_id", conn.GetId()),
			slog.Any("findings", findings))
	}
	sum := sha256.Sum256([]byte(strings.Join(findings, "\n")))
	return Observation{HTTPStatus: status, Digest: sum[:]}, nil
}
