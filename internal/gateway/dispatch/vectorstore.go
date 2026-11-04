// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"crypto/sha256"
	"encoding/json/v2"
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
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// KindVectorstore is the kind of a retrieval-index connection on pgvector
// (G0 M30 D922).
const KindVectorstore = "vectorstore"

// Codes of a vectorstore dispatch (G0 M30 D923, D924).
const (
	// CodeRoleSuperuser: the connection's role is a superuser, or the
	// vector extension is missing; the connection dispatches nothing until
	// the check passes.
	CodeRoleSuperuser = "role_superuser"
	// CodeProvenanceMissing: a write's permit carried no run or agent, so
	// the record's provenance is not known; nothing is sent (HR-704).
	CodeProvenanceMissing = "provenance_missing"
)

func init() { kindSenders[KindVectorstore] = (*Engine).sendVectorstore }

// vecEntry is one vectorstore connection revision's pool and its check.
type vecEntry struct {
	key         string
	pool        *pgtarget.VectorPool
	credID      string
	credVersion int32

	mu      sync.Mutex
	checked time.Time
	used    time.Time
}

// vecPools are the open vectorstore pools of each engine, by connection id.
var vecPools = struct {
	sync.Mutex
	m map[*Engine]map[string]*vecEntry
}{m: map[*Engine]map[string]*vecEntry{}}

// sendVectorstore builds, commits, runs and records a vectorstore query or
// write (G0 M30 D922-D924). The statement is built from the permitted
// action alone; a write's pc_* columns come from the verified permit
// (D923, HR-704). A query, or a write refused before COMMIT is sent, is
// FAILED when it fails; a write whose COMMIT does not answer is UNKNOWN.
func (e *Engine) sendVectorstore(ctx context.Context, r Result, conn *control.Connection, def *defs.Definition, a actionir.Parsed, want permitWant,
	t *timer,
) Result {
	vc := conn.GetVectorstore()
	if vc == nil {
		return r.fail(CannotAuthorize, CodeKindConfigMissing)
	}
	st, write, buildErr := vecStatement(vc, def, a.Action, want)
	if errors.Is(buildErr, errProvenanceMissing) {
		// Refused before anything is committed or sent (D923a).
		r.Decision = pb.Decision_DECISION_CANNOT_AUTHORIZE
		return r.fail(CannotAuthorize, CodeProvenanceMissing)
	}
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
		}
		e.log.WarnContext(ctx, "gateway.request_not_built", slog.String("transaction_id", want.Txn), pclog.Err(buildErr))
		return e.record(ctx, r, want, pb.Outcome_OUTCOME_FAILED, 0, nil, 0, EnforcementFailed, code, t)
	}
	start := time.Now()
	ent, err := e.vecPool(ctx, conn, def, vc)
	if err != nil {
		return e.credentialFailed(ctx, r, conn, want, err, t)
	}
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(pgdispatch.VectorStatementTimeoutMS)*time.Millisecond+pgtarget.ConnectTimeout+5*time.Second)
	defer cancel()
	if findings, err := ent.check(runCtx); err != nil || len(findings) > 0 {
		class, code := pgClassify(err)
		if err == nil {
			class, code = EnforcementFailed, CodeRoleSuperuser
			e.log.ErrorContext(ctx, "security.vectorstore_role_refused", slog.String("connection_id", conn.GetId()),
				slog.Any("findings", findings))
		}
		e.breaker.record(ctx, conn, pb.Outcome_OUTCOME_FAILED)
		return e.record(ctx, r, want, pb.Outcome_OUTCOME_FAILED, 0, nil, time.Since(start), class, code, t)
	}
	var body []byte
	if write {
		n, err := ent.pool.Exec(runCtx, st)
		if errors.Is(err, pgtarget.ErrCommitUnknown) {
			e.breaker.record(ctx, conn, pb.Outcome_OUTCOME_UNKNOWN)
			e.log.WarnContext(ctx, "gateway.target_uncertain", slog.String("transaction_id", want.Txn), pclog.Err(err))
			return e.record(ctx, r, want, pb.Outcome_OUTCOME_UNKNOWN, 0, nil, time.Since(start), Uncertain, CodeTargetUncertain, t)
		}
		if err != nil {
			class, code := pgClassify(err)
			e.breaker.record(ctx, conn, pb.Outcome_OUTCOME_FAILED)
			e.log.WarnContext(ctx, "gateway.target_error", slog.String("transaction_id", want.Txn), pclog.Err(err))
			return e.record(ctx, r, want, pb.Outcome_OUTCOME_FAILED, 0, nil, time.Since(start), class, code, t)
		}
		body, err = json.Marshal(struct {
			Rows int64 `json:"rows"`
		}{n})
		if err != nil {
			return e.record(ctx, r, want, pb.Outcome_OUTCOME_UNKNOWN, 0, nil, time.Since(start), Uncertain, CodeTargetUncertain, t)
		}
	} else {
		res, err := ent.pool.Query(runCtx, st, pgdispatch.VectorMaxResultBytes)
		if err != nil {
			class, code := pgClassify(err)
			e.breaker.record(ctx, conn, pb.Outcome_OUTCOME_FAILED)
			e.log.WarnContext(ctx, "gateway.target_error", slog.String("transaction_id", want.Txn), pclog.Err(err))
			return e.record(ctx, r, want, pb.Outcome_OUTCOME_FAILED, 0, nil, time.Since(start), class, code, t)
		}
		body = res.Body
	}
	e.breaker.record(ctx, conn, pb.Outcome_OUTCOME_ACCEPTED)
	elapsed := time.Since(start)
	t.lap("target")
	sum := sha256.Sum256(body)
	r.Response = &egress.Response{Status: 200, Body: body, ContentType: "application/json"}
	return e.record(ctx, r, want, pb.Outcome_OUTCOME_ACCEPTED, 200, sum[:], elapsed, "", "", t)
}

// errProvenanceMissing: a write's permit carried no run or agent.
var errProvenanceMissing = errors.New("dispatch: the permit carries no provenance")

// vecTable is the connection's table as pgdispatch reads it.
func vecTable(vc *pb.VectorstoreConfig) pgdispatch.VectorTable {
	return pgdispatch.VectorTable{
		Schema: vc.GetSchemaName(), Name: vc.GetTableName(), Dimensions: int(vc.GetDimensions()), Distance: pgdispatch.Distance(vc.GetDistance()),
	}
}

// vecStatement builds the statement of a vectorstore action from the
// permitted action (its target and typed params) and, for a write, the
// permit's provenance. write reports an upsert or delete.
func vecStatement(vc *pb.VectorstoreConfig, def *defs.Definition, a actionir.ActionIR, want permitWant) (*pgdispatch.Statement, bool, error) {
	if def.Dispatch == nil || def.Dispatch.SQL == nil {
		return nil, false, fmt.Errorf("%w: no sql dispatch", egress.ErrBuild)
	}
	op := def.Dispatch.SQL.Operation
	write := op == defs.VectorUpsert || op == defs.VectorDelete
	if write && (want.Run == "" || want.Agent == "") {
		return nil, write, errProvenanceMissing
	}
	table := vecTable(vc)
	if a.Target.ID != table.Schema+"."+table.Name {
		return nil, write, errDatabaseMismatch
	}
	vals, err := def.DecodeParams(a.Params)
	if err != nil {
		return nil, write, err
	}
	var st *pgdispatch.Statement
	switch op {
	case defs.VectorQuery:
		st, err = pgdispatch.BuildVectorQuery(pgdispatch.VectorQuery{
			Table: table, Embedding: vals["embedding"].Floats, TopK: int(min(max(vals["top_k"].Int, 0), int64(pgdispatch.MaxTopK)+1)), Filter: vals["filter"].Map,
		})
	case defs.VectorUpsert:
		st, err = pgdispatch.BuildVectorUpsert(pgdispatch.VectorUpsert{
			Table: table, ID: vals["id"].Str, Content: vals["content"].Str, Embedding: vals["embedding"].Floats, Metadata: vals["metadata"].Map,
			Provenance: pgdispatch.Provenance{RunID: want.Run, AgentID: want.Agent, TransactionID: want.Txn},
		})
	case defs.VectorDelete:
		st, err = pgdispatch.BuildVectorDelete(pgdispatch.VectorDelete{Table: table, ID: vals["id"].Str})
	default:
		return nil, write, fmt.Errorf("%w: sql operation %q", egress.ErrBuild, op)
	}
	return st, write, err
}

// vecPool returns the pool of this connection revision and credential,
// opening it with the sealed password.
func (e *Engine) vecPool(ctx context.Context, conn *control.Connection, def *defs.Definition, vc *pb.VectorstoreConfig) (*vecEntry, error) {
	if def.Dispatch != nil && def.Dispatch.CredentialPattern != "" {
		plain, err := e.openStatic(ctx, conn)
		if err != nil {
			return nil, err
		}
		err = CheckCredentialPattern(def, conn.Credential.GetKind(), plain)
		clear(plain)
		if err != nil {
			return nil, err
		}
	}
	key, err := vecKey(conn, vc)
	if err != nil {
		return nil, err
	}
	vecPools.Lock()
	defer vecPools.Unlock()
	pools := vecPools.m[e]
	if pools == nil {
		pools = map[string]*vecEntry{}
		vecPools.m[e] = pools
	}
	now := time.Now()
	for id, ent := range pools {
		if id != conn.GetId() && now.Sub(ent.used) > pgIdle {
			go ent.pool.Close()
			delete(pools, id)
		}
	}
	if ent, ok := pools[conn.GetId()]; ok {
		if ent.key == key {
			ent.used = now
			usedCredentialVersion(ctx, conn.GetId(), ent.credID, ent.credVersion)
			return ent, nil
		}
		go ent.pool.Close()
		delete(pools, conn.GetId())
	}
	plain, err := e.openStatic(ctx, conn)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	p, err := pgtarget.OpenVector(ctx, pgtarget.VectorConfig{
		Endpoint: pgtarget.Endpoint{
			Host: vc.GetHost(), Port: int(vc.GetPort()), Database: vc.GetDatabase(), User: vc.GetUser(), SSLMode: vc.GetSslmode(),
			CAPEM: vc.GetCaPem(), Internal: vc.GetInternal(),
		},
		Password: string(plain),
		Allowed:  e.allowed,
	})
	if err != nil {
		return nil, err
	}
	ent := &vecEntry{key: key, pool: p, used: now, credID: conn.Credential.GetId(), credVersion: conn.Credential.GetVersion()}
	pools[conn.GetId()] = ent
	return ent, nil
}

// check runs the role check when it has not passed within roleRecheck; a
// failed check is not cached.
func (ent *vecEntry) check(ctx context.Context) ([]string, error) {
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

// vectorConfigured closes the pools of vectorstore connections a new
// configuration no longer serves, or serves with another configuration.
func (e *Engine) vectorConfigured(cfg *control.Config) {
	var closing []*pgtarget.VectorPool
	defer func() {
		for _, p := range closing {
			go p.Close()
		}
	}()
	vecPools.Lock()
	defer vecPools.Unlock()
	for id, ent := range vecPools.m[e] {
		conn, ok := cfg.ByID[id]
		if ok && conn.GetKind() == KindVectorstore && conn.GetVectorstore() != nil {
			if key, err := vecKey(conn, conn.GetVectorstore()); err == nil && key == ent.key {
				continue
			}
		}
		closing = append(closing, ent.pool)
		delete(vecPools.m[e], id)
	}
}

// vecKey identifies what a pool was opened for: the connection revision,
// the credential version and the configuration.
func vecKey(conn *control.Connection, vc *pb.VectorstoreConfig) (string, error) {
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(vc)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return fmt.Sprintf("%d/%s/%d/%x", conn.GetRevision(), conn.Credential.GetId(), conn.Credential.GetVersion(), sum), nil
}
