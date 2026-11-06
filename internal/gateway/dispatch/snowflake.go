// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"crypto/sha256"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	"github.com/katocxl/pantherclaw/internal/gateway/pgdispatch"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// KindSnowflake is the kind of a Snowflake account read over the Snowflake
// SQL API (G0 M31 D962).
const KindSnowflake = "snowflake"

func init() { kindSenders[KindSnowflake] = (*Engine).sendSnowflake }

// SnowflakeStatementsPath is the SQL API's statements endpoint.
const SnowflakeStatementsPath = "/api/v2/statements"

// snowflakePoll is how often a statement still running is asked about.
const snowflakePoll = 500 * time.Millisecond

// snowflakeHandleRe is a statement handle: a UUID, nothing else.
var snowflakeHandleRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// sendSnowflake builds, commits, sends and records a read of a snowflake
// connection (G0 M31 D962). The statement is built from the permitted
// action alone, by the postgres builder in the Snowflake dialect (HR-307):
// identifiers from the manifest, every value bound as TEXT and cast in
// SQL. BeginDispatch binds the POST's body; a key-pair JWT signed for this
// call is placed, never the key (HR-726). A statement Snowflake has not
// finished is asked about until its timeout. A refused query, a failed
// call or a timeout is FAILED: a read has no effect to be uncertain about.
func (e *Engine) sendSnowflake(ctx context.Context, r Result, conn *control.Connection, def *defs.Definition, a actionir.Parsed, want permitWant,
	t *timer,
) Result {
	sc := conn.GetSnowflake()
	if sc == nil {
		// No confirmed manifest reached this gateway: nothing is committed
		// or sent.
		return r.fail(CannotAuthorize, CodeKindConfigMissing)
	}
	plan, buildErr := sfQuery(sc, def, a.Action, scopeOf(ctx))
	if pgdispatch.CodeOf(buildErr) == pgdispatch.CodeScopeUnsupported {
		r.Decision = pb.Decision_DECISION_CANNOT_AUTHORIZE
		return r.fail(CannotAuthorize, CodeScopeUnsupported)
	}
	var (
		body []byte
		u    *url.URL
	)
	if buildErr == nil && plan.statement != nil {
		body, buildErr = sfBody(sc, plan.statement)
		if buildErr == nil {
			u, buildErr = url.Parse(strings.TrimSuffix(conn.GetBaseUrl(), "/") + SnowflakeStatementsPath)
		}
	}
	begin := &pb.BeginDispatchRequest{PermitId: want.PermitID, Epoch: want.Epoch}
	if buildErr == nil && body != nil {
		sum := sha256.Sum256(body)
		begin.OutboundMethod, begin.OutboundUrl, begin.OutboundBodySha256 = http.MethodPost, u.String(), sum[:]
	}
	_, err := e.authority.BeginDispatch(ctx, begin)
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
	var answer []byte
	if plan.statement == nil {
		// snowflake.tables.read answers from the manifest alone.
		answer, err = pgdispatch.Describe(plan.manifest, plan.access)
		if err != nil {
			return e.record(ctx, r, want, pb.Outcome_OUTCOME_FAILED, 0, nil, 0, EnforcementFailed, CodeRequest, t)
		}
	} else {
		client, err := e.client(conn)
		var req *http.Request
		if err == nil {
			req, err = client.HTTPRequest(ctx, egress.Request{Method: http.MethodPost, URL: u, Body: body, ContentType: "application/json"})
		}
		if err != nil {
			return e.record(ctx, r, want, pb.Outcome_OUTCOME_FAILED, 0, nil, 0, EnforcementFailed, CodeRequest, t)
		}
		req.Header.Set("Accept", "application/json")
		secret, release, _, err := e.credential(ctx, conn, def, a.Action.Target, req, client, "")
		if err != nil {
			return e.credentialFailed(ctx, r, conn, want, err, t)
		}
		defer release()
		_ = secret
		deadline := start.Add(time.Duration(sc.GetStatementTimeoutMs())*time.Millisecond + 10*time.Second)
		answer, err = e.runSnowflake(ctx, client, req, u, plan, deadline)
		if err != nil {
			class, code := sfClassify(err)
			e.breaker.record(ctx, conn, pb.Outcome_OUTCOME_FAILED)
			e.log.WarnContext(ctx, "gateway.target_error", slog.String("transaction_id", want.Txn), pclog.Err(err))
			return e.record(ctx, r, want, pb.Outcome_OUTCOME_FAILED, 0, nil, time.Since(start), class, code, t)
		}
		e.breaker.record(ctx, conn, pb.Outcome_OUTCOME_ACCEPTED)
	}
	elapsed := time.Since(start)
	t.lap("target")
	sum := sha256.Sum256(answer)
	r.Response = &egress.Response{Status: 200, Body: answer, ContentType: "application/json"}
	return e.record(ctx, r, want, pb.Outcome_OUTCOME_ACCEPTED, 200, sum[:], elapsed, "", "", t)
}

// Errors of a snowflake call.
var (
	errSnowflakeTimeout = errors.New("dispatch: the snowflake statement did not finish in time")
	errSnowflakeRefused = errors.New("dispatch: snowflake refused the statement")
	errSnowflakeAnswer  = errors.New("dispatch: the snowflake answer is not one the gateway reads")
)

// sfClassify is the class and code of a failed snowflake call; each is
// FAILED, since a read changes nothing.
func sfClassify(err error) (Class, string) {
	switch {
	case errors.Is(err, errSnowflakeTimeout), errors.Is(err, context.DeadlineExceeded):
		return ToolFailed, CodeStatementTimeout
	case errors.Is(err, httpx.ErrDestinationDenied):
		return EnforcementFailed, CodeEgressDenied
	}
	return ToolFailed, CodeTargetRefused
}

// sfAnswer is the part of a SQL API answer the gateway reads.
type sfAnswer struct {
	StatementHandle   string `json:"statementHandle"`
	ResultSetMetaData struct {
		RowType       []jsontext.Value `json:"rowType"`
		PartitionInfo []jsontext.Value `json:"partitionInfo"`
	} `json:"resultSetMetaData"`
	Data [][]*string `json:"data"`
}

// runSnowflake sends the statement and, while Snowflake answers 202 (still
// running), asks about it with the same JWT until the deadline. A 200's
// first partition is encoded as a postgres read's answer is; a later
// partition is never fetched, and the answer says it is truncated.
func (e *Engine) runSnowflake(ctx context.Context, client *egress.Client, req *http.Request, u *url.URL, plan pgPlan,
	deadline time.Time,
) ([]byte, error) {
	res, err := client.Do(req)
	for {
		if err != nil {
			return nil, err
		}
		if res.Truncated {
			return nil, errSnowflakeAnswer
		}
		var a sfAnswer
		switch res.Status {
		case http.StatusOK:
			if json.Unmarshal(res.Body, &a) != nil {
				return nil, errSnowflakeAnswer
			}
			return sfEncode(plan, a)
		case http.StatusAccepted:
			if json.Unmarshal(res.Body, &a) != nil || !snowflakeHandleRe.MatchString(a.StatementHandle) {
				return nil, errSnowflakeAnswer
			}
		case http.StatusRequestTimeout:
			return nil, errSnowflakeTimeout
		default:
			return nil, fmt.Errorf("%w: HTTP %d", errSnowflakeRefused, res.Status)
		}
		if time.Now().Add(snowflakePoll).After(deadline) {
			return nil, errSnowflakeTimeout
		}
		time.Sleep(snowflakePoll)
		// A poll goes only to the connection's own host, at
		// /api/v2/statements/{handle} with handle a UUID (G0 M31 D962,
		// choice 11): the URL is rebuilt from the base URL's scheme and host,
		// never taken from the answer.
		if u.Path != SnowflakeStatementsPath || !snowflakeHandleRe.MatchString(a.StatementHandle) {
			return nil, errSnowflakeAnswer
		}
		poll := url.URL{Scheme: u.Scheme, Host: u.Host, Path: SnowflakeStatementsPath + "/" + a.StatementHandle}
		next, perr := client.HTTPRequest(ctx, egress.Request{Method: http.MethodGet, URL: &poll})
		if perr != nil {
			return nil, perr
		}
		for _, h := range []string{"Authorization", "X-Snowflake-Authorization-Token-Type", "Accept"} {
			next.Header.Set(h, req.Header.Get(h))
		}
		res, err = client.Do(next)
	}
}

// sfEncode encodes a finished statement's first partition.
func sfEncode(plan pgPlan, a sfAnswer) ([]byte, error) {
	st := plan.statement
	if len(a.ResultSetMetaData.RowType) != st.Selected() {
		return nil, errSnowflakeAnswer
	}
	enc := pgdispatch.NewEncoder(st, plan.manifest.MaxResultBytes)
	for _, row := range a.Data {
		if len(row) != st.Selected() {
			return nil, errSnowflakeAnswer
		}
		more, err := enc.Add(row)
		if err != nil {
			return nil, errors.Join(errSnowflakeAnswer, err)
		}
		if !more {
			break
		}
	}
	if len(a.ResultSetMetaData.PartitionInfo) > 1 {
		enc.MarkTruncated()
	}
	return enc.Bytes(), nil
}

// sfBody is the SQL API request of a statement: the statement, its
// bindings, the timeout in seconds and the account's warehouse, database
// and schema, upper case as Snowflake stores them.
func sfBody(sc *pb.SnowflakeConfig, st *pgdispatch.Statement) ([]byte, error) {
	bindings, err := st.Bindings()
	if err != nil {
		return nil, err
	}
	timeout := (int64(sc.GetStatementTimeoutMs()) + 999) / 1000
	return json.Marshal(map[string]any{
		"statement": st.SQL, "bindings": bindings, "timeout": max(timeout, 1),
		"warehouse": strings.ToUpper(sc.GetWarehouse()), "database": strings.ToUpper(sc.GetDatabase()),
		"schema": strings.ToUpper(sc.GetSchema()),
	}, json.Deterministic(true))
}

// sfQuery builds the statement of a snowflake read from the permitted
// action, as pgQuery does for postgres, in the Snowflake dialect.
func sfQuery(sc *pb.SnowflakeConfig, def *defs.Definition, a actionir.ActionIR, scope *dataScope) (pgPlan, error) {
	// The statement timeout goes in the SQL API request (sfBody), not the
	// builder, whose postgres bound (30 s) is below Snowflake's (60 s).
	pc := &pb.PostgresConfig{
		Database: sc.GetDatabase(), Tables: sc.GetTables(), MaxRows: sc.GetMaxRows(), StatementTimeoutMs: 1,
		MaxResultBytes: sc.GetMaxResultBytes(), MinGroupSize: sc.GetMinGroupSize(),
	}
	return pgQueryIn(pc, def, a, scope, nil, pgdispatch.DialectSnowflake)
}
