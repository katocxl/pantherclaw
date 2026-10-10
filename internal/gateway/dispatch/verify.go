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
	"net/http"
	"strconv"

	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Verification reads (G0 M7 design decision 1, HR-190). The server leases
// a task to the gateway serving its connection; the gateway makes the
// reviewed read the task names through the same egress path as a dispatch
// (host pinning, URL checks, the sealed credential opened for that request
// only, response caps), and reports only the fields the verifier declares.
// A read never writes, and stops when a dispatch would be refused for
// containment.

// Lease is a verification task leased to this gateway.
type Lease struct {
	Connection string
	Task       string
	Secret     []byte
	Purpose    string
	Operation  string
	// Request is the read the server computed: mode, target and params.
	Request []byte
	// Correlate is the idempotency key a listing item must carry.
	Correlate string
}

// Observation is what a leased read observed. Items are a target log's
// listed objects (HR-112).
type Observation struct {
	HTTPStatus int
	Found      bool
	Complete   bool
	Fields     map[string]string
	Digest     []byte
	Items      []TargetLogItem
}

// TargetLogItem is one object a target log lists.
type TargetLogItem struct {
	ObjectRef   string
	Correlation string
	Created     int64
}

// maxTargetLogItems is the most objects one target-log read reports.
const maxTargetLogItems = 1000

// ErrNotReviewedRead refuses a task whose operation is not a GET read
// that a verifier of the connection's pinned package names: nothing is
// sent.
var ErrNotReviewedRead = errors.New("dispatch: the task names no reviewed verifier read of this connection")

// ErrContained refuses a read while a dispatch would be refused for
// containment (kill switch, quarantine, a stale stream): nothing is sent.
var ErrContained = errors.New("dispatch: containment stops verification reads")

// maxPages is the most pages one lookup reads.
const maxPages = 10

// verifyRequest is the read a task names.
type verifyRequest struct {
	Mode   string            `json:"mode"`
	Target actionir.Target   `json:"target"`
	Params map[string]string `json:"params"`
	// EffectOf names, for a target log, the write whose effects it lists.
	EffectOf string `json:"effect_of,omitzero"`
}

// VerifyEffect makes the read a lease names and returns what it observed.
func (e *Engine) VerifyEffect(ctx context.Context, conn *control.Connection, l Lease) (Observation, error) {
	if _, class, _ := e.contained(conn); class != "" {
		return Observation{}, ErrContained
	}
	if l.Purpose == "target_log" {
		return e.targetLog(ctx, conn, l)
	}
	read, v, list, err := reviewedRead(conn, l.Operation)
	if err != nil {
		return Observation{}, err
	}
	var req verifyRequest
	if err := json.Unmarshal(l.Request, &req, json.RejectUnknownMembers(true)); err != nil || (req.Mode != "reference" && req.Mode != "lookup") ||
		(req.Mode == "lookup") != (list != nil) {
		return Observation{}, fmt.Errorf("%w: request", ErrNotReviewedRead)
	}
	declared := map[string]bool{}
	for _, x := range v.Expect {
		declared[x.Field] = true
	}
	if v.States != nil {
		declared[v.States.Field] = true
	}
	params := req.Params
	var out Observation
	for range maxPages {
		status, body, ok := e.read(ctx, conn, read, req.Target, params)
		if !ok {
			return Observation{HTTPStatus: status}, nil // the read failed: inconclusive, retried
		}
		sum := sha256.Sum256(body)
		out.HTTPStatus, out.Digest = status, sum[:]
		if status < 200 || status > 299 {
			return out, nil // not found, refused or failed: the server assesses the status
		}
		if list == nil {
			out.Found, out.Fields = true, fields(body, declared)
			return out, nil
		}
		items, ok := defs.PointerItems(body, list.Items, 1000)
		if !ok {
			return Observation{HTTPStatus: status, Digest: out.Digest}, nil
		}
		last := ""
		for _, it := range items {
			if c, ok := defs.PointerValue(it, list.Correlate); ok && c == l.Correlate {
				out.Found, out.Complete, out.Fields = true, true, fields(it, declared)
				return out, nil
			}
			last, _ = defs.PointerValue(it, list.ID)
		}
		more, _ := defs.PointerValue(body, list.More)
		if list.More == "" || more != "true" {
			out.Complete = true
			return out, nil
		}
		if list.PageParam == "" || last == "" {
			return out, nil // more pages, and no way to reach them: incomplete
		}
		params = map[string]string{}
		for k, x := range req.Params {
			params[k] = x
		}
		params[list.PageParam] = last
	}
	return out, nil // more pages than one lookup reads: incomplete
}

// reviewedRead returns the GET read definition op of the connection's
// package, the verifier of the write that names it, and the listing spec
// when it names it as its lookup.
func reviewedRead(conn *control.Connection, op string) (*defs.Definition, *defs.VerifierSpec, *defs.ListSpec, error) {
	if conn.Package == nil {
		return nil, nil, nil, ErrNotReviewedRead
	}
	read, ok := conn.Package.Definition(op)
	if !ok || read.Access != defs.AccessRead || read.Dispatch == nil || read.Dispatch.HTTP == nil || read.Dispatch.HTTP.Method != http.MethodGet {
		return nil, nil, nil, ErrNotReviewedRead
	}
	for i := range conn.Package.Definitions {
		v := conn.Package.Definitions[i].Verifier
		switch {
		case v == nil || !v.Extended():
		case v.Lookup != nil && v.Lookup.Operation == op:
			return read, v, &v.Lookup.List, nil
		case v.Operation == op:
			return read, v, nil, nil
		}
	}
	return nil, nil, nil, ErrNotReviewedRead
}

// targetLog lists what the target created in the task's window (HR-112):
// the package's reviewed target-log read for the write the task names,
// every page up to maxPages, at most maxTargetLogItems objects, each as its
// id, correlation value and creation time.
func (e *Engine) targetLog(ctx context.Context, conn *control.Connection, l Lease) (Observation, error) {
	var req verifyRequest
	if err := json.Unmarshal(l.Request, &req, json.RejectUnknownMembers(true)); err != nil || req.Mode != "target_log" ||
		conn.Package == nil || req.Target.Type != defs.ConnectionTarget || req.Target.ID != conn.GetId() {
		return Observation{}, fmt.Errorf("%w: request", ErrNotReviewedRead)
	}
	var spec *defs.TargetLog
	for i := range conn.Package.TargetLogs {
		if t := &conn.Package.TargetLogs[i]; t.Operation == l.Operation && t.EffectOf == req.EffectOf {
			spec = t
		}
	}
	if spec == nil {
		return Observation{}, ErrNotReviewedRead
	}
	read, ok := conn.Package.Definition(spec.Operation)
	if !ok || read.Access != defs.AccessRead || read.Dispatch == nil || read.Dispatch.HTTP == nil || read.Dispatch.HTTP.Method != http.MethodGet {
		return Observation{}, ErrNotReviewedRead
	}
	out, params := Observation{}, req.Params
	for range maxPages {
		status, body, ok := e.read(ctx, conn, read, req.Target, params)
		if !ok {
			return Observation{HTTPStatus: status, Items: out.Items}, nil
		}
		sum := sha256.Sum256(body)
		out.HTTPStatus, out.Digest = status, sum[:]
		if status < 200 || status > 299 {
			return out, nil
		}
		items, ok := defs.PointerItems(body, spec.List.Items, maxTargetLogItems)
		if !ok {
			return out, nil
		}
		last := ""
		for _, it := range items {
			ref, ok := defs.PointerValue(it, spec.List.ID)
			if !ok || ref == "" || len(ref) > 256 || len(out.Items) == maxTargetLogItems {
				continue
			}
			corr, _ := defs.PointerValue(it, spec.List.Correlate)
			created, _ := defs.PointerValue(it, spec.List.Created)
			n, _ := strconv.ParseInt(created, 10, 64)
			if len(corr) > 256 {
				corr = ""
			}
			out.Items = append(out.Items, TargetLogItem{ObjectRef: ref, Correlation: corr, Created: max(n, 0)})
			last = ref
		}
		more, _ := defs.PointerValue(body, spec.List.More)
		if spec.List.More == "" || more != "true" {
			out.Complete = len(out.Items) < maxTargetLogItems || len(items) == 0
			return out, nil
		}
		if spec.List.PageParam == "" || last == "" || len(out.Items) == maxTargetLogItems {
			return out, nil
		}
		params = map[string]string{}
		for k, x := range req.Params {
			params[k] = x
		}
		params[spec.List.PageParam] = last
	}
	return out, nil
}

// read sends one GET of read with the connection's credential and returns
// the status and the capped body; false when the request could not be
// built or sent, or no answer came back (the read is inconclusive).
func (e *Engine) read(ctx context.Context, conn *control.Connection, read *defs.Definition, target actionir.Target,
	params map[string]string,
) (int, []byte, bool) {
	raw, err := json.Marshal(params, json.Deterministic(true))
	if err != nil {
		return 0, nil, false
	}
	a := actionir.Parsed{Action: actionir.ActionIR{Operation: read.Operation, Target: target, Params: raw}}
	p, err := e.prepare(ctx, conn, read, a, "")
	if err != nil {
		e.log.WarnContext(ctx, "gateway.verification_not_built", slog.String("connection_id", conn.GetId()), pclog.Err(err))
		return 0, nil, false
	}
	if conn.GetAccessMode() == "pantherclaw_held" {
		secret, err := e.credential(conn, p.req)
		if err != nil {
			e.log.WarnContext(ctx, "gateway.credential_unavailable", slog.String("connection_id", conn.GetId()), pclog.Err(err))
			return 0, nil, false
		}
		defer clear(secret)
	}
	res, err := p.client.Do(p.req)
	if err != nil {
		return res.Status, nil, false
	}
	return res.Status, res.Body, true
}

// fields reads the declared fields of a JSON object.
func fields(doc []byte, declared map[string]bool) map[string]string {
	out := map[string]string{}
	for ptr := range declared {
		if s, ok := defs.PointerValue(doc, ptr); ok && len(s) <= 256 {
			out[ptr] = s
		}
	}
	return out
}
