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
	"maps"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	"github.com/katocxl/pantherclaw/internal/gateway/githubscan"
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
	// Tokens gets a target_verifier test's action tokens under this lease
	// (N15); nil for any other lease.
	Tokens func(ctx context.Context) (TestTokens, error)
}

// TestTokens are a target_verifier test's action tokens: Fresh binds the
// test read's empty body, Mismatch another body.
type TestTokens struct {
	Fresh, Mismatch string
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
	// Installation is, for an org scan, the connection's own GitHub App
	// installation as read; nil when it was not.
	Installation *githubscan.Installation
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
	switch l.Purpose {
	case "connection_test":
		return e.connectionTest(ctx, conn, l)
	case "target_log":
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
	for _, ptr := range v.Capture {
		declared[ptr] = true
	}
	if v.Lookup != nil && v.Lookup.Creator != nil {
		declared[defs.OthersField] = true
	}
	params := req.Params
	var out Observation
	var matched [][]byte // a matched lookup's items, from every page (G0 M8 W1c)
	others, crowded := 0, false
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
		// A page as full as GitHub's default, with no way to ask for more,
		// may have cut the listing: the matches read are not all of them.
		crowded = crowded || (len(v.Lookup.Match) > 0 && list.More == "" && len(items) >= defaultPage)
		for _, it := range items {
			if len(v.Lookup.Match) > 0 {
				switch {
				case !matches(it, v.Lookup.Match, req.Params):
				case createdBy(it, v.Lookup.Creator):
					matched = append(matched, it)
				default:
					others++ // made by someone else: evidence, not the outcome
				}
			} else if c, ok := defs.PointerValue(it, list.Correlate); ok && c == l.Correlate {
				out.Found, out.Complete, out.Fields = true, true, fields(it, declared)
				return out, nil
			}
			last, _ = defs.PointerValue(it, list.ID)
		}
		more, _ := defs.PointerValue(body, list.More)
		if list.More == "" || more != "true" {
			out.Complete = true
			if len(v.Lookup.Match) > 0 {
				return e.judge(ctx, conn, v, req.Target, matched, others, crowded, list.ID, declared, out)
			}
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

// matches reports whether a listed item's fields equal the request's
// params, as a matched lookup names them (G0 M8 W1c).
func matches(item []byte, match []defs.Expectation, params map[string]string) bool {
	for _, m := range match {
		want, ok := params[strings.TrimPrefix(m.Equals, "params.")]
		if got, found := defs.PointerValue(item, m.Field); !ok || !found || got != want {
			return false
		}
	}
	return true
}

// maxMatched is the most matched items a lookup reads the statuses of;
// more is a disagreement, never a verdict from some of them (#349 review).
// defaultPage is GitHub's default page size: a listing that fills it
// without saying there is more may be cut, and is treated alike.
const (
	maxMatched  = 10
	defaultPage = 30
)

// createdBy reports whether an item or a status was made by a creator the
// lookup names; any is, when it names none.
func createdBy(item []byte, c *defs.CreatorSpec) bool {
	if c == nil {
		return true
	}
	who, ok := defs.PointerValue(item, c.Field)
	return ok && slices.Contains(c.OneOf, who)
}

// judge reads the verifier for the items a matched lookup found, each by
// its id in the verifier read's id_param (G0 M8 W1c, coordinator decision
// D13). With statuses declared, each item's verdict is its latest status
// from a named creator, unproven when it needs an earlier one that is not
// there; items whose verdicts differ give a disagreement, and the newest
// never wins. Without, the first item's read is the observation. Items
// made by others are only counted, as evidence. A failed read is
// inconclusive and retried.
func (e *Engine) judge(ctx context.Context, conn *control.Connection, v *defs.VerifierSpec, target actionir.Target, matched [][]byte,
	others int, crowded bool, idPtr string, declared map[string]bool, out Observation,
) (Observation, error) {
	l := v.Lookup
	if l.Creator != nil {
		out.Fields = map[string]string{defs.OthersField: strconv.Itoa(others)}
	}
	if len(matched) == 0 {
		return out, nil
	}
	read, found := conn.Package.Definition(v.Operation)
	if !found || read.Access != defs.AccessRead || read.Dispatch == nil || read.Dispatch.HTTP == nil || read.Dispatch.HTTP.Method != http.MethodGet {
		return Observation{}, fmt.Errorf("%w: lookup read", ErrNotReviewedRead)
	}
	if l.Statuses != nil && (len(matched) > maxMatched || crowded) {
		// Too many to read them all: a person decides, as for matches that
		// disagree; reading some would let newer ones hide the rest.
		out.Found = true
		if out.Fields == nil {
			out.Fields = map[string]string{}
		}
		out.Fields[l.Statuses.Field] = defs.VerdictDisagreement
		return out, nil
	}
	verdicts := map[string]bool{}
	for _, it := range matched[:min(len(matched), maxMatched)] {
		id, ok := defs.PointerValue(it, idPtr)
		if !ok || id == "" {
			return Observation{}, fmt.Errorf("%w: lookup item without an id", ErrNotReviewedRead)
		}
		status, body, ok := e.read(ctx, conn, read, target, map[string]string{l.IDParam: id})
		if !ok || status < 200 || status > 299 {
			return Observation{HTTPStatus: status}, nil
		}
		sum := sha256.Sum256(body)
		out.HTTPStatus, out.Digest, out.Found = status, sum[:], true
		if l.Statuses == nil {
			fs := fields(body, declared)
			if out.Fields != nil {
				maps.Copy(fs, out.Fields)
			}
			out.Fields = fs
			return out, nil
		}
		verdicts[verdict(body, l)] = true
	}
	delete(verdicts, "") // nothing counted yet: read again
	if out.Fields == nil {
		out.Fields = map[string]string{}
	}
	switch len(verdicts) {
	case 0:
	case 1:
		for state := range verdicts {
			out.Fields[l.Statuses.Field] = state
		}
	default:
		out.Fields[l.Statuses.Field] = defs.VerdictDisagreement
	}
	return out, nil
}

// verdict is an item's latest status from a creator the lookup names,
// newest first as the read lists them; a status that needs an earlier one
// it does not have is unproven; "" when none counts.
func verdict(body []byte, l *defs.VerifierLookup) string {
	items, ok := defs.PointerItems(body, l.Statuses.Items, 1000)
	if !ok {
		return ""
	}
	var counted []string
	for _, it := range items {
		if !createdBy(it, l.Creator) {
			continue
		}
		if st, ok := defs.PointerValue(it, l.Statuses.Field); ok && st != "" {
			counted = append(counted, st)
		}
	}
	if len(counted) == 0 {
		return ""
	}
	latest := counted[0]
	if need, ok := l.Statuses.Earlier[latest]; ok && !slices.ContainsFunc(counted[1:], func(s string) bool { return slices.Contains(need, s) }) {
		return defs.VerdictUnproven
	}
	return latest
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
	res, ok := e.readWith(ctx, conn, read, target, params, "")
	return res.Status, res.Body, ok
}

// readWith makes a reviewed read through the connection, with an action token
// when token is set, and returns the whole answer.
func (e *Engine) readWith(ctx context.Context, conn *control.Connection, read *defs.Definition, target actionir.Target,
	params map[string]string, token string,
) (egress.Response, bool) {
	raw, err := json.Marshal(params, json.Deterministic(true))
	if err != nil {
		return egress.Response{}, false
	}
	a := actionir.Parsed{Action: actionir.ActionIR{Operation: read.Operation, Target: target, Params: raw}}
	p, err := e.prepare(ctx, conn, read, a, "")
	if err != nil {
		e.log.WarnContext(ctx, "gateway.verification_not_built", slog.String("connection_id", conn.GetId()), pclog.Err(err))
		return egress.Response{}, false
	}
	if conn.GetAccessMode() == "pantherclaw_held" {
		_, release, _, err := e.credential(ctx, conn, read, target, p.req, p.client, "verification")
		if err != nil {
			e.log.WarnContext(ctx, "gateway.credential_unavailable", slog.String("connection_id", conn.GetId()), pclog.Err(err))
			return egress.Response{}, false
		}
		defer release()
	}
	if token != "" {
		p.req.Header.Set(HeaderAction, token)
	}
	res, err := p.client.Do(p.req)
	if err != nil {
		return egress.Response{Status: res.Status}, false
	}
	if e.stripeAnswerLive(ctx, conn, res.Body, "verify") {
		return egress.Response{Status: res.Status}, false
	}
	return res, true
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

// connectionTest makes a connection test's read (G0 M8 track C, F354): the
// package's one test read, against the connection itself, with no params.
// The format makes it a GET with no required params, and it is checked
// again here before anything is sent: a test never writes. Only the
// status and the digest of the answer are reported. A target_verifier test
// (N15) sends that read four times on a target_enforced connection; see
// verifierTest.
func (e *Engine) connectionTest(ctx context.Context, conn *control.Connection, l Lease) (Observation, error) {
	var req verifyRequest
	if err := json.Unmarshal(l.Request, &req, json.RejectUnknownMembers(true)); err != nil ||
		(req.Mode != "connection_test" && req.Mode != modeVerifierTest) ||
		conn.Package == nil || req.Target.Type != defs.ConnectionTarget || req.Target.ID != conn.GetId() || len(req.Params) != 0 ||
		req.EffectOf != "" {
		return Observation{}, fmt.Errorf("%w: request", ErrNotReviewedRead)
	}
	if conn.GetKind() == "postgres" {
		return e.postgresTest(ctx, conn, l.Operation)
	}
	read, ok := conn.Package.Definition(l.Operation)
	if !ok || !read.Test || read.Access != defs.AccessRead || read.Dispatch == nil || read.Dispatch.HTTP == nil ||
		read.Dispatch.HTTP.Method != http.MethodGet {
		return Observation{}, ErrNotReviewedRead
	}
	if req.Mode == modeVerifierTest {
		return e.verifierTest(ctx, conn, read, req.Target, l)
	}
	status, body, ok := e.read(ctx, conn, read, req.Target, nil)
	if !ok {
		return Observation{HTTPStatus: status}, nil // the read failed: inconclusive, retried
	}
	sum := sha256.Sum256(body)
	return Observation{HTTPStatus: status, Digest: sum[:]}, nil
}

// modeVerifierTest is a target_verifier test's request mode.
const modeVerifierTest = "target_verifier"

// problemRe is the type of a PantherClaw verifier's problem document.
var problemRe = regexp.MustCompile(`^urn:pantherclaw:action-token:[a-z_]{1,40}$`)

// verifierTest sends a target_verifier test's four requests (N15): the
// test read without a token, with the token bound to another body, with
// the fresh token and with the same token again. It reports each as
// "<status> <problem type>", the type only when the answer is a
// PantherClaw verifier's problem document; the server judges them. A
// request the gateway could not make leaves the test inconclusive, and it
// is tried again.
func (e *Engine) verifierTest(ctx context.Context, conn *control.Connection, read *defs.Definition, target actionir.Target,
	l Lease,
) (Observation, error) {
	if conn.GetAccessMode() != "target_enforced" || l.Tokens == nil {
		return Observation{}, fmt.Errorf("%w: a target_verifier test needs a target_enforced connection", ErrNotReviewedRead)
	}
	tokens, err := l.Tokens(ctx)
	if err != nil {
		return Observation{}, fmt.Errorf("dispatch: test tokens: %w", err)
	} else if tokens.Fresh == "" || tokens.Mismatch == "" {
		return Observation{}, errors.New("dispatch: test tokens: missing")
	}
	out := Observation{Fields: map[string]string{}}
	for _, step := range []struct{ field, token string }{
		{"/missing", ""}, {"/body_mismatch", tokens.Mismatch}, {"/fresh", tokens.Fresh}, {"/replayed", tokens.Fresh},
	} {
		res, ok := e.readWith(ctx, conn, read, target, nil, step.token)
		if !ok {
			return Observation{}, nil // inconclusive, retried
		}
		out.Fields[step.field] = strconv.Itoa(res.Status)
		if t := problemType(res); t != "" {
			out.Fields[step.field] += " " + t
		}
		if step.field == "/fresh" {
			sum := sha256.Sum256(res.Body)
			out.HTTPStatus, out.Digest = res.Status, sum[:]
		}
	}
	return out, nil
}

// problemType is the type of a PantherClaw verifier's problem document, or
// "" for any other answer.
func problemType(res egress.Response) string {
	if !strings.HasPrefix(res.ContentType, "application/problem+json") || res.Truncated {
		return ""
	}
	var doc struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(res.Body, &doc); err != nil || !problemRe.MatchString(doc.Type) {
		return ""
	}
	return doc.Type
}
