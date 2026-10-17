// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/authority"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/enforcementpoints"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The request mapping (D27, HR-318). The subject is the agent: type
// pantherclaw_workload with its PAP/1 token, proof and run (and the
// action id of a resubmission). The resource is the request the point is
// about to forward: type pantherclaw:http_request, id the connection's
// name, its protocol, method, URL and base64 body. The action is the HTTP
// method, or the JSON-RPC method for protocol mcp (tools/call for a tool
// call). The server rebuilds the agent's PAP/1 credentials over exactly
// that request and maps it through the connection's pinned package, as
// the gateway would.
const (
	authzenSubjectType  = "pantherclaw_workload"
	authzenResourceType = "pantherclaw:http_request"
	authzenMaxForwarded = 64 << 10
)

// Evaluation semantics of a batch (AuthZEN 1.0 §8.1).
const (
	semanticExecuteAll          = "execute_all"
	semanticDenyOnFirstDeny     = "deny_on_first_deny"
	semanticPermitOnFirstPermit = "permit_on_first_permit"
)

type azEntity struct {
	Type       string         `json:"type"`
	ID         string         `json:"id"`
	Properties jsontext.Value `json:"properties,omitempty"`
}

type azAction struct {
	Name       string         `json:"name"`
	Properties jsontext.Value `json:"properties,omitempty"`
}

type azEvaluation struct {
	Subject  *azEntity      `json:"subject,omitempty"`
	Resource *azEntity      `json:"resource,omitempty"`
	Action   *azAction      `json:"action,omitempty"`
	Context  jsontext.Value `json:"context,omitempty"`
}

type azBatch struct {
	Subject     *azEntity      `json:"subject,omitempty"`
	Resource    *azEntity      `json:"resource,omitempty"`
	Action      *azAction      `json:"action,omitempty"`
	Context     jsontext.Value `json:"context,omitempty"`
	Evaluations []azEvaluation `json:"evaluations,omitempty"`
	Options     struct {
		Semantic string `json:"evaluations_semantic,omitempty"`
	} `json:"options"`
}

// azSubject is a pantherclaw_workload subject's properties.
type azSubject struct {
	Token    string `json:"pap_token"`
	Proof    string `json:"pap_proof"`
	Run      string `json:"pap_run_id"`
	ActionID string `json:"pc_action_id,omitempty"`
}

// azResource is a pantherclaw:http_request resource's properties.
type azResource struct {
	Protocol string `json:"protocol"`
	Method   string `json:"method"`
	URL      string `json:"url"`
	Body     string `json:"body_b64,omitempty"`
}

var errAuthZENRequest = errors.New("authzen: invalid request")

// parseAuthZEN reads one evaluation, or a batch of 1 to 10 whose entries
// default to its top-level subject, resource, action and context.
func parseAuthZEN(body []byte, batch bool) ([]azEvaluation, string, error) {
	var b azBatch
	if err := json.Unmarshal(body, &b); err != nil {
		return nil, "", errAuthZENRequest
	}
	top := azEvaluation{Subject: b.Subject, Resource: b.Resource, Action: b.Action, Context: b.Context}
	if !batch {
		if len(b.Evaluations) > 0 {
			return nil, "", errAuthZENRequest
		}
		return []azEvaluation{top}, semanticExecuteAll, nil
	}
	semantic := b.Options.Semantic
	switch semantic {
	case "":
		semantic = semanticExecuteAll
	case semanticExecuteAll, semanticDenyOnFirstDeny, semanticPermitOnFirstPermit:
	default:
		return nil, "", errAuthZENRequest
	}
	if len(b.Evaluations) == 0 {
		return []azEvaluation{top}, semantic, nil
	}
	if len(b.Evaluations) > authzenMaxBatch {
		return nil, "", errAuthZENRequest
	}
	out := make([]azEvaluation, len(b.Evaluations))
	for i, ev := range b.Evaluations {
		if ev.Subject == nil {
			ev.Subject = top.Subject
		}
		if ev.Resource == nil {
			ev.Resource = top.Resource
		}
		if ev.Action == nil {
			ev.Action = top.Action
		}
		if len(ev.Context) == 0 {
			ev.Context = top.Context
		}
		out[i] = ev
	}
	return out, semantic, nil
}

// boundConnection is a connection an enforcement point is bound to.
type boundConnection = dbq.EnforcementPointConnectionRow

// errNotBound: an evaluation names a connection the point is not bound to
// (HR-317).
var errNotBound = errors.New("authzen: connection not bound to the enforcement point")

// connections resolves each evaluation's connection among the point's: a
// resource naming another connection refuses the whole request. An
// evaluation without a usable resource gets none and is denied.
func (e *authzenEndpoint) connections(ctx context.Context, p point, evals []azEvaluation) ([]*boundConnection, error) {
	out := make([]*boundConnection, len(evals))
	if !slices.ContainsFunc(evals, named) {
		return out, nil
	}
	byName := map[string]*boundConnection{}
	err := e.pool.InTenantTx(ctx, p.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		for i, ev := range evals {
			if !named(ev) {
				continue
			}
			name := ev.Resource.ID
			if c, ok := byName[name]; ok {
				out[i] = c
				continue
			}
			row, err := q.EnforcementPointConnection(ctx, p.Org, p.ID, name)
			if db.IsNoRows(err) {
				return errNotBound
			} else if err != nil {
				return err
			}
			byName[name], out[i] = &row, &row
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

func isUnauthenticated(err error) bool { return pcerr.CodeOf(err) == pcerr.Unauthenticated }

// User-facing reasons (D28 reason_user).
var authzenReasons = map[string]string{
	authority.ExternalAllow:           "PantherClaw allowed this action.",
	authority.ExternalObserve:         "PantherClaw is observing this route; the action may proceed and is recorded.",
	authority.ExternalHold:            "This action needs an approval first; resubmit it with the same action id once it is approved.",
	authority.ExternalDeny:            "PantherClaw's policy does not allow this action.",
	authority.ExternalCannotAuthorize: "PantherClaw could not authorize this action, so it must not proceed.",
}

// refusal is a decision false made before the Authority decides.
func refusal(code string) authzenResponse {
	return authzenDenied(authority.ExternalCannotAuthorize, code, authzenReasons[authority.ExternalCannotAuthorize])
}

// Codes of evaluations refused before the Authority decides.
const (
	codeSubject     = "SUBJECT_NOT_A_WORKLOAD"
	codeCredentials = "PAP_CREDENTIALS_REQUIRED"
	codeResource    = "RESOURCE_INVALID"
	codeProtocol    = "PROTOCOL_MISMATCH"
	codeURL         = "URL_OUTSIDE_CONNECTION"
	codeBody        = "BODY_TOO_LARGE"
	codeAction      = "ACTION_MISMATCH"
	codeBindable    = "CONNECTION_NOT_BINDABLE"
	codeAgent       = "SUBJECT_MISMATCH"
	codeRoute       = "UNKNOWN_ROUTE"
	codeAmbiguous   = "AMBIGUOUS_INPUT"
	codeMethod      = "MCP_METHOD_REFUSED"
)

// evaluate decides one evaluation.
func (e *authzenEndpoint) evaluate(ctx context.Context, p point, conn *boundConnection, ev azEvaluation) (authzenResponse, error) {
	// The subject must carry the agent's own credentials: a subject that
	// only names an agent is refused (F2).
	if ev.Subject == nil || ev.Subject.Type != authzenSubjectType || !jsonObject(ev.Subject.Properties) {
		return refusal(codeSubject), nil
	}
	var sub azSubject
	if json.Unmarshal(ev.Subject.Properties, &sub) != nil || sub.Token == "" || sub.Proof == "" || sub.Run == "" ||
		len(sub.Token) > 8192 || len(sub.Proof) > 8192 {
		return refusal(codeCredentials), nil //nolint:nilerr // a decision, not a failure
	}
	if conn == nil || !jsonObject(ev.Resource.Properties) || ev.Action == nil {
		return refusal(codeResource), nil
	}
	var res azResource
	if json.Unmarshal(ev.Resource.Properties, &res) != nil || res.Method == "" || res.URL == "" || len(res.URL) > 4096 {
		return refusal(codeResource), nil //nolint:nilerr // a decision, not a failure
	}
	switch {
	case res.Protocol != "http" && res.Protocol != "mcp", res.Protocol != conn.Kind:
		return refusal(codeProtocol), nil
	case !enforcementpoints.Bindable(conn.Kind, conn.AccessMode, conn.State):
		// The connection changed since it was bound (D27).
		return refusal(codeBindable), nil
	}
	body, err := base64.StdEncoding.DecodeString(res.Body)
	if err != nil {
		return refusal(codeResource), nil //nolint:nilerr // a decision, not a failure
	}
	if len(body) > authzenMaxForwarded {
		return refusal(codeBody), nil
	}
	target, rest, ok := withinBase(conn.BaseUrl, res.URL)
	if !ok {
		return refusal(codeURL), nil
	}
	instance, env, agent, ok := workloadSubject(sub.Token)
	if !ok {
		return refusal(codeCredentials), nil
	}
	if ev.Subject.ID != "" && ev.Subject.ID != agent {
		return refusal(codeAgent), nil
	}
	run, err := ids.ParseUUID(sub.Run)
	if err != nil || run.IsZero() {
		return refusal(codeCredentials), nil //nolint:nilerr // a decision, not a failure
	}
	action := ids.NewV7()
	if sub.ActionID != "" {
		if action, err = ids.ParseUUID(sub.ActionID); err != nil || action.IsZero() {
			return refusal(codeCredentials), nil //nolint:nilerr // a decision, not a failure
		}
	}
	sum := sha256.Sum256(body)
	htu := (&url.URL{Scheme: target.Scheme, Host: target.Host, Path: target.Path, RawPath: target.RawPath}).String()
	creds := &authority.Credentials{Token: sub.Token, Proof: sub.Proof, BodySHA256: sum, Method: res.Method, URL: htu}
	gw := authority.Gateway{ID: conn.GatewayID.String(), Org: p.Org}
	tc := mapping.Context{
		Org: p.Org.String(), Env: env, RunID: run.String(), ActionID: action.String(), AgentInstance: instance, Connection: conn.ID.String(),
	}
	var mapped actionir.Parsed
	switch res.Protocol {
	case "http":
		if ev.Action.Name != res.Method {
			return refusal(codeAction), nil
		}
		mapper, merr := e.mappers.get(conn.PackageRaw)
		if merr != nil {
			return authzenResponse{}, merr
		}
		mapped, err = mapper.HTTP(ctx, tc, res.Method, rest, target.RawQuery, body)
	case "mcp":
		call, method, perr := jsonRPC(body)
		if perr != nil || res.Method != http.MethodPost {
			return refusal(codeAmbiguous), nil //nolint:nilerr // a decision, not a failure
		}
		if ev.Action.Name != method {
			return refusal(codeAction), nil
		}
		switch method {
		case "initialize", "tools/list", "ping":
			// Decides nothing, but the credentials are checked and the proof
			// consumed (HR-021).
			return e.verifyOnly(ctx, gw, creds, run)
		case "tools/call":
			mapper, merr := e.mappers.get(conn.PackageRaw)
			if merr != nil {
				return authzenResponse{}, merr
			}
			mapped, err = mapper.MCP(ctx, tc, call.Name, call.Arguments)
		default:
			return refusal(codeMethod), nil
		}
	}
	switch {
	case errors.Is(err, mapping.ErrUnmapped):
		return refusal(codeRoute), nil
	case err != nil:
		return refusal(codeAmbiguous), nil //nolint:nilerr // a decision, not a failure
	}
	a := mapped.Action
	a.Channel = "authzen"
	parsed, err := actionir.Encode(a)
	if err != nil {
		return refusal(codeAmbiguous), nil //nolint:nilerr // a decision, not a failure
	}
	out, err := e.decider.Decide(ctx, authority.ExternalRequest{
		Gateway: gw, Action: parsed, Credentials: creds, TargetEnforced: conn.AccessMode == "target_enforced",
		Outbound: authority.Outbound{Method: res.Method, URL: target.String(), BodySHA256: sum[:]},
		Decided:  func(ctx context.Context, txn ids.UUID) error { return e.decidedVia(ctx, p, txn) },
	})
	if err != nil {
		return authzenResponse{}, err
	}
	facts := authzenFacts{
		Outcome: out.Outcome, Code: out.Code, Receipt: out.Receipt, Coverage: "PARTIAL", ActionToken: out.ActionToken,
		ActionID: action.String(),
	}
	if !out.TransactionID.IsZero() {
		facts.TransactionID = out.TransactionID.String()
	}
	if w := out.Wait; w != nil && out.Outcome == authority.ExternalHold {
		facts.Wait = &authzenWait{Handle: w.Handle.String()}
		if !w.Deadline.IsZero() {
			facts.Wait.Deadline = w.Deadline.UTC().Format(time.RFC3339)
		}
	}
	return authzenResponse{Decision: out.Allowed, Context: authzenContext{
		PantherClaw: facts, ReasonUser: map[string]string{"en": authzenReasons[out.Outcome]},
	}}, nil
}

// verifyOnly answers an MCP request that decides nothing: true once the
// agent's credentials verify for it.
func (e *authzenEndpoint) verifyOnly(ctx context.Context, gw authority.Gateway, creds *authority.Credentials, run ids.UUID) (authzenResponse, error) {
	_, err := e.decider.Verify(ctx, gw, creds, run)
	var pe *pap.Error
	switch {
	case errors.As(err, &pe):
		return refusal("IDENTITY_UNVERIFIED"), nil
	case errors.Is(err, authority.ErrAgentUnusable):
		return authzenDenied(authority.ExternalDeny, "AGENT_UNUSABLE", authzenReasons[authority.ExternalDeny]), nil
	case err != nil:
		return authzenResponse{}, err
	}
	return authzenResponse{Decision: true, Context: authzenContext{
		PantherClaw: authzenFacts{Outcome: authority.ExternalAllow, Coverage: "PARTIAL"},
		ReasonUser:  map[string]string{"en": "This request decides nothing; the agent's credentials verified."},
	}}, nil
}

// decidedVia records that this point asked for the decision, with its
// audit event, in one transaction after the decision and before anything
// is committed (D28, D65). A transaction another point asked about
// already is refused.
func (e *authzenEndpoint) decidedVia(ctx context.Context, p point, txn ids.UUID) error {
	return e.pool.InTenantTx(ctx, p.Org, func(ctx context.Context, tx db.TenantTx) error {
		n, err := dbq.New(tx).SetTransactionDecidedVia(ctx, &p.ID, p.Org, txn)
		if err != nil {
			return err
		}
		if n == 0 {
			return errors.New("authzen: the transaction was asked for by another enforcement point")
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "authzen.decision_requested", Outcome: audit.Success,
			Actor:   evdomain.Actor{Type: string(td.KindServiceAccount), ID: p.Subject.String()},
			Object:  &audit.Object{Type: "transaction", ID: txn.String()},
			Details: map[string]string{"enforcement_point_id": p.ID.String(), "enforcement_point": p.Name},
		})
		return err
	})
}

// withinBase checks that raw is the connection's base URL or below it:
// the scheme, host and port exactly, the path at a segment boundary
// (D27). rest is the escaped path below the base, with its leading slash.
func withinBase(base *string, raw string) (*url.URL, string, bool) {
	if base == nil {
		return nil, "", false
	}
	b, err1 := url.Parse(*base)
	t, err2 := url.Parse(raw)
	if err1 != nil || err2 != nil || t.User != nil || t.Fragment != "" || t.Opaque != "" || t.ForceQuery ||
		(t.Scheme != "https" && t.Scheme != "http") || t.Scheme != b.Scheme ||
		!strings.EqualFold(t.Hostname(), b.Hostname()) || t.Port() != b.Port() {
		return nil, "", false
	}
	bp, tp := strings.TrimSuffix(b.EscapedPath(), "/"), t.EscapedPath()
	rest, ok := strings.CutPrefix(tp, bp)
	if !ok || (rest != "" && !strings.HasPrefix(rest, "/")) {
		return nil, "", false
	}
	if rest == "" {
		rest = "/"
	}
	return t, rest, true
}

// workloadSubject reads, WITHOUT verifying, the instance, environment and
// agent a workload token names, for the ActionIR and the subject id
// check. The Authority verifies the token, so a forged one decides
// nothing (the gateway's tokenSubject does the same).
func workloadSubject(token string) (instance, env, agent string, ok bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || len(token) > 8192 {
		return "", "", "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", "", false
	}
	var c struct {
		Sub string `json:"sub"`
		PAP struct {
			Env string `json:"env"`
		} `json:"pap"`
	}
	if json.Unmarshal(payload, &c) != nil {
		return "", "", "", false
	}
	id, err := pap.ParseInstance(c.Sub)
	if err != nil || c.PAP.Env == "" {
		return "", "", "", false
	}
	return id.Instance.String(), c.PAP.Env, id.Agent.String(), true
}

// toolCall is a JSON-RPC tools/call's params.
type toolCall struct {
	Name      string         `json:"name"`
	Arguments jsontext.Value `json:"arguments,omitempty"`
}

// jsonRPC reads one JSON-RPC 2.0 request (never a batch) and returns its
// method and, for tools/call, its tool and arguments.
func jsonRPC(body []byte) (toolCall, string, error) {
	var m struct {
		JSONRPC string         `json:"jsonrpc"`
		Method  string         `json:"method"`
		Params  jsontext.Value `json:"params,omitempty"`
	}
	if err := json.Unmarshal(body, &m); err != nil || m.JSONRPC != "2.0" || m.Method == "" {
		return toolCall{}, "", errAuthZENRequest
	}
	var tc toolCall
	if m.Method == "tools/call" {
		if !jsonObject(m.Params) || json.Unmarshal(m.Params, &tc) != nil || tc.Name == "" {
			return toolCall{}, "", errAuthZENRequest
		}
		if len(tc.Arguments) == 0 {
			tc.Arguments = jsontext.Value("{}")
		}
	}
	return tc, m.Method, nil
}

// mapperCache keeps compiled package mappings by the digest of the pinned
// version's manifest, bounded in memory.
type mapperCache struct {
	limits celenv.Limits
	mu     sync.Mutex
	byRaw  map[[sha256.Size]byte]*mapping.Mapper
}

func newMapperCache(limits celenv.Limits) *mapperCache {
	if limits == (celenv.Limits{}) {
		limits = celenv.DefaultLimits
	}
	return &mapperCache{limits: limits, byRaw: map[[sha256.Size]byte]*mapping.Mapper{}}
}

func (c *mapperCache) get(raw []byte) (*mapping.Mapper, error) {
	key := sha256.Sum256(raw)
	c.mu.Lock()
	m, ok := c.byRaw[key]
	c.mu.Unlock()
	if ok {
		return m, nil
	}
	pkg, err := manifest.Decode(raw)
	if err != nil {
		return nil, err
	}
	if m, err = mapping.New(pkg, c.limits); err != nil {
		return nil, err
	}
	c.mu.Lock()
	if len(c.byRaw) >= 64 {
		c.byRaw = map[[sha256.Size]byte]*mapping.Mapper{}
	}
	c.byRaw[key] = m
	c.mu.Unlock()
	return m, nil
}

// named reports whether an evaluation names a connection.
func named(ev azEvaluation) bool {
	return ev.Resource != nil && ev.Resource.Type == authzenResourceType && ev.Resource.ID != "" && len(ev.Resource.ID) <= 63
}
