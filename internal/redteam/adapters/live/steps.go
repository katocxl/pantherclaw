// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package live

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/redteam/app"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
)

// supported are the step kinds the live driver runs (D33). agent.direct is
// implemented but not offered: no scenario uses it. It has no harness
// powers: it cannot change a simulator (sim.mutate), act as an operator
// (operator.*), read another org's objects (server.read) or probe a sandbox.
var supported = map[string]bool{
	"agent.call": true, "agent.child": true, "agent.steal": true,
	"target.replay": true, "wait": true, "check.receipt": true, "person.approve": true, "person.decline": true,
}

// Supports implements app.Driver.
func (d *Driver) Supports(kind string) bool { return supported[kind] }

type runKey struct{}

func runFrom(ctx context.Context, def string) string {
	if v, ok := ctx.Value(runKey{}).(string); ok && v != "" {
		return v
	}
	return def
}

func runOr(run, def string) string {
	if run != "" {
		return run
	}
	return def
}

// refusal is the JSON body of a gateway refusal.
type refusal struct {
	ErrorClass    string   `json:"error_class"`
	Error         string   `json:"error"`
	Decision      string   `json:"decision"`
	Outcome       string   `json:"outcome"`
	Reasons       []string `json:"reasons"`
	TransactionID string   `json:"transaction_id"`
}

// observeREST reads an HTTP-face answer (or the gateway's refusal of a
// request that did not reach a decision).
func observeREST(status int, h http.Header, b []byte) (domain.Observation, error) {
	if status < 300 {
		return domain.Observation{Outcome: domain.OutcomeAllow, TransactionID: h.Get("PC-Transaction-Id"), Response: response(b)}, nil
	}
	var r refusal
	if json.Unmarshal(b, &r) != nil || r.ErrorClass == "" {
		code := h.Get("PAP-Error")
		if code == "" {
			code = "http_" + strconv.Itoa(status)
		}
		return domain.Observation{Outcome: domain.OutcomeRefused, Code: code, Detail: truncateDetail(b)}, nil
	}
	o := classify(facts{Class: r.ErrorClass, Code: r.Error, Decision: r.Decision, Outcome: r.Outcome, Reasons: r.Reasons, TransactionID: r.TransactionID})
	o.Response = response(b)
	return o, nil
}

// observeMCP reads an MCP-face answer. h may be nil.
func observeMCP(status int, h http.Header, b []byte) (domain.Observation, error) {
	var r struct {
		Result *struct {
			Content           jsontext.Value `json:"content"`
			StructuredContent jsontext.Value `json:"structuredContent"`
			IsError           bool           `json:"isError"`
			Meta              struct {
				Error struct {
					ErrorClass    string   `json:"error_class"`
					Error         string   `json:"error"`
					Decision      string   `json:"decision"`
					Outcome       string   `json:"outcome"`
					Reasons       []string `json:"reasons"`
					TransactionID string   `json:"transaction_id"`
				} `json:"io.pantherclaw/error"`
				Result struct {
					TransactionID string `json:"transaction_id"`
				} `json:"io.pantherclaw/result"`
			} `json:"_meta"`
		} `json:"result"`
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(b, &r); err != nil || (r.Result == nil && r.Error == nil) {
		if code := h.Get("PAP-Error"); code != "" {
			return domain.Observation{Outcome: domain.OutcomeRefused, Code: code}, nil
		}
		var ref refusal
		if json.Unmarshal(b, &ref) == nil && ref.ErrorClass != "" {
			return observeREST(status, h, b)
		}
		return domain.Observation{}, fmt.Errorf("mcp face answered HTTP %d without a JSON-RPC answer", status)
	}
	if r.Error != nil {
		return domain.Observation{Outcome: domain.OutcomeRefused, Code: "rpc_" + strconv.Itoa(r.Error.Code), Detail: r.Error.Message}, nil
	}
	var f facts
	if r.Result.IsError {
		e := r.Result.Meta.Error
		f = facts{Class: e.ErrorClass, Code: e.Error, Decision: e.Decision, Outcome: e.Outcome, Reasons: e.Reasons, TransactionID: e.TransactionID}
		if f.Class == "" {
			return domain.Observation{}, errors.New("mcp tool error without PantherClaw's error facts")
		}
	} else {
		f.TransactionID = r.Result.Meta.Result.TransactionID
	}
	o := classify(f)
	o.Response = toolJSON(r.Result.StructuredContent, r.Result.Content)
	return o, nil
}

func truncateDetail(b []byte) string {
	if len(b) > 200 {
		b = b[:200]
	}
	return string(b)
}

// ---- agent.child --------------------------------------------------------

// child starts a child run of the range instance, asks to delegate a grant
// wider than the parent's, and has the child act (D33). The observation is
// the child's action; the delegation's refusal is its code.
func (d *Driver) child(ctx context.Context, s domain.Scenario, st domain.Step) (domain.Observation, error) {
	if d.cfg.Workload == nil || d.cfg.AgentID == "" {
		return domain.Observation{}, fmt.Errorf("%w: agent.child needs the range instance's workload service", app.ErrUnsupported)
	}
	var w struct {
		Grant struct {
			Widen []string `json:"widen"`
		} `json:"grant"`
		Then callWith `json:"then"`
	}
	if err := json.Unmarshal(st.With, &w); err != nil {
		return domain.Observation{}, err
	}
	req := &pantherclawv1.DelegateGrantRequest{RunId: d.cfg.Run, Bounds: []byte(`{}`)}
	for _, dim := range w.Grant.Widen {
		switch dim {
		case "operations":
			req.Bounds = []byte(`{"operations": ["github.*", "payments.*"]}`)
		case "lifetime":
			req.ExpireTime = timestamppb.New(time.Now().Add(1000 * time.Hour))
		default:
			return domain.Observation{}, fmt.Errorf("%w: widening %q", app.ErrUnsupported, dim)
		}
	}
	child, err := d.cfg.Workload.StartChildRun(ctx, &pantherclawv1.StartChildRunRequest{ParentRunId: d.cfg.Run, AgentId: d.cfg.AgentID})
	if err != nil {
		return domain.Observation{}, fmt.Errorf("StartChildRun: %w", err)
	}
	req.ChildRunId = child.GetRun().GetId()
	_, derr := d.cfg.Workload.DelegateGrant(ctx, req)
	code := ""
	if derr != nil {
		code = "DELEGATION_REFUSED"
		if strings.Contains(derr.Error(), "OUTSIDE_ALLOWED_AUTHORITY") {
			code = "OUTSIDE_ALLOWED_AUTHORITY"
		}
	}
	w.Then.run = req.ChildRunId
	obs, _, err := d.one(ctx, s, st.ID, 0, w.Then)
	if err != nil {
		return obs, err
	}
	widened := "widened " + strings.Join(w.Grant.Widen, ", ") + "; "
	if derr == nil {
		obs.Detail = widened + "the delegation was accepted: " + obs.Detail
	} else {
		obs.Detail = widened + "delegation: " + derr.Error() + " " + obs.Detail
	}
	obs.Code = code
	return obs, nil
}

// ---- agent.steal --------------------------------------------------------

// steal makes a call with what an attacker holding the agent's token would
// have: the token without its key, a proof replayed, a stale nonce.
func (d *Driver) steal(ctx context.Context, st domain.Step) (domain.Observation, error) {
	if d.cfg.Key == nil || d.cfg.Token == nil {
		return domain.Observation{}, fmt.Errorf("%w: agent.steal needs the instance's key and token", app.ErrUnsupported)
	}
	var w struct {
		Mode string   `json:"mode"`
		Call callWith `json:"call"`
	}
	if err := json.Unmarshal(st.With, &w); err != nil {
		return domain.Observation{}, err
	}
	switch w.Mode {
	case "token_without_key":
		_, thief, err := ed25519.GenerateKey(nil)
		if err != nil {
			return domain.Observation{}, err
		}
		req, err := d.stolenRequest(ctx, w.Call)
		if err != nil {
			return domain.Observation{}, err
		}
		return d.send(w.Call.Face, &http.Client{Timeout: time.Minute, Transport: &workloadclient.Transport{Key: thief, Token: d.cfg.Token, Base: d.cfg.Transport}}, req)
	case "proof_replay":
		return d.replayProof(ctx, w.Call)
	case "stale_nonce":
		return d.staleNonce(ctx, w.Call)
	}
	return domain.Observation{}, fmt.Errorf("%w: agent.steal %s", app.ErrUnsupported, w.Mode)
}

// stolenRequest is the unsigned request of a call on the http or mcp face.
func (d *Driver) stolenRequest(ctx context.Context, w callWith) (*http.Request, error) {
	conn := w.Connection
	if mapped, ok := d.cfg.Roles[conn]; ok {
		conn = mapped
	}
	var req *http.Request
	var err error
	switch w.Face {
	case "http":
		method := w.Method
		if method == "" {
			method = http.MethodGet
		}
		var body io.Reader
		if len(w.Body) > 0 {
			body = bytes.NewReader(w.Body)
		}
		req, err = http.NewRequestWithContext(ctx, method, d.base()+"/"+url.PathEscape(conn)+w.Path, body)
	case "mcp":
		var b []byte
		b, err = json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{
			"name": w.Tool, "arguments": rawOr(w.Args), "_meta": map[string]string{"io.modelcontextprotocol/protocolVersion": "2026-07-28"},
		}})
		if err != nil {
			return nil, err
		}
		if req, err = http.NewRequestWithContext(ctx, http.MethodPost, d.base()+"/mcp/"+url.PathEscape(conn), bytes.NewReader(b)); err == nil {
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			req.Header.Set("MCP-Protocol-Version", "2026-07-28")
			req.Header.Set("Mcp-Method", "tools/call")
			req.Header.Set("Mcp-Name", w.Tool)
		}
	default:
		return nil, fmt.Errorf("%w: agent.steal on the %s face", app.ErrUnsupported, w.Face)
	}
	if err != nil {
		return nil, err
	}
	req.Header.Set("PAP-Run-Id", d.cfg.Run)
	req.Header.Set("PC-Action-Id", ids.NewV7().String())
	return req, nil
}

func (d *Driver) send(face string, c *http.Client, req *http.Request) (domain.Observation, error) {
	res, err := c.Do(req)
	if err != nil {
		return domain.Observation{}, err
	}
	defer func() { _ = res.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(res.Body, maxAnswer+1))
	if err != nil {
		return domain.Observation{}, err
	}
	if face == "mcp" {
		return observeMCP(res.StatusCode, res.Header, b)
	}
	return observeREST(res.StatusCode, res.Header, b)
}

// recorder keeps the request as it left the signing transport.
type recorder struct {
	base http.RoundTripper
	mu   sync.Mutex
	got  *http.Request
	body []byte
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	b, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	_ = req.Body.Close()
	r.mu.Lock()
	r.got, r.body = req.Clone(context.Background()), b
	r.mu.Unlock()
	req.Body = io.NopCloser(bytes.NewReader(b))
	base := r.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}

// replayProof sends a call once, signed as the instance, then sends exactly
// the same signed request again.
func (d *Driver) replayProof(ctx context.Context, w callWith) (domain.Observation, error) {
	req, err := d.stolenRequest(ctx, w)
	if err != nil {
		return domain.Observation{}, err
	}
	rec := &recorder{base: d.cfg.Transport}
	c := &http.Client{Timeout: time.Minute, Transport: &workloadclient.Transport{Key: d.cfg.Key, Token: d.cfg.Token, Base: rec}}
	first, err := c.Do(req)
	if err != nil {
		return domain.Observation{}, err
	}
	_, _ = io.Copy(io.Discard, first.Body)
	_ = first.Body.Close()
	rec.mu.Lock()
	got, body := rec.got, rec.body
	rec.mu.Unlock()
	if got == nil {
		return domain.Observation{}, errors.New("no request was sent")
	}
	again, err := http.NewRequestWithContext(ctx, got.Method, got.URL.String(), bytes.NewReader(body))
	if err != nil {
		return domain.Observation{}, err
	}
	again.Header = got.Header.Clone()
	return d.send(w.Face, &http.Client{Timeout: time.Minute, Transport: d.cfg.Transport}, again)
}

// staleNonce sends a call whose proof carries a nonce the server never issued.
func (d *Driver) staleNonce(ctx context.Context, w callWith) (domain.Observation, error) {
	req, err := d.stolenRequest(ctx, w)
	if err != nil {
		return domain.Observation{}, err
	}
	var body []byte
	if req.Body != nil {
		if body, err = io.ReadAll(req.Body); err != nil {
			return domain.Observation{}, err
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
	}
	u := *req.URL
	u.RawQuery, u.Fragment = "", ""
	token := d.cfg.Token()
	stale := base64.RawURLEncoding.EncodeToString([]byte("stale-stale-stale-stale-stale-0"))
	proof, err := pap.NewProof(d.cfg.Key, pap.ProofParams{Method: req.Method, URL: u.String(), Body: body, Token: token, Nonce: stale, Now: time.Now()})
	if err != nil {
		return domain.Observation{}, err
	}
	req.Header.Set("Authorization", "PAP "+token)
	req.Header.Set("PAP-Proof", proof)
	return d.send(w.Face, &http.Client{Timeout: time.Minute, Transport: d.cfg.Transport}, req)
}

// ---- target.replay and agent.direct -----------------------------------

// targetReplay delivers the request an SDK call was handed to its target,
// which is the action token's job to refuse the second time (HR-188).
func (d *Driver) targetReplay(ctx context.Context, st domain.Step) (domain.Observation, error) {
	var w struct {
		Of string `json:"of"`
	}
	if err := json.Unmarshal(st.With, &w); err != nil {
		return domain.Observation{}, err
	}
	d.mu.Lock()
	disp := d.dispatches[w.Of]
	d.mu.Unlock()
	if disp == nil {
		return domain.Observation{}, fmt.Errorf("step %s was handed no request to deliver (only a target-enforced sdk call is)", w.Of)
	}
	body, err := base64.RawURLEncoding.DecodeString(disp.Body)
	if err != nil {
		return domain.Observation{}, err
	}
	req, err := http.NewRequestWithContext(ctx, disp.Method, disp.URL, bytes.NewReader(body))
	if err != nil {
		return domain.Observation{}, err
	}
	for k, v := range disp.Headers {
		req.Header.Set(k, v)
	}
	return d.deliver(req)
}

// deliver sends a request straight to a simulator, unsigned and unproxied.
func (d *Driver) deliver(req *http.Request) (domain.Observation, error) {
	if !localLiteral(req.URL.Hostname()) {
		return domain.Observation{}, fmt.Errorf("refusing to send to %q: the range sends only to a loopback or private IP literal", req.URL.Hostname())
	}
	res, err := (&http.Client{
		Timeout: 10 * time.Second, Transport: d.cfg.Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}).Do(req)
	if err != nil {
		return domain.Observation{}, err
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(res.Body, maxAnswer))
	if res.StatusCode < 300 {
		return domain.Observation{Outcome: domain.OutcomeAllow}, nil
	}
	var e struct {
		Error string `json:"error"`
		Code  string `json:"code"`
	}
	_ = json.Unmarshal(b, &e)
	code := e.Error
	if code == "" {
		code = e.Code
	}
	if code == "" {
		code = "http_" + strconv.Itoa(res.StatusCode)
	}
	return domain.Observation{Outcome: domain.OutcomeTargetRefused, Code: code, Detail: truncateDetail(b)}, nil
}

// direct calls the simulator of a connection role straight, bypassing the
// gateway, with no credential or with the fixture's planted one.
func (d *Driver) direct(ctx context.Context, st domain.Step) (domain.Observation, error) {
	var w struct {
		Connection string         `json:"connection"`
		Method     string         `json:"method"`
		Path       string         `json:"path"`
		Body       jsontext.Value `json:"body"`
		Credential string         `json:"credential"`
	}
	if err := json.Unmarshal(st.With, &w); err != nil {
		return domain.Observation{}, err
	}
	base := d.cfg.Direct[w.Connection]
	if base == "" {
		return domain.Observation{}, fmt.Errorf("%w: no simulator address for role %s", app.ErrUnsupported, w.Connection)
	}
	var body io.Reader
	if len(w.Body) > 0 {
		body = bytes.NewReader(w.Body)
	}
	req, err := http.NewRequestWithContext(ctx, w.Method, strings.TrimSuffix(base, "/")+w.Path, body)
	if err != nil {
		return domain.Observation{}, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if w.Credential == "found_pat" {
		pat := d.cfg.Fixture["found_pat"]
		if pat == "" {
			return domain.Observation{}, fmt.Errorf("%w: no found_pat fixture", app.ErrUnsupported)
		}
		req.Header.Set("Authorization", "Bearer "+pat)
	}
	return d.deliver(req)
}

// localLiteral reports whether host is a loopback or private IP literal: the
// only addresses a simulated target may have (D3).
func localLiteral(host string) bool {
	a, err := netip.ParseAddr(host)
	return err == nil && (a.IsLoopback() || a.IsPrivate())
}
