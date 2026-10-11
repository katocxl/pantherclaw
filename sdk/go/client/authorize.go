// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/sdk/go/pap"
)

// ToolCall is a raw tool call as the agent made it. The gateway maps it
// through the connection's signed package (HR-201); the SDK sends no
// ActionIR, hash or canonical form and never changes the input.
type ToolCall struct {
	// Tool is the agent's name for the tool: mcp__<server>__<tool>, or the
	// name of a tool the agent SDK has built in.
	Tool string `json:"tool"`
	// Server is the MCP server's name, for an MCP tool only.
	Server string `json:"server,omitempty"`
	// Input is the tool input, a JSON object.
	Input jsontext.Value `json:"input"`
	// ToolUseID is the agent's id of the call.
	ToolUseID string `json:"tool_use_id"`
}

// Class is how an SDK sends a tool call to the /sdk face.
type Class string

// Classes of tool calls.
const (
	// Mapped is an MCP tool, mcp__<server>__<tool>, which PantherClaw
	// decides.
	Mapped Class = "mapped"
	// Builtin is a tool the agent SDK has built in: sent so PantherClaw
	// records it, and the only kind of call an observe answer lets run.
	Builtin Class = "builtin"
	// Refused is any other name: never sent, never run (HR-200).
	Refused Class = "refused"
)

// Classify sorts an agent's tool name. mcp__<server>__<tool>, with server
// the longest of servers that fits (a server name may contain "__") and a
// tool name after it, is Mapped with that server; a name in builtins
// (exactly, case included) is Builtin; anything else is Refused.
func Classify(tool string, servers, builtins []string) (server string, class Class) {
	if rest, ok := strings.CutPrefix(tool, "mcp__"); ok {
		for _, s := range servers {
			if len(s) > len(server) && len(rest) > len(s)+2 && strings.HasPrefix(rest, s+"__") {
				server = s
			}
		}
		if server == "" {
			return "", Refused
		}
		return server, Mapped
	}
	if slices.Contains(builtins, tool) {
		return "", Builtin
	}
	return "", Refused
}

// classOf is the class of a call as the client sends it: an MCP tool names
// its server, and a built-in names none and is one of the configured
// built-ins.
func (c *Client) classOf(call ToolCall) Class {
	if call.Server != "" {
		if name, ok := strings.CutPrefix(call.Tool, "mcp__"+call.Server+"__"); ok && name != "" {
			return Mapped
		}
		return Refused
	}
	if !strings.HasPrefix(call.Tool, "mcp__") && slices.Contains(c.cfg.Builtins, call.Tool) {
		return Builtin
	}
	return Refused
}

// Outcome is what the agent may do with a tool call. Only Allow, and
// Observe for a built-in tool, let it run.
type Outcome string

// Outcomes.
const (
	Allow        Outcome = "allow"
	Observe      Outcome = "observe"
	Hold         Outcome = "hold"
	Deny         Outcome = "deny"
	CannotDecide Outcome = "cannot_decide"
)

// Coverage labels (HR-024, HR-200).
const (
	CoveragePartial     = "PARTIAL"
	CoverageObserveOnly = "OBSERVE_ONLY"
)

// MaxCallBody is the largest request the /sdk face reads.
const MaxCallBody = 64 << 10

// Answer is the /sdk face's answer.
type Answer struct {
	// Decision is allow, hold or deny.
	Decision   string   `json:"decision"`
	Reason     string   `json:"reason"`
	ErrorClass string   `json:"error_class"`
	Code       string   `json:"code"`
	Reasons    []string `json:"reasons"`
	// ActionID is the action's id; ActionHash the hex SHA-256 of the
	// action the gateway mapped, and ActionIR its canonical bytes
	// (base64url).
	ActionID      string     `json:"action_id"`
	ActionHash    string     `json:"action_hash"`
	ActionIR      string     `json:"action_ir"`
	TransactionID string     `json:"transaction_id"`
	Receipt       string     `json:"receipt"`
	Mode          string     `json:"mode"`
	Coverage      string     `json:"coverage"`
	Wait          *WaitState `json:"wait"`
	// Dispatch is, for an allowed call to a target-enforced connection,
	// the request the gateway built for the target.
	Dispatch *Dispatch `json:"dispatch"`
}

// Dispatch is the gateway's re-serialization of an allowed action for a
// target-enforced connection, with the action token that binds its body
// (HR-201, HR-188).
type Dispatch struct {
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body"`
	ActionToken string            `json:"action_token"`
}

// Outbound is the request the agent sends to a target-enforced
// connection's target: exactly the one the gateway built.
type Outbound struct {
	Method string
	URL    string
	Header http.Header
	Body   []byte
}

// Request returns the outbound request. Add the application's own
// credential for the target, when it has one, and change nothing else: the
// target refuses any other body (HR-202).
func (o *Outbound) Request(ctx context.Context) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, o.Method, o.URL, bytes.NewReader(o.Body))
	if err != nil {
		return nil, err
	}
	req.Header = o.Header.Clone()
	return req, nil
}

// WaitState is a held call's wait handle and state, as the /sdk answer and
// the server's wait event carry it.
type WaitState struct {
	// Handle is the transaction id.
	Handle string `json:"handle"`
	// State is PENDING, EVIDENCE_REQUESTED, READY, DECLINED,
	// NARROWER_PROPOSED, EXPIRED, SUPERSEDED, INVALIDATED or CONSUMED.
	State             string     `json:"state"`
	Code              string     `json:"code"`
	Deadline          time.Time  `json:"deadline"`
	ConsumeBy         *time.Time `json:"consume_by"`
	ApprovalRequestID string     `json:"approval_request_id"`
	RetryAfterSeconds int        `json:"retry_after_seconds"`
}

// Result is the outcome of asking PantherClaw about one tool call.
type Result struct {
	Outcome Outcome
	// Answer is the gateway's answer, when one could be read.
	Answer *Answer
	// Send is, for an Allow on a target-enforced connection, the request
	// to send the target instead of building one.
	Send *Outbound
	// Why says what decided the outcome, for logs and the agent.
	Why string
	// Err is the failure behind CannotDecide, if any.
	Err error
}

func cannot(why string, err error) Result { return Result{Outcome: CannotDecide, Why: why, Err: err} }

var (
	hexHash   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	toolUseID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
)

// Evaluate reads a /sdk answer to a call of class, for the action id the
// SDK sent. firstHash, when set, is the action hash of an earlier answer
// for the same action: a resubmission must map to the same action.
// Anything it cannot read or check is CannotDecide, never Allow (HR-200,
// HR-201).
func Evaluate(status int, h http.Header, body []byte, class Class, actionID, firstHash string) Result {
	switch {
	case status == http.StatusUnauthorized:
		return cannot("PAP/1: "+h.Get(pap.HeaderError), nil)
	case status != http.StatusOK:
		return cannot(fmt.Sprintf("the gateway answered HTTP %d", status), nil)
	}
	var a Answer
	if err := json.Unmarshal(body, &a); err != nil {
		return cannot("the gateway's answer is not readable", err)
	}
	r := Result{Answer: &a, Why: a.Reason}
	switch a.Decision {
	case "deny":
		r.Outcome = Deny
		return r
	case "allow":
		if a.Coverage == CoverageObserveOnly {
			switch {
			case class != Builtin:
				return cannot("an observe answer for a call that is not a built-in tool", nil)
			case a.Mode != "monitor" || a.ActionHash != "" || a.ActionIR != "" || a.Dispatch != nil:
				return cannot("an observed call that is not only recorded", nil)
			}
			r.Outcome = Observe
			return r
		}
		r.Outcome = Allow
	case "hold":
		if a.Wait == nil || a.Wait.Handle == "" {
			return cannot("a hold without a wait handle", nil)
		}
		if a.Dispatch != nil {
			return cannot("a hold with a request to send", nil)
		}
		r.Outcome = Hold
	default:
		return cannot("unknown decision "+a.Decision, nil)
	}
	if err := checkAction(a, actionID, firstHash); err != nil {
		return cannot(err.Error(), nil)
	}
	if a.Dispatch != nil {
		out, err := checkDispatch(a.Dispatch)
		if err != nil {
			return cannot(err.Error(), nil)
		}
		r.Send = out
	}
	return r
}

// checkAction checks what an allow or a hold says about the action: the
// label, the action id sent, the hash, the canonical action it hashes, an
// sdk-channel action through a connection under the action id sent, and
// for a resubmission the first answer's hash.
func checkAction(a Answer, actionID, firstHash string) error {
	switch {
	case a.Coverage != CoveragePartial:
		return errors.New("a decided call that is not labeled PARTIAL")
	case a.ActionID != actionID:
		return errors.New("the answer is for another action")
	case !hexHash.MatchString(a.ActionHash):
		return errors.New("the answer has no action hash")
	case firstHash != "" && a.ActionHash != firstHash:
		return errors.New("the resubmitted call mapped to another action")
	case a.ActionIR == "":
		return errors.New("the answer does not carry the action it decided")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(a.ActionIR)
	if err != nil {
		return errors.New("the canonical action is not base64url")
	}
	p, err := pap.ParseAction(raw)
	switch {
	case err != nil:
		return errors.New("the canonical action is not valid ActionIR")
	case p.Hash != a.ActionHash:
		return errors.New("the action hash does not match the action")
	case p.Action.ActionID != actionID:
		return errors.New("the mapped action is for another action id")
	case p.Action.Channel != "sdk" || p.Action.Connection == "":
		return errors.New("the mapped action did not come through an SDK connection")
	}
	return nil
}

// checkDispatch checks the request a target-enforced connection's allow
// carries: its PAP-Action header is its action token, and the token's
// pap.bh is the SHA-256 of the body. The token's signature is the target's
// to verify.
func checkDispatch(d *Dispatch) (*Outbound, error) {
	body, err := base64.RawURLEncoding.Strict().DecodeString(d.Body)
	if err != nil {
		return nil, errors.New("the request to send has a body that is not base64url")
	}
	u, err := url.Parse(d.URL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || d.Method == "" {
		return nil, errors.New("the request to send has no method or absolute URL")
	}
	h := http.Header{}
	for k, v := range d.Headers {
		h.Set(k, v)
	}
	if d.ActionToken == "" || h.Get(pap.HeaderAction) != d.ActionToken {
		return nil, errors.New("the request to send does not carry its action token")
	}
	parts := strings.Split(d.ActionToken, ".")
	if len(parts) != 3 {
		return nil, errors.New("the action token is not a compact JWS")
	}
	var claims struct {
		PAP struct {
			BH string `json:"bh"`
		} `json:"pap"`
	}
	sum := sha256.Sum256(body)
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil || json.Unmarshal(payload, &claims) != nil || claims.PAP.BH != hex.EncodeToString(sum[:]) {
		return nil, errors.New("the action token does not bind the body to send")
	}
	return &Outbound{Method: d.Method, URL: d.URL, Header: h, Body: body}, nil
}

// NewActionID returns a fresh UUIDv7 for one logical tool call. Send the
// same id for every retry and resubmission of that call.
func NewActionID() string {
	var u [16]byte
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(time.Now().UnixMilli()))
	copy(u[:6], ts[2:8])
	_, _ = rand.Read(u[6:])
	u[6] = u[6]&0x0f | 0x70
	u[8] = u[8]&0x3f | 0x80
	const hexdig = "0123456789abcdef"
	out := make([]byte, 0, 36)
	for i, b := range u {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			out = append(out, '-')
		}
		out = append(out, hexdig[b>>4], hexdig[b&0x0f])
	}
	return string(out)
}

// Authorize asks the gateway's /sdk face about one tool call through the
// named connection, as action actionID. It never returns an error: every
// failure is a CannotDecide result.
func (c *Client) Authorize(ctx context.Context, connection string, call ToolCall, actionID string) Result {
	return c.authorize(ctx, connection, call, actionID, "")
}

func (c *Client) authorize(ctx context.Context, connection string, call ToolCall, actionID, firstHash string) Result {
	if c.cfg.Gateway == "" || c.cfg.RunID == "" {
		return cannot("the gateway URL and the run id are required", nil)
	}
	if call.Tool == "" || !toolUseID.MatchString(call.ToolUseID) || call.Input.Kind() != '{' {
		return cannot("a tool call needs a tool name, its id and an input object", nil)
	}
	class := c.classOf(call)
	if class == Refused {
		return cannot("PantherClaw neither maps "+call.Tool+" as an MCP tool nor knows it as a built-in tool", nil)
	}
	body, err := json.Marshal(call)
	if err != nil {
		return cannot("the tool call cannot be encoded", err)
	}
	if len(body) > MaxCallBody {
		return cannot("the tool call is larger than the /sdk face takes", nil)
	}
	h := http.Header{"Content-Type": {"application/json"}, "PAP-Run-Id": {c.cfg.RunID}, "PC-Action-Id": {actionID}}
	r, err := c.do(ctx, http.MethodPost, c.cfg.Gateway+"/sdk/"+url.PathEscape(connection), body, h, 0)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return cannot("PantherClaw did not answer in time", err)
		}
		return cannot("PantherClaw is unreachable", err)
	}
	return Evaluate(r.status, r.header, r.body, class, actionID, firstHash)
}
