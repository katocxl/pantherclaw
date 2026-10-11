// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

package client

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/katocxl/pantherclaw/sdk/go/pap"
)

// ToolCall is a raw tool call as the agent made it. The gateway maps it
// through the connection's signed package (HR-201); the SDK sends no
// ActionIR, hash or canonical form and never changes the input.
type ToolCall struct {
	// Tool is the agent's name for the tool: a built-in such as Bash, or
	// mcp__<server>__<tool>.
	Tool string `json:"tool"`
	// Server is the MCP server's name, for an MCP tool only.
	Server string `json:"server,omitempty"`
	// Input is the tool input, a JSON object.
	Input jsontext.Value `json:"input"`
	// ToolUseID is the agent's id of the call.
	ToolUseID string `json:"tool_use_id"`
	// Cwd is a shell tool's working directory (Bash, PowerShell) only.
	Cwd string `json:"cwd,omitempty"`
}

// Outcome is what the agent may do with a tool call. Only Allow, and
// Observe for an unmapped built-in tool, let it run.
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
	// (base64url), when the gateway sends them.
	ActionID      string     `json:"action_id"`
	ActionHash    string     `json:"action_hash"`
	ActionIR      string     `json:"action_ir"`
	TransactionID string     `json:"transaction_id"`
	Receipt       string     `json:"receipt"`
	Mode          string     `json:"mode"`
	Coverage      string     `json:"coverage"`
	Wait          *WaitState `json:"wait"`
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
	// Why says what decided the outcome, for logs and the agent.
	Why string
	// Err is the failure behind CannotDecide, if any.
	Err error
}

func cannot(why string, err error) Result { return Result{Outcome: CannotDecide, Why: why, Err: err} }

var hexHash = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Evaluate reads a /sdk answer for the action id the SDK sent. firstHash,
// when set, is the action hash of an earlier answer for the same action:
// a resubmission must map to the same action. Anything it cannot read or
// check is CannotDecide, never Allow (HR-200, HR-201).
func Evaluate(status int, h http.Header, body []byte, actionID, firstHash string) Result {
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
			if a.Mode != "monitor" || a.ActionHash != "" {
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
		r.Outcome = Hold
	default:
		return cannot("unknown decision "+a.Decision, nil)
	}
	if err := checkAction(a, actionID, firstHash); err != nil {
		return cannot(err.Error(), nil)
	}
	return r
}

// checkAction checks what an allow or a hold says about the action: the
// label, the action id sent, a hash the canonical action (when sent)
// hashes to and whose action id is the one sent, and for a resubmission
// the first answer's hash.
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
	}
	if a.ActionIR == "" {
		return nil
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
	}
	return nil
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
	if call.Tool == "" || call.ToolUseID == "" || call.Input.Kind() != '{' {
		return cannot("a tool call needs a tool name, its id and an input object", nil)
	}
	body, err := json.Marshal(call)
	if err != nil {
		return cannot("the tool call cannot be encoded", err)
	}
	h := http.Header{"Content-Type": {"application/json"}, "PAP-Run-Id": {c.cfg.RunID}, "PC-Action-Id": {actionID}}
	r, err := c.do(ctx, http.MethodPost, c.cfg.Gateway+"/sdk/"+url.PathEscape(connection), body, h, 0)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return cannot("PantherClaw did not answer in time", err)
		}
		return cannot("PantherClaw is unreachable", err)
	}
	return Evaluate(r.status, r.header, r.body, actionID, firstHash)
}
