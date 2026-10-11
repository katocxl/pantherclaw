// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

package client

import (
	"bufio"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// What a wait state asks of the agent (PAP/1 §8).
const (
	// NextWait: keep waiting (PENDING, EVIDENCE_REQUESTED).
	NextWait = "wait"
	// NextResubmit: resubmit the identical call with the same action id
	// (READY; CONSUMED, whose stored decision a resubmission returns).
	NextResubmit = "resubmit"
	// NextDeny: the hold ended without an approval.
	NextDeny = "deny"
)

// Next says what the state asks of the agent. An unknown state denies.
func (w WaitState) Next() string {
	switch w.State {
	case "PENDING", "EVIDENCE_REQUESTED":
		return NextWait
	case "READY", "CONSUMED":
		return NextResubmit
	default:
		return NextDeny
	}
}

// ParseWaitResponse reads a WorkloadService.Wait answer (Connect JSON).
func ParseWaitResponse(body []byte) (WaitState, bool, error) {
	var res struct {
		Wait *struct {
			Handle            string     `json:"handle"`
			RetryAfterSeconds int        `json:"retryAfterSeconds"`
			Deadline          time.Time  `json:"deadlineTime"`
			State             string     `json:"state"`
			ConsumeBy         *time.Time `json:"consumeByTime"`
			ApprovalRequestID string     `json:"approvalRequestId"`
			Code              string     `json:"code"`
		} `json:"wait"`
		TimedOut bool `json:"timedOut"`
	}
	if err := json.Unmarshal(body, &res); err != nil || res.Wait == nil {
		return WaitState{}, false, fmt.Errorf("client: wait answer: %w", errors.Join(err, errors.New("no wait state")))
	}
	w := res.Wait
	return WaitState{
		Handle: w.Handle, State: strings.TrimPrefix(w.State, "WAIT_STATE_"), Code: w.Code, Deadline: w.Deadline, ConsumeBy: w.ConsumeBy,
		ApprovalRequestID: w.ApprovalRequestID, RetryAfterSeconds: w.RetryAfterSeconds,
	}, res.TimedOut, nil
}

// Wait long-polls a held call at the server: it answers as soon as the
// state differs from known ("" answers at once) or after timeout (at most
// 30 seconds), and reports whether the timeout ended it.
func (c *Client) Wait(ctx context.Context, handle, known string, timeout time.Duration) (WaitState, bool, error) {
	req := map[string]any{"runId": c.cfg.RunID, "handle": handle, "timeoutSeconds": min(int(timeout/time.Second), 30)}
	if known != "" {
		req["knownState"] = "WAIT_STATE_" + known
	}
	body, err := json.Marshal(req)
	if err != nil {
		return WaitState{}, false, err
	}
	r, err := c.do(ctx, http.MethodPost, c.cfg.Server+"/pantherclaw.v1.WorkloadService/Wait", body, connectHeaders(), timeout)
	if err != nil {
		return WaitState{}, false, err
	}
	if r.status != http.StatusOK {
		return WaitState{}, false, fmt.Errorf("client: wait: HTTP %d", r.status)
	}
	return ParseWaitResponse(r.body)
}

// ReadStream reads an SSE wait stream, calling fn for every state event
// until fn returns false or the stream ends. Heartbeats and other events
// are skipped.
func ReadStream(r io.Reader, fn func(WaitState) bool) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	event, data := "", ""
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			if event == "state" && data != "" {
				var w WaitState
				if err := json.Unmarshal([]byte(data), &w); err != nil {
					return fmt.Errorf("client: wait event: %w", err)
				}
				if !fn(w) {
					return nil
				}
			}
			event, data = "", ""
		case strings.HasPrefix(line, ":"):
		case strings.HasPrefix(line, "event:"):
			event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			data += strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " ")
		}
	}
	return sc.Err()
}

// Stream follows the server's SSE stream for a held call (GET
// /v1/wait/{handle}), calling fn for every state until fn returns false,
// the state is final or the server ends the stream.
func (c *Client) Stream(ctx context.Context, handle string, fn func(WaitState) bool) error {
	r, err := c.do(ctx, http.MethodGet, c.cfg.Server+"/v1/wait/"+url.PathEscape(handle), nil, http.Header{"Accept": {"text/event-stream"}}, 0)
	if err != nil {
		return err
	}
	if r.stream == nil {
		return fmt.Errorf("client: wait stream: HTTP %d %s", r.status, strings.TrimSpace(string(r.body)))
	}
	defer func() { _ = r.stream.Close() }()
	return ReadStream(r.stream, func(w WaitState) bool { return fn(w) && w.Next() == NextWait })
}

// AuthorizeAndWait asks about a tool call and, while it is held, waits in
// PantherClaw (the SSE stream, else long-polls) and resubmits the
// identical call with the same action id once it is ready (PAP/1 §8). It
// returns when the call is allowed, denied, cannot be decided, or ctx ends
// (CannotDecide: the call does not run).
func (c *Client) AuthorizeAndWait(ctx context.Context, connection string, call ToolCall, actionID string) Result {
	res := c.authorize(ctx, connection, call, actionID, "")
	for res.Outcome == Hold {
		first, handle := res.Answer.ActionHash, res.Answer.Wait.Handle
		next, err := c.waitReady(ctx, handle, res.Answer.Wait.State)
		switch {
		case err != nil:
			return cannot("the wait for PantherClaw's decision ended", err)
		case next.Next() == NextDeny:
			return Result{Outcome: Deny, Answer: res.Answer, Why: "the hold ended: " + next.State + " " + next.Code}
		}
		res = c.authorize(ctx, connection, call, actionID, first)
	}
	return res
}

// waitReady waits until the state asks for something other than waiting.
func (c *Client) waitReady(ctx context.Context, handle, known string) (WaitState, error) {
	var last WaitState
	if err := c.Stream(ctx, handle, func(w WaitState) bool { last = w; return true }); err == nil && last.Next() != NextWait && last.State != "" {
		return last, nil
	}
	for {
		w, _, err := c.Wait(ctx, handle, known, 30*time.Second)
		if err != nil {
			return WaitState{}, err
		}
		if w.Next() != NextWait {
			return w, nil
		}
		known = w.State
	}
}
