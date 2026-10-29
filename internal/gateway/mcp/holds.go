// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mcp

import (
	"crypto/sha256"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
)

// Holds and tasks (G0 M6 design decision 15, HR-185, PAP-1 §8).
//
// A held tools/call is remembered by its canonical action without the
// action id, which names the org, connection, run, instance, tool target
// and parameters. An identical call by the same run and instance on the
// same connection reuses the held action id, so an approval binds to it;
// any changed argument is a new action. A client that declares the tasks
// extension gets a task instead of a held tool error: polling it resubmits
// the same action with the poll's own credentials, so the Authority runs
// the whole pipeline again, and only the run, instance and connection that
// created it can see it.
//
// Both live only in this gateway's memory, for at most a hold's default
// deadline; a restart forgets them, and the agent's next identical call
// starts a new action.
const (
	// holdTTL is how long a hold or task is remembered: the default hold
	// deadline (G0 M5 part 2, decision 6).
	holdTTL = time.Hour
	// taskPollMs is the polling interval suggested to clients.
	taskPollMs = 5000
	// Memory bounds: entries (holds and tasks) per instance and in all,
	// and the bytes of the actions tasks keep. Beyond them a hold is not
	// remembered and a task is not created, which only costs the agent a
	// new action.
	maxPerInstance = 32
	maxEntries     = 2000
	maxTaskBytes   = 64 << 20
)

const (
	extTasks         = "io.modelcontextprotocol/tasks"
	metaCapabilities = "io.modelcontextprotocol/clientCapabilities"
)

// Task statuses (tasks extension).
const (
	statusWorking   = "working"
	statusCompleted = "completed"
	statusFailed    = "failed"
	statusCancelled = "cancelled" //nolint:misspell // the tasks extension spells it so
)

// binding is who a hold or task belongs to (HR-185): the connection, the
// run and the instance, in this gateway's org.
type binding struct {
	conn, run, instance string
}

type key [sha256.Size]byte

type hold struct {
	binding binding
	action  string
	expires time.Time
}

// task is one MCP task: a held call the client polls.
type task struct {
	id               string
	binding          binding
	action           actionir.Parsed
	key              key
	created, updated time.Time
	expires          time.Time
	status           string
	result           *toolResult
	// busy: a poll is resubmitting the action; other polls only read.
	busy bool
	// actionID is the action's id, and version the server entry's
	// (state_server.go).
	actionID string
	version  int64
}

// actionKey identifies a call without its action id: two calls with equal
// keys are the same tool call by the same run and instance on the same
// connection.
func actionKey(a actionir.ActionIR) key {
	a.ActionID = ""
	b, _ := json.Marshal(a)
	v := jsontext.Value(b)
	_ = v.Canonicalize()
	return sha256.Sum256(v)
}

// holdStore keeps a gateway's holds and tasks (G0 M15 D14): in memory
// (state_memory.go) or on the server (state_server.go), where every
// replica sees them and a restart loses nothing. A miss, a conflict or a
// full store only costs the agent a new action (HR-412).
type holdStore interface {
	// heldAction returns the action id of an open hold on the same call.
	heldAction(k key) (string, bool)
	// settle records what an answer means for the call's hold.
	settle(k key, b binding, action string, res dispatch.Result)
	// newTask returns a task for a call's answer, or nil.
	newTask(b binding, a actionir.Parsed, k key, res dispatch.Result, result toolResult) *task
	// lookup returns a task of this binding, claiming a working one for
	// a resubmission when resubmit is set.
	lookup(id string, b binding, resubmit bool) (snapshot task, claimed, found bool)
	// finish records a resubmission's answer.
	finish(snap task, res dispatch.Result, result toolResult) task
	// release ends a claim that produced no answer.
	release(id string)
	// cancel forgets a task of this binding and the hold of its call.
	cancel(id string, b binding) bool
	// now is the store's clock.
	now() time.Time

	// An elicitation relayed to the agent (G0 M15 D39), kept like a task:
	// bound to (connection, run, instance), its body sealed on the server,
	// within the same bounds. putElicitation writes it compare-and-set
	// (ifVersion 0: it must not exist) and returns its version;
	// errStateConflict and errStateFull say why not, any other error that
	// the store cannot be asked. getElicitation returns a live one;
	// deleteElicitation deletes it (ifVersion 0: whatever version).
	putElicitation(k key, b binding, body []byte, expires time.Time, ifVersion int64) (int64, error)
	getElicitation(k key) (e elicitation, found bool, err error)
	deleteElicitation(k key, ifVersion int64) (deleted bool, err error)
}

// elicitation is a stored elicitation (D39).
type elicitation struct {
	binding binding
	body    []byte
	version int64
	expires time.Time
}

// Why a state write was refused (D39).
var (
	errStateConflict = errors.New("mcp: the state entry changed or exists")
	errStateFull     = errors.New("mcp: the gateway keeps as much MCP state as it may")
)

// supportsTasks reports whether a request's client capabilities declare
// the tasks extension; only then may a task be returned.
func supportsTasks(meta map[string]jsontext.Value) bool {
	var caps struct {
		Extensions map[string]jsontext.Value `json:"extensions"`
	}
	if v, ok := meta[metaCapabilities]; !ok || json.Unmarshal(v, &caps) != nil {
		return false
	}
	_, ok := caps.Extensions[extTasks]
	return ok
}

// taskResult is a task as clients see it: a CreateTaskResult (resultType
// "task") or a GetTaskResult (resultType "complete", with the tool's
// result once completed).
type taskResult struct {
	ResultType     string         `json:"resultType"`
	TaskID         string         `json:"taskId"`
	Status         string         `json:"status"`
	StatusMessage  string         `json:"statusMessage,omitzero"`
	CreatedAt      string         `json:"createdAt"`
	LastUpdatedAt  string         `json:"lastUpdatedAt"`
	TTLMs          int64          `json:"ttlMs"`
	PollIntervalMs int            `json:"pollIntervalMs,omitzero"`
	Result         *toolResult    `json:"result,omitzero"`
	Meta           map[string]any `json:"_meta,omitzero"`
}

// legacyTask is a task as 2025-11-25 clients see it (Task): ttl and
// pollInterval, and a tool error is "failed".
type legacyTask struct {
	TaskID        string         `json:"taskId"`
	Status        string         `json:"status"`
	StatusMessage string         `json:"statusMessage,omitzero"`
	CreatedAt     string         `json:"createdAt"`
	LastUpdatedAt string         `json:"lastUpdatedAt"`
	TTL           int64          `json:"ttl"`
	PollInterval  int            `json:"pollInterval,omitzero"`
	Meta          map[string]any `json:"_meta,omitzero"`
}

func (t task) legacyView(txn string) legacyTask {
	v := t.view("", txn)
	out := legacyTask{
		TaskID: v.TaskID, Status: v.Status, StatusMessage: v.StatusMessage, CreatedAt: v.CreatedAt, LastUpdatedAt: v.LastUpdatedAt,
		TTL: v.TTLMs, PollInterval: v.PollIntervalMs, Meta: v.Meta,
	}
	switch {
	case t.status == statusCompleted && t.result != nil && t.result.IsError:
		out.Status, out.StatusMessage = statusFailed, "PantherClaw did not run the call, or the tool failed: tasks/result says why."
	case t.status == statusCancelled:
		out.StatusMessage = "Canceled by request."
	}
	return out
}

// view is the task as clients see it; txn is the held transaction, when
// this answer has one.
func (t task) view(resultType, txn string) taskResult {
	out := taskResult{
		ResultType: resultType, TaskID: t.id, Status: t.status, CreatedAt: t.created.UTC().Format(time.RFC3339Nano),
		LastUpdatedAt: t.updated.UTC().Format(time.RFC3339Nano), TTLMs: holdTTL.Milliseconds(), Result: t.result,
	}
	if t.status == statusWorking {
		out.PollIntervalMs = taskPollMs
		out.StatusMessage = "Held for approval or step-up. Keep polling: PantherClaw decides again on each poll and runs the call once it is allowed."
		if txn != "" {
			out.Meta = map[string]any{metaHold: map[string]any{"transaction_id": txn, "retry_after_s": taskPollMs / 1000}}
		}
	}
	return out
}
