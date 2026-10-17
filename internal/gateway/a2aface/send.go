// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package a2aface

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"net/http"

	wire "github.com/katocxl/pantherclaw/internal/a2a"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// errEvent stops a stream whose event is not one this call may relay.
var errEvent = errors.New("a2aface: an event this call may not relay")

// dispatch maps a call through the connection's package and sends it down
// the one dispatch path; a stream's events go to sink.
func (h *Handler) dispatch(c call, sink dispatch.A2ASink) dispatch.Result {
	if c.conn.Mapper == nil {
		return dispatch.Result{Class: dispatch.CannotAuthorize, Code: "invalid_arguments"}
	}
	action := c.in.Action
	if action == "" {
		action = ids.NewV7().String()
	}
	ctx := c.r.Context()
	parsed, err := c.conn.Mapper.A2A(ctx, mapping.Context{
		Org: h.config.Current().Org, Env: c.in.Env, RunID: c.in.Run, ActionID: action, AgentInstance: c.in.Instance,
		Connection: c.conn.GetId(),
	}, c.method, c.mapParams)
	if err != nil {
		return dispatch.Result{Class: dispatch.CannotAuthorize, Code: "invalid_arguments"}
	}
	if sink != nil {
		ctx = dispatch.WithA2AStream(ctx, sink)
	}
	return h.engine.Dispatch(ctx, dispatch.Call{Connection: c.conn, Action: parsed, Workload: c.in.Creds})
}

// stream serves SendStreamingMessage and SubscribeToTask: the events are
// relayed as they arrive, each checked (HR-327); a call refused before any
// event is answered as an error.
func (h *Handler) stream(w http.ResponseWriter, c call) {
	started := false
	task := c.taskID // SubscribeToTask: the one task; a send learns it
	o := c.owner()
	sink := func(event []byte) error {
		var ev wire.StreamResponse
		if json.Unmarshal(event, &ev) != nil {
			return errEvent
		}
		id := ev.TaskID()
		switch {
		case id == "" && ev.Message != nil:
		case !wire.ValidID(id):
			return errEvent
		case task == "":
			task = id
		case id != task:
			// Another task's events never reach this run.
			return errEvent
		}
		if ev.Task != nil {
			h.owned.record(o, ev.Task.ID, ev.Task.ContextID)
		} else if ev.Message != nil && ev.Message.ContextID != "" {
			h.owned.record(o, "", ev.Message.ContextID)
		} else if id != "" {
			if _, ok := h.owned.task(o, id); !ok {
				return errEvent
			}
		}
		if !started {
			started = true
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "private, no-store")
			w.WriteHeader(http.StatusOK)
		}
		out := event
		if c.binding == wire.BindingJSONRPC {
			var err error
			if out, err = json.Marshal(map[string]any{"jsonrpc": "2.0", "id": c.id, "result": jsontext.Value(event)}); err != nil {
				return err
			}
		}
		if _, err := w.Write(append(append([]byte("data: "), out...), '\n', '\n')); err != nil {
			return err
		}
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		return nil
	}
	res := h.send(c, sink)
	if started {
		// The stream was answered; how it ended is on the transaction.
		return
	}
	if res.Class == "" {
		res.Class, res.Code = dispatch.EnforcementFailed, dispatch.CodeA2AStream
	}
	h.answer(w, c, res)
}
