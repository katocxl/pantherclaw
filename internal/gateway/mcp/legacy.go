// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mcp

import (
	"encoding/json/jsontext"
	"maps"
	"net/http"
	"slices"

	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
)

// The 2025-11-25 face (G0 M6 design decision 13): initialize opens a
// session (sessions.go), and every later request names it, carries PAP/1
// credentials of the same instance and key in the same run, and is
// verified again (HR-083). Tools are the same reviewed tools; a tools/call
// may be task-augmented (params.task), and then always answers with a task
// (HR-185, holds.go).
//
// One deviation from the tasks utility: tasks/result on a task that is
// still held cannot block until it ends, because only the client's own
// fresh credentials can resubmit the action. It resubmits once and, when
// the action is still held, answers the held tool error; the task stays
// working, and an identical call reuses the held action.

const metaRelatedTask = "io.modelcontextprotocol/related-task"

// legacy serves a 2025-11-25 request.
func (h *Handler) legacy(w http.ResponseWriter, r *http.Request, conn *control.Connection, body []byte, req request, p params) {
	if req.Method == "initialize" {
		h.initialize(w, r, conn, body, req)
		return
	}
	if vs := r.Header.Values(HeaderProtocolVersion); len(vs) != 1 || vs[0] != LegacyVersion {
		fail(w, http.StatusBadRequest, req.ID, codeInvalidRequest, "unsupported "+HeaderProtocolVersion, nil)
		return
	}
	sids := r.Header.Values(HeaderSessionID)
	if len(sids) != 1 || sids[0] == "" {
		fail(w, http.StatusBadRequest, req.ID, codeInvalidRequest, "the "+HeaderSessionID+" header is required: initialize first", nil)
		return
	}
	sid := sids[0]
	sess, ok := h.sessions.get(sid)
	if !ok || sess.conn != conn.GetId() {
		noSession(w, req.ID)
		return
	}
	in, ok := h.inbound(w, r, conn, body, req.ID, req.Method, p.Name)
	if !ok {
		return
	}
	if !sess.binds(conn.GetId(), in) {
		noSession(w, req.ID)
		return
	}
	in.Run = sess.run
	switch {
	case len(req.ID) == 0:
		// A notification (such as notifications/initialized): verified,
		// then ignored.
		if h.verifySession(w, r, req.ID, in, sid, sess) {
			w.WriteHeader(http.StatusAccepted)
		}
	case req.Method == "tools/call":
		h.legacyCall(w, r, conn, req, p, in, sid)
	case req.Method == "tasks/get" || req.Method == "tasks/result" || req.Method == "tasks/cancel":
		h.legacyTask(w, r, conn, req, p, in, sid, sess)
	case isResourceMethod(req.Method) && resourceCapability(conn) != nil:
		// Reviewed resources (resources.go, G0 M15 D31).
		if req.Method == "resources/read" {
			if res, ok := h.readResource(w, r, conn, req, p, in, false); ok && slices.Contains(res.Reasons, "RUN_MISMATCH") {
				h.sessions.end(sid)
			} else if ok {
				h.sessions.touch(sid)
			}
			return
		}
		if h.verifySession(w, r, req.ID, in, sid, sess) {
			write(w, http.StatusOK, response{ID: req.ID, Result: listResources(conn, req.Method, false)})
		}
	case req.Method == "ping" || req.Method == "tools/list":
		if !h.verifySession(w, r, req.ID, in, sid, sess) {
			return
		}
		result := map[string]any{}
		if req.Method == "tools/list" {
			ts := tools(conn)
			for i := range ts {
				ts[i].Execution = map[string]string{"taskSupport": "optional"}
			}
			result["tools"] = append([]tool{}, ts...)
		}
		write(w, http.StatusOK, response{ID: req.ID, Result: result})
	default:
		fail(w, http.StatusOK, req.ID, codeMethodNotFound, "Method not found: "+req.Method, nil)
	}
}

func noSession(w http.ResponseWriter, id jsontext.Value) {
	fail(w, http.StatusNotFound, id, codeInvalidRequest, "Session not found: initialize a new session", nil)
}

// initialize opens a session for the verified workload in its run.
func (h *Handler) initialize(w http.ResponseWriter, r *http.Request, conn *control.Connection, body []byte, req request) {
	switch {
	case len(req.ID) == 0:
		fail(w, http.StatusBadRequest, nil, codeInvalidRequest, "initialize is a request", nil)
		return
	case len(r.Header.Values(HeaderSessionID)) > 0:
		fail(w, http.StatusBadRequest, req.ID, codeInvalidRequest, "initialize opens a new session: send it without "+HeaderSessionID, nil)
		return
	}
	in, ok := h.inbound(w, r, conn, body, req.ID, req.Method, "")
	if !ok {
		return
	}
	if in.Run == "" {
		fail(w, http.StatusBadRequest, req.ID, codeInvalidParams, "the "+dispatch.HeaderRunID+" header is required: a session lives in a run", nil)
		return
	}
	v, ok := h.verifyRun(w, r, req.ID, in, in.Run)
	if !ok {
		if v.Code == pap.CodeRunMismatch {
			h.refusePAP(w, r, req.ID, v.Code, v.Nonce)
		}
		return
	}
	sid, err := h.sessions.open(conn.GetId(), v.Instance, v.JKT, in.Run, v.RunExpires)
	if err != nil {
		fail(w, http.StatusServiceUnavailable, req.ID, codeUnavailable, "the gateway holds too many MCP sessions", nil)
		return
	}
	w.Header().Set(HeaderSessionID, sid)
	caps := map[string]any{
		"tools": map[string]any{"listChanged": false},
		"tasks": map[string]any{"cancel": map[string]any{}, "requests": map[string]any{"tools": map[string]any{"call": map[string]any{}}}},
	}
	if rc := resourceCapability(conn); rc != nil {
		caps["resources"] = rc
	}
	write(w, http.StatusOK, response{ID: req.ID, Result: map[string]any{
		"protocolVersion": LegacyVersion,
		"capabilities":    caps,
		"serverInfo":      serverInfo()[metaServerInfo],
		"instructions":    discoverResult(conn)["instructions"],
	}})
}

// verifySession verifies a request in a session that decides nothing:
// the workload, the run and the instance and key the session is bound to.
// A run that ended ends the session.
func (h *Handler) verifySession(w http.ResponseWriter, r *http.Request, id jsontext.Value, in dispatch.Inbound, sid string, sess session) bool {
	v, ok := h.verifyRun(w, r, id, in, sess.run)
	if !ok {
		if v.Code == pap.CodeRunMismatch {
			h.sessions.end(sid)
			noSession(w, id)
		}
		return false
	}
	if v.Instance != sess.instance || v.JKT != sess.jkt {
		noSession(w, id)
		return false
	}
	h.sessions.touch(sid)
	return true
}

// endSession ends a session on DELETE, for its own workload only.
func (h *Handler) endSession(w http.ResponseWriter, r *http.Request, conn *control.Connection, body []byte) {
	sid := r.Header.Get(HeaderSessionID)
	sess, ok := h.sessions.get(sid)
	if !ok || sess.conn != conn.GetId() {
		noSession(w, nil)
		return
	}
	in, ok := h.inbound(w, r, conn, body, nil, "", "")
	if !ok {
		return
	}
	if !sess.binds(conn.GetId(), in) {
		noSession(w, nil)
		return
	}
	in.Run = sess.run
	if !h.verifySession(w, r, nil, in, sid, sess) {
		return
	}
	h.sessions.end(sid)
	w.WriteHeader(http.StatusNoContent)
}

// legacyCall serves a 2025-11-25 tools/call; a task-augmented one always
// answers with a task.
func (h *Handler) legacyCall(w http.ResponseWriter, r *http.Request, conn *control.Connection, req request, p params, in dispatch.Inbound, sid string) {
	// 2025-11-25 has no input responses: a retry's are ignored, as before.
	p.InputResponses, p.RequestState = nil, nil
	c, ok := h.callTool(w, r, conn, req, p, in)
	if !ok {
		return
	}
	if slices.Contains(c.res.Reasons, "RUN_MISMATCH") {
		h.sessions.end(sid) // the run ended: so does the session
	} else {
		h.sessions.touch(sid)
	}
	c.result.ResultType = ""
	if len(p.Task) == 0 {
		write(w, http.StatusOK, response{ID: req.ID, Result: c.result})
		return
	}
	t := h.holds.newTask(c.b, c.action, c.key, c.res, c.result)
	if t == nil {
		// No room for a task: the answer itself, rather than losing it.
		write(w, http.StatusOK, response{ID: req.ID, Result: c.result})
		return
	}
	out := map[string]any{"task": t.legacyView(c.res.TransactionID)}
	if t.status == statusWorking {
		out["_meta"] = map[string]any{"io.modelcontextprotocol/model-immediate-response": "PantherClaw is holding this call for " +
			"approval or step-up. It runs once allowed; the task's result says what happened."}
	}
	write(w, http.StatusOK, response{ID: req.ID, Result: out})
}

// legacyTask serves tasks/get, tasks/result and tasks/cancel in a session,
// for tasks of the session's run and instance on this connection only
// (HR-185). A poll of a working task resubmits it with the poll's
// credentials.
func (h *Handler) legacyTask(w http.ResponseWriter, r *http.Request, conn *control.Connection, req request, p params, in dispatch.Inbound,
	sid string, sess session,
) {
	b := binding{conn: sess.conn, run: sess.run, instance: sess.instance}
	notFound := func() {
		fail(w, http.StatusOK, req.ID, codeInvalidParams, "Failed to retrieve task: Task not found", nil)
	}
	if req.Method == "tasks/cancel" {
		if !h.verifySession(w, r, req.ID, in, sid, sess) {
			return
		}
		t, _, found := h.holds.lookup(p.TaskID, b, false)
		switch {
		case !found:
			notFound()
		case t.status != statusWorking:
			fail(w, http.StatusOK, req.ID, codeInvalidParams, "Cannot cancel task: already in terminal status '"+t.legacyView("").Status+"'", nil)
		case !h.holds.cancel(p.TaskID, b):
			notFound()
		default:
			t.status, t.updated = statusCancelled, h.holds.now()
			write(w, http.StatusOK, response{ID: req.ID, Result: t.legacyView("")})
		}
		return
	}
	t, claimed, found := h.holds.lookup(p.TaskID, b, true)
	held := dispatch.Result{Class: dispatch.Held}
	if claimed {
		done, res, ok := h.resubmit(w, r, conn, req, t, in)
		if !ok {
			return
		}
		h.sessions.touch(sid)
		t, held = done, res
	} else {
		if !h.verifySession(w, r, req.ID, in, sid, sess) {
			return
		}
		if !found {
			notFound()
			return
		}
	}
	if req.Method == "tasks/get" {
		txn := ""
		if t.status == statusWorking {
			txn = held.TransactionID
		}
		write(w, http.StatusOK, response{ID: req.ID, Result: t.legacyView(txn)})
		return
	}
	// tasks/result: the call's result, or the held tool error while held.
	result := errorResult(held, "")
	if t.result != nil {
		result = *t.result
	}
	result.ResultType = ""
	result.Meta = maps.Clone(result.Meta)
	if result.Meta == nil {
		result.Meta = map[string]any{}
	}
	result.Meta[metaRelatedTask] = map[string]string{"taskId": t.id}
	write(w, http.StatusOK, response{ID: req.ID, Result: result})
}
