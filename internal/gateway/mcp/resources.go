// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mcp

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"net/http"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Reviewed resources (G0 M15 D31, HR-419), in both protocol versions:
// resources/list lists the connection's reviewed static resources and
// resources/templates/list its reviewed templates, with the package's
// names and descriptions only. resources/read is a read operation: the URI
// must match a reviewed template, which maps it to the definition's
// action, and the action goes down the one dispatch path (Authorize,
// BeginDispatch, the upstream read, RecordExecution). A URI that matches
// no reviewed template is "Resource not found" and never reaches the
// server. There are no subscriptions. An identical held read reuses its
// held action (HR-185 parity, D44); tasks are for tools/call only.

// codeResourceNotFound is MCP's "Resource not found".
const codeResourceNotFound = -32002

// resourceView is a resource or a resource template as clients see it.
type resourceView struct {
	URI         string `json:"uri,omitzero"`
	URITemplate string `json:"uriTemplate,omitzero"`
	Name        string `json:"name"`
	Title       string `json:"title,omitzero"`
	Description string `json:"description,omitzero"`
}

// resources are the connection's reviewed resources: mcp_resource
// mappings of definitions this connection dispatches.
func resources(conn *control.Connection) []mapping.Resource {
	if conn.Mapper == nil {
		return nil
	}
	var out []mapping.Resource
	for _, r := range conn.Mapper.Resources() {
		if d, ok := conn.Package.Definition(r.Operation); ok && dispatches(conn.GetKind(), d) {
			out = append(out, r)
		}
	}
	return out
}

// resourceCapability is the resources capability a connection with a
// reviewed resource advertises; nil without one.
func resourceCapability(conn *control.Connection) map[string]any {
	if len(resources(conn)) == 0 {
		return nil
	}
	return map[string]any{"subscribe": false, "listChanged": false}
}

// resourceList is resources/list (templates false) or
// resources/templates/list (templates true).
func resourceList(conn *control.Connection, templates bool) []resourceView {
	out := []resourceView{}
	for _, r := range resources(conn) {
		if r.Static == templates {
			continue
		}
		v := resourceView{Name: r.Route, Title: r.Title, Description: r.Description}
		if templates {
			v.URITemplate = r.URI
		} else {
			v.URI = r.URI
		}
		out = append(out, v)
	}
	return out
}

// listResources answers a verified resources/list or
// resources/templates/list; modern adds 2026-07-28's result fields.
func listResources(conn *control.Connection, method string, modern bool) map[string]any {
	templates := method == "resources/templates/list"
	key := "resources"
	if templates {
		key = "resourceTemplates"
	}
	out := map[string]any{key: resourceList(conn, templates)}
	if modern {
		out["resultType"], out["ttlMs"], out["cacheScope"], out["_meta"] = "complete", listTTL, "private", serverInfo()
	}
	return out
}

// isResourceMethod reports a method of the resources face.
func isResourceMethod(method string) bool {
	return method == "resources/list" || method == "resources/templates/list" || method == "resources/read"
}

// readResource serves resources/read: ok is false when it already
// answered with a protocol error. modern says which version's result to
// build.
func (h *Handler) readResource(w http.ResponseWriter, r *http.Request, conn *control.Connection, req request, p params, in dispatch.Inbound,
	modern bool,
) (dispatch.Result, bool) {
	ctx := r.Context()
	if _, _, ok := conn.Mapper.ResourceRoute(p.URI); !ok || len(resources(conn)) == 0 {
		fail(w, http.StatusOK, req.ID, codeResourceNotFound, "Resource not found", map[string]string{"uri": p.URI})
		return dispatch.Result{}, false
	}
	if in.Run == "" {
		fail(w, http.StatusOK, req.ID, codeInvalidParams, "the "+dispatch.HeaderRunID+" header is required", nil)
		return dispatch.Result{}, false
	}
	// The action id is the client's, or the held one for an identical read
	// (HR-185 parity, D44 L6), or new. Tasks are for tools/call only.
	action := in.Action
	fresh := action == ""
	if fresh {
		action = ids.NewV7().String()
	}
	b := binding{conn: conn.GetId(), run: in.Run, instance: in.Instance}
	parsed, err := conn.Mapper.ReadResource(ctx, mapping.Context{
		Org: h.config.Current().Org, Env: in.Env, RunID: in.Run, ActionID: action, AgentInstance: in.Instance, Connection: conn.GetId(),
	}, p.URI)
	if err != nil {
		code := "invalid_arguments"
		if errors.Is(err, mapping.ErrUnsafeValue) {
			// A value that would change the upstream path (D44, HR-419).
			fail(w, http.StatusOK, req.ID, codeInvalidParams, "Invalid params: a resource URI value is empty, a dot segment, or holds a "+
				"slash, a backslash or a control character", nil)
			return dispatch.Result{}, false
		}
		if errors.Is(err, mapping.ErrUnmapped) {
			fail(w, http.StatusOK, req.ID, codeResourceNotFound, "Resource not found", map[string]string{"uri": p.URI})
			return dispatch.Result{}, false
		}
		if !errors.Is(err, actionir.ErrAmbiguous) {
			code = "unmapped"
		}
		res := dispatch.Result{Class: dispatch.CannotAuthorize, Code: code}
		h.readRefused(w, req, res, "The URI does not match the resource's reviewed identity.")
		return res, false
	}
	k := actionKey(parsed.Action)
	if fresh {
		if held, ok := h.holds.heldAction(k, b); ok {
			parsed.Action.ActionID, action = held, held
			if parsed, err = actionir.Encode(parsed.Action); err != nil {
				res := dispatch.Result{Class: dispatch.CannotAuthorize, Code: "invalid_arguments"}
				h.readRefused(w, req, res, "")
				return res, false
			}
		}
	}
	res := h.engine.Dispatch(ctx, dispatch.Call{Connection: conn, Action: parsed, Workload: in.Creds})
	if res.Class == dispatch.AuthenticationFailed {
		h.refusePAP(w, r, req.ID, res.PAPError, res.Nonce)
		return res, false
	}
	h.holds.settle(k, b, action, res)
	if res.Nonce != "" {
		w.Header().Set(dispatch.HeaderNonce, res.Nonce)
	}
	if res.Class != "" || res.Response == nil {
		h.readRefused(w, req, res, "")
		return res, true
	}
	var up struct {
		Contents jsontext.Value `json:"contents"`
	}
	if json.Unmarshal(res.Response.Body, &up) != nil || up.Contents.Kind() != '[' {
		// The server answered a JSON-RPC error: the read failed upstream.
		h.readRefused(w, req, res, "")
		return res, true
	}
	out := map[string]any{"contents": up.Contents, "_meta": map[string]any{metaResult: map[string]any{
		"transaction_id": res.TransactionID, "outcome": outcome(res), "decision": decision(res), "mode": mode(res),
		"receipt": res.Receipt, "target_status": res.Response.Status, "truncated": res.Response.Truncated,
	}}}
	if modern {
		out["resultType"] = "complete"
	}
	write(w, http.StatusOK, response{ID: req.ID, Result: out})
	return res, true
}

// readRefused answers a refused or failed read: resources/read has no tool
// error, so it is a JSON-RPC error whose data carries PantherClaw's facts,
// as a tool error's _meta does (F642).
func (h *Handler) readRefused(w http.ResponseWriter, req request, res dispatch.Result, detail string) {
	e := errorResult(res, detail)
	text := ""
	if cs, ok := e.Content.([]content); ok && len(cs) > 0 {
		text = cs[0].Text
	}
	fail(w, http.StatusOK, req.ID, codeForbidden, text, e.Meta)
}
