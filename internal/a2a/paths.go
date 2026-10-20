// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package a2a

import (
	"net/http"
	"net/url"
	"strings"
)

// maxTaskID bounds a task id taken from a path.
const maxTaskID = 256

// Route maps an HTTP+JSON request (method and path below the interface
// URL) to its A2A method and task id (§5.3, §11). ok is false for a path
// the binding does not define.
func Route(httpMethod, path string) (method, taskID string, ok bool) {
	switch {
	case httpMethod == http.MethodPost && path == "/message:send":
		return MethodSendMessage, "", true
	case httpMethod == http.MethodPost && path == "/message:stream":
		return MethodSendStreamingMessage, "", true
	case httpMethod == http.MethodGet && path == "/tasks":
		return MethodListTasks, "", true
	case httpMethod == http.MethodGet && path == "/extendedAgentCard":
		return MethodGetExtendedCard, "", true
	}
	rest, found := strings.CutPrefix(path, "/tasks/")
	if !found {
		return "", "", false
	}
	if id, sub, nested := strings.Cut(rest, "/"); nested {
		if !validTaskID(id) || !strings.HasPrefix(sub, "pushNotificationConfigs") {
			return "", "", false
		}
		switch httpMethod {
		case http.MethodPost:
			return MethodCreatePushConfig, id, sub == "pushNotificationConfigs"
		case http.MethodGet:
			if sub == "pushNotificationConfigs" {
				return MethodListPushConfigs, id, true
			}
			return MethodGetPushConfig, id, true
		case http.MethodDelete:
			return MethodDeletePushConfig, id, true
		}
		return "", "", false
	}
	if id, verb, colon := strings.Cut(rest, ":"); colon {
		if httpMethod != http.MethodPost || !validTaskID(id) {
			return "", "", false
		}
		switch verb {
		case "cancel":
			return MethodCancelTask, id, true
		case "subscribe":
			return MethodSubscribeToTask, id, true
		}
		return "", "", false
	}
	if httpMethod == http.MethodGet && validTaskID(rest) {
		return MethodGetTask, rest, true
	}
	return "", "", false
}

// Path returns the HTTP method and the path below the interface URL of an
// HTTP+JSON call (the inverse of Route for the relayed methods).
func Path(method, taskID string) (httpMethod, path string, ok bool) {
	id := url.PathEscape(taskID)
	switch method {
	case MethodSendMessage:
		return http.MethodPost, "/message:send", true
	case MethodSendStreamingMessage:
		return http.MethodPost, "/message:stream", true
	case MethodListTasks:
		return http.MethodGet, "/tasks", true
	case MethodGetTask:
		return http.MethodGet, "/tasks/" + id, validTaskID(taskID)
	case MethodCancelTask:
		return http.MethodPost, "/tasks/" + id + ":cancel", validTaskID(taskID)
	case MethodSubscribeToTask:
		return http.MethodPost, "/tasks/" + id + ":subscribe", validTaskID(taskID)
	}
	return "", "", false
}

// validTaskID is a task id PantherClaw accepts: printable ASCII without
// path or query separators.
func validTaskID(id string) bool {
	if id == "" || len(id) > maxTaskID {
		return false
	}
	for i := range len(id) {
		c := id[i]
		if c < 0x21 || c > 0x7e || c == '/' || c == '?' || c == '#' || c == ':' || c == '%' {
			return false
		}
	}
	return true
}

// ValidID reports whether id is an acceptable task, context or message id.
func ValidID(id string) bool { return validTaskID(id) }
