// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package telemetry

import (
	"go.opentelemetry.io/otel/attribute"
)

// Attribute keys: the one fixed allow-list every span and metric attribute
// comes from (G0 M13 D30, HR-380). They name a procedure, a code, an org, a
// decision outcome, a duration or a size, or the fixed label of a job or a
// limit; never a payload, secret, email, token or SQL argument. Any other
// key is dropped by Filter before anything is exported or rendered.
const (
	KeyProcedure = "procedure"   // an RPC procedure, for example /pantherclaw.v1.X/Y
	KeyCode      = "code"        // an RPC or platform code, for example permission_denied
	KeyOrgID     = "org_id"      // an organization id (a UUID, never a name)
	KeyOutcome   = "outcome"     // a decision outcome, for example ALLOW
	KeyDuration  = "duration_ms" // a duration in milliseconds
	KeySize      = "size_bytes"  // a size in bytes
	KeyKind      = "kind"        // a fixed kind: a job kind, a waitlist entry kind
	KeyState     = "state"       // a fixed state: a job state, a waitlist entry state
	KeyScope     = "scope"       // a rate limit's fixed scope (Scope*)
)

// allowed is the allow-list as a set.
var allowed = map[string]bool{
	KeyProcedure: true, KeyCode: true, KeyOrgID: true, KeyOutcome: true, KeyDuration: true,
	KeySize: true, KeyKind: true, KeyState: true, KeyScope: true,
}

// maxValueBytes caps a string attribute value; longer values are dropped,
// since an allowed key never carries one (ids, codes and names are short).
const maxValueBytes = 256

// Allowed reports whether key is on the allow-list (HR-380).
func Allowed(key string) bool { return allowed[key] }

// Filter is the single attribute filter (HR-380): it keeps an attribute
// only when its key is on the allow-list and its value is a scalar (a
// string of at most 256 bytes, a bool or a number). The metric SDK runs it
// as every instrument's view filter; the span and metric exporters and the
// /metrics text run it again on everything they write.
func Filter(kv attribute.KeyValue) bool {
	if !allowed[string(kv.Key)] {
		return false
	}
	switch kv.Value.Type() {
	case attribute.STRING:
		return len(kv.Value.AsString()) <= maxValueBytes
	case attribute.BOOL, attribute.INT64, attribute.FLOAT64:
		return true
	default:
		return false
	}
}

// filtered returns the attributes of kvs that pass Filter.
func filtered(kvs []attribute.KeyValue) []attribute.KeyValue {
	out := make([]attribute.KeyValue, 0, len(kvs))
	for _, kv := range kvs {
		if Filter(kv) {
			out = append(out, kv)
		}
	}
	return out
}
