// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"maps"
	"slices"
	"strings"
)

// validateMatchHeaders checks an http mapping's fixed match headers (G0
// M20 D254, HR-526): at most maxStaticHeaders, each an unreserved header
// with a literal value, as a dispatch template's static headers are. An
// aws-json mapping must match its operation's X-Amz-Target, since every
// aws-json operation shares POST /.
func validateMatchHeaders(at string, m Mapping) error {
	if len(m.Headers) > maxStaticHeaders {
		return invalid("%s.headers: at most %d", at, maxStaticHeaders)
	}
	for _, name := range slices.Sorted(maps.Keys(m.Headers)) {
		lower := strings.ToLower(name)
		if !headerRe.MatchString(name) || slices.Contains(reservedHeaders, lower) || strings.HasPrefix(lower, "pap-") ||
			strings.HasPrefix(lower, "pc-") || !staticHeaderRe.MatchString(m.Headers[name]) ||
			slices.ContainsFunc(slices.Collect(maps.Keys(m.Headers)), func(o string) bool { return o != name && strings.EqualFold(o, name) }) {
			return invalid("%s.headers: %q must be a distinct unreserved header with a literal value of 1..128 printable ASCII characters", at, name)
		}
	}
	if m.Encoding == EncodingAWSJSON && !slices.ContainsFunc(slices.Collect(maps.Keys(m.Headers)), func(k string) bool { return strings.EqualFold(k, AWSTargetHeader) }) {
		return invalid("%s: an aws-json mapping matches its operation's %s", at, AWSTargetHeader)
	}
	return nil
}

// matchKey is a mapping's match headers in a canonical form, for the
// package's duplicate-route check.
func matchKey(h map[string]string) string {
	var b strings.Builder
	for _, name := range slices.Sorted(maps.Keys(h)) {
		b.WriteString(" " + strings.ToLower(name) + "=" + h[name])
	}
	return b.String()
}

// validateAWSDispatch checks an aws-json or aws-query template (G0 M20
// D254, HR-526): a POST to the service root whose operation is fixed by the
// signed package, never by the agent. An aws-json template names its
// operation in a literal X-Amz-Target header; an aws-query template in
// literal Action and Version body fields, and sends only scalar values
// (its flat form has no lists).
func (d *Definition) validateAWSDispatch(at string, h *HTTPDispatch) error {
	// aws-query may also be a GET with its operation in the query (a
	// connection test reads that way); aws-json is always a POST.
	get := h.Encoding == EncodingAWSQuery && h.Method == "GET"
	if (h.Method != "POST" && !get) || h.Path != RootPath {
		return invalid("%s: %s is a POST to %s (aws-query also a GET)", at, h.Encoding, RootPath)
	}
	if h.IdempotencyHeader != "" {
		return invalid("%s: %s carries an idempotency token in its body, never a header", at, h.Encoding)
	}
	switch h.Encoding {
	case EncodingAWSJSON:
		if !slices.ContainsFunc(slices.Collect(maps.Keys(h.Headers)), func(k string) bool { return strings.EqualFold(k, AWSTargetHeader) }) {
			return invalid("%s: aws-json names its operation in a literal %s header", at, AWSTargetHeader)
		}
	case EncodingAWSQuery:
		named, where := h.Body, "body"
		if get {
			named, where = h.Query, "query"
		}
		for _, k := range []string{"Action", "Version"} {
			if !strings.HasPrefix(named[k], "literal.") {
				return invalid("%s.%s: aws-query names its operation in a literal %s", at, where, k)
			}
		}
		if !get && (h.Query["Action"] != "" || h.Query["Version"] != "") {
			return invalid("%s.query: a POST names its operation in its body only", at)
		}
		for _, k := range slices.Sorted(maps.Keys(h.Body)) {
			name, isParam := strings.CutPrefix(h.Body[k], "params.")
			if isParam && d.Params[name].Type == TypeIdentifierList {
				return invalid("%s.body.%s: aws-query sends no lists", at, k)
			}
		}
	}
	return nil
}

// AWSAction is the one AWS action an aws-json or aws-query dispatch names,
// fixed by the package (G0 M20 D254): the operation of its X-Amz-Target
// ("Service_Version.Operation"), or its literal Action. A session for the
// dispatch is narrowed to exactly this action (HR-525).
func (d *Definition) AWSAction() (string, bool) {
	if d.Dispatch == nil || d.Dispatch.HTTP == nil {
		return "", false
	}
	h := d.Dispatch.HTTP
	switch h.Encoding {
	case EncodingAWSJSON:
		for k, v := range h.Headers {
			if strings.EqualFold(k, AWSTargetHeader) {
				i := strings.LastIndexByte(v, '.')
				return v[i+1:], i >= 0 && i < len(v)-1
			}
		}
	case EncodingAWSQuery:
		ref := h.Body["Action"]
		if h.Method == "GET" {
			ref = h.Query["Action"]
		}
		a, ok := strings.CutPrefix(ref, "literal.")
		return a, ok && a != ""
	}
	return "", false
}
