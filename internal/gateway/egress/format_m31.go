// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package egress

import (
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"maps"
	"mime"
	"slices"
	"strings"
	"unicode/utf8"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
)

// indexed is an array a JSON body's index keys build ([0], [1], …) before
// it is checked for gaps (G0 M31 D950 b).
type indexed struct{ items map[int]any }

// nestJSONBody turns a JSON body's keys into one document (G0 M31 D950 a,
// b; G0 M20 D260): a[b] nests an object, a[0] indexes an array, and a[*]
// builds one element per item of the key's list, at most
// defs.MaxEachItems. The keys are the reviewed package's, checked again
// here, so no value ever adds a key; an array whose present keys leave a
// gap (an optional param left out) builds nothing.
func nestJSONBody(obj map[string]any) (map[string]any, error) {
	keys := slices.Sorted(maps.Keys(obj))
	if err := defs.CheckJSONBodyKeys(keys); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBuild, err)
	}
	var root any = map[string]any{}
	for _, k := range keys {
		p, err := defs.ParseJSONBodyKey(k)
		if err != nil {
			return nil, fmt.Errorf("%w: JSON body key %q", ErrBuild, k)
		}
		segs := append([]defs.JSONSeg{{Name: p.Root, Kind: defs.SegName}}, p.Segs...)
		if root, err = put(root, segs, obj[k]); err != nil {
			return nil, fmt.Errorf("%w: JSON body key %q: %w", ErrBuild, k, err)
		}
	}
	out, err := settle(root)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBuild, err)
	}
	m, _ := out.(map[string]any)
	return m, nil
}

// put places v at segs below node and returns the node.
func put(node any, segs []defs.JSONSeg, v any) (any, error) {
	if len(segs) == 0 {
		if node != nil {
			return nil, fmt.Errorf("a value and a container")
		}
		return v, nil
	}
	s := segs[0]
	switch s.Kind {
	case defs.SegName:
		m, ok := node.(map[string]any)
		if node == nil {
			m, ok = map[string]any{}, true
		}
		if !ok {
			return nil, fmt.Errorf("an object and another value")
		}
		c, err := put(m[s.Name], segs[1:], v)
		if err != nil {
			return nil, err
		}
		m[s.Name] = c
		return m, nil
	case defs.SegIndex:
		a, ok := node.(*indexed)
		if node == nil {
			a, ok = &indexed{items: map[int]any{}}, true
		}
		if !ok {
			return nil, fmt.Errorf("an array and another value")
		}
		c, err := put(a.items[s.Index], segs[1:], v)
		if err != nil {
			return nil, err
		}
		a.items[s.Index] = c
		return a, nil
	case defs.SegEach:
	}
	// [*]: one element per item of the key's list (D950 a).
	list, ok := v.([]string)
	if node != nil || !ok {
		return nil, fmt.Errorf("[*] takes one list")
	}
	if len(list) > defs.MaxEachItems {
		return nil, fmt.Errorf("[*] builds at most %d elements", defs.MaxEachItems)
	}
	out := make([]any, len(list))
	for i, item := range list {
		e, err := put(nil, segs[1:], item)
		if err != nil {
			return nil, err
		}
		out[i] = e
	}
	return out, nil
}

// settle turns every indexed array into a list, refusing a gap.
func settle(node any) (any, error) {
	switch n := node.(type) {
	case map[string]any:
		for k, v := range n {
			s, err := settle(v)
			if err != nil {
				return nil, err
			}
			n[k] = s
		}
		return n, nil
	case *indexed:
		out := make([]any, len(n.items))
		for i := range out {
			v, ok := n.items[i]
			if !ok {
				return nil, fmt.Errorf("array index %d left unfilled", i)
			}
			s, err := settle(v)
			if err != nil {
				return nil, err
			}
			out[i] = s
		}
		return out, nil
	case []any:
		for i, v := range n {
			s, err := settle(v)
			if err != nil {
				return nil, err
			}
			n[i] = s
		}
		return n, nil
	}
	return node, nil
}

// graphQLBody is a GraphQL request (D950 c): the package's fixed document
// and the body mapping as its variables.
func graphQLBody(doc string, vars map[string]any) map[string]any {
	if vars == nil {
		vars = map[string]any{}
	}
	return map[string]any{"query": doc, "variables": vars}
}

// mailLineWidth is where the base64 text body is wrapped (RFC 2045 §6.8).
const mailLineWidth = 76

// mailBody builds an rfc5322-raw request body (D950 d): an RFC 5322
// message whose To, Cc and Bcc are the mapped lists, whose Subject is the
// mapped subject (RFC 2047 encoded when it is not ASCII) and whose body is
// the mapped text as text/plain; charset=utf-8 in base64, sent as
// {"raw": <base64url of the message>}. A line break in an address or the
// subject, or an address holding a separator, builds nothing: no value can
// write a header of its own.
func mailBody(obj map[string]any) ([]byte, error) {
	var b strings.Builder
	for _, h := range []struct{ name, key string }{{"To", defs.MailTo}, {"Cc", defs.MailCc}, {"Bcc", defs.MailBcc}} {
		v, ok := obj[h.key]
		if !ok {
			continue
		}
		list, isList := v.([]string)
		if !isList {
			return nil, fmt.Errorf("%w: %s is not a list of addresses", ErrBuild, h.key)
		}
		if len(list) == 0 {
			continue
		}
		for _, a := range list {
			if a == "" || strings.ContainsAny(a, "\r\n,;<>()\"\\ \t") || !utf8.ValidString(a) {
				return nil, fmt.Errorf("%w: a mail address holds a line break or a separator (PARAM_INVALID)", ErrBuild)
			}
		}
		b.WriteString(h.name + ": " + strings.Join(list, ",\r\n ") + "\r\n")
	}
	if to, _ := obj[defs.MailTo].([]string); len(to) == 0 {
		return nil, fmt.Errorf("%w: a mail message names at least one To address", ErrBuild)
	}
	if v, ok := obj[defs.MailSubject]; ok {
		s, isStr := v.(string)
		if !isStr || strings.ContainsAny(s, "\r\n") || !utf8.ValidString(s) {
			return nil, fmt.Errorf("%w: a line break in the subject (PARAM_INVALID)", ErrBuild)
		}
		b.WriteString("Subject: " + mime.BEncoding.Encode("utf-8", s) + "\r\n")
	}
	text := ""
	if v, ok := obj[defs.MailText]; ok {
		s, isStr := v.(string)
		if !isStr || !utf8.ValidString(s) {
			return nil, fmt.Errorf("%w: the mail text is not UTF-8 text", ErrBuild)
		}
		text = s
	}
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n")
	enc := base64.StdEncoding.EncodeToString([]byte(text))
	for len(enc) > mailLineWidth {
		b.WriteString(enc[:mailLineWidth] + "\r\n")
		enc = enc[mailLineWidth:]
	}
	if enc != "" {
		b.WriteString(enc + "\r\n")
	}
	raw := base64.URLEncoding.EncodeToString([]byte(b.String()))
	out, err := json.Marshal(map[string]string{"raw": raw}, json.Deterministic(true))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBuild, err)
	}
	return out, nil
}
