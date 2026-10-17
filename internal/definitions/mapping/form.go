// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mapping

import (
	"mime"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/definitions/domain"
)

// FormContentType is the only media type a form mapping reads (G0 M14 D8).
const FormContentType = "application/x-www-form-urlencoded"

// DecodeForm strictly decodes an application/x-www-form-urlencoded body
// into the same input a JSON mapping sees (G0 M14 D8, HR-300): keys in the
// Stripe bracket syntax (a[b]=, a[b][c]=, a[]=) become nested objects and
// lists of strings; every value is a string. Anything that a target could
// read another way is refused, never guessed: a media type other than the
// form's (charset utf-8 at most), a body over domain.MaxFormBytes or with
// more than domain.MaxFormKeys pairs, an empty pair, a pair without "=",
// an invalid escape, invalid UTF-8 or a control character, a key outside
// the grammar or deeper than domain.MaxFormDepth, a scalar key twice, and
// one name used as a value, a list and an object.
func DecodeForm(contentType string, raw []byte) (map[string]any, error) {
	if err := checkFormType(contentType); err != nil {
		return nil, err
	}
	if len(raw) > domain.MaxFormBytes {
		return nil, ambiguous("form body larger than %d bytes", domain.MaxFormBytes)
	}
	out := map[string]any{}
	if len(raw) == 0 {
		return out, nil
	}
	pairs := strings.Split(string(raw), "&")
	if len(pairs) > domain.MaxFormKeys {
		return nil, ambiguous("form body with more than %d pairs", domain.MaxFormKeys)
	}
	seen := map[string]bool{}
	var keys []string
	for _, pair := range pairs {
		rk, rv, ok := strings.Cut(pair, "=")
		if !ok || rk == "" {
			return nil, ambiguous("form pair %q is not key=value", clipped(pair))
		}
		k, err := formUnescape(rk)
		if err != nil {
			return nil, err
		}
		v, err := formUnescape(rv)
		if err != nil {
			return nil, err
		}
		fk, err := domain.ParseFormKey(k)
		if err != nil {
			return nil, ambiguous("%v", err)
		}
		if seen[k] && !fk.List {
			return nil, ambiguous("form key %q appears twice", clipped(k))
		}
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
		if err := place(out, fk, v); err != nil {
			return nil, err
		}
	}
	if err := domain.CheckFormKeys(keys); err != nil {
		return nil, ambiguous("%v", err)
	}
	return out, nil
}

// checkFormType accepts the form media type, with charset=utf-8 at most.
func checkFormType(ct string) error {
	mt, params, err := mime.ParseMediaType(ct)
	if err != nil || mt != FormContentType {
		return ambiguous("a form mapping reads %s only", FormContentType)
	}
	for k, v := range params {
		if k != "charset" || !strings.EqualFold(v, "utf-8") {
			return ambiguous("a form body takes no media type parameter but charset=utf-8")
		}
	}
	return nil
}

// formUnescape decodes one key or value: + is a space, escapes must be
// valid, and the text must be valid UTF-8 without control characters.
func formUnescape(s string) (string, error) {
	v, err := url.QueryUnescape(s)
	if err != nil {
		return "", ambiguous("form escape in %q", clipped(s))
	}
	if !utf8.ValidString(v) || strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "", ambiguous("form text that is not UTF-8 or holds a control character")
	}
	return v, nil
}

// place puts one decoded value at its key's path.
func place(out map[string]any, k domain.FormKey, v string) error {
	obj := out
	for i, name := range k.Path {
		last := i == len(k.Path)-1
		cur, exists := obj[name]
		switch {
		case !last:
			if !exists {
				next := map[string]any{}
				obj[name] = next
				obj = next
				continue
			}
			next, ok := cur.(map[string]any)
			if !ok {
				return ambiguous("form key %q is both a value and an object", name)
			}
			obj = next
		case k.List:
			if !exists {
				obj[name] = []any{v}
				return nil
			}
			list, ok := cur.([]any)
			if !ok {
				return ambiguous("form key %q is both a list and something else", name)
			}
			if len(list) >= domain.MaxFormKeys {
				return ambiguous("form list %q too long", name)
			}
			obj[name] = append(list, v)
		default:
			if exists {
				return ambiguous("form key %q is both a value and something else", name)
			}
			obj[name] = v
		}
	}
	return nil
}

// clipped shortens untrusted text for an error message.
func clipped(s string) string {
	for i := range s {
		if i >= 64 {
			return s[:i] + "…"
		}
	}
	return s
}
