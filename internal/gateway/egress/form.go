// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package egress

import (
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
)

// Body media types.
const (
	JSONContentType = "application/json"
	FormContentType = "application/x-www-form-urlencoded"
)

var errForm = errors.New("egress: form body")

// EncodeForm writes a resolved body as application/x-www-form-urlencoded
// (G0 M14 D8): keys sorted, each key and value escaped per RFC 3986 (every
// byte but the unreserved ones is %XX, so a space is %20 and brackets are
// %5B and %5D), a list under its key ending in [] once per item in order.
// The keys are the reviewed template's, checked again against the form
// grammar; values are strings, integers or booleans, and a list only under
// a [] key. Nothing comes from the agent's original request.
func EncodeForm(obj map[string]any) ([]byte, error) {
	keys := slices.Sorted(maps.Keys(obj))
	if err := defs.CheckFormKeys(keys); err != nil {
		return nil, fmt.Errorf("%w: %w", errForm, err)
	}
	var b strings.Builder
	write := func(k, v string) {
		if b.Len() > 0 {
			b.WriteByte('&')
		}
		b.WriteString(escape3986(k))
		b.WriteByte('=')
		b.WriteString(escape3986(v))
	}
	for _, k := range keys {
		list := strings.HasSuffix(k, "[]")
		switch v := obj[k].(type) {
		case []string:
			if !list {
				return nil, fmt.Errorf("%w: a list under %q", errForm, k)
			}
			for _, item := range v {
				write(k, item)
			}
			continue
		case string:
			write(k, v)
		case jsontext.Value: // an integer
			write(k, string(v))
		case bool:
			write(k, strconv.FormatBool(v))
		default:
			return nil, fmt.Errorf("%w: %q is not a form value", errForm, k)
		}
	}
	if b.Len() > defs.MaxFormBytes {
		return nil, fmt.Errorf("%w: larger than %d bytes", errForm, defs.MaxFormBytes)
	}
	return []byte(b.String()), nil
}

// escape3986 percent-encodes every byte that is not unreserved (RFC 3986
// §2.3: ALPHA DIGIT - . _ ~), with upper-case hex digits.
func escape3986(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := range len(s) {
		c := s[i]
		if ('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z') || ('0' <= c && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&0x0f])
	}
	return b.String()
}
