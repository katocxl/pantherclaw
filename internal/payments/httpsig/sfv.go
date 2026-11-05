// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package httpsig

import (
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
)

// A minimal RFC 8941 structured field parser and serializer: the
// dictionaries of Signature-Input and Signature, and the string of
// Signature-Agent. Anything it does not understand is an error.

var errSyntax = errors.New("httpsig: structured field syntax")

// bareKind is a bare item's type.
type bareKind int

const (
	kindInteger bareKind = iota + 1
	kindString
	kindToken
	kindBytes
	kindBool
)

// bare is a bare item.
type bare struct {
	kind  bareKind
	i     int64
	s     string // string or token
	b     []byte
	t     bool
	valid bool
}

// param is one parameter, in order.
type param struct {
	name  string
	value bare
}

// member is one dictionary member: an item or an inner list of items.
type member struct {
	name   string
	inner  bool
	item   bare
	list   []bare // inner list items
	lparam [][]param
	params []param
}

type parser struct {
	s   string
	pos int
}

func (p *parser) eof() bool { return p.pos >= len(p.s) }

func (p *parser) peek() byte {
	if p.eof() {
		return 0
	}
	return p.s[p.pos]
}

func (p *parser) ows() {
	for !p.eof() && (p.s[p.pos] == ' ' || p.s[p.pos] == '\t') {
		p.pos++
	}
}

func (p *parser) sp() {
	for !p.eof() && p.s[p.pos] == ' ' {
		p.pos++
	}
}

// parseDictionary parses an RFC 8941 dictionary, keeping member order. A
// duplicated name is an error (the later would silently win otherwise).
func parseDictionary(s string) ([]member, error) {
	p := &parser{s: strings.TrimSpace(s)}
	var out []member
	seen := map[string]bool{}
	for !p.eof() {
		name, err := p.key()
		if err != nil {
			return nil, err
		}
		if seen[name] {
			return nil, errSyntax
		}
		seen[name] = true
		m := member{name: name}
		if p.peek() == '=' {
			p.pos++
			if p.peek() == '(' {
				m.inner = true
				if m.list, m.lparam, err = p.innerList(); err != nil {
					return nil, err
				}
			} else if m.item, err = p.bareItem(); err != nil {
				return nil, err
			}
		} else {
			m.item = bare{kind: kindBool, t: true, valid: true}
		}
		if m.params, err = p.parameters(); err != nil {
			return nil, err
		}
		out = append(out, m)
		p.ows()
		if p.eof() {
			break
		}
		if p.peek() != ',' {
			return nil, errSyntax
		}
		p.pos++
		p.ows()
		if p.eof() {
			return nil, errSyntax
		}
	}
	return out, nil
}

func (p *parser) key() (string, error) {
	start := p.pos
	if c := p.peek(); (c < 'a' || c > 'z') && c != '*' {
		return "", errSyntax
	}
	for !p.eof() {
		c := p.s[p.pos]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' || c == '*' {
			p.pos++
			continue
		}
		break
	}
	return p.s[start:p.pos], nil
}

func (p *parser) innerList() ([]bare, [][]param, error) {
	p.pos++ // (
	var items []bare
	var params [][]param
	for {
		p.sp()
		if p.peek() == ')' {
			p.pos++
			return items, params, nil
		}
		it, err := p.bareItem()
		if err != nil {
			return nil, nil, err
		}
		ps, err := p.parameters()
		if err != nil {
			return nil, nil, err
		}
		items, params = append(items, it), append(params, ps)
		if c := p.peek(); c != ' ' && c != ')' {
			return nil, nil, errSyntax
		}
	}
}

func (p *parser) parameters() ([]param, error) {
	var out []param
	for p.peek() == ';' {
		p.pos++
		p.sp()
		name, err := p.key()
		if err != nil {
			return nil, err
		}
		v := bare{kind: kindBool, t: true, valid: true}
		if p.peek() == '=' {
			p.pos++
			if v, err = p.bareItem(); err != nil {
				return nil, err
			}
		}
		for _, q := range out {
			if q.name == name {
				return nil, errSyntax
			}
		}
		out = append(out, param{name: name, value: v})
	}
	return out, nil
}

func (p *parser) bareItem() (bare, error) {
	c := p.peek()
	switch {
	case c == '-' || (c >= '0' && c <= '9'):
		start := p.pos
		if c == '-' {
			p.pos++
		}
		for !p.eof() && p.s[p.pos] >= '0' && p.s[p.pos] <= '9' {
			p.pos++
		}
		if p.peek() == '.' {
			return bare{}, errSyntax // decimals are never used here
		}
		digits := p.s[start:p.pos]
		if len(strings.TrimPrefix(digits, "-")) == 0 || len(strings.TrimPrefix(digits, "-")) > 15 {
			return bare{}, errSyntax
		}
		n, err := strconv.ParseInt(digits, 10, 64)
		if err != nil {
			return bare{}, errSyntax
		}
		return bare{kind: kindInteger, i: n, valid: true}, nil
	case c == '"':
		p.pos++
		var b strings.Builder
		for {
			if p.eof() {
				return bare{}, errSyntax
			}
			ch := p.s[p.pos]
			p.pos++
			switch {
			case ch == '\\':
				if p.eof() {
					return bare{}, errSyntax
				}
				n := p.s[p.pos]
				if n != '"' && n != '\\' {
					return bare{}, errSyntax
				}
				b.WriteByte(n)
				p.pos++
			case ch == '"':
				return bare{kind: kindString, s: b.String(), valid: true}, nil
			case ch < 0x20 || ch > 0x7e:
				return bare{}, errSyntax
			default:
				b.WriteByte(ch)
			}
		}
	case c == ':':
		p.pos++
		end := strings.IndexByte(p.s[p.pos:], ':')
		if end < 0 {
			return bare{}, errSyntax
		}
		raw, err := base64.StdEncoding.DecodeString(p.s[p.pos : p.pos+end])
		if err != nil {
			return bare{}, errSyntax
		}
		p.pos += end + 1
		return bare{kind: kindBytes, b: raw, valid: true}, nil
	case c == '?':
		p.pos++
		switch p.peek() {
		case '1':
			p.pos++
			return bare{kind: kindBool, t: true, valid: true}, nil
		case '0':
			p.pos++
			return bare{kind: kindBool, valid: true}, nil
		}
		return bare{}, errSyntax
	case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '*':
		start := p.pos
		for !p.eof() {
			ch := p.s[p.pos]
			if ch <= ' ' || ch >= 0x7f || strings.IndexByte(`"(),;<=>?@[\]{}`, ch) >= 0 {
				break
			}
			p.pos++
		}
		return bare{kind: kindToken, s: p.s[start:p.pos], valid: true}, nil
	}
	return bare{}, errSyntax
}

// serialize writes a bare item (RFC 8941 §4.1.3).
func (b bare) serialize(sb *strings.Builder) {
	switch b.kind {
	case kindInteger:
		sb.WriteString(strconv.FormatInt(b.i, 10))
	case kindString:
		sb.WriteByte('"')
		for i := range len(b.s) {
			if b.s[i] == '"' || b.s[i] == '\\' {
				sb.WriteByte('\\')
			}
			sb.WriteByte(b.s[i])
		}
		sb.WriteByte('"')
	case kindToken:
		sb.WriteString(b.s)
	case kindBytes:
		sb.WriteByte(':')
		sb.WriteString(base64.StdEncoding.EncodeToString(b.b))
		sb.WriteByte(':')
	case kindBool:
		if b.t {
			sb.WriteString("?1")
		} else {
			sb.WriteString("?0")
		}
	}
}

func serializeParams(sb *strings.Builder, ps []param) {
	for _, p := range ps {
		sb.WriteByte(';')
		sb.WriteString(p.name)
		if p.value.kind == kindBool && p.value.t {
			continue
		}
		sb.WriteByte('=')
		p.value.serialize(sb)
	}
}

// serializeInner writes an inner list with its parameters: the value of
// @signature-params (RFC 9421 §2.3).
func (m member) serializeInner() string {
	var sb strings.Builder
	sb.WriteByte('(')
	for i, it := range m.list {
		if i > 0 {
			sb.WriteByte(' ')
		}
		it.serialize(&sb)
		serializeParams(&sb, m.lparam[i])
	}
	sb.WriteByte(')')
	serializeParams(&sb, m.params)
	return sb.String()
}

// parseString parses a header that is one sf-string.
func parseString(s string) (string, error) {
	p := &parser{s: strings.TrimSpace(s)}
	b, err := p.bareItem()
	if err != nil || b.kind != kindString {
		return "", errSyntax
	}
	if _, err := p.parameters(); err != nil || !p.eof() {
		return "", errSyntax
	}
	return b.s, nil
}
