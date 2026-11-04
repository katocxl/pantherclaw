// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// HTTP dispatch extensions of G0 M31 D950: a JSON body key may build one
// object per item of a list ([*]) and may index an array ([0]); a GraphQL
// dispatch sends a fixed document the package reviewed with the body
// mapping as its variables; and the rfc5322-raw encoding builds a mail
// message from mapped fields and sends it base64url-encoded.

// EncodingRFC5322Raw sends {"raw": <base64url of an RFC 5322 message>}
// built by the gateway from the mapped fields to, cc, bcc, subject and
// text (D950 d). The body is text/plain; charset=utf-8.
const EncodingRFC5322Raw Encoding = "rfc5322-raw"

// The fields an rfc5322-raw body maps: the recipient lists, the subject
// and the plain text body.
const (
	MailTo      = "to"
	MailCc      = "cc"
	MailBcc     = "bcc"
	MailSubject = "subject"
	MailText    = "text"
)

// mailFields are the keys an rfc5322-raw body may map; mailLists are the
// ones that take an identifier_list.
var (
	mailFields = []string{MailBcc, MailCc, MailSubject, MailText, MailTo}
	mailLists  = []string{MailBcc, MailCc, MailTo}
)

// GraphQLDocument is a GraphQL dispatch's fixed document (D950 c): the
// request body is {"query": <Document>, "variables": <the body mapping>}.
// The document is the package's, reviewed and signed with it; the agent
// never supplies document text, only the values the mapping references.
type GraphQLDocument struct {
	Document string `json:"document"`
}

// MaxGraphQLDocument bounds a GraphQL document (4 KiB).
const MaxGraphQLDocument = 4 << 10

// JSON body key limits (D950 a, b): at most MaxJSONBodyDepth names from
// the root, an index at most MaxJSONIndex, and at most MaxEachItems
// objects built by one [*] key.
const (
	MaxJSONBodyDepth = 8
	MaxJSONIndex     = 63
	MaxEachItems     = 64
)

// EachSegment is the [*] segment of a JSON body key.
const EachSegment = "*"

var indexRe = regexp.MustCompile(`^(0|[1-9][0-9]?)$`)

// JSONSeg is one segment of a JSON body key after its root: an object
// member's name, an array index, or [*] (one object per list item).
type JSONSeg struct {
	Name  string
	Index int
	Kind  JSONSegKind
}

// JSONSegKind says what a JSONSeg is.
type JSONSegKind int

// JSON segment kinds.
const (
	SegName JSONSegKind = iota
	SegIndex
	SegEach
)

// JSONKey is a parsed JSON body key: its root name and its segments.
type JSONKey struct {
	Root string
	Segs []JSONSeg
}

// Each returns the position of the key's [*] segment, or -1.
func (k JSONKey) Each() int {
	return slices.IndexFunc(k.Segs, func(s JSONSeg) bool { return s.Kind == SegEach })
}

// ParseJSONBodyKey parses a JSON body key (D950 a, b; G0 M20 D260): a root
// name, then bracketed segments, each a member name (letters, digits,
// _ . or -, not digits only), an array index (0..63, no leading zero) or
// [*], at most one [*] and at most MaxJSONBodyDepth names in all. A key
// without brackets is a flat field. [] (a form list) is refused here.
func ParseJSONBodyKey(k string) (JSONKey, error) {
	root, rest, bracket := strings.Cut(k, "[")
	if !formRootRe.MatchString(root) {
		return JSONKey{}, fmt.Errorf("%w %q: the root must be a name", ErrFormKey, k)
	}
	out := JSONKey{Root: root}
	if !bracket {
		return out, nil
	}
	rest = "[" + rest
	each := false
	for rest != "" {
		end := strings.IndexByte(rest, ']')
		if rest[0] != '[' || end < 0 {
			return JSONKey{}, fmt.Errorf("%w %q: brackets must pair", ErrFormKey, k)
		}
		seg := rest[1:end]
		rest = rest[end+1:]
		switch {
		case seg == EachSegment:
			if each {
				return JSONKey{}, fmt.Errorf("%w %q: at most one [*]", ErrFormKey, k)
			}
			each = true
			out.Segs = append(out.Segs, JSONSeg{Kind: SegEach})
		case digitsRe.MatchString(seg):
			if !indexRe.MatchString(seg) {
				return JSONKey{}, fmt.Errorf("%w %q: an index is 0..%d without a leading zero", ErrFormKey, k, MaxJSONIndex)
			}
			n, _ := strconv.Atoi(seg)
			if n > MaxJSONIndex {
				return JSONKey{}, fmt.Errorf("%w %q: an index is 0..%d", ErrFormKey, k, MaxJSONIndex)
			}
			out.Segs = append(out.Segs, JSONSeg{Index: n, Kind: SegIndex})
		case formSegRe.MatchString(seg):
			out.Segs = append(out.Segs, JSONSeg{Name: seg, Kind: SegName})
		default:
			return JSONKey{}, fmt.Errorf("%w %q: a bracket is a name, an index or *", ErrFormKey, k)
		}
	}
	if 1+len(out.Segs) > MaxJSONBodyDepth {
		return JSONKey{}, fmt.Errorf("%w %q: deeper than %d", ErrFormKey, k, MaxJSONBodyDepth)
	}
	return out, nil
}

// jsonNode is one node of the document a JSON body's keys describe.
type jsonNode struct {
	leaf     bool
	names    map[string]*jsonNode
	indices  map[int]*jsonNode
	each     *jsonNode
	eachKeys int
}

func (n *jsonNode) child(s JSONSeg) *jsonNode {
	switch s.Kind {
	case SegName:
		if n.names == nil {
			n.names = map[string]*jsonNode{}
		}
		if n.names[s.Name] == nil {
			n.names[s.Name] = &jsonNode{}
		}
		return n.names[s.Name]
	case SegIndex:
		if n.indices == nil {
			n.indices = map[int]*jsonNode{}
		}
		if n.indices[s.Index] == nil {
			n.indices[s.Index] = &jsonNode{}
		}
		return n.indices[s.Index]
	case SegEach:
	}
	if n.each == nil {
		n.each = &jsonNode{}
	}
	n.eachKeys++
	return n.each
}

// check refuses a document that is ambiguous: a node that is both a value
// and a container, both an object and an array, an array whose indices
// leave a gap, or a [*] list that more than one key builds.
func (n *jsonNode) check(at string) error {
	kinds := 0
	for _, has := range []bool{n.leaf, n.names != nil, n.indices != nil, n.each != nil} {
		if has {
			kinds++
		}
	}
	if kinds > 1 {
		return fmt.Errorf("%w: %q is more than one of a value, an object, an indexed array and a [*] list", ErrFormKey, at)
	}
	if n.eachKeys > 1 {
		return fmt.Errorf("%w: %q: one key builds a [*] list", ErrFormKey, at)
	}
	for i := range len(n.indices) {
		if n.indices[i] == nil {
			return fmt.Errorf("%w: %q: array indices must run from 0 without a gap", ErrFormKey, at)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(n.names)) {
		if err := n.names[name].check(at + "[" + name + "]"); err != nil {
			return err
		}
	}
	for i := range len(n.indices) {
		if err := n.indices[i].check(at + "[" + strconv.Itoa(i) + "]"); err != nil {
			return err
		}
	}
	if n.each != nil {
		return n.each.check(at + "[*]")
	}
	return nil
}

// CheckJSONBodyKeys checks that distinct JSON body keys make one
// unambiguous document (D950 a, b; G0 M20 D260).
func CheckJSONBodyKeys(keys []string) error {
	root := &jsonNode{}
	for _, k := range keys {
		p, err := ParseJSONBodyKey(k)
		if err != nil {
			return err
		}
		n := root.child(JSONSeg{Name: p.Root})
		for _, s := range p.Segs {
			n = n.child(s)
		}
		if n.leaf {
			return fmt.Errorf("%w: %q twice", ErrFormKey, k)
		}
		n.leaf = true
	}
	return root.check("")
}

// jsonBody reports whether a body of this encoding is a plain JSON
// document, which takes the D950 key grammar.
func jsonBody(enc Encoding) bool { return enc == EncodingDefault || enc == EncodingJSON }

// checkJSONBodyRefs checks what a JSON body's keys reference: a [*] key
// takes an identifier_list param, and only such a key does (D950 a).
func (d *Definition) checkJSONBodyRefs(at string, f map[string]string) error {
	for _, k := range slices.Sorted(maps.Keys(f)) {
		p, err := ParseJSONBodyKey(k)
		if err != nil {
			return invalid("%s: field name %q: %v", at, k, err)
		}
		if p.Each() < 0 {
			continue
		}
		name, isParam := strings.CutPrefix(f[k], "params.")
		if !isParam || d.Params[name].Type != TypeIdentifierList {
			return invalid("%s.%s: a [*] key takes an identifier_list param", at, k)
		}
		if d.Params[name].MaxItems > MaxEachItems {
			return invalid("%s.%s: a [*] list builds at most %d objects; declare max_items %d or fewer", at, k, MaxEachItems, MaxEachItems)
		}
	}
	return nil
}

// validateMailDispatch checks an rfc5322-raw template (D950 d): a POST
// whose body maps only to, cc, bcc (identifier_list params), subject and
// text, with to always mapped. The gateway builds the message; no header
// other than these is ever written.
func (d *Definition) validateMailDispatch(at string, h *HTTPDispatch) error {
	if h.Method != methodPost || h.GraphQL != nil {
		return invalid("%s: rfc5322-raw is a POST without a GraphQL document", at)
	}
	if _, ok := h.Body[MailTo]; !ok {
		return invalid("%s.body: rfc5322-raw maps %q", at, MailTo)
	}
	for _, k := range slices.Sorted(maps.Keys(h.Body)) {
		if !slices.Contains(mailFields, k) {
			return invalid("%s.body.%s: rfc5322-raw maps only %v", at, k, mailFields)
		}
		name, isParam := strings.CutPrefix(h.Body[k], "params.")
		if !isParam {
			return invalid("%s.body.%s: rfc5322-raw maps params only", at, k)
		}
		list := d.Params[name].Type == TypeIdentifierList
		if list != slices.Contains(mailLists, k) {
			return invalid("%s.body.%s: to, cc and bcc take an identifier_list; subject and text take one value", at, k)
		}
		if t := d.Params[name].Type; !list && t != TypeContent && t != TypeEnum && t != TypeIdentifier {
			return invalid("%s.body.%s: subject and text take a content, enum or identifier param", at, k)
		}
	}
	return nil
}

// validateGraphQL checks a GraphQL template (D950 c): a JSON POST whose
// document is fixed text of at most 4 KiB, a query or a mutation.
func validateGraphQL(at string, h *HTTPDispatch) error {
	g := h.GraphQL
	if h.Method != methodPost || !jsonBody(h.Encoding) {
		return invalid("%s: a GraphQL document is sent in a JSON POST", at)
	}
	doc := strings.TrimSpace(g.Document)
	if doc == "" || len(g.Document) > MaxGraphQLDocument || !utf8.ValidString(g.Document) ||
		strings.ContainsFunc(g.Document, func(r rune) bool { return (r < 0x20 && r != '\t' && r != '\n' && r != '\r') || r == 0x7f }) {
		return invalid("%s.graphql.document: 1..%d bytes of UTF-8 text without control characters", at, MaxGraphQLDocument)
	}
	if !strings.HasPrefix(doc, "query") && !strings.HasPrefix(doc, "mutation") && !strings.HasPrefix(doc, "{") {
		return invalid("%s.graphql.document: a query or a mutation (never a subscription)", at)
	}
	return nil
}

// mailAddressUnsafe are the bytes a mail address in an rfc5322-raw message
// never holds: line breaks (a header injection, PARAM_INVALID) and the
// separators that would add a recipient the list does not name.
const mailAddressUnsafe = "\r\n,;<>()\"\\ \t"

// CheckMailHeaders refuses an rfc5322-raw action whose header values could
// write another header (D950 d): a line break in an address or the
// subject, or an address holding a separator. The gateway checks the same
// again when it builds the message.
func (d *Definition) CheckMailHeaders(vals Values) error {
	if d.Dispatch == nil || d.Dispatch.HTTP == nil || d.Dispatch.HTTP.Encoding != EncodingRFC5322Raw {
		return nil
	}
	for _, k := range slices.Sorted(maps.Keys(d.Dispatch.HTTP.Body)) {
		name := strings.TrimPrefix(d.Dispatch.HTTP.Body[k], "params.")
		v, ok := vals[name]
		if !ok {
			continue
		}
		switch {
		case slices.Contains(mailLists, k):
			for _, a := range v.List {
				if a == "" || strings.ContainsAny(a, mailAddressUnsafe) {
					return ambiguous("%s: a mail address holds a line break or a separator (PARAM_INVALID)", name)
				}
			}
		case k == MailSubject:
			if strings.ContainsAny(v.Str, "\r\n") {
				return ambiguous("%s: a line break in the subject (PARAM_INVALID)", name)
			}
		}
	}
	return nil
}
