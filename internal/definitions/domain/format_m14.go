// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Encoding is how an HTTP body is written: JSON, or a form (G0 M14 D8).
type Encoding string

// Encodings. The empty encoding is JSON. aws-json and aws-query are AWS's
// protocols (G0 M20 D254): a JSON body as application/x-amz-json-1.1 with
// the operation in a fixed X-Amz-Target header, and a flat form body whose
// fixed Action and Version name the operation, answered in XML. Both are
// POSTs to the service's root path.
const (
	EncodingDefault  Encoding = ""
	EncodingJSON     Encoding = "json"
	EncodingForm     Encoding = "form"
	EncodingAWSJSON  Encoding = "aws-json"
	EncodingAWSQuery Encoding = "aws-query"
)

// AWS returns whether e is one of AWS's protocols.
func (e Encoding) AWS() bool { return e == EncodingAWSJSON || e == EncodingAWSQuery }

// AWS protocol details (D254): the media types of aws-json bodies (1.1
// sent, 1.0 or 1.1 read) and the header that names an aws-json operation.
const (
	AWSJSONContentType = "application/x-amz-json-1.1"
	AWSQueryType       = "application/x-www-form-urlencoded; charset=utf-8"
	AWSTargetHeader    = "X-Amz-Target"
)

// AWSJSONContentTypes are the aws-json media types a mapping reads.
var AWSJSONContentTypes = []string{"application/x-amz-json-1.0", AWSJSONContentType}

// RootPath is the only path an aws-json or aws-query template has.
const RootPath = "/"

// SuccessCheck is a top-level JSON boolean a 2xx answer must carry (D8).
type SuccessCheck struct {
	Field  string `json:"field"`
	Equals bool   `json:"equals"`
}

// SQLDispatch is a structured read of a postgres connection (D9, D16).
type SQLDispatch struct {
	Operation string `json:"operation"`
}

// A2ADispatch is a call to a peer agent by A2A method (D9, D31).
type A2ADispatch struct {
	Method string `json:"method"`
}

// SQLOperations are the structured reads a postgres connection serves.
var SQLOperations = []string{"rows", "aggregate", "tables"}

// A2AMethods are the A2A 1.0 methods the gateway mediates (D31).
var A2AMethods = []string{"SendMessage", "SendStreamingMessage", "GetTask", "ListTasks", "CancelTask", "SubscribeToTask"}

const maxStaticHeaders = 8

// staticHeaderRe is a static header's literal value (D8): printable ASCII
// without braces, so it can never read as a reference.
var staticHeaderRe = regexp.MustCompile(`^[\x20-\x7a\x7c\x7e]{1,128}$`)

// Form limits (D8): the form key grammar is shared by the agent-facing
// parser, the outbound builder and package validation.
const (
	MaxFormDepth = 3
	MaxFormKeys  = 256
	MaxFormBytes = 64 << 10
)

var (
	formRootRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	formSegRe  = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	digitsRe   = regexp.MustCompile(`^[0-9]+$`)
)

// ErrFormKey reports a form key outside the grammar.
var ErrFormKey = errors.New("form key")

// FormKey is a parsed form key: its names from the root, and whether it
// ends in [] (a list).
type FormKey struct {
	Path []string
	List bool
}

// ParseFormKey parses a decoded form key: a root name, then bracketed
// names, then optionally [] for a list, at most MaxFormDepth levels in all
// (a, a[b], a[b][c], a[], a[b][]). A name of digits only (a[0]) is refused:
// it could be an index or a key, and ambiguity is refused, never guessed
// (HR-300).
func ParseFormKey(k string) (FormKey, error) {
	root, rest, bracket := strings.Cut(k, "[")
	if !formRootRe.MatchString(root) {
		return FormKey{}, fmt.Errorf("%w %q: the root must be a name", ErrFormKey, k)
	}
	out := FormKey{Path: []string{root}}
	if !bracket {
		return out, nil
	}
	rest = "[" + rest
	for rest != "" {
		if out.List {
			return FormKey{}, fmt.Errorf("%w %q: [] ends a key", ErrFormKey, k)
		}
		end := strings.IndexByte(rest, ']')
		if rest[0] != '[' || end < 0 {
			return FormKey{}, fmt.Errorf("%w %q: brackets must pair", ErrFormKey, k)
		}
		seg := rest[1:end]
		rest = rest[end+1:]
		switch {
		case seg == "":
			out.List = true
		case formSegRe.MatchString(seg) && !digitsRe.MatchString(seg):
			out.Path = append(out.Path, seg)
		default:
			return FormKey{}, fmt.Errorf("%w %q: a bracket name is letters, digits, _ . or - and not digits only", ErrFormKey, k)
		}
	}
	depth := len(out.Path)
	if out.List {
		depth++
	}
	if depth > MaxFormDepth {
		return FormKey{}, fmt.Errorf("%w %q: deeper than %d", ErrFormKey, k, MaxFormDepth)
	}
	return out, nil
}

// CheckFormKeys checks that distinct keys make one unambiguous document: no
// key is both a value and the parent of another (a and a[b]), and none is
// both a value and a list (a[b] and a[b][]).
func CheckFormKeys(keys []string) error {
	leaves := map[string]bool{}
	parents := map[string]bool{}
	for _, k := range keys {
		p, err := ParseFormKey(k)
		if err != nil {
			return err
		}
		for i := 1; i < len(p.Path); i++ {
			parents[strings.Join(p.Path[:i], "\x00")] = true
		}
		leaf := strings.Join(p.Path, "\x00")
		if leaves[leaf] {
			return fmt.Errorf("%w: %q is both a value and a list", ErrFormKey, k)
		}
		leaves[leaf] = true
	}
	for leaf := range leaves {
		if parents[leaf] {
			return fmt.Errorf("%w: %q is both a value and an object", ErrFormKey, strings.ReplaceAll(leaf, "\x00", "."))
		}
	}
	return nil
}

// Binding operators (G0 M14 D48).
const (
	BindEq = "eq"
	BindLe = "le"
)

// ResponseSpec is a definition's answer (G0 M14 D9): its format, and the
// data class of the fields that are not public.
type ResponseSpec struct {
	Format string          `json:"format"`
	Fields []ResponseField `json:"fields,omitzero"`
}

// ResponseField classifies one answer field: a dotted path into a JSON
// answer (* for every item of an array), or a column of rows. A path that
// names an object or an array classifies its whole subtree; where several
// fields cover one value, the strictest class wins (G0 M14 D73).
type ResponseField struct {
	Path  string `json:"path"`
	Class string `json:"class"`
}

// Response formats, data classes and scoping kinds (D9, D11).
var (
	ResponseFormats = []string{"json", "rows"}
	DataClasses     = []string{"public", "internal", "pii", "secret"}
	ScopingKinds    = []string{"records", "classes"}
)

const (
	maxResponseFields = 64
	maxResponseDepth  = 8
)

var responseSegRe = regexp.MustCompile(`^([A-Za-z0-9_-]{1,64}|\*)$`)

func (d *Definition) validateResponse() error {
	at := d.Operation
	if r := d.Response; r != nil {
		if !slices.Contains(ResponseFormats, r.Format) || len(r.Fields) > maxResponseFields {
			return invalid("%s: response.format must be json or rows, with at most %d fields", at, maxResponseFields)
		}
		for i, f := range r.Fields {
			segs := strings.Split(f.Path, ".")
			if len(segs) > maxResponseDepth || slices.ContainsFunc(segs, func(s string) bool { return !responseSegRe.MatchString(s) }) ||
				slices.ContainsFunc(r.Fields[:i], func(g ResponseField) bool { return g.Path == f.Path }) ||
				!slices.Contains(DataClasses, f.Class) {
				return invalid("%s: response.fields[%d]: a distinct dotted path (* for array items) and a class of %v", at, i, DataClasses)
			}
		}
	}
	if len(d.Scoping) > 0 && d.Access != AccessRead {
		return invalid("%s: only a read can enforce a data scope", at)
	}
	for i, s := range d.Scoping {
		if !slices.Contains(ScopingKinds, s) || slices.Contains(d.Scoping[:i], s) {
			return invalid("%s: scoping is a set of %v", at, ScopingKinds)
		}
	}
	return nil
}

// CredentialMatches reports whether an opened credential matches the
// dispatch's credential pattern (G0 M14 D8, HR-301); true when there is no
// pattern. It reads the bytes in place, never as a copied string.
func (x *Dispatch) CredentialMatches(credential []byte) bool {
	if x == nil || x.CredentialPattern == "" {
		return true
	}
	re := compiled(x.CredentialPattern)
	return re != nil && re.Match(credential)
}

// classRank orders the data classes from the most open to the strictest.
var classRank = map[string]int{"public": 0, "internal": 1, "pii": 2, "secret": 3}

// Stricter is the stricter of two data classes.
func Stricter(a, b string) string {
	if classRank[b] > classRank[a] {
		return b
	}
	return a
}

// ClassOf is the data class of the answer value at path (G0 M14 D73): the
// strictest class of every declared field whose path is the value's path
// or one of its ancestors, public when none is. A path segment is an
// object member's name, or * for an array item; a declared * matches any
// segment.
func (r *ResponseSpec) ClassOf(path []string) string {
	class := "public"
	if r == nil {
		return class
	}
	for _, f := range r.Fields {
		segs := strings.Split(f.Path, ".")
		if len(segs) > len(path) {
			continue
		}
		covers := true
		for i, s := range segs {
			if s != "*" && s != path[i] {
				covers = false
				break
			}
		}
		if covers {
			class = Stricter(class, f.Class)
		}
	}
	return class
}
